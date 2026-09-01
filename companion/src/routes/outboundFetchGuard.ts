import { lookup } from "node:dns/promises";
import { Agent, type Dispatcher } from "undici";
import { isInternalTarget } from "../analysis/iocValue.js";
import { isGloballyRoutable } from "./publicAddress.js";

// Guarded outbound fetch for routes that take a URL from the caller (issue #760).
//
// PROBLEM. POST /kev/import-url handed req.body.url straight to fetch(). The route is global-admin
// gated, but "may administer the companion" is not "may make the companion connect to
// http://169.254.169.254/ and report what it found". Anything the host can reach — cloud instance
// credentials, an internal Grafana, a management port — was one request body away, and the reply
// came back through the route's error message.
//
// FIX. Four checks, all of which have to hold for every hop:
//   1. SCHEME. https:// only. http:// travels in the clear and is the spelling every SSRF payload
//      reaches for first; it needs the operator opt-in below.
//   2. LITERAL ADDRESS. isInternalTarget() (analysis/iocValue.ts) already classifies loopback,
//      RFC1918, CGNAT, link-local, 0.0.0.0, IPv6 unique-local/link-local and IPv4-mapped IPv6 in
//      both its spellings. Reused rather than re-derived, so this guard cannot drift from the one
//      the enrichment service uses.
//   3. RESOLVED ADDRESS, AGAINST DELEGATED SPACE. The literal check stops at the URL text, so a
//      hostname is still free to point wherever its owner likes — a cloud provider's metadata
//      alias, or an A record the attacker controls. Resolve it, and require every address to sit in
//      space IANA has actually delegated (see routes/publicAddress.ts). An allowlist, so a range
//      nobody thought of is refused by default rather than permitted: that is what 240.0.0.0/4,
//      198.18.0.0/15, NAT64, 3fff::/20 and the whole unallocated half of 2000::/3 each relied on.
//   4. PINNED CONNECTION. Checks 1-3 all describe a name. The socket is opened by a SECOND
//      resolution inside fetch, and a DNS record with a one-second TTL can answer differently in
//      each — public to the check, 169.254.169.254 to the connect. That is DNS rebinding, and it
//      defeats every name-based check ever written. So the connection is pinned: the request goes
//      out through an undici Agent whose lookup returns ONLY the addresses check 3 approved, which
//      means the socket cannot land anywhere else no matter what DNS says a millisecond later.
//      The whole approved set is handed over rather than one of it, so undici keeps its ordinary
//      address fallback and a dual-stack host stays reachable when only one family works here.
//      TLS is unaffected — only the address is overridden, so SNI and certificate verification
//      still run against the hostname, and an https:// URL still fails on a bad certificate.
//
// FAIL CLOSED ON RESOLUTION FAILURE. An earlier version of this module let an unresolvable host
// through unpinned, reasoning that a name which will not resolve here will not resolve for the
// fetch either. That reasoning is wrong, because WHO DECIDES the lookup fails is the attacker: the
// authoritative nameserver for their own domain can answer SERVFAIL to this query and 169.254.169.254
// to the one fetch makes a millisecond later. A failure was therefore a way to skip check 3 AND
// check 4 together, which is the whole hostname defence. So resolution failure — and an empty
// answer, which a resolver may return instead of throwing — is a refusal.
//
// The invariant that falls out, and the one to preserve when editing this file: OUTSIDE the
// operator opt-in, a request is never sent without a pin. `pins: null` means allowInternal, nothing
// else. The message names DNS as the cause so a genuine outage is not mistaken for a policy block.
//
// The deadline covers resolution too. A lookup takes no AbortSignal, so an earlier version left the
// one step whose duration the far side chooses outside the budget it advertised — see withDeadline.

/** The URL was refused before any bytes left the host. The message names the rule that refused it,
 *  never an address it resolved to — that is the internal detail the guard exists to withhold. */
export class OutboundUrlBlockedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "OutboundUrlBlockedError";
  }
}

/** One resolved address, and the family net.connect needs to use it. */
export interface PinnedAddress {
  address: string;
  family: number;
}

export interface OutboundFetchOptions {
  /** Budget for the WHOLE redirect chain, not per hop. Default 30s. */
  timeoutMs?: number;
  /** Hops followed before giving up. Default 5. */
  maxRedirects?: number;
  /** Operator opt-in: permit http:// and private/loopback/link-local targets (an internal mirror). */
  allowInternal?: boolean;
  /** Injected by tests so they never touch real DNS. Defaults to a DNS A/AAAA lookup. */
  resolveHost?: (host: string) => Promise<PinnedAddress[]>;
  /** Injected by tests. Defaults to the global fetch. */
  fetchImpl?: typeof fetch;
  /** Injected by tests to observe what the connection was pinned to. Defaults to an undici Agent. */
  agentFactory?: (pins: PinnedAddress[]) => Dispatcher;
}

export interface OutboundFetchResult {
  response: Response;
  /** The URL the bytes actually came from — the last hop, not necessarily the one asked for. */
  url: URL;
  /** Tears down the pinned connection. Call it once the body has been read, in a finally. */
  dispose: () => Promise<void>;
}

const REDIRECT_STATUS = new Set([301, 302, 303, 307, 308]);
const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_REDIRECTS = 5;

async function resolveViaDns(host: string): Promise<PinnedAddress[]> {
  return (await lookup(host, { all: true })).map((r) => ({ address: r.address, family: r.family }));
}

// The address test lives in routes/publicAddress.ts: an ALLOWLIST of the space IANA has delegated,
// because every denylist shape this was tried in permitted some range nobody had thought of. See
// that module's header for why it is a table rather than a chain of conditions.

/**
 * A net.connect-shaped lookup that ignores the hostname and answers with the addresses this
 * request was approved for.
 *
 * ALL of them, not just one. Every address in the set has already been checked, so handing over
 * the whole set keeps the guarantee identical while leaving undici its ordinary address fallback:
 * a dual-stack feed whose AAAA record sorts first would otherwise fail outright on an IPv4-only
 * deployment, even though its A record was checked and reachable.
 *
 * Both call shapes are handled: undici asks with `{ all: true }` on the happy-eyeballs path and
 * without it elsewhere, and answering the wrong shape makes the connect throw rather than fail
 * closed. The single-answer shape can only carry the first address; that is undici's constraint,
 * not a choice here.
 */
export type PinnedLookupCallback = (
  err: NodeJS.ErrnoException | null,
  address: string | PinnedAddress[],
  family?: number,
) => void;

export function pinnedLookup(
  pins: PinnedAddress[],
): (hostname: string, options: { all?: boolean }, callback: PinnedLookupCallback) => void {
  return (_hostname, options, callback) => {
    if (options?.all) {
      return callback(
        null,
        pins.map((p) => ({ address: p.address, family: p.family })),
      );
    }
    return callback(null, pins[0].address, pins[0].family);
  };
}

function defaultAgent(pins: PinnedAddress[]): Dispatcher {
  return new Agent({
    connect: { lookup: pinnedLookup(pins) },
    // One-shot fetch, not a pool: do not hold the socket open for a reuse that never comes.
    keepAliveTimeout: 1,
    keepAliveMaxTimeout: 1,
  });
}

/**
 * Races `work` against the chain's deadline.
 *
 * DNS resolution is not cancellable — `dns.promises.lookup` takes no signal — so a stalled lookup
 * would sit outside the AbortSignal that bounds the fetches and hold the request open past the
 * budget the caller asked for. Whoever runs the authoritative server for the name decides how long
 * that is. Racing does not stop the lookup, which runs to completion in the background and is then
 * discarded; it stops the REQUEST waiting on it, which is what the budget is about.
 */
async function withDeadline<T>(work: Promise<T>, signal: AbortSignal, what: string): Promise<T> {
  if (signal.aborted) throw new OutboundUrlBlockedError(`${what} exceeded the time budget`);
  let onAbort: (() => void) | undefined;
  try {
    return await Promise.race([
      work,
      new Promise<never>((_resolve, reject) => {
        onAbort = () => reject(new OutboundUrlBlockedError(`${what} exceeded the time budget`));
        signal.addEventListener("abort", onAbort, { once: true });
      }),
    ]);
  } finally {
    // Every hop races against the SAME signal, so a listener left behind would accumulate.
    if (onAbort) signal.removeEventListener("abort", onAbort);
  }
}

/** The URL, and the addresses the connection may be pinned to. `pins` is null in exactly one case —
 *  the operator opted into internal targets — and fetchOutbound enforces that (see the header). */
interface ValidatedTarget {
  url: URL;
  pins: PinnedAddress[] | null;
}

async function validateAndResolve(
  raw: string,
  opts: OutboundFetchOptions,
  signal: AbortSignal,
): Promise<ValidatedTarget> {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new OutboundUrlBlockedError("not a valid absolute URL");
  }

  const scheme = parsed.protocol.toLowerCase();
  const schemeOk = scheme === "https:" || (scheme === "http:" && opts.allowInternal === true);
  if (!schemeOk) {
    throw new OutboundUrlBlockedError(`the URL must use https: (got ${scheme})`);
  }
  // The operator has said this companion may talk to its own network, so there is nothing for the
  // address checks to decide and nothing to pin against.
  if (opts.allowInternal === true) return { url: parsed, pins: null };

  // Strip the brackets an IPv6 URL host carries — isInternalTarget classifies the address, not the
  // URL spelling of it.
  const host = parsed.hostname.replace(/^\[|\]$/g, "");
  // Three calls, because each covers a case the others do not: the url form handles the host inside
  // a URL, the bare form handles an address, and the domain form is the only one that recognises a
  // "*.localhost" subdomain.
  if (isInternalTarget(parsed.href, "url") || isInternalTarget(host) || isInternalTarget(host, "domain")) {
    throw new OutboundUrlBlockedError("the URL points at a loopback, private or link-local address");
  }

  const resolve = opts.resolveHost ?? resolveViaDns;
  let addresses: PinnedAddress[];
  try {
    // Under the SAME deadline as the fetches. A lookup takes no AbortSignal of its own, so without
    // this the documented whole-chain budget would not cover the one step whose duration the far
    // side chooses. A timeout here surfaces as OutboundUrlBlockedError, which the rethrow below
    // deliberately passes through rather than relabelling as a resolution failure.
    addresses = await withDeadline(resolve(host), signal, `resolving "${host}"`);
  } catch (err) {
    if (err instanceof OutboundUrlBlockedError) throw err;
    // Fail closed — see this module's header. The attacker picks when this happens.
    throw new OutboundUrlBlockedError(`the host "${host}" could not be resolved`);
  }
  // An empty answer is the same hole wearing a different hat: no address to check, none to pin to.
  if (addresses.length === 0) {
    throw new OutboundUrlBlockedError(`the host "${host}" could not be resolved`);
  }
  // The allowlist: EVERY address must be globally routable unicast. Checking every one, not just
  // the pinned one, keeps a host that answers with a mix of public and internal addresses from
  // being reachable at all — the pin would pick a safe one this time and a different one later.
  if (!addresses.every((a) => isGloballyRoutable(a.address))) {
    // Names the host the caller already gave us, never the address it pointed at.
    throw new OutboundUrlBlockedError(`the host "${host}" does not resolve to a public address`);
  }
  // Pin to the WHOLE checked set, not the first of it. Every address has passed the allowlist, so
  // handing over all of them costs nothing in guarantee and keeps undici's address fallback: a
  // host answering with both an A and an AAAA record stays reachable when only one family works
  // on this deployment. Non-empty — the empty case was refused above.
  return { url: parsed, pins: addresses };
}

/**
 * Parses and checks one URL. Returns the parsed URL when it is allowed; throws
 * OutboundUrlBlockedError when it is not. Call it for the URL the caller supplied AND for every
 * redirect target — a first-hop check alone is exactly the hole that makes redirect-based SSRF work.
 */
export async function assertOutboundUrlAllowed(raw: string, opts: OutboundFetchOptions = {}): Promise<URL> {
  // Its own deadline: this resolves a hostname too, so on its own it must not hang either.
  const signal = AbortSignal.timeout(opts.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  return (await validateAndResolve(raw, opts, signal)).url;
}

/**
 * fetch() with every redirect hop re-checked AND its connection pinned to the address that was
 * checked. Redirects are followed by hand (`redirect: "manual"`) because the automatic follow does
 * the one thing this module exists to prevent: connect to an address nothing checked.
 *
 * The caller MUST call result.dispose() once it has finished reading the body.
 */
export async function fetchOutbound(
  raw: string,
  opts: OutboundFetchOptions = {},
): Promise<OutboundFetchResult> {
  const doFetch = opts.fetchImpl ?? globalThis.fetch;
  const makeAgent = opts.agentFactory ?? defaultAgent;
  const maxRedirects = opts.maxRedirects ?? DEFAULT_MAX_REDIRECTS;
  // ONE signal for the whole chain, and it covers the DNS lookups as well as the fetches. A fresh
  // AbortSignal.timeout() per hop would let five hops spend five times the budget the caller asked
  // for; a signal that reached only the fetches would leave the step whose duration the far side
  // controls — resolution — outside the budget entirely.
  const signal = AbortSignal.timeout(opts.timeoutMs ?? DEFAULT_TIMEOUT_MS);

  const agents: Dispatcher[] = [];
  const dispose = async (): Promise<void> => {
    await Promise.all(agents.map((a) => Promise.resolve(a.close()).catch(() => {})));
  };

  try {
    let target = await validateAndResolve(raw, opts, signal);
    for (let hop = 0; ; hop += 1) {
      const init: RequestInit & { dispatcher?: Dispatcher } = { redirect: "manual", signal };
      if (target.pins) {
        const agent = makeAgent(target.pins);
        agents.push(agent);
        init.dispatcher = agent;
      } else if (opts.allowInternal !== true) {
        // The invariant from the module header, enforced rather than trusted: the ONLY reason to
        // send without a pin is the operator opt-in. If a future edit ever produces a null pin on
        // any other path, this refuses instead of quietly making an unchecked connection.
        throw new OutboundUrlBlockedError("the connection could not be pinned to a checked address");
      }
      const response = await doFetch(target.url, init);
      if (!REDIRECT_STATUS.has(response.status)) return { response, url: target.url, dispose };

      const location = response.headers.get("location");
      // Tear the hop down rather than leaving its body to be drained or to sit on the connection.
      await response.body?.cancel().catch(() => {});
      if (!location) {
        throw new OutboundUrlBlockedError(`redirect (HTTP ${response.status}) carried no Location header`);
      }
      if (hop >= maxRedirects) {
        throw new OutboundUrlBlockedError(`more than ${maxRedirects} redirects`);
      }
      let next: string;
      try {
        next = new URL(location, target.url).toString();
      } catch {
        throw new OutboundUrlBlockedError("the redirect Location is not a valid URL");
      }
      target = await validateAndResolve(next, opts, signal);
    }
  } catch (err) {
    // Nothing will read a body now, so the sockets opened on the way here are ours to close.
    await dispose();
    throw err;
  }
}
