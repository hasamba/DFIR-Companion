import { lookup } from "node:dns/promises";
import { isMetadataOrLinkLocalHost, metadataTargetError } from "../analysis/metadataTarget.js";

// The "LAN yes, metadata no" target policy (issue #2146), shared by every outbound sender whose
// destination an admin types: notification webhooks and the SMTP host here, audit-export HTTP and
// syslog destinations in #2147.
//
// The outbound guard (outboundFetchGuard.ts) was built for routes that fetch a feed from the
// internet, so its default policy is an allowlist of public address space. Those senders are
// different: a self-hosted Mattermost, an internal Splunk, or a syslog forwarder on 127.0.0.1 is
// the NORMAL target, so the allowlist would break them. Its existing escape hatch, allowInternal,
// is all-or-nothing and lets 169.254.169.254 through as well. This policy sits between the two:
//
//   - LAN, loopback and public addresses are allowed;
//   - cloud-metadata and link-local targets are refused (analysis/metadataTarget.ts), as a
//     literal BEFORE any lookup, and again for EVERY address a hostname resolves to;
//   - resolution failure, an empty answer, or a stalled lookup is a refusal (fail closed — the
//     owner of the name decides when the lookup fails, see outboundFetchGuard.ts's header);
//   - the caller connects to the addresses returned here, never to the name again (the pin).
//
// HTTP senders get this through fetchOutbound({ policy: "lan" }). Socket senders (SMTP, syslog)
// call resolveLanHost and connect to the address it returns.

/** The URL or host was refused before any bytes left the host. The message names the rule that
 *  refused it, never an address a name resolved to. */
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

/** "public": https only, globally routable addresses only (KEV, Velociraptor). "lan": http or
 *  https, anything except cloud-metadata and link-local (notification channels, audit export). */
export type OutboundPolicy = "public" | "lan";

/** TLS trust merged into the pinned connection (DFIR_NOTIFY_CA / DFIR_NOTIFY_INSECURE and kin). */
export interface OutboundTlsOptions {
  ca?: string;
  rejectUnauthorized?: boolean;
}

export type ResolveHost = (host: string) => Promise<PinnedAddress[]>;

export async function resolveViaDns(host: string): Promise<PinnedAddress[]> {
  return (await lookup(host, { all: true })).map((r) => ({ address: r.address, family: r.family }));
}

/** Throws when the host, as written, is a cloud-metadata or link-local target. Synchronous. */
export function assertLanHostLiteral(host: string): void {
  if (isMetadataOrLinkLocalHost(host)) throw new OutboundUrlBlockedError(metadataTargetError(host));
}

/** Throws unless `addresses` is non-empty and none of them is metadata or link-local. */
export function assertLanAddresses(host: string, addresses: readonly PinnedAddress[]): void {
  if (addresses.length === 0) throw new OutboundUrlBlockedError(`the host "${host}" could not be resolved`);
  // EVERY address, not just the one a connect would pick: a mixed answer would let a later
  // connection land on the bad one.
  if (addresses.some((a) => isMetadataOrLinkLocalHost(a.address))) {
    throw new OutboundUrlBlockedError(
      `the host "${host}" resolves to a cloud-metadata or link-local address, which is blocked`,
    );
  }
}

export interface ResolveLanHostOptions {
  /** Injected by tests so they never touch real DNS. Defaults to a DNS A/AAAA lookup. */
  resolveHost?: ResolveHost;
  /** Budget for the lookup. Default 15s. */
  timeoutMs?: number;
}

const DEFAULT_LOOKUP_TIMEOUT_MS = 15_000;

/**
 * Resolve `host` under the "lan" policy and return the checked addresses to connect to. For
 * socket senders (SMTP, syslog): connect to one of THESE, never to `host`, or a second lookup can
 * answer differently (DNS rebinding). Throws OutboundUrlBlockedError on refusal or lookup failure.
 */
export async function resolveLanHost(
  rawHost: string,
  opts: ResolveLanHostOptions = {},
): Promise<PinnedAddress[]> {
  const host = rawHost.trim().replace(/^\[|\]$/g, "");
  assertLanHostLiteral(host);
  const resolve = opts.resolveHost ?? resolveViaDns;
  const timeoutMs = opts.timeoutMs ?? DEFAULT_LOOKUP_TIMEOUT_MS;
  let timer: NodeJS.Timeout | undefined;
  let addresses: PinnedAddress[];
  try {
    addresses = await Promise.race([
      resolve(host),
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(
          () => reject(new OutboundUrlBlockedError(`resolving "${host}" exceeded the time budget`)),
          timeoutMs,
        );
      }),
    ]);
  } catch (err) {
    if (err instanceof OutboundUrlBlockedError) throw err;
    throw new OutboundUrlBlockedError(`the host "${host}" could not be resolved`);
  } finally {
    if (timer) clearTimeout(timer);
  }
  assertLanAddresses(host, addresses);
  return addresses;
}
