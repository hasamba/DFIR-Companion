import type { Request, RequestHandler, Response, NextFunction } from "express";

/**
 * Browser gate for the companion API (issues #211, #212), in two independent checks.
 *
 * Binding to 127.0.0.1 keeps other MACHINES out; it does nothing about other ORIGINS. A page on
 * any website you visit while the companion is running can issue cross-origin requests to
 * http://127.0.0.1:4773 — and the API once answered every one of them with
 * `Access-Control-Allow-Origin: *` plus a private-network opt-in. That turned "visited a web page"
 * into custom-tool creation and, from there, local process execution.
 *
 * ── Gate 1: the `Host` header ({@link isHostAllowed}) ─────────────────────────────────────────
 * This is the DNS-rebinding stop (CWE-346). An attacker points `evil.example` at 127.0.0.1, the
 * victim visits it, and the browser then believes it is talking to its OWN origin — so it applies
 * no same-origin policy and, on a GET, sends no `Origin` header at all. An origin check alone
 * cannot see that attack: there is no origin to judge, and the page reads every response body.
 *
 * What the attacker cannot do is change the `Host` header: the browser fills it in from the URL,
 * so it is always the attacker's DOMAIN NAME. Refusing names we do not recognise ends the attack
 * for every method, including the no-Origin GETs. Recognised without configuration: loopback, and
 * any bare IP literal — an address cannot be rebound to, so serving the dashboard on 0.0.0.0 and
 * browsing to http://192.168.1.50:4773 from another machine stays a one-step setup. Deployments
 * behind a name (reverse proxy, PaaS) name themselves via DFIR_ALLOWED_ORIGINS / DFIR_ALLOWED_HOSTS
 * / DFIR_ALLOWED_HOST_SUFFIXES.
 *
 * ── Gate 2: the `Origin` header ({@link isOriginAllowed}) ─────────────────────────────────────
 * This is the cross-origin stop. Callers split three ways:
 *
 *  1. NO `Origin` header — curl, the push-to-companion scripts, Velociraptor, MCP clients. Allowed.
 *     These are not the threat: a process that can already run on this machine does not need the
 *     companion's help to run more code, and blocking them breaks every documented scripted flow.
 *  2. A TRUSTED browser origin — the capture extension, the dashboard on loopback, an
 *     operator-configured origin, or an origin identical to the (already validated) `Host`.
 *     Allowed, and answered with that exact origin echoed back rather than a wildcard.
 *  3. Anything else — a real web page. Rejected with 403 before the route runs, and with no CORS or
 *     private-network headers, so the browser fails the preflight too.
 *
 * The `Origin == Host` case in group 2 is what lets a LAN or reverse-proxied dashboard work with no
 * per-origin configuration: it can only match when the page really was served by this companion.
 * It lived here before as a check against a RAW `Host` and was a rebinding bypass in that form
 * (#280) — both values are client-supplied, so an attacker could always make them agree. It is
 * sound only downstream of gate 1, which is why {@link isRequestAllowed} owns it and neither
 * exported predicate can be called in the unsafe order by accident.
 */

// Browser-extension schemes. An unpacked/dev install gets a randomly generated extension id, so the
// id itself is not something we can pin — the scheme is the durable signal. A hostile extension is
// out of scope here: it would need to be installed, at which point it has its own host permissions.
const EXTENSION_SCHEMES = new Set(["chrome-extension:", "moz-extension:", "safari-web-extension:"]);

// The dashboard is served by this same process, so in a normal install its origin is loopback on
// whatever port the companion picked (DFIR_PORT). Any port is fine; a remote page cannot forge these.
const LOOPBACK_HOSTNAMES = new Set(["localhost", "127.0.0.1", "[::1]"]);

/** Everything the two gates are willing to trust beyond the built-in loopback/IP/extension set. */
export interface GuardConfig {
  /** DFIR_ALLOWED_ORIGINS — full origins, e.g. "https://soc.example.com". */
  allowedOrigins?: string[];
  /** DFIR_ALLOWED_HOSTS — bare hostnames, for a proxy that rewrites Host to something else. */
  allowedHosts?: string[];
  /** DFIR_ALLOWED_HOST_SUFFIXES — for platforms that mint a fresh hostname per session. */
  allowedHostSuffixes?: string[];
}

export type GuardDecision = { ok: true } | { ok: false; kind: "host" | "origin"; reason: string };

/** Parse `DFIR_ALLOWED_ORIGINS` — a comma-separated origin list — into normalized origins. */
export function parseAllowedOrigins(raw: string | undefined): string[] {
  return (raw ?? "")
    .split(",")
    .map((s) => s.trim().replace(/\/+$/, "")) // tolerate a pasted trailing slash
    .filter((s) => s.length > 0);
}

/**
 * Reduce anything host-shaped — "a.example", "a.example:8443", "https://a.example/" — to its bare
 * lowercase hostname, or undefined if it is not a host at all. Parsing rather than string-slicing
 * is what makes the comparisons below safe: `new URL` rejects a Host header with a space or a
 * non-numeric port, and normalizes IPv6 brackets and IPv4 shorthand for us.
 */
function hostnameOf(value: string): string | undefined {
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(value) ? value : `http://${value}`;
  try {
    const hostname = new URL(withScheme).hostname.toLowerCase();
    return hostname.length > 0 ? hostname : undefined;
  } catch {
    return undefined;
  }
}

/** Parse a comma-separated hostname list (`DFIR_ALLOWED_HOSTS`), tolerating pasted full origins. */
export function parseAllowedHosts(raw: string | undefined): string[] {
  return (raw ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0)
    .map(hostnameOf)
    .filter((h): h is string => h !== undefined);
}

/** Parse a comma-separated suffix list (`DFIR_ALLOWED_HOST_SUFFIXES`) into dotted, lowercase form. */
export function parseAllowedHostSuffixes(raw: string | undefined): string[] {
  return (raw ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0 && s !== ".")
    .map(normalizeSuffix);
}

/**
 * A raw address cannot be the target of a DNS rebind — rebinding works by resolving a NAME to an
 * address, so the name is what lands in `Host`. Trusting literals outright is therefore what makes
 * "another investigator opens http://192.168.1.50:4773" work with no configuration at all.
 */
function isIpLiteral(hostname: string): boolean {
  // `new URL` has already validated the contents of the brackets as IPv6 by the time we see this.
  if (hostname.startsWith("[") && hostname.endsWith("]")) return true;
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) return false;
  return hostname.split(".").every((octet) => Number(octet) <= 255);
}

/** A suffix always compares with a leading dot, so `.acme.com` cannot match `evilacme.com`. */
function normalizeSuffix(raw: string): string {
  const s = raw.trim().toLowerCase();
  return s.startsWith(".") ? s : `.${s}`;
}

/**
 * Is this `Host` header one we recognise? Gate 1 — see the module docblock for why this, and not
 * the origin check, is what stops DNS rebinding.
 *
 * An absent Host is allowed: only pre-HTTP/1.1 and hand-rolled clients omit it, and a browser —
 * the only thing that can be rebound — always sends one.
 */
export function isHostAllowed(host: string | undefined, cfg: GuardConfig): boolean {
  if (!host) return true;

  const hostname = hostnameOf(host);
  if (hostname === undefined) return false; // malformed; refuse rather than guess

  if (LOOPBACK_HOSTNAMES.has(hostname)) return true;
  if (isIpLiteral(hostname)) return true;

  // A configured ORIGIN also vouches for its own host, so a deployment names itself once.
  const named = new Set<string>();
  for (const value of [...(cfg.allowedHosts ?? []), ...(cfg.allowedOrigins ?? [])]) {
    const parsed = hostnameOf(value);
    if (parsed !== undefined) named.add(parsed);
  }
  if (named.has(hostname)) return true;

  return (cfg.allowedHostSuffixes ?? [])
    .map(normalizeSuffix)
    .some((suffix) => hostname.endsWith(suffix) || hostname === suffix.slice(1));
}

/**
 * Is this browser origin allowed to talk to the companion? Gate 2.
 *
 * Trust here is derived ONLY from the origin itself plus the operator's allow-list. The
 * same-origin (`Origin == Host`) case deliberately does NOT live here — it needs a validated Host
 * to be sound, so it belongs to {@link isRequestAllowed}, which has one.
 */
export function isOriginAllowed(origin: string | undefined, extra: string[]): boolean {
  if (!origin) return true; // non-browser caller — see group 1 above

  let url: URL;
  try {
    url = new URL(origin);
  } catch {
    return false; // unparseable, including the literal "null" origin of a sandboxed iframe/data: URL
  }

  if (EXTENSION_SCHEMES.has(url.protocol)) return true;
  // Compare parsed components, never substrings: `https://127.0.0.1.evil.example` contains a
  // trusted host as a prefix but is a completely different origin.
  if (LOOPBACK_HOSTNAMES.has(url.hostname.toLowerCase())) return true;
  return extra.includes(`${url.protocol}//${url.host}`);
}

/**
 * Both gates, in the only order that is sound: `Host` first, then `Origin`.
 *
 * Every caller goes through here — the HTTP middleware below and the `/ws` upgrade in
 * live/wsGate.ts — so the same-origin shortcut can never be reached with an unvalidated Host.
 */
export function isRequestAllowed(req: { origin?: string; host?: string }, cfg: GuardConfig): GuardDecision {
  if (!isHostAllowed(req.host, cfg)) {
    return {
      ok: false,
      kind: "host",
      reason: `host "${req.host}" is not served by the DFIR companion` +
        " — add it to DFIR_ALLOWED_HOSTS if this is your own deployment",
    };
  }

  if (isOriginAllowed(req.origin, cfg.allowedOrigins ?? [])) return { ok: true };

  // Same-origin: this page was served by this companion, on the host we just validated. Safe here
  // and nowhere else — see the module docblock.
  if (req.origin !== undefined && req.host !== undefined) {
    const originHost = (() => {
      try {
        return new URL(req.origin).host.toLowerCase();
      } catch {
        return undefined;
      }
    })();
    if (originHost !== undefined && originHost === req.host.toLowerCase()) return { ok: true };
  }

  return {
    ok: false,
    kind: "origin",
    reason: `origin "${req.origin}" is not allowed to reach the DFIR companion` +
      " — add it to DFIR_ALLOWED_ORIGINS if this is your own dashboard",
  };
}

// Liveness probes are issued by infrastructure, not by a browser: Railway, Kubernetes, and load
// balancers all pick their own Host (Railway sends healthcheck.railway.app) long before any public
// hostname is settled. Applying the host allow-list to these would fail every deploy, so the probe
// path is exempt from GATE 1 — but only for a caller sending no Origin, which is what infrastructure
// looks like and what a real page never is. The route returns feature flags only: no case data, no
// secrets. Nothing else is exempt from anything.
const HOST_CHECK_EXEMPT_PATHS = new Set(["/health"]);

/** Express middleware enforcing {@link isRequestAllowed}, and emitting origin-scoped CORS headers. */
export function createOriginGuard(cfg: GuardConfig = {}): RequestHandler {
  return (req: Request, res: Response, next: NextFunction): void => {
    const origin = req.headers.origin;
    let decision = isRequestAllowed({ origin, host: req.headers.host }, cfg);
    if (!decision.ok && decision.kind === "host" && origin === undefined && HOST_CHECK_EXEMPT_PATHS.has(req.path)) {
      decision = { ok: true };
    }
    if (!decision.ok) {
      // 403 with no CORS headers: the page cannot read this response, and a preflight shaped like
      // this fails, so the browser never sends the real request either.
      res.status(403).json({ error: decision.reason });
      return;
    }

    if (origin) {
      res.header("Access-Control-Allow-Origin", origin); // echo the caller, never "*"
      res.header("Vary", "Origin"); // the response varies by origin, so it must not be cached across them
      res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
      res.header("Access-Control-Allow-Headers", "Content-Type");
      // Chromium Private Network Access: a request from an extension page to a private address
      // (127.0.0.1) is blocked unless the preflight allows it. Only ever granted to a trusted origin.
      res.header("Access-Control-Allow-Private-Network", "true");
    }

    if (req.method === "OPTIONS") {
      res.sendStatus(204);
      return;
    }
    next();
  };
}
