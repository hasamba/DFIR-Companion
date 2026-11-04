/**
 * The built-in HTTPS listener and its optional plain-HTTP side door (#2285).
 *
 * The main port is a standard `https.Server` running the same Express app, with the same proxy-safe
 * idle timeouts as the plain listener (keepAlive.ts) — so WebSocket upgrades, graceful shutdown and
 * `setSecureContext` renewal all behave as Node documents them. `req.secure` is true on it, which is
 * what makes team-mode Secure cookies and the case-unlock cookie work with no proxy.
 *
 * The side door is a SEPARATE port, off unless DFIR_HTTPS_PLAIN_HTTP asks for it:
 *   redirect — serves nothing. A GET/HEAD gets a 308 to the https URL; anything else (a login POST,
 *              an upload) gets a 400, because a redirect cannot un-send a password that already
 *              crossed the network in clear text.
 *   serve    — the full app over plain HTTP, for scripts and health checks on the box itself.
 */
import { createServer as createHttpServer, type RequestListener, type Server as HttpServer } from "node:http";
import { createServer as createHttpsServer, type Server as HttpsServer } from "node:https";
import { PROXY_SAFE_HEADERS_MS, PROXY_SAFE_KEEP_ALIVE_MS } from "./keepAlive.js";

export interface TlsKeyPair {
  keyPem: string;
  certPem: string;
}

/** Start the main HTTPS listener. Errors (EADDRINUSE) surface as the server's `error` event. */
export function listenHttps(
  app: RequestListener,
  port: number,
  host: string,
  material: TlsKeyPair,
  onListening: () => void,
): HttpsServer {
  const server = createHttpsServer(
    { key: material.keyPem, cert: material.certPem, minVersion: "TLSv1.2" },
    app,
  );
  server.keepAliveTimeout = PROXY_SAFE_KEEP_ALIVE_MS;
  server.headersTimeout = PROXY_SAFE_HEADERS_MS;
  server.listen(port, host, onListening);
  return server;
}

export interface RedirectOptions {
  /** The main HTTPS port — the redirect never trusts the port a client put in its Host header. */
  httpsPort: number;
  /** DFIR_PUBLIC_URL's origin when it is an https URL; wins over the Host header. */
  publicOrigin?: string;
  /** The companion's existing Host allowlist (originGuard.isHostAllowed). */
  isHostAllowed: (host: string) => boolean;
}

const HOST_HEADER = /^(?:\[([0-9a-f:.]+)\]|([a-z0-9.-]+))(?::\d{1,5})?$/i;
// A path the redirect may echo: absolute, not protocol-relative, printable ASCII, no backslash.
const SAFE_PATH = /^\/(?!\/)[\x21-\x5b\x5d-\x7e]*$/;

/** Where a plain-HTTP request should go over HTTPS, or undefined when it must not be redirected. */
export function httpsRedirectTarget(
  method: string | undefined,
  url: string | undefined,
  host: string | undefined,
  opts: RedirectOptions,
): string | undefined {
  if (method !== "GET" && method !== "HEAD") return undefined;
  if (!url || !SAFE_PATH.test(url)) return undefined;
  if (opts.publicOrigin) return `${opts.publicOrigin}${url}`;
  const trimmed = host?.trim() ?? "";
  const match = HOST_HEADER.exec(trimmed);
  if (!match || !opts.isHostAllowed(trimmed)) return undefined;
  const authority = match[1] !== undefined ? `[${match[1].toLowerCase()}]` : match[2].toLowerCase();
  const port = opts.httpsPort === 443 ? "" : `:${opts.httpsPort}`;
  return `https://${authority}${port}${url}`;
}

export function redirectToHttps(opts: RedirectOptions): RequestListener {
  return (req, res) => {
    const target = httpsRedirectTarget(req.method, req.url, req.headers.host, opts);
    if (!target) {
      res.writeHead(400, { "Content-Type": "text/plain; charset=utf-8", Connection: "close" });
      res.end("This DFIR Companion only accepts HTTPS. Open the https:// address instead.\n");
      return;
    }
    res.writeHead(308, {
      Location: target,
      "Content-Type": "text/plain; charset=utf-8",
      Connection: "close",
    });
    res.end(`Moved to ${target}\n`);
  };
}

/** Start the plain-HTTP side door. No `upgrade`/`connect` listeners: Node closes those sockets. */
export function listenPlainHttp(
  handler: RequestListener,
  port: number,
  host: string,
  onListening: () => void,
): HttpServer {
  const server = createHttpServer(handler);
  server.keepAliveTimeout = PROXY_SAFE_KEEP_ALIVE_MS;
  server.headersTimeout = PROXY_SAFE_HEADERS_MS;
  server.listen(port, host, onListening);
  return server;
}
