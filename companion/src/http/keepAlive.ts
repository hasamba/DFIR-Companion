import type { Server } from "node:http";

/**
 * Idle keep-alive timeout for the companion's HTTP server (#2038).
 *
 * WHY THIS EXISTS: Node closes an idle keep-alive socket after 5 s by default. A reverse proxy in
 * front of the companion — Tailscale `serve`, nginx, Caddy, Traefik — keeps its idle upstream
 * sockets far longer (Go's http.Transport: 90 s; nginx upstream keepalive: 60 s) and reuses them.
 * When the proxy writes a request into a socket Node is closing, the request is lost before it
 * reaches Express. Proxies retry idempotent GETs, so page loads hide the race; a POST is never
 * retried, so a button action (Run tagger, import, synthesis) surfaces as an empty 502 and the
 * dashboard's `res.json()` throws "Unexpected end of JSON input". A long event-loop stall on a big
 * case widens the window.
 *
 * The fix is the standard one: the upstream must outlive the proxy's idle timeout, so the PROXY is
 * always the side that closes an idle connection. 95 s clears Go's 90 s (Tailscale serve, Traefik),
 * nginx's 60 s and the common 60 s load-balancer idle default. headersTimeout must exceed keepAliveTimeout, or Node can drop a
 * reused socket while waiting for the next request's headers.
 */
export const PROXY_SAFE_KEEP_ALIVE_MS = 95_000;
export const PROXY_SAFE_HEADERS_MS = 96_000;

/** Anything that starts an HTTP server the way Express's `app.listen` does. */
export interface Listenable {
  listen(port: number, host: string, onListening: () => void): Server;
}

/**
 * Start listening with the proxy-safe idle timeouts already set. The timeouts are written on the
 * server this function creates, never on a caller's object.
 */
export function listenProxySafe(
  app: Listenable,
  port: number,
  host: string,
  onListening: () => void,
): Server {
  const server = app.listen(port, host, onListening);
  server.keepAliveTimeout = PROXY_SAFE_KEEP_ALIVE_MS;
  server.headersTimeout = PROXY_SAFE_HEADERS_MS;
  return server;
}
