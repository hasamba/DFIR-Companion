import { describe, it, expect, afterEach } from "vitest";
import { createServer, request, type Server, type RequestListener } from "node:http";
import type { AddressInfo } from "node:net";
import {
  listenProxySafe,
  PROXY_SAFE_KEEP_ALIVE_MS,
  PROXY_SAFE_HEADERS_MS,
} from "../../src/http/keepAlive.js";

// #2038: a reverse proxy (Tailscale serve, nginx, Caddy…) reuses idle upstream sockets for far
// longer than Node's 5 s default keep-alive. A POST sent down a socket the server just closed is
// not retried by the proxy and surfaces as an empty 502 in the dashboard.
const NODE_DEFAULT_KEEP_ALIVE_MS = 5_000;
const NGINX_KEEPALIVE_MS = 60_000; // nginx upstream keepalive_timeout default
const GO_TRANSPORT_IDLE_MS = 90_000; // Go http.Transport IdleConnTimeout (Tailscale serve, Traefik)

// A stand-in for Express's app.listen: a plain node:http handler behind the same listen() shape.
const startServer = (handler: RequestListener = (_req, res) => res.end("ok")) =>
  new Promise<Server>((resolve) => {
    const app = {
      listen: (port: number, host: string, cb: () => void) => createServer(handler).listen(port, host, cb),
    };
    const s = listenProxySafe(app, 0, "127.0.0.1", () => resolve(s));
  });

let server: Server | undefined;
afterEach(
  () =>
    new Promise<void>((done) => {
      if (!server) return done();
      server.closeAllConnections();
      server.close(() => done());
      server = undefined;
    }),
);

describe("listenProxySafe (#2038)", () => {
  it("keeps idle connections open longer than common proxy idle timeouts", async () => {
    server = await startServer();
    expect(server.keepAliveTimeout).toBe(PROXY_SAFE_KEEP_ALIVE_MS);
    expect(server.keepAliveTimeout).toBeGreaterThan(NGINX_KEEPALIVE_MS);
    expect(server.keepAliveTimeout).toBeGreaterThan(GO_TRANSPORT_IDLE_MS);
    expect(server.keepAliveTimeout).toBeGreaterThan(NODE_DEFAULT_KEEP_ALIVE_MS);
  });

  it("sets headersTimeout above keepAliveTimeout so Node does not cut a reused socket early", async () => {
    server = await startServer();
    expect(server.headersTimeout).toBe(PROXY_SAFE_HEADERS_MS);
    expect(server.headersTimeout).toBeGreaterThan(server.keepAliveTimeout);
  });

  it("advertises the longer idle timeout on a live keep-alive response", async () => {
    server = await startServer();
    const { port } = server.address() as AddressInfo;
    const keepAliveHeader = await new Promise<string | undefined>((resolve, reject) => {
      const req = request({ port, host: "127.0.0.1", headers: { connection: "keep-alive" } }, (res) => {
        res.resume();
        res.on("end", () => resolve(res.headers["keep-alive"] as string | undefined));
      });
      req.on("error", reject);
      req.end();
    });
    expect(keepAliveHeader).toBe(`timeout=${PROXY_SAFE_KEEP_ALIVE_MS / 1000}`);
  });
});
