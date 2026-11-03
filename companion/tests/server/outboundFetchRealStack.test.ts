import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { fetchOutbound } from "../../src/routes/outboundFetchGuard.js";

// Every other fetchOutbound test injects `fetchImpl`, so none of them ever ran the real default
// fetch against the real pinned undici Agent. That pairing broke in production: the Agent came from
// the npm `undici` package (v8) while the default fetch was Node's built-in one (bundled undici v6),
// and the older fetch refused the newer Agent with "invalid onRequestStart method". Every guarded
// download — the Velociraptor binary, Sigma rules, KEV import, webhooks, audit export — failed.
//
// This test injects nothing but the resolver, so the default fetch and the default Agent meet for
// real. `policy: "lan"` permits loopback while keeping the pin, so the Agent is still in play.
describe("fetchOutbound — real fetch + real pinned Agent", () => {
  let server: Server;
  let port: number;

  beforeAll(async () => {
    server = createServer((_req, res) => {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("pinned-ok");
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    port = (server.address() as AddressInfo).port;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it("sends through the pinned Agent without a dispatcher/fetch version mismatch", async () => {
    const { response, dispose } = await fetchOutbound(`http://pinned.example:${port}/`, {
      policy: "lan",
      resolveHost: async () => [{ address: "127.0.0.1", family: 4 }],
      timeoutMs: 5000,
    });
    try {
      expect(response.status).toBe(200);
      expect(await response.text()).toBe("pinned-ok");
    } finally {
      await dispose();
    }
  });
});
