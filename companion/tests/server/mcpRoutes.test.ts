import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { McpServerStore } from "../../src/integrations/mcp/mcpServerStore.js";
import type { McpHttpRequest, McpHttpResponse, McpHttpTransport } from "../../src/integrations/mcp/mcpClient.js";
import { createApp } from "../../src/server.js";

const LAN_URL = "http://192.168.1.50:8080/mcp";
const TOKEN_KEY = "DFIR_MCP_SIFT_TOKEN";

/**
 * A transport that answers the handshake and tools/list the way a server would, so route tests
 * exercise the real client without a socket. Dispatches on the request rather than a fixed queue —
 * each probe builds a fresh client whose ids restart at 1.
 */
function fakeTransport(opts: {
  tools?: { name: string; description?: string }[];
  fail?: string;
  seen?: McpHttpRequest[];
} = {}): McpHttpTransport {
  return {
    async send(req: McpHttpRequest): Promise<McpHttpResponse> {
      opts.seen?.push(req);
      if (opts.fail) throw new Error(opts.fail);
      if (req.method === "DELETE") return { status: 204, headers: {}, body: "" };
      const msg = JSON.parse(req.body ?? "{}") as { id?: number; method?: string };
      if (msg.id === undefined) return { status: 202, headers: {}, body: "" };   // a notification
      const result = msg.method === "initialize"
        ? { protocolVersion: "2025-06-18", capabilities: {}, serverInfo: { name: "sift-mcp", version: "1.0" } }
        : { tools: opts.tools ?? [] };
      return {
        status: 200,
        headers: { "content-type": "application/json", "mcp-session-id": "sess-1" },
        body: JSON.stringify({ jsonrpc: "2.0", id: msg.id, result }),
      };
    },
  };
}

let cases: CaseStore;
let store: McpServerStore;
const appWith = (transport?: McpHttpTransport) => createApp(cases, { mcpServerStore: store, mcpTransport: transport });

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-mcproute-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  store = new McpServerStore(join(root, "mcp-servers.json"));
  delete process.env[TOKEN_KEY];
});

afterEach(() => {
  delete process.env[TOKEN_KEY];
});

describe("GET /mcp/status", () => {
  it("501s when no MCP server store is configured", async () => {
    const bare = createApp(cases, {});
    const res = await request(bare).get("/mcp/status");
    expect(res.status).toBe(501);
    expect(res.body.enabled).toBe(false);
  });

  it("reports an empty registry as enabled with no servers", async () => {
    const res = await request(appWith()).get("/mcp/status");
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ enabled: true, servers: [] });
  });

  it("lists a registered server as never probed", async () => {
    await store.add({ label: "SIFT", url: LAN_URL, allowedTools: ["pslist"] });

    const res = await request(appWith()).get("/mcp/status");

    expect(res.body.servers[0]).toMatchObject({
      id: "sift", label: "SIFT", url: LAN_URL, enabled: true, allowedTools: ["pslist"],
      tokenEnvKey: TOKEN_KEY, hasToken: false, reachable: null, checkedAt: null, tools: [],
    });
  });

  it("reports whether a token is set without ever returning its value", async () => {
    await store.add({ label: "SIFT", url: LAN_URL });
    process.env[TOKEN_KEY] = "super-secret-value";

    const res = await request(appWith()).get("/mcp/status");

    expect(res.body.servers[0].hasToken).toBe(true);
    expect(JSON.stringify(res.body)).not.toContain("super-secret-value");
  });

  // Opening the Settings tab must not hang on a lab host that is powered off.
  it("does not touch the network", async () => {
    await store.add({ label: "SIFT", url: LAN_URL });
    const seen: McpHttpRequest[] = [];

    await request(appWith(fakeTransport({ seen }))).get("/mcp/status");

    expect(seen).toHaveLength(0);
  });
});

describe("/mcp/servers CRUD", () => {
  it("registers a server and reports where its token belongs", async () => {
    const res = await request(appWith()).post("/mcp/servers").send({ label: "SIFT", url: LAN_URL });

    expect(res.status).toBe(201);
    expect(res.body).toMatchObject({ ok: true, tokenEnvKey: TOKEN_KEY, server: { id: "sift" } });
    expect((await store.load())).toHaveLength(1);
  });

  it("400s on a URL that would send evidence over cleartext to a public host", async () => {
    const res = await request(appWith()).post("/mcp/servers").send({ label: "hosted", url: "http://mcp.example.com/mcp" });

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/cleartext/);
    expect(await store.load()).toEqual([]);
  });

  it("400s when the label or URL is missing", async () => {
    expect((await request(appWith()).post("/mcp/servers").send({ url: LAN_URL })).status).toBe(400);
    expect((await request(appWith()).post("/mcp/servers").send({ label: "SIFT" })).status).toBe(400);
  });

  it("lists registered servers", async () => {
    await store.add({ label: "SIFT", url: LAN_URL });
    const res = await request(appWith()).get("/mcp/servers");
    expect(res.status).toBe(200);
    expect(res.body.servers.map((s: { id: string }) => s.id)).toEqual(["sift"]);
  });

  it("updates a server", async () => {
    await store.add({ label: "SIFT", url: LAN_URL });

    const res = await request(appWith()).put("/mcp/servers/sift").send({ allowedTools: ["pslist", "malfind"] });

    expect(res.status).toBe(200);
    expect(res.body.server.allowedTools).toEqual(["pslist", "malfind"]);
  });

  it("sets the command allowlist that bounds a command-runner tool", async () => {
    await store.add({ label: "SIFT", url: LAN_URL, allowedTools: ["run_command"] });

    const res = await request(appWith()).put("/mcp/servers/sift").send({ allowedCommands: "vol.py, /usr/bin/grep" });

    expect(res.body.server.allowedCommands).toEqual(["vol.py", "grep"]);
    const status = await request(appWith()).get("/mcp/status");
    expect(status.body.servers[0].allowedCommands).toEqual(["vol.py", "grep"]);
  });

  it("404s when updating a server that is not registered", async () => {
    expect((await request(appWith()).put("/mcp/servers/ghost").send({ label: "x" })).status).toBe(404);
  });

  it("400s when an update would make the URL unsafe", async () => {
    await store.add({ label: "SIFT", url: LAN_URL });
    const res = await request(appWith()).put("/mcp/servers/sift").send({ url: "http://mcp.example.com/mcp" });
    expect(res.status).toBe(400);
  });

  it("removes a server and says whether there was one", async () => {
    await store.add({ label: "SIFT", url: LAN_URL });

    expect((await request(appWith()).delete("/mcp/servers/sift")).body).toEqual({ ok: true, removed: true });
    expect((await request(appWith()).delete("/mcp/servers/sift")).body).toEqual({ ok: true, removed: false });
  });

  it("501s on every CRUD route when unconfigured", async () => {
    const bare = createApp(cases, {});
    expect((await request(bare).get("/mcp/servers")).status).toBe(501);
    expect((await request(bare).post("/mcp/servers").send({ label: "x", url: LAN_URL })).status).toBe(501);
    expect((await request(bare).put("/mcp/servers/sift").send({})).status).toBe(501);
    expect((await request(bare).delete("/mcp/servers/sift")).status).toBe(501);
    expect((await request(bare).post("/mcp/servers/sift/probe")).status).toBe(501);
  });
});

describe("POST /mcp/servers/:id/probe", () => {
  it("handshakes and returns the server's tools", async () => {
    await store.add({ label: "SIFT", url: LAN_URL });
    const transport = fakeTransport({ tools: [{ name: "pslist", description: "processes" }, { name: "malfind" }] });

    const res = await request(appWith(transport)).post("/mcp/servers/sift/probe");

    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.info).toMatchObject({ serverName: "sift-mcp" });
    expect(res.body.tools.map((t: { name: string }) => t.name)).toEqual(["pslist", "malfind"]);
  });

  it("caches what it found, so /mcp/status can report it without probing again", async () => {
    await store.add({ label: "SIFT", url: LAN_URL });
    const app = appWith(fakeTransport({ tools: [{ name: "pslist" }] }));

    await request(app).post("/mcp/servers/sift/probe");
    const status = await request(app).get("/mcp/status");

    expect(status.body.servers[0]).toMatchObject({ reachable: true });
    expect(status.body.servers[0].tools).toEqual([{ name: "pslist" }]);
    expect(status.body.servers[0].checkedAt).toBeTruthy();
  });

  // An unreachable lab host is an answer, not a server error.
  it("reports an unreachable server as 200 with ok:false", async () => {
    await store.add({ label: "SIFT", url: LAN_URL });
    const app = appWith(fakeTransport({ fail: "connect ECONNREFUSED 192.168.1.50:8080" }));

    const res = await request(app).post("/mcp/servers/sift/probe");
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ ok: false });
    expect(res.body.error).toMatch(/ECONNREFUSED/);

    const status = await request(app).get("/mcp/status");
    expect(status.body.servers[0]).toMatchObject({ reachable: false });
    expect(status.body.servers[0].error).toMatch(/ECONNREFUSED/);
  });

  it("sends the bearer token from the server's env key", async () => {
    await store.add({ label: "SIFT", url: LAN_URL });
    process.env[TOKEN_KEY] = "lab-token";
    const seen: McpHttpRequest[] = [];

    await request(appWith(fakeTransport({ seen }))).post("/mcp/servers/sift/probe");

    expect(seen[0].headers["authorization"]).toBe("Bearer lab-token");
  });

  it("404s for a server that is not registered", async () => {
    expect((await request(appWith(fakeTransport())).post("/mcp/servers/ghost/probe")).status).toBe(404);
  });

  // Checking a URL and token before switching the server on is exactly when this is most useful.
  it("probes a disabled server too", async () => {
    await store.add({ label: "SIFT", url: LAN_URL, enabled: false });
    const res = await request(appWith(fakeTransport())).post("/mcp/servers/sift/probe");
    expect(res.body.ok).toBe(true);
  });
});

describe("POST /mcp/reconnect", () => {
  it("re-reads the env prefix and drops cached reachability", async () => {
    await store.add({ label: "SIFT", url: LAN_URL });
    const app = appWith(fakeTransport({ tools: [{ name: "pslist" }] }));
    await request(app).post("/mcp/servers/sift/probe");
    expect((await request(app).get("/mcp/status")).body.servers[0].reachable).toBe(true);

    const res = await request(app).post("/mcp/reconnect");

    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    // A new token can change the answer, so the old verdict must not survive the reload.
    expect((await request(app).get("/mcp/status")).body.servers[0].reachable).toBeNull();
  });
});
