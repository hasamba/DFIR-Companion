import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { McpServerStore } from "../../src/integrations/mcp/mcpServerStore.js";
import type { ClaudeRunner, ClaudeRunOptions } from "../../src/providers/claudeRunner.js";
import { createApp } from "../../src/server.js";

// Synthetic `claude mcp list` output. It has the same credential-bearing shape as a real line
// without copying an operator's private host or bearer value into source control.
const TOKEN = "SIFT_TEST_BEARER_VALUE";
const LIST = [
  "Checking MCP server health…",
  "",
  `sift-mcp: npx -y mcp-remote http://192.0.2.10:4508/mcp/sift-mcp --header Authorization:Bearer ${TOKEN} --allow-http - ✔ Connected`,
  "windows-triage-mcp: npx -y mcp-remote http://192.0.2.10:4508/mcp/windows-triage-mcp --allow-http - ✔ Connected",
  "broken-mcp: npx broken - ✘ Failed to connect",
].join("\n");

function fakeClaude(stdout = LIST, extra: Record<string, unknown> = {}): ClaudeRunner {
  return async () => ({ code: 0, stdout, stderr: "", ...extra });
}

let cases: CaseStore;
let store: McpServerStore;
const appWith = (runner?: ClaudeRunner) =>
  createApp(cases, { mcpServerStore: store, ...(runner ? { mcpClaudeRunner: runner } : {}) });

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-mcproute-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  store = new McpServerStore(join(root, "mcp-servers.json"));
});

describe("GET /mcp/status", () => {
  it("501s when no MCP policy store is configured", async () => {
    const res = await request(createApp(cases, {})).get("/mcp/status");
    expect(res.status).toBe(501);
    expect(res.body.enabled).toBe(false);
  });

  it("reports an empty policy list, and that Claude Code has not been asked yet", async () => {
    const res = await request(appWith()).get("/mcp/status");
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ enabled: true, claudeCode: null, servers: [] });
  });

  it("carries no URL and no token, because the Companion holds neither", async () => {
    await store.add({ id: "sift-mcp", allowedTools: ["run_command"] });

    const res = await request(appWith()).get("/mcp/status");

    expect(res.body.servers[0]).toMatchObject({
      id: "sift-mcp", enabled: true, allowedTools: ["run_command"], knownToClaudeCode: null,
    });
    expect(JSON.stringify(res.body)).not.toMatch(/url|token/i);
  });

  // Discovery is a cached `claude mcp list`; the tab must not spawn anything to render.
  it("does not run the CLI", async () => {
    await store.add({ id: "sift-mcp" });
    const seen: ClaudeRunOptions[] = [];

    await request(appWith(async (o) => { seen.push(o); return { code: 0, stdout: LIST, stderr: "" }; })).get("/mcp/status");

    expect(seen).toHaveLength(0);
  });
});

describe("POST /mcp/discover", () => {
  it("asks Claude Code which servers it has", async () => {
    const res = await request(appWith(fakeClaude())).post("/mcp/discover");

    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.servers.map((s: { name: string }) => s.name))
      .toEqual(["sift-mcp", "windows-triage-mcp", "broken-mcp"]);
  });

  // `claude mcp list` prints command lines that contain bearer tokens.
  it("never surfaces the token that Claude Code printed", async () => {
    const res = await request(appWith(fakeClaude())).post("/mcp/discover");
    const body = JSON.stringify(res.body);
    expect(body).not.toContain(TOKEN);
    expect(body).not.toContain("Authorization");
    expect(body).not.toContain("192.0.2.10");
  });

  it("runs `claude mcp list` and nothing else", async () => {
    const seen: ClaudeRunOptions[] = [];
    await request(appWith(async (o) => { seen.push(o); return { code: 0, stdout: LIST, stderr: "" }; }))
      .post("/mcp/discover");

    expect(seen[0].args).toEqual(["mcp", "list"]);
  });

  it("marks a policy entry as known or unknown to Claude Code once discovered", async () => {
    await store.add({ id: "sift-mcp" });
    await store.add({ id: "gone-mcp" });
    const app = appWith(fakeClaude());

    await request(app).post("/mcp/discover");
    const status = await request(app).get("/mcp/status");

    const byId = Object.fromEntries(status.body.servers.map((s: { id: string }) => [s.id, s]));
    expect(byId["sift-mcp"]).toMatchObject({ knownToClaudeCode: true, connected: true, status: "connected" });
    expect(byId["gone-mcp"]).toMatchObject({ knownToClaudeCode: false, connected: null });
    expect(status.body.claudeCode.servers).toHaveLength(3);
  });

  // Claude Code being unavailable is an answer, not a server error.
  it("reports a missing CLI as 200 with ok:false and how to fix it", async () => {
    const enoent = Object.assign(new Error("spawn claude ENOENT"), { code: "ENOENT" });
    const app = appWith(async () => ({ code: null, stdout: "", stderr: "", spawnError: enoent }));

    const res = await request(app).post("/mcp/discover");

    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(false);
    expect(res.body.error).toMatch(/installed and authenticated on THIS host/);

    const status = await request(app).get("/mcp/status");
    expect(status.body.claudeCode.error).toMatch(/THIS host/);
  });

  it("501s when unconfigured", async () => {
    expect((await request(createApp(cases, {})).post("/mcp/discover")).status).toBe(501);
  });
});

describe("/mcp/servers CRUD", () => {
  it("stores policy for a Claude Code server", async () => {
    const res = await request(appWith()).post("/mcp/servers")
      .send({ id: "sift-mcp", allowedTools: "run_command", allowedCommands: "vol.py" });

    expect(res.status).toBe(201);
    expect(res.body.server).toMatchObject({ id: "sift-mcp", allowedTools: ["run_command"], allowedCommands: ["vol.py"] });
    // Nothing about credentials comes back, because none was taken.
    expect(res.body).not.toHaveProperty("tokenEnvKey");
  });

  it("400s without a server name, or with an implausible one", async () => {
    expect((await request(appWith()).post("/mcp/servers").send({})).status).toBe(400);
    expect((await request(appWith()).post("/mcp/servers").send({ id: "../x" })).status).toBe(400);
  });

  it("lists stored policy", async () => {
    await store.add({ id: "sift-mcp" });
    const res = await request(appWith()).get("/mcp/servers");
    expect(res.body.servers.map((s: { id: string }) => s.id)).toEqual(["sift-mcp"]);
  });

  it("updates a server", async () => {
    await store.add({ id: "sift-mcp" });
    const res = await request(appWith()).put("/mcp/servers/sift-mcp").send({ allowedTools: ["run_command", "check_tools"] });
    expect(res.status).toBe(200);
    expect(res.body.server.allowedTools).toEqual(["run_command", "check_tools"]);
  });

  it("sets the command allowlist that bounds a command-runner tool", async () => {
    await store.add({ id: "sift-mcp", allowedTools: ["run_command"] });
    const res = await request(appWith()).put("/mcp/servers/sift-mcp").send({ allowedCommands: "vol.py, /usr/bin/grep" });
    expect(res.body.server.allowedCommands).toEqual(["vol.py", "grep"]);
  });

  it("404s when updating a server with no policy stored", async () => {
    expect((await request(appWith()).put("/mcp/servers/ghost").send({ label: "x" })).status).toBe(404);
  });

  it("400s when an update would make delivery unsafe", async () => {
    await store.add({ id: "sift-mcp" });
    const res = await request(appWith()).put("/mcp/servers/sift-mcp").send({ delivery: { mode: "scp", host: "evil;host", remoteDir: "/x" } });
    expect(res.status).toBe(400);
  });

  it("removes a server and says whether there was one", async () => {
    await store.add({ id: "sift-mcp" });
    expect((await request(appWith()).delete("/mcp/servers/sift-mcp")).body).toEqual({ ok: true, removed: true });
    expect((await request(appWith()).delete("/mcp/servers/sift-mcp")).body).toEqual({ ok: true, removed: false });
  });

  it("501s on every CRUD route when unconfigured", async () => {
    const bare = createApp(cases, {});
    expect((await request(bare).get("/mcp/servers")).status).toBe(501);
    expect((await request(bare).post("/mcp/servers").send({ id: "sift-mcp" })).status).toBe(501);
    expect((await request(bare).put("/mcp/servers/sift-mcp").send({})).status).toBe(501);
    expect((await request(bare).delete("/mcp/servers/sift-mcp")).status).toBe(501);
  });
});

describe("POST /mcp/reconnect", () => {
  it("drops cached discovery so the next status reflects a newly added server", async () => {
    await store.add({ id: "sift-mcp" });
    const app = appWith(fakeClaude());
    await request(app).post("/mcp/discover");
    expect((await request(app).get("/mcp/status")).body.claudeCode).not.toBeNull();

    const res = await request(app).post("/mcp/reconnect");

    expect(res.status).toBe(200);
    expect((await request(app).get("/mcp/status")).body.claudeCode).toBeNull();
  });
});

describe("POST /mcp/servers/:id/tools", () => {
  const toolsRunner: ClaudeRunner = async () => ({
    code: 0, stderr: "",
    stdout: JSON.stringify({
      type: "result", subtype: "success",
      result: '["list_available_tools","run_command","mcp__sift-mcp__check_tools"]',
    }) + "\n",
  });

  it("asks Claude Code what one server offers, and strips a qualified prefix", async () => {
    await store.add({ id: "sift-mcp" });
    const res = await request(appWith(toolsRunner)).post("/mcp/servers/sift-mcp/tools");

    expect(res.status).toBe(200);
    expect(res.body.tools).toEqual(["list_available_tools", "run_command", "check_tools"]);
  });

  it("grants the whole server while asking, since the point is to see everything", async () => {
    await store.add({ id: "sift-mcp" });
    const seen: ClaudeRunOptions[] = [];
    await request(appWith(async (o) => { seen.push(o); return toolsRunner(o); }))
      .post("/mcp/servers/sift-mcp/tools");

    expect(seen[0].args[seen[0].args.indexOf("--allowed-tools") + 1]).toBe("mcp__sift-mcp__*");
  });

  it("caches the list onto /mcp/status for the run form's picker", async () => {
    await store.add({ id: "sift-mcp" });
    const app = appWith(toolsRunner);
    await request(app).post("/mcp/servers/sift-mcp/tools");

    const status = await request(app).get("/mcp/status");
    expect(status.body.servers[0].tools).toContain("run_command");
  });

  // A model answer, so a bad one must not become a server error.
  it("reports an unusable reply as 200 with ok:false", async () => {
    await store.add({ id: "sift-mcp" });
    const app = appWith(async () => ({
      code: 0, stderr: "",
      stdout: JSON.stringify({ type: "result", subtype: "success", result: "I could not tell." }) + "\n",
    }));

    const res = await request(app).post("/mcp/servers/sift-mcp/tools");
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(false);
  });

  it("404s a server with no policy, 501s when unconfigured", async () => {
    expect((await request(appWith(toolsRunner)).post("/mcp/servers/ghost/tools")).status).toBe(404);
    expect((await request(createApp(cases, {})).post("/mcp/servers/sift-mcp/tools")).status).toBe(501);
  });
});
