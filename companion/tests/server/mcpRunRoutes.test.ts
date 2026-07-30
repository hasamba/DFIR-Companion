import { describe, it, expect, afterEach } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ImportUndoStore } from "../../src/analysis/importUndo.js";
import { CustodyStore } from "../../src/analysis/custody.js";
import { JobManager } from "../../src/analysis/jobManager.js";
import { McpServerStore } from "../../src/integrations/mcp/mcpServerStore.js";
import type { TransferRunner } from "../../src/integrations/mcp/mcpDelivery.js";
import type { ClaudeRunner } from "../../src/providers/claudeRunner.js";

// Output the existing importers recognize, so the run exercises the real ingest chain.
const YARA_OUT = "EvilRule /x/a.bin\n0x10:$s: 4d 5a";

/** A Claude Code that reports whatever the tool "returned". */
function fakeClaude(opts: { text?: string } = {}): ClaudeRunner {
  return async () => ({
    code: 0, stderr: "",
    stdout: JSON.stringify({ type: "result", subtype: "success", result: opts.text ?? YARA_OUT }) + "\n",
  });
}

async function harness(opts: { text?: string } = {}) {
  const root = await mkdtemp(join(tmpdir(), "dfir-mcprun-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const pipeline = buildRuntimePipeline({
    provider: undefined, synthesisProvider: undefined, stateStore, store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const mcpServerStore = new McpServerStore(join(root, "mcp-servers.json"));
  const custodyStore = new CustodyStore(store);
  const jobManager = new JobManager();
  const importUndoStore = new ImportUndoStore(store);
  const transfers: { binary: string; args: string[] }[] = [];
  const mcpTransferRunner: TransferRunner = async (binary, args) => {
    transfers.push({ binary, args });
    return { stdout: "", stderr: "", code: 0 };
  };

  const app = createApp(store, {
    pipeline, stateStore, importUndoStore,
    mcpServerStore, custodyStore, jobManager,
    mcpClaudeRunner: fakeClaude(opts), mcpTransferRunner,
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });

  const evidence = join(store.caseDir("c1"), "imports", "mem.raw");
  await writeFile(evidence, "MZ evidence bytes\n", "utf8");

  await mcpServerStore.add({
    id: "sift-mcp",
    allowedTools: ["run_command"], allowedCommands: ["vol.py"],
    delivery: { mode: "scp", host: "sift.lab", user: "analyst", remoteDir: "/cases/incoming" },
  });

  return { app, store, mcpServerStore, custodyStore, jobManager, transfers,
           pipeline, stateStore, importUndoStore, mcpTransferRunner };
}

/** The run is backgrounded, so wait for its job to reach a terminal state. */
async function settle(jobManager: JobManager, jobId: string) {
  for (let i = 0; i < 200; i++) {
    const job = jobManager.get(jobId);
    if (job && (job.status === "done" || job.status === "error" || job.status === "cancelled")) return job;
    await new Promise((r) => setTimeout(r, 10));
  }
  throw new Error("job never settled");
}

const RUN_BODY = {
  tool: "run_command",
  args: { command: ["vol.py", "-f", "<target>", "pslist"] },
  targetPath: "imports/mem.raw",
};

describe("POST /cases/:id/mcp/:serverId/run", () => {
  it("delivers, runs, and ingests the result into the case", async () => {
    const { app, jobManager, transfers } = await harness();

    const res = await request(app).post("/cases/c1/mcp/sift-mcp/run").send(RUN_BODY);
    expect(res.status).toBe(202);
    expect(res.body).toMatchObject({ ok: true, server: "sift-mcp", tool: "run_command" });

    const job = await settle(jobManager, res.body.jobId);
    expect(job.status).toBe("done");

    // scp out, ssh in to clean up.
    expect(transfers.map((t) => t.binary)).toEqual(["scp", "ssh"]);
    const state = await request(app).get("/cases/c1/state");
    expect(state.body.iocs.length + state.body.forensicTimeline.length).toBeGreaterThan(0);
  });

  it("records a custody transferred event naming where the evidence went", async () => {
    const { app, jobManager, custodyStore } = await harness();

    const res = await request(app).post("/cases/c1/mcp/sift-mcp/run").send(RUN_BODY);
    await settle(jobManager, res.body.jobId);

    const transferred = (await custodyStore.load("c1")).filter((r) => r.event === "transferred");
    expect(transferred).toHaveLength(1);
    expect(transferred[0]).toMatchObject({
      source: "analyst@sift.lab:/cases/incoming/mem.raw",
      trigger: "mcp:sift-mcp",
    });
    expect(transferred[0].artifactPath).toContain("mem.raw");
  });

  it("registers a cancellable job of kind mcp", async () => {
    const { app, jobManager } = await harness();

    const res = await request(app).post("/cases/c1/mcp/sift-mcp/run").send(RUN_BODY);
    const job = jobManager.get(res.body.jobId);

    expect(job).toMatchObject({ kind: "mcp", caseId: "c1", cancellable: true, label: "sift-mcp/run_command" });
    await settle(jobManager, res.body.jobId);
  });

  // §8's rough edge: the generic tool-runner message names no server and no tool.
  it("fails with a message naming the server and tool when the server returns nothing", async () => {
    const { app, jobManager } = await harness({ text: "   " });

    const res = await request(app).post("/cases/c1/mcp/sift-mcp/run").send(RUN_BODY);
    const job = await settle(jobManager, res.body.jobId);

    expect(job.status).toBe("error");
    expect(job.error).toMatch(/sift-mcp\/run_command: returned no output/);
  });

  // Detection routes unstructured prose to the generic "log" kind rather than refusing it, so a
  // narrative answer from REMnux still yields events instead of being rejected (§8). This is why
  // the refusal above is worded "returned no output" and not "unrecognized format" — with any
  // output at all, detection finds a kind.
  it("ingests prose through the generic log path rather than refusing it", async () => {
    const { app, jobManager } = await harness({ text: "Sample drops a payload and beacons to 10.2.3.4" });

    const res = await request(app).post("/cases/c1/mcp/sift-mcp/run").send(RUN_BODY);
    const job = await settle(jobManager, res.body.jobId);

    expect(job.status).toBe("done");
  });

  it("400s a target path outside the case directory", async () => {
    const { app } = await harness();
    const res = await request(app).post("/cases/c1/mcp/sift-mcp/run")
      .send({ ...RUN_BODY, targetPath: "../../../etc/passwd" });

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/outside the case directory/);
  });

  // The harness server opts into a command allowlist, so the narrowing applies.
  it("400s a command the server is not allowed to run", async () => {
    const { app, jobManager } = await harness();
    const res = await request(app).post("/cases/c1/mcp/sift-mcp/run")
      .send({ ...RUN_BODY, args: { command: ["curl", "http://x", "<target>"] } });

    // The guard runs inside the job, so the refusal lands there — and nothing was transferred.
    const job = await settle(jobManager, res.body.jobId);
    expect(job.status).toBe("error");
    expect(job.error).toMatch(/not allowed to run "curl"/);
  });

  it("400s an unknown or disabled server", async () => {
    const { app, mcpServerStore } = await harness();
    expect((await request(app).post("/cases/c1/mcp/ghost/run").send(RUN_BODY)).status).toBe(400);

    await mcpServerStore.update("sift-mcp", { enabled: false });
    const res = await request(app).post("/cases/c1/mcp/sift-mcp/run").send(RUN_BODY);
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/is disabled/);
  });

  it("400s without a tool, 404s an unknown case, 501s when unconfigured", async () => {
    const { app, store } = await harness();
    expect((await request(app).post("/cases/c1/mcp/sift-mcp/run").send({ args: {} })).status).toBe(400);
    expect((await request(app).post("/cases/nope/mcp/sift-mcp/run").send(RUN_BODY)).status).toBe(404);

    const bare = createApp(store, {});
    expect((await request(bare).post("/cases/c1/mcp/sift-mcp/run").send(RUN_BODY)).status).toBe(501);
  });
});

// A tool can return reference data as readily as evidence — a capability listing is structurally
// identical to a Volatility table — so the analyst gets to look before any of it reaches the case.
describe("preview before import", () => {
  it("fetches the output without touching the case", async () => {
    const { app, jobManager } = await harness();

    const res = await request(app).post("/cases/c1/mcp/sift-mcp/run").send({ ...RUN_BODY, preview: true });
    expect(res.body.preview).toBe(true);
    const job = await settle(jobManager, res.body.jobId);
    expect(job.status).toBe("done");

    const state = await request(app).get("/cases/c1/state");
    expect(state.body.iocs).toHaveLength(0);
    expect(state.body.forensicTimeline).toHaveLength(0);
  });

  it("labels the job as a preview", async () => {
    const { app, jobManager } = await harness();
    const res = await request(app).post("/cases/c1/mcp/sift-mcp/run").send({ ...RUN_BODY, preview: true });
    expect(jobManager.get(res.body.jobId)?.label).toBe("sift-mcp/run_command (preview)");
    await settle(jobManager, res.body.jobId);
  });

  it("returns the output and the kind it would import as", async () => {
    const { app, jobManager } = await harness();
    const res = await request(app).post("/cases/c1/mcp/sift-mcp/run").send({ ...RUN_BODY, preview: true });
    await settle(jobManager, res.body.jobId);

    const p = await request(app).get(`/cases/c1/mcp/preview/${res.body.jobId}`);
    expect(p.status).toBe(200);
    expect(p.body).toMatchObject({ server: "sift-mcp", tool: "run_command", kind: "yara", bytes: YARA_OUT.length, truncated: false });
    expect(p.body.text).toBe(YARA_OUT);
  });

  it("caps a large body so the point is the shape, not the volume", async () => {
    const big = "EvilRule /x/a.bin\n" + "0x10:$s: 4d 5a\n".repeat(2000);
    const { app, jobManager } = await harness({ text: big });
    const res = await request(app).post("/cases/c1/mcp/sift-mcp/run").send({ ...RUN_BODY, preview: true });
    await settle(jobManager, res.body.jobId);

    const p = await request(app).get(`/cases/c1/mcp/preview/${res.body.jobId}`);
    expect(p.body.bytes).toBe(big.length);
    expect(p.body.truncated).toBe(true);
    expect(p.body.text.length).toBe(8 * 1024);
  });

  it("imports exactly the fetched bytes on approval, without re-running the tool", async () => {
    const { app, jobManager, transfers } = await harness();
    const res = await request(app).post("/cases/c1/mcp/sift-mcp/run").send({ ...RUN_BODY, preview: true });
    await settle(jobManager, res.body.jobId);
    const transfersAfterPreview = transfers.length;

    const imp = await request(app).post(`/cases/c1/mcp/preview/${res.body.jobId}/import`);

    expect(imp.status).toBe(200);
    expect(imp.body.addedEvents + imp.body.addedIocs).toBeGreaterThan(0);
    // Approval must not mean executing the tool a second time.
    expect(transfers.length).toBe(transfersAfterPreview);
    const state = await request(app).get("/cases/c1/state");
    expect(state.body.iocs.length + state.body.forensicTimeline.length).toBeGreaterThan(0);
  });

  it("makes an approved import undoable", async () => {
    const { app, jobManager } = await harness();
    const res = await request(app).post("/cases/c1/mcp/sift-mcp/run").send({ ...RUN_BODY, preview: true });
    await settle(jobManager, res.body.jobId);
    await request(app).post(`/cases/c1/mcp/preview/${res.body.jobId}/import`);

    const undo = await request(app).get("/cases/c1/import/undo-stack");
    expect(undo.body.undo?.[0]?.label ?? undo.body.entries?.[0]?.label).toBe("MCP: sift-mcp/run_command");
  });

  it("is consumed by importing, so it cannot be imported twice", async () => {
    const { app, jobManager } = await harness();
    const res = await request(app).post("/cases/c1/mcp/sift-mcp/run").send({ ...RUN_BODY, preview: true });
    await settle(jobManager, res.body.jobId);

    expect((await request(app).post(`/cases/c1/mcp/preview/${res.body.jobId}/import`)).status).toBe(200);
    expect((await request(app).post(`/cases/c1/mcp/preview/${res.body.jobId}/import`)).status).toBe(404);
  });

  it("discards a preview and leaves the case untouched", async () => {
    const { app, jobManager } = await harness();
    const res = await request(app).post("/cases/c1/mcp/sift-mcp/run").send({ ...RUN_BODY, preview: true });
    await settle(jobManager, res.body.jobId);

    const del = await request(app).delete(`/cases/c1/mcp/preview/${res.body.jobId}`);
    expect(del.body).toEqual({ ok: true, discarded: true });

    expect((await request(app).get(`/cases/c1/mcp/preview/${res.body.jobId}`)).status).toBe(404);
    const state = await request(app).get("/cases/c1/state");
    expect(state.body.iocs).toHaveLength(0);
  });

  // The job id names the file on disk and arrives from the client.
  it("refuses a job id that is not one JobManager could have minted", async () => {
    const { app } = await harness();
    expect((await request(app).get("/cases/c1/mcp/preview/..%2F..%2Fetc%2Fpasswd")).status).toBe(404);
    expect((await request(app).get("/cases/c1/mcp/preview/job_1x")).status).toBe(404);
    expect((await request(app).post("/cases/c1/mcp/preview/nope/import")).status).toBe(404);
  });

  it("404s a preview that never existed", async () => {
    const { app } = await harness();
    expect((await request(app).get("/cases/c1/mcp/preview/job_999")).status).toBe(404);
  });
});

describe("POST /cases/:id/mcp/agent", () => {
  const AGENT_JSON = '{"findings":[{"title":"Injected process","description":"malfind hit","severity":"High"}],"iocs":[{"type":"ip","value":"10.2.3.4"}]}';
  const agentRunner: ClaudeRunner = async () => ({
    code: 0, stderr: "",
    stdout: JSON.stringify({ type: "result", subtype: "success", result: AGENT_JSON }) + "\n",
  });

  async function agentHarness(opts: { agentEnabled?: boolean; runner?: ClaudeRunner } = {}) {
    const h = await harness();
    await h.mcpServerStore.update("sift-mcp", { agentEnabled: opts.agentEnabled ?? true });
    // Rebuild the app so it picks up the injected agent runner.
    const app = createApp(h.store, {
      pipeline: h.pipeline, stateStore: h.stateStore, importUndoStore: h.importUndoStore,
      mcpServerStore: h.mcpServerStore, custodyStore: h.custodyStore, jobManager: h.jobManager,
      mcpClaudeRunner: fakeClaude(), mcpTransferRunner: h.mcpTransferRunner, mcpAgentRunner: opts.runner ?? agentRunner,
    });
    return { ...h, app };
  }

  // Allowing the MCP server is the permission boundary. The analyst should not need a second hidden
  // opt-in before a plain-English request can use a server they explicitly allowed.
  it("uses an enabled server even when an older policy file says agentEnabled false", async () => {
    const { app } = await agentHarness({ agentEnabled: false });
    const res = await request(app).post("/cases/c1/mcp/agent").send({ prompt: "investigate" });
    expect(res.status).toBe(202);
    expect(res.body.servers).toEqual(["sift-mcp"]);
  });

  it("runs the loop and merges what it found", async () => {
    const { app, jobManager } = await agentHarness();

    const res = await request(app).post("/cases/c1/mcp/agent").send({ prompt: "investigate the dump" });
    expect(res.status).toBe(202);
    expect(res.body.servers).toEqual(["sift-mcp"]);
    const job = await settle(jobManager, res.body.jobId);
    expect(job.status).toBe("done");

    const state = await request(app).get("/cases/c1/state");
    expect(state.body.findings.some((f: { title: string }) => f.title === "Injected process")).toBe(true);
    expect(state.body.iocs.some((i: { value: string }) => i.value === "10.2.3.4")).toBe(true);
  });

  it("publishes live sanitized tool activity on the background job", async () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const runner: ClaudeRunner = async (run) => {
      run.onStdout?.(JSON.stringify({
        type: "assistant",
        message: { content: [{ type: "tool_use", id: "t1", name: "mcp__sift-mcp__windows.pslist", input: { path: "secret" } }] },
      }) + "\n");
      await gate;
      return { code: 0, stderr: "", stdout: JSON.stringify({ type: "result", subtype: "success", result: AGENT_JSON }) + "\n" };
    };
    const { app, jobManager } = await agentHarness({ runner });
    const res = await request(app).post("/cases/c1/mcp/agent").send({ prompt: "investigate" });

    for (let i = 0; i < 50 && !jobManager.get(res.body.jobId)?.detail?.includes("windows.pslist"); i++) {
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
    const running = jobManager.get(res.body.jobId)!;
    expect(running.detail).toContain("running windows.pslist");
    expect(running.detail).not.toContain("secret");
    expect(running.progress).toEqual({ done: 2, total: 4 });

    release();
    expect((await settle(jobManager, res.body.jobId)).status).toBe("done");
  });

  it("makes an agent run undoable", async () => {
    const { app, jobManager } = await agentHarness();
    const res = await request(app).post("/cases/c1/mcp/agent").send({ prompt: "go" });
    await settle(jobManager, res.body.jobId);

    const undo = await request(app).get("/cases/c1/import/undo-stack");
    expect((undo.body.undo || [])[0]?.label).toBe("MCP agent: sift-mcp");
  });

  it("previews the delta without merging it", async () => {
    const { app, jobManager } = await agentHarness();
    const res = await request(app).post("/cases/c1/mcp/agent").send({ prompt: "go", preview: true });
    const job = await settle(jobManager, res.body.jobId);
    expect(job.status).toBe("done");

    const before = await request(app).get("/cases/c1/state");
    expect(before.body.findings).toHaveLength(0);

    const p = await request(app).get(`/cases/c1/mcp/preview/${res.body.jobId}`);
    expect(p.body.text).toContain("Injected process");

    const imp = await request(app).post(`/cases/c1/mcp/preview/${res.body.jobId}/import`);
    expect(imp.status).toBe(200);
    const after = await request(app).get("/cases/c1/state");
    expect(after.body.findings).toHaveLength(1);
  });

  it("400s without a prompt", async () => {
    const { app } = await agentHarness();
    expect((await request(app).post("/cases/c1/mcp/agent").send({})).status).toBe(400);
  });

  // No allowlist is the default and means the whole server, so this must run rather than refuse.
  it("runs against a server with no tool allowlist", async () => {
    const { app, jobManager, mcpServerStore } = await agentHarness();
    await mcpServerStore.update("sift-mcp", { allowedTools: [] });
    const res = await request(app).post("/cases/c1/mcp/agent").send({ prompt: "go" });
    expect(res.status).toBe(202);
    expect((await settle(jobManager, res.body.jobId)).status).toBe("done");
  });

  it("delivers case evidence and tells the agent its analysis-host path", async () => {
    let prompt = "";
    const runner: ClaudeRunner = async (run) => {
      const line = JSON.parse(run.stdin.trim()) as { message: { content: Array<{ text: string }> } };
      prompt = line.message.content[0].text;
      return { code: 0, stderr: "", stdout: JSON.stringify({ type: "result", subtype: "success", result: AGENT_JSON }) + "\n" };
    };
    const { app, jobManager, transfers, custodyStore } = await agentHarness({ runner });

    const res = await request(app).post("/cases/c1/mcp/agent").send({
      prompt: "Investigate this RAM dump",
      servers: ["sift-mcp"],
      targetPath: "imports/mem.raw",
    });
    expect(res.status).toBe(202);
    expect((await settle(jobManager, res.body.jobId)).status).toBe("done");
    expect(prompt).toContain("Investigate this RAM dump");
    expect(prompt).toContain("/cases/incoming/mem.raw");
    expect(transfers.map((t) => t.binary)).toEqual(["scp", "ssh"]);
    expect((await custodyStore.load("c1")).some((r) => r.event === "transferred")).toBe(true);
  });

  it("stages a browser-selected file for a plain-English investigation", async () => {
    let prompt = "";
    const runner: ClaudeRunner = async (run) => {
      prompt = (JSON.parse(run.stdin.trim()) as { message: { content: Array<{ text: string }> } }).message.content[0].text;
      return { code: 0, stderr: "", stdout: JSON.stringify({ type: "result", subtype: "success", result: AGENT_JSON }) + "\n" };
    };
    const { app, jobManager, transfers } = await agentHarness({ runner });
    const res = await request(app).post("/cases/c1/mcp/agent-upload").send({
      prompt: "Analyze this binary with REMnux",
      servers: ["sift-mcp"],
      filename: "sample.exe",
      dataBase64: Buffer.from("MZ\x90\x00").toString("base64"),
      preview: true,
    });
    expect(res.status).toBe(202);
    expect((await settle(jobManager, res.body.jobId)).status).toBe("done");
    expect(prompt).toContain("/cases/incoming/sample.exe");
    expect(transfers[0].args.some((a) => a.includes("sample.exe"))).toBe(true);
  });
});

describe("POST /cases/:id/mcp/:serverId/run-upload", () => {
  it("stages uploaded bytes, runs against them, and ingests", async () => {
    const { app, jobManager, transfers } = await harness();

    const res = await request(app).post("/cases/c1/mcp/sift-mcp/run-upload").send({
      ...RUN_BODY,
      targetPath: undefined,
      filename: "sample.bin",
      dataBase64: Buffer.from("MZ\x90\x00").toString("base64"),
    });

    expect(res.status).toBe(202);
    const job = await settle(jobManager, res.body.jobId);
    expect(job.status).toBe("done");
    // The staged file was what got pushed.
    expect(transfers[0].args.some((a) => a.includes("sample.bin"))).toBe(true);
  });

  it("400s without filename or bytes", async () => {
    const { app } = await harness();
    const res = await request(app).post("/cases/c1/mcp/sift-mcp/run-upload").send({ ...RUN_BODY, filename: "x.bin" });
    expect(res.status).toBe(400);
  });
});
