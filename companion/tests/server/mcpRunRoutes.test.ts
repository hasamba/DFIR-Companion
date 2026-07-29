import { describe, it, expect } from "vitest";
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
import type { McpHttpResponse, McpHttpTransport } from "../../src/integrations/mcp/mcpClient.js";
import type { TransferRunner } from "../../src/integrations/mcp/mcpDelivery.js";

const LAN_URL = "http://192.168.1.50:8080/mcp";
// Output the existing importers recognize, so the run exercises the real ingest chain.
const YARA_OUT = "EvilRule /x/a.bin\n0x10:$s: 4d 5a";

function fakeTransport(opts: { text?: string; isError?: boolean } = {}): McpHttpTransport {
  return {
    async send(req): Promise<McpHttpResponse> {
      if (req.method === "DELETE") return { status: 204, headers: {}, body: "" };
      const msg = JSON.parse(req.body ?? "{}") as { id?: number; method?: string };
      if (msg.id === undefined) return { status: 202, headers: {}, body: "" };
      const result = msg.method === "initialize"
        ? { protocolVersion: "2025-06-18", capabilities: {}, serverInfo: { name: "sift-mcp", version: "1" } }
        : { content: [{ type: "text", text: opts.text ?? YARA_OUT }], isError: opts.isError === true };
      return {
        status: 200,
        headers: { "content-type": "application/json", "mcp-session-id": "s1" },
        body: JSON.stringify({ jsonrpc: "2.0", id: msg.id, result }),
      };
    },
  };
}

async function harness(opts: { text?: string; isError?: boolean } = {}) {
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
  const transfers: { binary: string; args: string[] }[] = [];
  const mcpTransferRunner: TransferRunner = async (binary, args) => {
    transfers.push({ binary, args });
    return { stdout: "", stderr: "", code: 0 };
  };

  const app = createApp(store, {
    pipeline, stateStore, importUndoStore: new ImportUndoStore(store),
    mcpServerStore, custodyStore, jobManager,
    mcpTransport: fakeTransport(opts), mcpTransferRunner,
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });

  const evidence = join(store.caseDir("c1"), "imports", "mem.raw");
  await writeFile(evidence, "MZ evidence bytes\n", "utf8");

  await mcpServerStore.add({
    label: "SIFT", url: LAN_URL,
    allowedTools: ["run_command"], allowedCommands: ["vol.py"],
    delivery: { mode: "scp", host: "sift.lab", user: "analyst", remoteDir: "/cases/incoming" },
  });

  return { app, store, mcpServerStore, custodyStore, jobManager, transfers };
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

    const res = await request(app).post("/cases/c1/mcp/sift/run").send(RUN_BODY);
    expect(res.status).toBe(202);
    expect(res.body).toMatchObject({ ok: true, server: "sift", tool: "run_command" });

    const job = await settle(jobManager, res.body.jobId);
    expect(job.status).toBe("done");

    // scp out, ssh in to clean up.
    expect(transfers.map((t) => t.binary)).toEqual(["scp", "ssh"]);
    const state = await request(app).get("/cases/c1/state");
    expect(state.body.iocs.length + state.body.forensicTimeline.length).toBeGreaterThan(0);
  });

  it("records a custody transferred event naming where the evidence went", async () => {
    const { app, jobManager, custodyStore } = await harness();

    const res = await request(app).post("/cases/c1/mcp/sift/run").send(RUN_BODY);
    await settle(jobManager, res.body.jobId);

    const transferred = (await custodyStore.load("c1")).filter((r) => r.event === "transferred");
    expect(transferred).toHaveLength(1);
    expect(transferred[0]).toMatchObject({
      source: "analyst@sift.lab:/cases/incoming/mem.raw",
      trigger: "mcp:sift",
    });
    expect(transferred[0].artifactPath).toContain("mem.raw");
  });

  it("registers a cancellable job of kind mcp", async () => {
    const { app, jobManager } = await harness();

    const res = await request(app).post("/cases/c1/mcp/sift/run").send(RUN_BODY);
    const job = jobManager.get(res.body.jobId);

    expect(job).toMatchObject({ kind: "mcp", caseId: "c1", cancellable: true, label: "sift/run_command" });
    await settle(jobManager, res.body.jobId);
  });

  // §8's rough edge: the generic tool-runner message names no server and no tool.
  it("fails with a message naming the server and tool when the server returns nothing", async () => {
    const { app, jobManager } = await harness({ text: "   " });

    const res = await request(app).post("/cases/c1/mcp/sift/run").send(RUN_BODY);
    const job = await settle(jobManager, res.body.jobId);

    expect(job.status).toBe("error");
    expect(job.error).toMatch(/sift\/run_command: returned no output/);
  });

  // Detection routes unstructured prose to the generic "log" kind rather than refusing it, so a
  // narrative answer from REMnux still yields events instead of being rejected (§8). This is why
  // the refusal above is worded "returned no output" and not "unrecognized format" — with any
  // output at all, detection finds a kind.
  it("ingests prose through the generic log path rather than refusing it", async () => {
    const { app, jobManager } = await harness({ text: "Sample drops a payload and beacons to 10.2.3.4" });

    const res = await request(app).post("/cases/c1/mcp/sift/run").send(RUN_BODY);
    const job = await settle(jobManager, res.body.jobId);

    expect(job.status).toBe("done");
  });

  it("fails the job when the tool reports its own failure", async () => {
    const { app, jobManager } = await harness({ text: "unsupported profile", isError: true });

    const res = await request(app).post("/cases/c1/mcp/sift/run").send(RUN_BODY);
    const job = await settle(jobManager, res.body.jobId);

    expect(job.status).toBe("error");
    expect(job.error).toMatch(/reported a failure: unsupported profile/);
  });

  it("400s a target path outside the case directory", async () => {
    const { app } = await harness();
    const res = await request(app).post("/cases/c1/mcp/sift/run")
      .send({ ...RUN_BODY, targetPath: "../../../etc/passwd" });

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/outside the case directory/);
  });

  it("400s a command the server is not allowed to run", async () => {
    const { app, jobManager } = await harness();
    const res = await request(app).post("/cases/c1/mcp/sift/run")
      .send({ ...RUN_BODY, args: { command: ["curl", "http://x", "<target>"] } });

    // The guard runs inside the job, so the refusal lands there — and nothing was transferred.
    const job = await settle(jobManager, res.body.jobId);
    expect(job.status).toBe("error");
    expect(job.error).toMatch(/not allowed to run "curl"/);
  });

  it("400s an unknown or disabled server", async () => {
    const { app, mcpServerStore } = await harness();
    expect((await request(app).post("/cases/c1/mcp/ghost/run").send(RUN_BODY)).status).toBe(400);

    await mcpServerStore.update("sift", { enabled: false });
    const res = await request(app).post("/cases/c1/mcp/sift/run").send(RUN_BODY);
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/is disabled/);
  });

  it("400s without a tool, 404s an unknown case, 501s when unconfigured", async () => {
    const { app, store } = await harness();
    expect((await request(app).post("/cases/c1/mcp/sift/run").send({ args: {} })).status).toBe(400);
    expect((await request(app).post("/cases/nope/mcp/sift/run").send(RUN_BODY)).status).toBe(404);

    const bare = createApp(store, {});
    expect((await request(bare).post("/cases/c1/mcp/sift/run").send(RUN_BODY)).status).toBe(501);
  });
});

// A tool can return reference data as readily as evidence — a capability listing is structurally
// identical to a Volatility table — so the analyst gets to look before any of it reaches the case.
describe("preview before import", () => {
  it("fetches the output without touching the case", async () => {
    const { app, jobManager } = await harness();

    const res = await request(app).post("/cases/c1/mcp/sift/run").send({ ...RUN_BODY, preview: true });
    expect(res.body.preview).toBe(true);
    const job = await settle(jobManager, res.body.jobId);
    expect(job.status).toBe("done");

    const state = await request(app).get("/cases/c1/state");
    expect(state.body.iocs).toHaveLength(0);
    expect(state.body.forensicTimeline).toHaveLength(0);
  });

  it("labels the job as a preview", async () => {
    const { app, jobManager } = await harness();
    const res = await request(app).post("/cases/c1/mcp/sift/run").send({ ...RUN_BODY, preview: true });
    expect(jobManager.get(res.body.jobId)?.label).toBe("sift/run_command (preview)");
    await settle(jobManager, res.body.jobId);
  });

  it("returns the output and the kind it would import as", async () => {
    const { app, jobManager } = await harness();
    const res = await request(app).post("/cases/c1/mcp/sift/run").send({ ...RUN_BODY, preview: true });
    await settle(jobManager, res.body.jobId);

    const p = await request(app).get(`/cases/c1/mcp/preview/${res.body.jobId}`);
    expect(p.status).toBe(200);
    expect(p.body).toMatchObject({ server: "sift", tool: "run_command", kind: "yara", bytes: YARA_OUT.length, truncated: false });
    expect(p.body.text).toBe(YARA_OUT);
  });

  it("caps a large body so the point is the shape, not the volume", async () => {
    const big = "EvilRule /x/a.bin\n" + "0x10:$s: 4d 5a\n".repeat(2000);
    const { app, jobManager } = await harness({ text: big });
    const res = await request(app).post("/cases/c1/mcp/sift/run").send({ ...RUN_BODY, preview: true });
    await settle(jobManager, res.body.jobId);

    const p = await request(app).get(`/cases/c1/mcp/preview/${res.body.jobId}`);
    expect(p.body.bytes).toBe(big.length);
    expect(p.body.truncated).toBe(true);
    expect(p.body.text.length).toBe(8 * 1024);
  });

  it("imports exactly the fetched bytes on approval, without re-running the tool", async () => {
    const { app, jobManager, transfers } = await harness();
    const res = await request(app).post("/cases/c1/mcp/sift/run").send({ ...RUN_BODY, preview: true });
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
    const res = await request(app).post("/cases/c1/mcp/sift/run").send({ ...RUN_BODY, preview: true });
    await settle(jobManager, res.body.jobId);
    await request(app).post(`/cases/c1/mcp/preview/${res.body.jobId}/import`);

    const undo = await request(app).get("/cases/c1/import/undo-stack");
    expect(undo.body.undo?.[0]?.label ?? undo.body.entries?.[0]?.label).toBe("MCP: sift/run_command");
  });

  it("is consumed by importing, so it cannot be imported twice", async () => {
    const { app, jobManager } = await harness();
    const res = await request(app).post("/cases/c1/mcp/sift/run").send({ ...RUN_BODY, preview: true });
    await settle(jobManager, res.body.jobId);

    expect((await request(app).post(`/cases/c1/mcp/preview/${res.body.jobId}/import`)).status).toBe(200);
    expect((await request(app).post(`/cases/c1/mcp/preview/${res.body.jobId}/import`)).status).toBe(404);
  });

  it("discards a preview and leaves the case untouched", async () => {
    const { app, jobManager } = await harness();
    const res = await request(app).post("/cases/c1/mcp/sift/run").send({ ...RUN_BODY, preview: true });
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

describe("POST /cases/:id/mcp/:serverId/run-upload", () => {
  it("stages uploaded bytes, runs against them, and ingests", async () => {
    const { app, jobManager, transfers } = await harness();

    const res = await request(app).post("/cases/c1/mcp/sift/run-upload").send({
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
    const res = await request(app).post("/cases/c1/mcp/sift/run-upload").send({ ...RUN_BODY, filename: "x.bin" });
    expect(res.status).toBe(400);
  });
});
