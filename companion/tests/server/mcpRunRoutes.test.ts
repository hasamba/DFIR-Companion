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
