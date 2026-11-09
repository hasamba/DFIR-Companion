import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import { ForensicGateControlStore } from "../../src/analysis/forensicGateControl.js";
import { JobManager } from "../../src/analysis/jobManager.js";
import { pollFor, POLL_TIMEOUT_MS } from "../helpers/poll.js";

// #2407: the ~24 dedicated `import-*` kinds commit through routes/importCommit.ts, which never
// registered a job. They were missing from the Jobs panel, and every "is the case busy?" reader
// (they read jobs only) saw an idle case while one ran. Now each runs under an "import" job.

const ISO = "2026-05-02T10:00:00Z";
const THOR =
  [
    { level: "Warning", module: "Filescan", message: "Suspicious file", time: ISO, file: "C:\\Temp\\a.exe" },
    { level: "Notice", module: "Filescan", message: "Noticed file", time: ISO, file: "C:\\Temp\\b.exe" },
  ]
    .map((r) => JSON.stringify(r))
    .join("\n") + "\n";

async function makeApp(jobManager: JobManager) {
  const root = await mkdtemp(join(tmpdir(), "dfir-2407-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const superTimelineStore = new SuperTimelineStore(store);
  const pipeline = buildRuntimePipeline({
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, {
    pipeline,
    stateStore,
    superTimelineStore,
    importMetaStore: new ImportMetaStore(store),
    forensicGateControlStore: new ForensicGateControlStore(store),
    jobManager,
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, stateStore, superTimelineStore };
}

const importJobs = (m: JobManager) => m.list("c1").filter((j) => j.kind === "import");

describe("dedicated imports run under a job (#2407)", () => {
  it("shows a dedicated import as an import job that ends succeeded", async () => {
    const jobManager = new JobManager();
    const { app } = await makeApp(jobManager);
    const res = await request(app).post("/cases/c1/import-thor").send({ text: THOR, filename: "thor.json" });
    expect(res.status).toBe(202);
    const job = await pollFor("the thor import job to succeed", async () => {
      const j = importJobs(jobManager)[0];
      return j?.status === "succeeded" ? j : undefined;
    });
    expect(job.label).toBe(`thor: ${res.body.file}`);
    // #2425: Cancel closes once the importer has returned, so a finished row is not cancellable.
    expect(job.cancellable).toBe(false);
  });

  it("fails the job when the importer fails", async () => {
    const jobManager = new JobManager();
    const { app, stateStore } = await makeApp(jobManager);
    stateStore.save = async () => {
      throw new Error("disk full (staged)");
    };
    const res = await request(app).post("/cases/c1/import-thor").send({ text: THOR, filename: "thor.json" });
    expect(res.status).toBe(202);
    const job = await pollFor("the thor import job to fail", async () => {
      const j = importJobs(jobManager)[0];
      return j?.status === "failed" ? j : undefined;
    });
    expect(job.failure).toMatchObject({
      code: "import_failed",
      message: expect.stringContaining("disk full"),
    });
  });

  it(
    "waits for the case's job slot instead of running beside other case work",
    async () => {
      const jobManager = new JobManager({ globalConcurrency: 1, perCaseConcurrency: 1 });
      const { app, superTimelineStore } = await makeApp(jobManager);
      const busy = jobManager.register({ caseId: "c1", kind: "synthesis", label: "synthesis" });
      await busy.ready;
      const res = await request(app)
        .post("/cases/c1/import-thor")
        .send({ text: THOR, filename: "thor.json" });
      expect(res.status).toBe(202);
      await new Promise((r) => setTimeout(r, 300));
      expect(importJobs(jobManager)[0]?.status).toBe("queued");
      expect((await superTimelineStore.query("c1", {})).total).toBe(0);

      await jobManager.finish(busy.jobId);
      await pollFor("the queued import to run and succeed", async () =>
        importJobs(jobManager)[0]?.status === "succeeded" ? true : undefined,
      );
      expect((await superTimelineStore.query("c1", {})).total).toBe(2);
    },
    POLL_TIMEOUT_MS * 2,
  );

  it("a queued import whose case is forgotten stops quietly, without recording a failure", async () => {
    const jobManager = new JobManager({ globalConcurrency: 1, perCaseConcurrency: 1 });
    const { app } = await makeApp(jobManager);
    const busy = jobManager.register({ caseId: "c1", kind: "synthesis", label: "synthesis" });
    await busy.ready;
    const res = await request(app).post("/cases/c1/import-thor").send({ text: THOR, filename: "thor.json" });
    expect(res.status).toBe(202);
    await pollFor("the import to queue", async () => (importJobs(jobManager)[0] ? true : undefined));
    await jobManager.forgetCase("c1");
    await new Promise((r) => setTimeout(r, 200));
    const { report } = (await request(app).get("/diagnostics")).body as {
      report: { importers: { recentFailures: Array<{ caseId: string }> } };
    };
    expect(report.importers.recentFailures.filter((f) => f.caseId === "c1")).toEqual([]);
  });

  // #2425: a dedicated import can be cancelled while it waits for the case's slot. Cancelling one
  // while its importer runs is covered in dedicatedImportCancel.test.ts.
  it("a queued dedicated import can be cancelled: nothing is imported and no failure is recorded", async () => {
    const jobManager = new JobManager({ globalConcurrency: 1, perCaseConcurrency: 1 });
    const { app, superTimelineStore, stateStore } = await makeApp(jobManager);
    const busy = jobManager.register({ caseId: "c1", kind: "synthesis", label: "synthesis" });
    await busy.ready;
    const res = await request(app).post("/cases/c1/import-thor").send({ text: THOR, filename: "thor.json" });
    expect(res.status).toBe(202);
    const queued = await pollFor("the import to queue", async () => importJobs(jobManager)[0]);
    expect(queued).toMatchObject({ status: "queued", cancellable: true });
    expect((await jobManager.cancel(queued.id)).ok).toBe(true);
    await jobManager.finish(busy.jobId);
    await new Promise((r) => setTimeout(r, 300));
    expect(importJobs(jobManager)[0]?.status).toBe("cancelled");
    expect((await superTimelineStore.query("c1", {})).total).toBe(0);
    expect((await stateStore.load("c1")).forensicTimeline).toEqual([]);
    const { report } = (await request(app).get("/diagnostics")).body as {
      report: { importers: { recentFailures: Array<{ caseId: string }> } };
    };
    expect(report.importers.recentFailures.filter((f) => f.caseId === "c1")).toEqual([]);
  });

  it("a cancelled queued import leaves nothing that blocks re-creating the case id", async () => {
    const jobManager = new JobManager({ globalConcurrency: 1, perCaseConcurrency: 1 });
    const { app } = await makeApp(jobManager);
    const busy = jobManager.register({ caseId: "c1", kind: "synthesis", label: "synthesis" });
    await busy.ready;
    await request(app).post("/cases/c1/import-thor").send({ text: THOR, filename: "thor.json" });
    const queued = await pollFor("the import to queue", async () => importJobs(jobManager)[0]);
    await jobManager.cancel(queued.id);
    await jobManager.finish(busy.jobId);
    await new Promise((r) => setTimeout(r, 100));
    await jobManager.forgetCase("c1");
    expect(jobManager.isStopping("c1")).toBe(false);
  });
});
