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
import { ImportUndoStore } from "../../src/analysis/importUndo.js";
import { ActivityLogStore } from "../../src/analysis/activityLog.js";
import { ForensicGateControlStore } from "../../src/analysis/forensicGateControl.js";
import { JobManager } from "../../src/analysis/jobManager.js";
import type { JobLedgerStore } from "../../src/analysis/jobLedgerStore.js";
import type { Job } from "../../src/analysis/jobRegistry.js";
import { pollFor, POLL_TIMEOUT_MS } from "../helpers/poll.js";

// #2425: a dedicated import can be cancelled while its importer runs. A cancel either merges
// nothing (the importer stops before its merge) or — for an importer that kept what it had merged —
// leaves a partial import that is settled (tagger + demote) and recorded with an undo checkpoint.
// Either way, the case's slot stays taken until the import has stopped: a cancel frees the job row's
// slot at once, so the import holds the case in memory instead. The same hold covers a job ledger
// that refused the import's row (degraded mode).

const ISO = "2026-05-02T10:00:00Z";
const THOR =
  [
    { level: "Warning", module: "Filescan", message: "Suspicious file", time: ISO, file: "C:\\Temp\\a.exe" },
    { level: "Notice", module: "Filescan", message: "Noticed file", time: ISO, file: "C:\\Temp\\b.exe" },
  ]
    .map((r) => JSON.stringify(r))
    .join("\n") + "\n";

type ImportThor = ReturnType<typeof buildRuntimePipeline>["importThor"];

async function makeApp(jobManager: JobManager) {
  const root = await mkdtemp(join(tmpdir(), "dfir-2425-"));
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
    importUndoStore: new ImportUndoStore(store),
    activityLogStore: new ActivityLogStore(store),
    forensicGateControlStore: new ForensicGateControlStore(store),
    jobManager,
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  // The real THOR importer, held at a gate the test opens. `before` holds it ahead of the merge,
  // `after` once the merge has saved (an importer that returns what it merged after a cancel).
  const real: ImportThor = pipeline.importThor.bind(pipeline);
  const gates = {
    before: Promise.resolve(),
    after: Promise.resolve(),
    entered: 0,
    merged: 0,
    throwAfter: false,
  };
  pipeline.importThor = async (...args: Parameters<ImportThor>) => {
    gates.entered++;
    await gates.before;
    const state = await real(...args);
    gates.merged++;
    await gates.after;
    // An aborted model call in a later batch: the importer throws after earlier batches saved.
    if (gates.throwAfter) throw Object.assign(new Error("aborted mid-batch"), { name: "AbortError" });
    return state;
  };
  return { app, stateStore, superTimelineStore, gates };
}

function gate(): { promise: Promise<void>; open: () => void } {
  let open!: () => void;
  const promise = new Promise<void>((r) => (open = r));
  return { promise, open };
}

const importJob = (m: JobManager) => m.list("c1").find((j) => j.kind === "import");
const synthesisJob = (m: JobManager) => m.list("c1").find((j) => j.kind === "synthesis");

async function recentFailures(app: ReturnType<typeof createApp>): Promise<unknown[]> {
  const { report } = (await request(app).get("/diagnostics")).body as {
    report: { importers: { recentFailures: Array<{ caseId: string }> } };
  };
  return report.importers.recentFailures.filter((f) => f.caseId === "c1");
}

describe("cancelling a running dedicated import (#2425)", () => {
  it(
    "a cancel before the merge imports nothing, records no failure, and holds the case until the import stops",
    async () => {
      const jobManager = new JobManager({ globalConcurrency: 1, perCaseConcurrency: 1 });
      const { app, stateStore, superTimelineStore, gates } = await makeApp(jobManager);
      const before = gate();
      gates.before = before.promise;
      const res = await request(app)
        .post("/cases/c1/import-thor")
        .send({ text: THOR, filename: "thor.json" });
      expect(res.status).toBe(202);
      const running = await pollFor("the importer to start", async () => {
        const j = importJob(jobManager);
        return gates.entered && j?.status === "running" ? j : undefined;
      });
      expect(running.cancellable).toBe(true);
      expect((await jobManager.cancel(running.id)).ok).toBe(true);

      // The row is cancelled and its slot freed, but the importer is still running: nothing else
      // of the case may start yet.
      jobManager.register({ caseId: "c1", kind: "synthesis", label: "synthesis" });
      await new Promise((r) => setTimeout(r, 200));
      expect(synthesisJob(jobManager)?.status).toBe("queued");

      before.open();
      await pollFor("the synthesis to start once the import stopped", async () =>
        synthesisJob(jobManager)?.status === "running" ? true : undefined,
      );
      expect(importJob(jobManager)?.status).toBe("cancelled");
      expect((await stateStore.load("c1")).forensicTimeline).toEqual([]);
      expect((await superTimelineStore.query("c1", {})).total).toBe(0);
      expect(await recentFailures(app)).toEqual([]);
      const undo = (await request(app).get("/cases/c1/import/undo-stack")).body as { canUndo: boolean };
      expect(undo.canUndo).toBe(false);
    },
    POLL_TIMEOUT_MS * 2,
  );

  for (const how of ["returns", "throws an AbortError"] as const) {
    it(
      `an importer that ${how} after a cancel leaves a partial import: settled, recorded and undoable`,
      async () => {
        const jobManager = new JobManager();
        const { app, superTimelineStore, gates } = await makeApp(jobManager);
        gates.throwAfter = how !== "returns";
        const after = gate();
        gates.after = after.promise;
        const res = await request(app)
          .post("/cases/c1/import-thor")
          .send({ text: THOR, filename: "thor.json" });
        expect(res.status).toBe(202);
        const running = await pollFor("the importer to merge", async () => {
          const j = importJob(jobManager);
          return gates.merged && j?.status === "running" ? j : undefined;
        });
        expect((await jobManager.cancel(running.id)).ok).toBe(true);
        after.open();

        // Settled: the super-timeline dual-write (the seam's tagger + demote) ran on what landed.
        await pollFor("the partial import to settle", async () =>
          (await superTimelineStore.query("c1", {})).total === 2 ? true : undefined,
        );
        const meta = await pollFor("the import record", async () => {
          const m = (await request(app).get("/cases/c1/import-meta")).body as { lastImportFile?: string };
          return m.lastImportFile === res.body.file ? m : undefined;
        });
        expect(meta.lastImportFile).toBe(res.body.file);
        const undo = await pollFor("the undo checkpoint", async () => {
          const u = (await request(app).get("/cases/c1/import/undo-stack")).body as { canUndo?: boolean };
          return u.canUndo ? u : undefined;
        });
        expect(undo.canUndo).toBe(true);
        const log = (await request(app).get("/cases/c1/activity-log?category=import")).body as Array<{
          detail: string;
        }>;
        expect(log.some((e) => /cancelled; kept what was imported before the cancel/.test(e.detail))).toBe(
          true,
        );
        expect(importJob(jobManager)?.status).toBe("cancelled");
        expect(await recentFailures(app)).toEqual([]);
      },
      POLL_TIMEOUT_MS * 2,
    );
  }

  it("Cancel closes once the importer has returned, so a finished import stays succeeded", async () => {
    const jobManager = new JobManager();
    const { app } = await makeApp(jobManager);
    await request(app).post("/cases/c1/import-thor").send({ text: THOR, filename: "thor.json" });
    const done = await pollFor("the import to succeed", async () => {
      const j = importJob(jobManager);
      return j?.status === "succeeded" ? j : undefined;
    });
    expect(done.cancellable).toBe(false);
  });
});

describe("degraded mode: the job ledger refuses the import's row (#2425)", () => {
  it(
    "the import still runs, but waits for the case's running job and keeps new jobs out while it runs",
    async () => {
      // Every row but the import's is stored: the import alone runs without a row.
      const ledger: Pick<JobLedgerStore, "listAll" | "insert" | "update" | "prune" | "delete"> = {
        listAll: async () => [],
        insert: async (job: Job) => {
          if (job.kind === "import") throw new Error("ledger disk full (staged)");
          return { inserted: true };
        },
        update: async () => undefined,
        prune: async () => 0,
        delete: async () => 0,
      };
      const jobManager = new JobManager({ ledger: ledger as JobLedgerStore });
      const { app, stateStore, superTimelineStore, gates } = await makeApp(jobManager);
      const busy = jobManager.register({ caseId: "c1", kind: "synthesis", label: "busy" });
      await busy.ready;

      const before = gate();
      gates.before = before.promise;
      const res = await request(app)
        .post("/cases/c1/import-thor")
        .send({ text: THOR, filename: "thor.json" });
      expect(res.status).toBe(202);
      await new Promise((r) => setTimeout(r, 200));
      // Waiting for the running synthesis: nothing imported yet.
      expect((await stateStore.load("c1")).forensicTimeline).toEqual([]);
      // The refused row does not linger as a queued phantom.
      expect(importJob(jobManager)?.status).toBe("failed");

      await jobManager.finish(busy.jobId);
      await new Promise((r) => setTimeout(r, 100));
      // The import is running now (held at the gate). A new job of the case waits for it.
      const second = jobManager.register({ caseId: "c1", kind: "deep-pass", label: "second" });
      await new Promise((r) => setTimeout(r, 200));
      expect(jobManager.list("c1").find((j) => j.id === second.jobId)?.status).toBe("queued");

      before.open();
      await pollFor("the import to land", async () =>
        (await superTimelineStore.query("c1", {})).total === 2 ? true : undefined,
      );
      await second.ready;
      expect(jobManager.list("c1").find((j) => j.id === second.jobId)?.status).toBe("running");
    },
    POLL_TIMEOUT_MS * 2,
  );
});
