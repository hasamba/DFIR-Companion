import { describe, it, expect } from "vitest";
import {
  emptyJobTable,
  createJob,
  progressJob,
  checkpointJob,
  finishJob,
  failJob,
  cancelJob,
  interruptJob,
  requeueJob,
  getJob,
  listJobs,
  capJobs,
  isTerminal,
  type JobTable,
} from "../../src/analysis/jobRegistry.js";

const T0 = "2026-07-05T00:00:00.000Z";
const T1 = "2026-07-05T00:00:01.000Z";

function withJobs(n: number, kind: "import" | "synthesis" | "enrichment" = "import"): JobTable {
  let t = emptyJobTable();
  for (let i = 0; i < n; i++) t = createJob(t, { id: `job_${i}`, caseId: "c1", kind, now: T0 });
  return t;
}

describe("jobRegistry", () => {
  it("createJob appends a running, immutable job", () => {
    const t0 = emptyJobTable();
    const t1 = createJob(t0, {
      id: "job_1",
      caseId: "c1",
      kind: "synthesis",
      label: "x",
      cancellable: true,
      now: T0,
    });
    expect(t0.jobs).toHaveLength(0); // original untouched
    const j = getJob(t1, "job_1")!;
    expect(j.status).toBe("running");
    expect(j.cancellable).toBe(true);
    expect(j.startedAt).toBe(T0);
    expect(j.updatedAt).toBe(T0);
    expect(j.endedAt).toBeUndefined();
  });

  it("defaults cancellable to false", () => {
    const t = createJob(emptyJobTable(), { id: "j", caseId: "c1", kind: "import", now: T0 });
    expect(getJob(t, "j")!.cancellable).toBe(false);
  });

  it("progressJob updates progress + detail without mutating", () => {
    const t1 = withJobs(1);
    const t2 = progressJob(t1, "job_0", { done: 3, total: 10 }, "extracting", T1);
    expect(getJob(t1, "job_0")!.progress).toBeUndefined();
    expect(getJob(t2, "job_0")!.progress).toEqual({ done: 3, total: 10 });
    expect(getJob(t2, "job_0")!.detail).toBe("extracting");
    expect(getJob(t2, "job_0")!.updatedAt).toBe(T1);
  });

  // #2470: a cloud collection downloads 29 pages, then imports them from 1 again. The import updates
  // were dropped as out of order, so the job froze on "29/29".
  describe("multi-step progress", () => {
    const T60 = "2026-07-05T00:01:00.000Z";
    const T70 = "2026-07-05T00:01:10.000Z";

    it("still drops a lower count in the same step", () => {
      let t = progressJob(withJobs(1), "job_0", { done: 29, total: 29 }, "downloading", T1);
      t = progressJob(t, "job_0", { done: 5, total: 29 }, "late update", T1);
      expect(getJob(t, "job_0")).toMatchObject({ progress: { done: 29, total: 29 }, detail: "downloading" });
    });

    it("accepts a lower count that begins a new step, and keeps later steps' updates", () => {
      let t = progressJob(withJobs(1), "job_0", { done: 29, total: 29 }, "downloading", T1);
      t = progressJob(t, "job_0", { done: 0, total: 29, stepStartedAt: T60 }, "importing 0/29", T60);
      expect(getJob(t, "job_0")).toMatchObject({
        progress: { done: 0, total: 29, stepStartedAt: T60 },
        detail: "importing 0/29",
      });
      t = progressJob(t, "job_0", { done: 2, total: 29, stepStartedAt: T60 }, "importing 2/29", T70);
      expect(getJob(t, "job_0")!.progress).toEqual({ done: 2, total: 29, stepStartedAt: T60 });
      // A late update of the same step is still dropped.
      t = progressJob(t, "job_0", { done: 1, total: 29, stepStartedAt: T60 }, "importing 1/29", T70);
      expect(getJob(t, "job_0")!.progress?.done).toBe(2);
    });

    it("measures a step's speed and ETA from the step's start, not the job's", () => {
      const started = { ...getJob(withJobs(1), "job_0")!, startedAt: T0 };
      let t: JobTable = { ...withJobs(1), jobs: [started] };
      t = progressJob(t, "job_0", { done: 2, total: 12, stepStartedAt: T60 }, "importing", T70);
      const job = getJob(t, "job_0")!;
      // 2 pages in the 10 s since the step began → 0.2/s; 10 left → 50 s.
      expect(job.throughputPerSecond).toBeCloseTo(0.2);
      expect(job.etaAt).toBe("2026-07-05T00:02:00.000Z");
    });

    // Codex review: a collection resumed at 990/1000 imported pages would have counted all 990 as work
    // done in the new step — a speed of hundreds per second and an ETA of under a second.
    it("counts only the work since the step began, for a step resumed part-way", () => {
      const started = { ...getJob(withJobs(1), "job_0")!, startedAt: T0 };
      let t: JobTable = { ...withJobs(1), jobs: [started] };
      const step = { stepStartedAt: T60, stepBaseline: 990 };
      t = progressJob(t, "job_0", { done: 990, total: 1000, ...step }, "importing", T60);
      expect(getJob(t, "job_0")!.etaAt).toBeUndefined();
      t = progressJob(
        t,
        "job_0",
        { done: 991, total: 1000, ...step },
        "importing",
        "2026-07-05T00:02:00.000Z",
      );
      const job = getJob(t, "job_0")!;
      // 1 page in 60 s → 1/60 per second; 9 left → 540 s after 00:02:00.
      expect(job.throughputPerSecond).toBeCloseTo(1 / 60);
      expect(job.etaAt).toBe("2026-07-05T00:11:00.000Z");
      expect(job.progress).toEqual({ done: 991, total: 1000, stepStartedAt: T60, stepBaseline: 990 });
    });

    it("ignores a step start that is not a time", () => {
      const t = progressJob(withJobs(1), "job_0", { done: 1, total: 2, stepStartedAt: "soon" }, "x", T1);
      expect(getJob(t, "job_0")!.progress).toEqual({ done: 1, total: 2 });
    });
  });

  it("keeps live parser progress separate from resumable durable checkpoints", () => {
    let table = checkpointJob(
      withJobs(1),
      "job_0",
      { progress: { done: 0, total: 1 }, detail: "evidence committed" },
      T0,
    );
    table = progressJob(table, "job_0", { done: 500, total: 1000 }, "reading events", T1);
    expect(getJob(table, "job_0")?.lastCheckpoint?.progress).toEqual({ done: 0, total: 1 });

    table = checkpointJob(
      table,
      "job_0",
      { progress: { done: 1, total: 1 }, detail: "timeline committed" },
      T1,
    );
    table = requeueJob(interruptJob(table, "job_0", T1), "job_0", T1);
    expect(getJob(table, "job_0")).toMatchObject({
      status: "queued",
      progress: { done: 1, total: 1 },
      detail: "timeline committed",
      lastCheckpoint: { progress: { done: 1, total: 1 } },
    });
  });

  it("finish / fail / cancel set a terminal status + endedAt", () => {
    const t = withJobs(3);
    const done = finishJob(t, "job_0", T1);
    const errored = failJob(done, "job_1", "boom", T1);
    const cancelled = cancelJob(errored, "job_2", T1);
    expect(getJob(cancelled, "job_0")!.status).toBe("succeeded");
    expect(getJob(cancelled, "job_1")!).toMatchObject({ status: "failed", error: "boom", endedAt: T1 });
    expect(getJob(cancelled, "job_2")!.status).toBe("cancelled");
    expect(getJob(cancelled, "job_2")!.updatedAt).toBe(T1);
    for (const id of ["job_0", "job_1", "job_2"])
      expect(isTerminal(getJob(cancelled, id)!.status)).toBe(true);
  });

  it("a terminal job cannot be re-terminated (late finish can't clobber a cancel)", () => {
    const t = cancelJob(withJobs(1), "job_0", T0);
    const late = finishJob(t, "job_0", T1);
    expect(getJob(late, "job_0")!.status).toBe("cancelled");
    expect(getJob(late, "job_0")!.endedAt).toBe(T0);
  });

  it("progress on a terminal job is ignored", () => {
    const t = finishJob(withJobs(1), "job_0", T1);
    const after = progressJob(t, "job_0", { done: 9, total: 9 });
    expect(getJob(after, "job_0")!.progress).toBeUndefined();
  });

  it("unknown id is a no-op (same table reference)", () => {
    const t = withJobs(1);
    expect(progressJob(t, "nope", { done: 1, total: 1 })).toBe(t);
    expect(finishJob(t, "nope", T1)).toBe(t);
  });

  it("listJobs is newest-first and filters by case", () => {
    let t = withJobs(2, "import");
    t = createJob(t, { id: "job_c2", caseId: "c2", kind: "synthesis", now: T0 });
    expect(listJobs(t).map((j) => j.id)).toEqual(["job_c2", "job_1", "job_0"]);
    expect(listJobs(t, { caseId: "c1" }).map((j) => j.id)).toEqual(["job_1", "job_0"]);
  });

  it("capJobs evicts oldest terminal jobs but never a running one", () => {
    let t = withJobs(4); // job_0..job_3, all running
    t = finishJob(t, "job_1", T1); // only job_1 is terminal
    const capped = capJobs(t, 3);
    // Over by 1 → the single terminal job (job_1) is evicted; running jobs survive.
    expect(capped.jobs.map((j) => j.id)).toEqual(["job_0", "job_2", "job_3"]);
  });

  it("capJobs keeps everything when nothing terminal to evict", () => {
    const t = withJobs(5); // all running
    expect(capJobs(t, 3)).toBe(t);
  });

  it("capJobs is a no-op under the limit", () => {
    const t = withJobs(2);
    expect(capJobs(t, 10)).toBe(t);
  });
});
