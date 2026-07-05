import { describe, it, expect } from "vitest";
import {
  emptyJobTable,
  createJob,
  progressJob,
  finishJob,
  failJob,
  cancelJob,
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
    const t1 = createJob(t0, { id: "job_1", caseId: "c1", kind: "synthesis", label: "x", cancellable: true, now: T0 });
    expect(t0.jobs).toHaveLength(0); // original untouched
    const j = getJob(t1, "job_1")!;
    expect(j.status).toBe("running");
    expect(j.cancellable).toBe(true);
    expect(j.startedAt).toBe(T0);
    expect(j.endedAt).toBeUndefined();
  });

  it("defaults cancellable to false", () => {
    const t = createJob(emptyJobTable(), { id: "j", caseId: "c1", kind: "import", now: T0 });
    expect(getJob(t, "j")!.cancellable).toBe(false);
  });

  it("progressJob updates progress + detail without mutating", () => {
    const t1 = withJobs(1);
    const t2 = progressJob(t1, "job_0", { done: 3, total: 10 }, "extracting");
    expect(getJob(t1, "job_0")!.progress).toBeUndefined();
    expect(getJob(t2, "job_0")!.progress).toEqual({ done: 3, total: 10 });
    expect(getJob(t2, "job_0")!.detail).toBe("extracting");
  });

  it("finish / fail / cancel set a terminal status + endedAt", () => {
    const t = withJobs(3);
    const done = finishJob(t, "job_0", T1);
    const errored = failJob(done, "job_1", "boom", T1);
    const cancelled = cancelJob(errored, "job_2", T1);
    expect(getJob(cancelled, "job_0")!.status).toBe("done");
    expect(getJob(cancelled, "job_1")!).toMatchObject({ status: "error", error: "boom", endedAt: T1 });
    expect(getJob(cancelled, "job_2")!.status).toBe("cancelled");
    for (const id of ["job_0", "job_1", "job_2"]) expect(isTerminal(getJob(cancelled, id)!.status)).toBe(true);
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
