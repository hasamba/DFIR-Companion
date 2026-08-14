import { describe, it, expect, vi } from "vitest";
import { JobManager } from "../../src/analysis/jobManager.js";
import { createImportJobTracking } from "../../src/routes/importJobTracking.js";

function mkClock(): () => string {
  let n = 0;
  return () => `2026-07-05T00:00:${String(n++).padStart(2, "0")}.000Z`;
}

describe("JobManager", () => {
  it("register creates a running job and fires onJob", () => {
    const onJob = vi.fn();
    const m = new JobManager({ onJob, now: mkClock() });
    const { jobId, signal } = m.register({ caseId: "c1", kind: "import", label: "f.csv" });
    expect(jobId).toBe("job_1");
    expect(signal).toBeUndefined(); // not cancellable
    expect(m.get(jobId)!.status).toBe("running");
    expect(onJob).toHaveBeenCalledWith("c1");
  });

  it("a cancellable job hands out an AbortSignal", () => {
    const m = new JobManager({ now: mkClock() });
    const { signal } = m.register({ caseId: "c1", kind: "synthesis", cancellable: true });
    expect(signal).toBeInstanceOf(AbortSignal);
    expect(signal!.aborted).toBe(false);
  });

  it("live progress reports metrics without replacing the durable checkpoint", async () => {
    const onJob = vi.fn();
    const m = new JobManager({ onJob, now: mkClock() });
    const { jobId } = m.register({ caseId: "c1", kind: "import" });
    await m.checkpoint(jobId, {
      done: 1,
      total: 5,
      detail: "batch 1 committed",
      cursor: { nextBatch: 1 },
    });
    m.progress(jobId, 2, 5, "extracting");
    expect(m.get(jobId)).toMatchObject({
      progress: { done: 2, total: 5 },
      detail: "extracting",
      throughputPerSecond: 1,
      lastCheckpoint: {
        progress: { done: 1, total: 5 },
        cursor: { nextBatch: 1 },
      },
    });
    await m.finish(jobId);
    expect(m.get(jobId)!.status).toBe("succeeded");
    expect(onJob).toHaveBeenCalledTimes(4); // register + checkpoint + progress + finish
  });

  it("tracks EVTX parsing separately from evidence and timeline commits", async () => {
    const m = new JobManager({ now: mkClock() });
    const job = m.register({ caseId: "c1", kind: "import", resumable: true });
    const reportStatus = vi.fn();
    const tracking = createImportJobTracking(m, job, "evtxxml", reportStatus);

    await tracking.start();
    expect(m.get(job.jobId)?.lastCheckpoint?.detail).toContain("evidence committed");

    tracking.onParseProgress(250, 1000);
    expect(m.get(job.jobId)).toMatchObject({
      progress: { done: 250, total: 1000 },
      lastCheckpoint: { progress: { done: 0, total: 1 } },
    });

    tracking.onParseProgress(1250, 2000, "processing Windows events");
    expect(m.get(job.jobId)).toMatchObject({
      progress: { done: 1250, total: 2000 },
      detail: "processing Windows events",
      lastCheckpoint: { progress: { done: 0, total: 1 } },
    });

    await tracking.onProgress(1, 1);
    expect(reportStatus).toHaveBeenCalledWith(1, 1);
    expect(m.get(job.jobId)?.lastCheckpoint).toMatchObject({
      progress: { done: 1, total: 1 },
      detail: "evtxxml import — committed batch 1/1",
    });
  });

  it("fail records the error message", async () => {
    const m = new JobManager({ now: mkClock() });
    const { jobId } = m.register({ caseId: "c1", kind: "synthesis", cancellable: true });
    await m.fail(jobId, new Error("provider 402"));
    expect(m.get(jobId)!).toMatchObject({ status: "failed", error: "provider 402" });
  });

  it("records warnings once and enforces a runtime budget", async () => {
    vi.useFakeTimers();
    try {
      const m = new JobManager({ now: mkClock() });
      const job = m.register({
        caseId: "c1",
        kind: "deep-pass",
        resourceBudget: { maxRuntimeMs: 10 },
      });
      await m.warn(job.jobId, "one batch had partial coverage");
      await m.warn(job.jobId, "one batch had partial coverage");
      expect(m.get(job.jobId)?.warnings).toEqual(["one batch had partial coverage"]);

      await vi.advanceTimersByTimeAsync(11);

      expect(job.signal?.aborted).toBe(true);
      expect(m.get(job.jobId)).toMatchObject({
        status: "failed",
        failure: {
          code: "runtime_budget_exceeded",
          retryable: false,
        },
      });
    } finally {
      vi.useRealTimers();
    }
  });

  it("cancel aborts the signal and marks cancelled", async () => {
    const m = new JobManager({ now: mkClock() });
    const { jobId, signal } = m.register({ caseId: "c1", kind: "enrichment", cancellable: true });
    const res = await m.cancel(jobId);
    expect(res.ok).toBe(true);
    expect(signal!.aborted).toBe(true);
    expect(m.get(jobId)!.status).toBe("cancelled");
  });

  it("a late fail after cancel does not clobber the cancelled status", async () => {
    const m = new JobManager({ now: mkClock() });
    const { jobId } = m.register({ caseId: "c1", kind: "synthesis", cancellable: true });
    await m.cancel(jobId);
    await m.fail(jobId, new Error("AbortError")); // the aborted fetch rejects afterwards
    expect(m.get(jobId)!.status).toBe("cancelled");
  });

  it("cancel is rejected with a reason for unknown / terminal / non-cancellable jobs", async () => {
    const m = new JobManager({ now: mkClock() });
    expect(await m.cancel("nope")).toEqual({ ok: false, reason: "unknown" });

    const deterministic = m.register({ caseId: "c1", kind: "import" }); // cancellable:false
    expect(await m.cancel(deterministic.jobId)).toEqual({ ok: false, reason: "not-cancellable" });

    const done = m.register({ caseId: "c1", kind: "synthesis", cancellable: true });
    await m.finish(done.jobId);
    expect(await m.cancel(done.jobId)).toEqual({ ok: false, reason: "terminal" });
  });

  it("list filters by case, newest first", () => {
    const m = new JobManager({ now: mkClock() });
    m.register({ caseId: "c1", kind: "import" });
    m.register({ caseId: "c2", kind: "import" });
    m.register({ caseId: "c1", kind: "synthesis", cancellable: true });
    expect(m.list("c1").map((j) => j.id)).toEqual(["job_3", "job_1"]);
    expect(m.list().map((j) => j.id)).toEqual(["job_3", "job_2", "job_1"]);
  });

  it("respects the max cap by evicting oldest terminal jobs", async () => {
    const m = new JobManager({ max: 2, now: mkClock() });
    const a = m.register({ caseId: "c1", kind: "import" });
    await m.finish(a.jobId);
    const b = m.register({ caseId: "c1", kind: "import" });
    await m.finish(b.jobId);
    m.register({ caseId: "c1", kind: "import" }); // over cap → evict oldest terminal (a)
    expect(m.get(a.jobId)).toBeUndefined();
    expect(m.list()).toHaveLength(2);
  });

  it("an onJob that throws never breaks a transition", () => {
    const m = new JobManager({
      onJob: () => {
        throw new Error("ws down");
      },
      now: mkClock(),
    });
    expect(() => m.register({ caseId: "c1", kind: "import" })).not.toThrow();
  });

  describe("exclusive registration", () => {
    it("cancels a running same-kind job for the same case and aborts its signal", () => {
      const m = new JobManager({ now: mkClock() });
      const first = m.register({ caseId: "c1", kind: "synthesis", cancellable: true, exclusive: true });
      const second = m.register({ caseId: "c1", kind: "synthesis", cancellable: true, exclusive: true });
      expect(m.get(first.jobId)!.status).toBe("cancelled");
      expect(first.signal!.aborted).toBe(true);
      expect(m.get(second.jobId)!.status).toBe("running");
    });

    it("leaves other cases and other kinds alone", () => {
      const m = new JobManager({ now: mkClock() });
      const otherCase = m.register({ caseId: "c2", kind: "synthesis", cancellable: true });
      const otherKind = m.register({ caseId: "c1", kind: "import", cancellable: true });
      m.register({ caseId: "c1", kind: "synthesis", cancellable: true, exclusive: true });
      expect(m.get(otherCase.jobId)!.status).toBe("running");
      expect(m.get(otherKind.jobId)!.status).toBe("running");
    });

    it("does not touch an already-terminal same-kind job", async () => {
      const m = new JobManager({ now: mkClock() });
      const first = m.register({ caseId: "c1", kind: "synthesis", cancellable: true });
      await m.finish(first.jobId);
      const second = m.register({ caseId: "c1", kind: "synthesis", cancellable: true, exclusive: true });
      expect(m.get(first.jobId)!.status).toBe("succeeded"); // untouched, not re-marked cancelled
      expect(m.get(second.jobId)!.status).toBe("running");
    });

    it("without exclusive, two same-kind jobs for the same case both stay running", () => {
      const m = new JobManager({ now: mkClock() });
      const first = m.register({ caseId: "c1", kind: "synthesis", cancellable: true });
      const second = m.register({ caseId: "c1", kind: "synthesis", cancellable: true });
      expect(m.get(first.jobId)!.status).toBe("running");
      expect(m.get(second.jobId)!.status).toBe("running");
    });
  });

  describe("hasActive", () => {
    it("is true while a non-terminal job of that kind exists for the case", async () => {
      const m = new JobManager({ now: mkClock() });
      const { jobId } = m.register({ caseId: "c1", kind: "synthesis", cancellable: true });
      expect(m.hasActive("c1", "synthesis")).toBe(true);
      await m.finish(jobId);
      expect(m.hasActive("c1", "synthesis")).toBe(false);
    });

    it("is false for a different case or a different kind", () => {
      const m = new JobManager({ now: mkClock() });
      m.register({ caseId: "c1", kind: "synthesis", cancellable: true });
      expect(m.hasActive("c2", "synthesis")).toBe(false);
      expect(m.hasActive("c1", "import")).toBe(false);
    });
  });

  // A deleted case must take its jobs with it. The table is keyed by case id alone, so anything
  // left behind is inherited wholesale by the next case that claims the id — and the dashboard's
  // Resume button would then replay the dead case's import into the live one.
  describe("forgetCase", () => {
    it("drops every job belonging to the case", async () => {
      const m = new JobManager({ now: mkClock() });
      m.register({ caseId: "c1", kind: "import", label: "a.json" });
      m.register({ caseId: "c1", kind: "import", label: "b.json" });
      expect(m.list("c1")).toHaveLength(2);
      await m.forgetCase("c1");
      expect(m.list("c1")).toEqual([]);
    });

    it("leaves other cases and global jobs untouched", async () => {
      const m = new JobManager({ now: mkClock() });
      m.register({ caseId: "c1", kind: "import" });
      m.register({ caseId: "c2", kind: "import" });
      m.register({ kind: "synthesis" }); // global — caseId null
      await m.forgetCase("c1");
      expect(m.list("c1")).toEqual([]);
      expect(m.list("c2")).toHaveLength(1);
      expect(m.list()).toHaveLength(2);
    });

    it("aborts a still-running job before dropping it", async () => {
      const m = new JobManager({ now: mkClock() });
      const { jobId, signal } = m.register({ caseId: "c1", kind: "import", cancellable: true });
      expect(signal!.aborted).toBe(false);
      await m.forgetCase("c1");
      expect(signal!.aborted).toBe(true);
      expect(m.get(jobId)).toBeUndefined();
    });

    it("forgetting an unknown case is a no-op", async () => {
      const m = new JobManager({ now: mkClock() });
      m.register({ caseId: "c1", kind: "import" });
      await m.forgetCase("nope");
      expect(m.list("c1")).toHaveLength(1);
    });

    it("a re-created case with the same id starts with an empty job list", async () => {
      const m = new JobManager({ now: mkClock() });
      m.register({ caseId: "INC-2026-003", kind: "import", label: "velociraptor.json" });
      await m.forgetCase("INC-2026-003");
      expect(m.list("INC-2026-003")).toEqual([]);
      m.register({ caseId: "INC-2026-003", kind: "import", label: "fresh.json" });
      expect(m.list("INC-2026-003").map((job) => job.label)).toEqual(["fresh.json"]);
    });
  });
});
