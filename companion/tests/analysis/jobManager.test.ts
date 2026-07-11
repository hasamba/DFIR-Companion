import { describe, it, expect, vi } from "vitest";
import { JobManager } from "../../src/analysis/jobManager.js";

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

  it("progress then finish transitions and broadcasts", () => {
    const onJob = vi.fn();
    const m = new JobManager({ onJob, now: mkClock() });
    const { jobId } = m.register({ caseId: "c1", kind: "import" });
    m.progress(jobId, 2, 5, "extracting");
    expect(m.get(jobId)!.progress).toEqual({ done: 2, total: 5 });
    m.finish(jobId);
    expect(m.get(jobId)!.status).toBe("done");
    expect(onJob).toHaveBeenCalledTimes(3); // register + progress + finish
  });

  it("fail records the error message", () => {
    const m = new JobManager({ now: mkClock() });
    const { jobId } = m.register({ caseId: "c1", kind: "synthesis", cancellable: true });
    m.fail(jobId, new Error("provider 402"));
    expect(m.get(jobId)!).toMatchObject({ status: "error", error: "provider 402" });
  });

  it("cancel aborts the signal and marks cancelled", () => {
    const m = new JobManager({ now: mkClock() });
    const { jobId, signal } = m.register({ caseId: "c1", kind: "enrichment", cancellable: true });
    const res = m.cancel(jobId);
    expect(res.ok).toBe(true);
    expect(signal!.aborted).toBe(true);
    expect(m.get(jobId)!.status).toBe("cancelled");
  });

  it("a late fail after cancel does not clobber the cancelled status", () => {
    const m = new JobManager({ now: mkClock() });
    const { jobId } = m.register({ caseId: "c1", kind: "synthesis", cancellable: true });
    m.cancel(jobId);
    m.fail(jobId, new Error("AbortError")); // the aborted fetch rejects afterwards
    expect(m.get(jobId)!.status).toBe("cancelled");
  });

  it("cancel is rejected with a reason for unknown / terminal / non-cancellable jobs", () => {
    const m = new JobManager({ now: mkClock() });
    expect(m.cancel("nope")).toEqual({ ok: false, reason: "unknown" });

    const deterministic = m.register({ caseId: "c1", kind: "import" }); // cancellable:false
    expect(m.cancel(deterministic.jobId)).toEqual({ ok: false, reason: "not-cancellable" });

    const done = m.register({ caseId: "c1", kind: "synthesis", cancellable: true });
    m.finish(done.jobId);
    expect(m.cancel(done.jobId)).toEqual({ ok: false, reason: "terminal" });
  });

  it("list filters by case, newest first", () => {
    const m = new JobManager({ now: mkClock() });
    m.register({ caseId: "c1", kind: "import" });
    m.register({ caseId: "c2", kind: "import" });
    m.register({ caseId: "c1", kind: "synthesis", cancellable: true });
    expect(m.list("c1").map((j) => j.id)).toEqual(["job_3", "job_1"]);
    expect(m.list().map((j) => j.id)).toEqual(["job_3", "job_2", "job_1"]);
  });

  it("respects the max cap by evicting oldest terminal jobs", () => {
    const m = new JobManager({ max: 2, now: mkClock() });
    const a = m.register({ caseId: "c1", kind: "import" });
    m.finish(a.jobId);
    const b = m.register({ caseId: "c1", kind: "import" });
    m.finish(b.jobId);
    m.register({ caseId: "c1", kind: "import" }); // over cap → evict oldest terminal (a)
    expect(m.get(a.jobId)).toBeUndefined();
    expect(m.list()).toHaveLength(2);
  });

  it("an onJob that throws never breaks a transition", () => {
    const m = new JobManager({ onJob: () => { throw new Error("ws down"); }, now: mkClock() });
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

    it("does not touch an already-terminal same-kind job", () => {
      const m = new JobManager({ now: mkClock() });
      const first = m.register({ caseId: "c1", kind: "synthesis", cancellable: true });
      m.finish(first.jobId);
      const second = m.register({ caseId: "c1", kind: "synthesis", cancellable: true, exclusive: true });
      expect(m.get(first.jobId)!.status).toBe("done"); // untouched, not re-marked cancelled
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
    it("is true while a non-terminal job of that kind exists for the case", () => {
      const m = new JobManager({ now: mkClock() });
      const { jobId } = m.register({ caseId: "c1", kind: "synthesis", cancellable: true });
      expect(m.hasActive("c1", "synthesis")).toBe(true);
      m.finish(jobId);
      expect(m.hasActive("c1", "synthesis")).toBe(false);
    });

    it("is false for a different case or a different kind", () => {
      const m = new JobManager({ now: mkClock() });
      m.register({ caseId: "c1", kind: "synthesis", cancellable: true });
      expect(m.hasActive("c2", "synthesis")).toBe(false);
      expect(m.hasActive("c1", "import")).toBe(false);
    });
  });
});
