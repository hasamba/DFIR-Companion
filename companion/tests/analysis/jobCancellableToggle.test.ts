import { describe, it, expect, vi } from "vitest";
import { JobManager } from "../../src/analysis/jobManager.js";

// #2425: a job can close its Cancel for a window where a cancel would free the case's slot while the
// work is still writing rows (Second Look's promotion, a dedicated import once its importer runs),
// and open it again afterwards. The toggle is synchronous, so "close, then check the signal" in one
// turn is atomic with cancel(): either the cancel already landed, or it is refused.
describe("JobManager.setCancellable (#2425)", () => {
  it("a closed Cancel refuses cancel() and leaves the job running with its signal live", async () => {
    const onJob = vi.fn();
    const m = new JobManager({ onJob });
    const job = m.register({ caseId: "c1", kind: "second-look", cancellable: true });
    await job.ready;
    onJob.mockClear();
    m.setCancellable(job.jobId, false);
    expect(m.get(job.jobId)!.cancellable).toBe(false);
    expect(onJob).toHaveBeenCalledWith("c1"); // the dashboard hides the button
    expect(await m.cancel(job.jobId)).toEqual({ ok: false, reason: "not-cancellable" });
    expect(job.signal!.aborted).toBe(false);
    expect(m.get(job.jobId)!.status).toBe("running");
  });

  it("re-opening Cancel lets cancel() abort the signal again", async () => {
    const m = new JobManager();
    const job = m.register({ caseId: "c1", kind: "second-look", cancellable: true });
    await job.ready;
    m.setCancellable(job.jobId, false);
    m.setCancellable(job.jobId, true);
    expect((await m.cancel(job.jobId)).ok).toBe(true);
    expect(job.signal!.aborted).toBe(true);
  });

  it("a cancel that lands first wins: closing afterwards sees the aborted signal", async () => {
    const m = new JobManager();
    const job = m.register({ caseId: "c1", kind: "import", cancellable: true });
    await job.ready;
    await m.cancel(job.jobId);
    m.setCancellable(job.jobId, false); // ignored on a terminal row
    expect(job.signal!.aborted).toBe(true);
    expect(m.get(job.jobId)).toMatchObject({ status: "cancelled", cancellable: true });
  });

  it("a cancelled running job settles its stop record once its work reports, so the case id is free", async () => {
    const m = new JobManager();
    const job = m.register({ caseId: "c1", kind: "import", cancellable: true });
    await job.ready;
    await m.cancel(job.jobId);
    await m.forgetCase("c1");
    expect(m.isStopping("c1")).toBe(true);
    await m.finish(job.jobId); // the work reports its end: a no-op on the row, settles the record
    expect(m.isStopping("c1")).toBe(false);
  });

  it("an unknown job is ignored", () => {
    const m = new JobManager();
    expect(() => m.setCancellable("nope", false)).not.toThrow();
  });
});
