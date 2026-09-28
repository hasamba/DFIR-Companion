// #1801: a gate hold (Presidio approval, duplicate-host merge) is not the analyst's ✕ Cancel.
//
// Every gate writer used jobManager.cancel(), and the registry stamped `cancelRequestedAt` on every
// cancelled row, so /api/jobs showed a hold as a user cancellation. Second opinion used a second
// encoding (`failed` + held_for_analyst). Now all four share one: `cancelled` (so the cockpit never
// reports "synthesis failed"), no `cancelRequestedAt`, and a `held_for_analyst` failure code.
import { describe, it, expect, vi, afterEach } from "vitest";
import {
  emptyJobTable,
  createJob,
  cancelJob,
  holdJob,
  isHeldJob,
  getJob,
  HELD_FOR_ANALYST,
} from "../../src/analysis/jobRegistry.js";
import { JobManager } from "../../src/analysis/jobManager.js";
import { createSynthesisDeferral } from "../../src/composition/synthesisDeferral.js";

const T0 = "2026-07-05T00:00:00.000Z";
const T1 = "2026-07-05T00:00:01.000Z";
const REASON = "Presidio found 3 new PII value(s) awaiting approval";

const oneJob = () => createJob(emptyJobTable(), { id: "job_0", caseId: "c1", kind: "synthesis", now: T0 });

describe("holdJob", () => {
  it("ends the job cancelled, with the hold code and no cancelRequestedAt", () => {
    const job = getJob(holdJob(oneJob(), "job_0", REASON, T1), "job_0")!;
    expect(job.status).toBe("cancelled");
    expect(job.cancelRequestedAt).toBeUndefined();
    expect(job.failure).toEqual({ code: HELD_FOR_ANALYST, message: REASON, retryable: false, at: T1 });
    expect(job.detail).toBe(`on hold — ${REASON}`);
    expect(job.endedAt).toBe(T1);
    expect(isHeldJob(job)).toBe(true);
  });

  it("leaves the analyst's cancel stamped, and not held", () => {
    const job = getJob(cancelJob(oneJob(), "job_0", T1), "job_0")!;
    expect(job.status).toBe("cancelled");
    expect(job.cancelRequestedAt).toBe(T1);
    expect(isHeldJob(job)).toBe(false);
  });
});

describe("JobManager.hold", () => {
  it("holds a non-cancellable job (second opinion) and frees the case slot", async () => {
    const m = new JobManager({ perCaseConcurrency: 1 });
    const { jobId } = m.register({ caseId: "c1", kind: "second-opinion", cancellable: false });
    await m.hold(jobId, REASON);
    const job = m.get(jobId)!;
    expect(job.status).toBe("cancelled");
    expect(job.cancelRequestedAt).toBeUndefined();
    expect(job.failure?.code).toBe(HELD_FOR_ANALYST);
    expect(m.hasActive("c1", "second-opinion")).toBe(false);
  });

  it("does not re-terminate a job that already ended", async () => {
    const m = new JobManager({ perCaseConcurrency: 1 });
    const { jobId } = m.register({ caseId: "c1", kind: "synthesis", cancellable: true });
    await m.cancel(jobId);
    await m.hold(jobId, REASON);
    expect(m.get(jobId)!.cancelRequestedAt).toBeDefined();
    expect(isHeldJob(m.get(jobId))).toBe(false);
  });
});

describe("an automatic kick waiting on a synthesis that the gate held", () => {
  afterEach(() => vi.useRealTimers());

  async function settle(end: (m: JobManager, jobId: string) => Promise<unknown>) {
    vi.useFakeTimers();
    const m = new JobManager({ perCaseConcurrency: 1 });
    const { jobId } = m.register({ caseId: "c1", kind: "synthesis", cancellable: true });
    const deferral = createSynthesisDeferral({ jobManager: m, retryMs: 10 });
    const outcome: string[] = [];
    deferral.defer(
      "c1",
      () => outcome.push("start"),
      (held) => outcome.push(held ? "held" : "cancelled"),
    );
    await end(m, jobId);
    await vi.advanceTimersByTimeAsync(20);
    return outcome;
  }

  // Not a Cancel, but not a start either: a new run would stop at the same gate, and resolving the
  // gate starts one. The caller marks the conclusions out of date and keeps the pill on hold.
  it("reports the hold, not a Cancel, and starts nothing", async () => {
    expect(await settle((m, id) => m.hold(id, REASON))).toEqual(["held"]);
  });

  it("stays cancelled after an analyst Cancel (#1608 unchanged)", async () => {
    expect(await settle((m, id) => m.cancel(id))).toEqual(["cancelled"]);
  });
});
