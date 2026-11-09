import { describe, it, expect } from "vitest";
import { JobManager } from "../../src/analysis/jobManager.js";
import { createSynthesisDeferral } from "../../src/composition/synthesisDeferral.js";

// #2425: a running Second Look that re-synthesizes is a paid synthesis in all but its job kind.
// The case's one-job slot serializes it with an automatic kick only when the durable ledger is on
// and DFIR_JOBS_PER_CASE is 1; without that, the kick would start a second paid run beside it, the
// later one overwriting the earlier (#1608). So the deferral waits on it as on a synthesis.
describe("synthesis deferral and a running Second Look (#2425)", () => {
  const unbounded = () => new JobManager(); // no ledger: no per-case limit, nothing serializes

  it("counts a running Second Look that will re-synthesize as a running synthesis", async () => {
    const m = unbounded();
    const job = m.register({ caseId: "c1", kind: "second-look", parameters: { resynthesize: true } });
    await job.ready;
    expect(createSynthesisDeferral({ jobManager: m, retryMs: 10 }).running("c1")).toBe(true);
  });

  it("does not wait on a Second Look that makes no model call", async () => {
    const m = unbounded();
    const job = m.register({ caseId: "c1", kind: "second-look", parameters: { resynthesize: false } });
    await job.ready;
    expect(createSynthesisDeferral({ jobManager: m, retryMs: 10 }).running("c1")).toBe(false);
  });

  it("starts the waiting kick once the Second Look ends", async () => {
    const m = unbounded();
    const job = m.register({ caseId: "c1", kind: "second-look", parameters: { resynthesize: true } });
    await job.ready;
    const deferral = createSynthesisDeferral({ jobManager: m, retryMs: 5 });
    const outcome: string[] = [];
    deferral.defer(
      "c1",
      () => outcome.push("start"),
      (held) => outcome.push(held ? "held" : "cancelled"),
    );
    await new Promise((r) => setTimeout(r, 20));
    expect(outcome).toEqual([]);
    await m.finish(job.jobId);
    await new Promise((r) => setTimeout(r, 30));
    expect(outcome).toEqual(["start"]);
  });
});
