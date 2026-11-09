import { describe, it, expect } from "vitest";
import { JobManager } from "../../src/analysis/jobManager.js";

// #2425: a case's job slot held in memory, with no ledger row. A held case admits no new job;
// a release admits what queued behind it. whenIdle waits for the case's running jobs to end.

const flush = () => new Promise((r) => setTimeout(r, 20));

describe("JobManager case holds (#2425)", () => {
  it("a held case admits no new job until the hold is released", async () => {
    const manager = new JobManager();
    const release = manager.caseHolds.hold("c1");
    const queued = manager.register({ caseId: "c1", kind: "synthesis", label: "s" });
    const other = manager.register({ caseId: "c2", kind: "synthesis", label: "s" });
    await other.ready; // another case is not held
    await flush();
    expect(manager.list("c1")[0]?.status).toBe("queued");
    release();
    await queued.ready;
    expect(manager.list("c1")[0]?.status).toBe("running");
  });

  it("holds count: the case stays held until every hold is released, and a release is idempotent", async () => {
    const manager = new JobManager();
    const a = manager.caseHolds.hold("c1");
    const b = manager.caseHolds.hold("c1");
    a();
    a();
    expect(manager.caseHolds.isHeld("c1")).toBe(true);
    b();
    expect(manager.caseHolds.isHeld("c1")).toBe(false);
  });

  it("whenIdle resolves once the case's running job ends", async () => {
    const manager = new JobManager();
    const busy = manager.register({ caseId: "c1", kind: "synthesis", label: "s" });
    await busy.ready;
    let idle = false;
    void manager.caseHolds.whenIdle("c1").then(() => (idle = true));
    await flush();
    expect(idle).toBe(false);
    await manager.finish(busy.jobId);
    await flush();
    expect(idle).toBe(true);
    await expect(manager.caseHolds.whenIdle("c2")).resolves.toBeUndefined();
  });
});
