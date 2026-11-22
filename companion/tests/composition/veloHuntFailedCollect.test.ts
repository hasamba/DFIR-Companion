import { describe, expect, it } from "vitest";
import type { VeloHuntJob } from "../../src/analysis/veloHuntStore.js";
import { completeness, failedCollect } from "../../src/composition/veloHuntCompleteness.js";

// #2842: the two writers of a collect that failed as a whole (the collect's own catch, and the
// startup sweep for a collect a restart cut off) share one rule for what the job's lists then mean.
// A collect replaces the lists when it leaves the "fetching" phase, so only a failure IN that phase
// leaves an earlier collect's lists behind — and only then is there anything to label.
const JOB: VeloHuntJob = {
  bundleId: "b",
  bundleName: "B",
  artifacts: ["A.one", "A.two"],
  huntId: "H.1",
  launchedAt: "2026-11-08T00:00:00.000Z",
  waitMinutes: 10,
  collectAt: "2026-11-08T00:10:00.000Z",
  status: "collecting",
};
const STOPPED = { skippedArtifacts: [{ name: "A.two", error: "refused", notImported: "stopped" as const }] };

describe("failedCollect (#2842)", () => {
  it("writes the failure and clears the collect's progress", () => {
    const out = failedCollect({ ...JOB, collectPhase: "importing", collectRows: 9 }, "boom");
    expect(out).toMatchObject({ status: "error", error: "boom", huntId: "H.1" });
    expect(out.collectPhase).toBeUndefined();
    expect(out.collectRows).toBeUndefined();
  });

  it("does not change the job it was given", () => {
    const cur: VeloHuntJob = { ...JOB, ...STOPPED, collectPhase: "fetching" };
    const before = structuredClone(cur);
    failedCollect(cur, "boom");
    expect(cur).toEqual(before);
  });

  it.each([
    ["a not-imported or failed artifact", STOPPED],
    ["a cut-short artifact", { truncatedArtifacts: [{ name: "A.one", kept: 10, total: 11 }] }],
    ["an unread artifact", { unreadArtifacts: [{ name: "A.one", rows: 0 }] }],
    ["an empty artifact", { emptyArtifacts: ["A.one"] }],
    [
      "a super-timeline-capped artifact",
      { superCappedArtifacts: [{ name: "A.one", kept: 1, total: 2, rows: 2, cap: 1 }] },
    ],
  ])("marks %s left by an earlier collect when the failure came while fetching", (_what, lists) => {
    const out = failedCollect({ ...JOB, ...lists, collectPhase: "fetching" }, "boom");
    expect(out.earlierCoverage).toBe(true);
    expect(out).toMatchObject(lists); // the lists stay: they are still true of the case
  });

  it("marks nothing when no earlier collect left a list", () => {
    expect(failedCollect({ ...JOB, collectPhase: "fetching" }, "boom").earlierCoverage).toBeUndefined();
    const emptied = { ...JOB, skippedArtifacts: [], emptyArtifacts: [], collectPhase: "fetching" as const };
    expect(failedCollect(emptied, "boom").earlierCoverage).toBeUndefined();
  });

  it.each([["queued" as const], ["importing" as const], [undefined]])(
    "marks nothing when the stored phase is %s: the lists are this collect's own",
    (collectPhase) => {
      expect(failedCollect({ ...JOB, ...STOPPED, collectPhase }, "boom").earlierCoverage).toBeUndefined();
    },
  );

  it("keeps the mark through a second failure, and a collect's own results clear it", () => {
    const once = failedCollect({ ...JOB, ...STOPPED, collectPhase: "fetching" }, "boom");
    const twice = failedCollect({ ...once, status: "collecting" }, "the first job write failed");
    expect(twice.earlierCoverage).toBe(true);
    const own: VeloHuntJob = { ...twice, ...completeness([], [], []) };
    expect("earlierCoverage" in own).toBe(true); // written, so the spread replaces the stored mark
    expect(own.earlierCoverage).toBeUndefined();
  });
});
