import { describe, it, expect } from "vitest";
import { createSweepProgress } from "../../src/composition/dropSweepProgress.js";

// #2742: a hunt zip in a drop sweep counts its result files, not "1 file".

const START = "2026-01-01T00:00:00.000Z";

function tracker(relpaths: string[]) {
  const reports: Array<{ done: number; total: number; detail?: string; baseline?: number }> = [];
  const labels: string[] = [];
  const t = createSweepProgress({
    relpaths,
    startedAt: START,
    report: (done, total, detail, step) => {
      expect(step.stepStartedAt).toBe(START);
      reports.push({ done, total, detail, baseline: step.stepBaseline });
      if (step.label) labels.push(step.label);
    },
  });
  return { t, reports, labels, last: () => reports[reports.length - 1] };
}

describe("drop sweep progress (#2742)", () => {
  it("counts one unit per plain file", () => {
    const { t, last } = tracker(["a.json", "b.json"]);
    t.fileDone("a.json");
    expect(last()).toMatchObject({ done: 1, total: 2, detail: "a.json" });
    t.fileDone("b.json");
    expect(last()).toMatchObject({ done: 2, total: 2 });
  });

  it("a hunt zip expands into its result files and names the one importing", () => {
    const { t, last, labels } = tracker(["hunt.zip", "other.json"]);
    t.hunt("hunt.zip", { done: 0, total: 40 });
    expect(last()).toMatchObject({ done: 0, total: 41 });
    expect(labels).toEqual(["drop import (hunt export, 40 result files + 1 other file)"]);
    t.hunt("hunt.zip", { done: 0, total: 40, current: "WS-1/results/A.json" });
    expect(last()).toMatchObject({
      done: 0,
      total: 41,
      detail: "hunt.zip — hunt file 1 of 40: WS-1/results/A.json",
    });
    t.hunt("hunt.zip", { done: 1, total: 40 });
    expect(last()).toMatchObject({ done: 1, total: 41 });
    t.fileDone("other.json");
    expect(last()).toMatchObject({ done: 2, total: 41 });
  });

  it("the sweep's own end-of-file tick never completes a hunt zip (a deferred zip stays partial)", () => {
    const { t, last } = tracker(["hunt.zip"]);
    t.hunt("hunt.zip", { done: 2, total: 40 });
    t.fileDone("hunt.zip");
    expect(last()).toMatchObject({ done: 2, total: 40 });
  });

  it("a resumed zip starts at the files already handled, credited as baseline so the speed counts only new work", () => {
    const { t, last } = tracker(["hunt.zip"]);
    t.hunt("hunt.zip", { done: 10, total: 40 });
    expect(last()).toMatchObject({ done: 10, total: 40, baseline: 10 });
    t.hunt("hunt.zip", { done: 11, total: 40 });
    expect(last()).toMatchObject({ done: 11, baseline: 10 });
  });

  it("two zips at once add up; the label covers both", () => {
    const { t, last, labels } = tracker(["a.zip", "b.zip", "c.json"]);
    t.hunt("a.zip", { done: 0, total: 5 });
    t.hunt("b.zip", { done: 3, total: 7 });
    expect(last()).toMatchObject({ done: 3, total: 13, baseline: 3 });
    t.hunt("a.zip", { done: 2, total: 5 });
    expect(last()).toMatchObject({ done: 5, total: 13 });
    expect(labels[labels.length - 1]).toBe("drop import (2 hunt exports, 12 result files + 1 other file)");
  });

  it("never counts backwards on a late update", () => {
    const { t, last } = tracker(["hunt.zip"]);
    t.hunt("hunt.zip", { done: 4, total: 9 });
    t.hunt("hunt.zip", { done: 3, total: 9 });
    expect(last().done).toBe(4);
  });
});
