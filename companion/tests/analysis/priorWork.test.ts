import { describe, it, expect } from "vitest";
import {
  renderPlaybookProgressBlock,
  renderRefutedHypothesesBlock,
  demoteCompletedNextSteps,
} from "../../src/analysis/priorWork.js";
import type { PlaybookTask } from "../../src/analysis/playbook.js";
import type { Hypothesis } from "../../src/analysis/hypothesis.js";
import type { NextStep } from "../../src/analysis/stateTypes.js";

function task(partial: Partial<PlaybookTask>): PlaybookTask {
  return {
    id: partial.id ?? "t1",
    title: partial.title ?? "A task",
    description: "",
    status: partial.status ?? "todo",
    priority: "medium",
    source: partial.source ?? "next_step",
    order: 0,
    createdAt: "2026-01-01T00:00:00Z",
    updatedAt: "2026-01-01T00:00:00Z",
    ...partial,
  } as PlaybookTask;
}

function hyp(partial: Partial<Hypothesis>): Hypothesis {
  return {
    id: partial.id ?? "h1",
    title: partial.title ?? "A hypothesis",
    description: "",
    expectedOutcome: "",
    status: partial.status ?? "open",
    relatedTechniques: [],
    relatedEventIds: [],
    relatedIocIds: [],
    assignee: "",
    notes: partial.notes ?? "",
    source: partial.source ?? "analyst",
    analystTouched: partial.analystTouched ?? false,
    createdAt: "2026-01-01T00:00:00Z",
    updatedAt: "2026-01-01T00:00:00Z",
    ...partial,
  } as Hypothesis;
}

function step(partial: Partial<NextStep>): NextStep {
  return {
    id: partial.id ?? "n1",
    priority: partial.priority ?? "high",
    action: partial.action ?? "do something",
    rationale: partial.rationale ?? "because",
    pointer: partial.pointer ?? "",
    ...partial,
  };
}

describe("renderPlaybookProgressBlock", () => {
  it("returns '' when nothing is done or skipped", () => {
    expect(renderPlaybookProgressBlock([task({ status: "todo" }), task({ status: "in_progress" })])).toBe("");
  });

  it("lists DONE and SKIPPED tasks under distinct labels", () => {
    const block = renderPlaybookProgressBlock([
      task({ id: "a", title: "Pull Security.evtx on HOST7", status: "done" }),
      task({ id: "b", title: "Sandbox foo.exe", status: "skipped" }),
      task({ id: "c", title: "todo one", status: "todo" }),
    ]);
    expect(block).toContain("[DONE] Pull Security.evtx on HOST7");
    expect(block).toContain("[SKIPPED] Sandbox foo.exe");
    expect(block).not.toContain("todo one");
    expect(block).toMatch(/do NOT re-recommend/i);
  });
});

describe("renderRefutedHypothesesBlock", () => {
  it("returns '' when there are no analyst-refuted hypotheses", () => {
    expect(renderRefutedHypothesesBlock([hyp({ status: "open" })])).toBe("");
  });

  it("includes analyst-authored refuted hypotheses with notes", () => {
    const block = renderRefutedHypothesesBlock([
      hyp({ title: "Access was RDP from DMZ", status: "refuted", source: "analyst", notes: "no 4624 type 10" }),
    ]);
    expect(block).toContain("Access was RDP from DMZ");
    expect(block).toContain("no 4624 type 10");
    expect(block).toMatch(/do NOT re-assert/i);
  });

  it("excludes model-only refutations (not analyst-touched)", () => {
    const block = renderRefutedHypothesesBlock([
      hyp({ title: "model theory", status: "refuted", source: "synthesis", analystTouched: false }),
    ]);
    expect(block).toBe("");
  });

  it("includes a synthesis hypothesis the analyst touched", () => {
    const block = renderRefutedHypothesesBlock([
      hyp({ title: "touched theory", status: "refuted", source: "synthesis", analystTouched: true }),
    ]);
    expect(block).toContain("touched theory");
  });
});

describe("demoteCompletedNextSteps", () => {
  it("demotes a step that repeats a completed task (shared specific token)", () => {
    const steps = [step({ id: "n1", action: "Pull Security.evtx 4624 on ALCLIENT07", priority: "high" })];
    const { steps: out, demotedIds } = demoteCompletedNextSteps(steps, ["Pull Security.evtx 4624 on ALCLIENT07 and timeline it"]);
    expect(demotedIds).toEqual(["n1"]);
    expect(out[0].priority).toBe("low");
    expect(out[0].rationale).toMatch(/already done/i);
  });

  it("does NOT demote a same-verb step targeting a different host", () => {
    const steps = [step({ id: "n1", action: "Pull Security.evtx 4624 on ALCLIENT09", priority: "high" })];
    const { demotedIds } = demoteCompletedNextSteps(steps, ["Pull Security.evtx 4624 on ALCLIENT07"]);
    expect(demotedIds).toEqual([]);
  });

  it("does NOT demote when only generic verbs overlap (no specific token)", () => {
    const steps = [step({ id: "n1", action: "review the findings again", priority: "high" })];
    const { demotedIds } = demoteCompletedNextSteps(steps, ["review the timeline"]);
    expect(demotedIds).toEqual([]);
  });

  it("uses the pointer to identify the target when the action is generic", () => {
    const steps = [step({ id: "n1", action: "collect logs", pointer: "pull $MFT on WKSTN-DB-01", priority: "critical" })];
    const { demotedIds, steps: out } = demoteCompletedNextSteps(steps, ["Pull $MFT on WKSTN-DB-01"]);
    expect(demotedIds).toEqual(["n1"]);
    expect(out[0].priority).toBe("low");
  });

  it("returns inputs unchanged when there are no done titles", () => {
    const steps = [step({ id: "n1" })];
    const { steps: out, demotedIds } = demoteCompletedNextSteps(steps, []);
    expect(demotedIds).toEqual([]);
    expect(out).toEqual(steps);
  });
});
