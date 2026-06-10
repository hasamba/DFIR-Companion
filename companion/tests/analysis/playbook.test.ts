import { describe, it, expect } from "vitest";
import { emptyState, type Finding, type NextStep } from "../../src/analysis/stateTypes.js";
import {
  derivePlaybookTasks,
  mergePlaybook,
  playbookStats,
  sortPlaybookTasks,
  type PlaybookTask,
} from "../../src/analysis/playbook.js";

const NOW = "2026-06-10T00:00:00.000Z";

function nextStep(over: Partial<NextStep> = {}): NextStep {
  return { id: "ns1", priority: "high", action: "Pull 4624/4672", rationale: "confirm logon", pointer: "ALClient07", ...over };
}
function finding(over: Partial<Finding> = {}): Finding {
  return {
    id: "f1",
    severity: "Critical",
    title: "Ransomware staged",
    description: "lockbit.exe dropped",
    relatedIocs: [],
    sourceScreenshots: [],
    mitreTechniques: [],
    firstSeen: NOW,
    lastUpdated: NOW,
    status: "open",
    ...over,
  };
}

describe("derivePlaybookTasks", () => {
  it("makes one seed per next step, carrying priority and folding the pointer into the description", () => {
    const state = { ...emptyState("c1"), nextSteps: [nextStep()] };
    const seeds = derivePlaybookTasks(state);
    expect(seeds).toHaveLength(1);
    expect(seeds[0]).toMatchObject({ title: "Pull 4624/4672", priority: "high", source: "next_step", sourceKey: "next_step:ns1" });
    expect(seeds[0].description).toContain("confirm logon");
    expect(seeds[0].description).toContain("ALClient07");
  });

  it("derives a task from Critical and High findings, linked back to the finding", () => {
    const state = {
      ...emptyState("c1"),
      findings: [finding({ id: "fa", severity: "Critical" }), finding({ id: "fb", severity: "High", title: "Persistence" })],
    };
    const seeds = derivePlaybookTasks(state);
    expect(seeds.map((s) => s.sourceKey)).toEqual(["finding:fa", "finding:fb"]);
    expect(seeds[0]).toMatchObject({ source: "finding", priority: "critical", relatedFindingId: "fa" });
    expect(seeds[0].title).toContain("Ransomware staged");
  });

  it("skips Medium/Low/Info findings and dismissed findings (avoid flooding)", () => {
    const state = {
      ...emptyState("c1"),
      findings: [
        finding({ id: "m", severity: "Medium" }),
        finding({ id: "l", severity: "Low" }),
        finding({ id: "i", severity: "Info" }),
        finding({ id: "d", severity: "Critical", status: "dismissed" }),
      ],
    };
    expect(derivePlaybookTasks(state)).toHaveLength(0);
  });
});

describe("mergePlaybook", () => {
  it("adds new seeds as todo tasks with id = sourceKey and increasing order", () => {
    const seeds = derivePlaybookTasks({ ...emptyState("c1"), nextSteps: [nextStep(), nextStep({ id: "ns2", action: "Isolate host" })] });
    const { tasks, changed } = mergePlaybook([], seeds, NOW);
    expect(changed).toBe(true);
    expect(tasks).toHaveLength(2);
    expect(tasks[0]).toMatchObject({ id: "next_step:ns1", status: "todo", order: 0 });
    expect(tasks[1]).toMatchObject({ id: "next_step:ns2", status: "todo", order: 1 });
  });

  it("is idempotent: re-merging identical seeds reports no change", () => {
    const seeds = derivePlaybookTasks({ ...emptyState("c1"), nextSteps: [nextStep()] });
    const first = mergePlaybook([], seeds, NOW);
    const second = mergePlaybook(first.tasks, seeds, "2026-06-11T00:00:00.000Z");
    expect(second.changed).toBe(false);
    expect(second.tasks).toEqual(first.tasks);
  });

  it("refreshes a reworded task's text/priority but PRESERVES analyst status/assignee/order", () => {
    const seeds0 = derivePlaybookTasks({ ...emptyState("c1"), nextSteps: [nextStep()] });
    const base = mergePlaybook([], seeds0, NOW).tasks.map((t) => ({ ...t, status: "in_progress" as const, assignee: "ana", order: 7 }));
    const seeds1 = derivePlaybookTasks({ ...emptyState("c1"), nextSteps: [nextStep({ action: "Pull 4624/4672/4688", priority: "critical" })] });
    const { tasks, changed } = mergePlaybook(base, seeds1, "2026-06-12T00:00:00.000Z");
    expect(changed).toBe(true);
    expect(tasks[0]).toMatchObject({ title: "Pull 4624/4672/4688", priority: "critical", status: "in_progress", assignee: "ana", order: 7 });
  });

  it("keeps an existing task whose seed disappeared (never silently dropped)", () => {
    const seeds0 = derivePlaybookTasks({ ...emptyState("c1"), nextSteps: [nextStep()] });
    const base = mergePlaybook([], seeds0, NOW).tasks;
    const { tasks, changed } = mergePlaybook(base, [], NOW);
    expect(changed).toBe(false);
    expect(tasks).toHaveLength(1);
  });

  it("leaves custom tasks untouched", () => {
    const custom: PlaybookTask = {
      id: "custom:1", title: "Call client", description: "", status: "todo", priority: "medium",
      source: "custom", order: 0, createdAt: NOW, updatedAt: NOW,
    };
    const seeds = derivePlaybookTasks({ ...emptyState("c1"), nextSteps: [nextStep()] });
    const { tasks } = mergePlaybook([custom], seeds, NOW);
    expect(tasks.find((t) => t.id === "custom:1")).toEqual(custom);
    expect(tasks).toHaveLength(2);
  });
});

describe("playbookStats", () => {
  it("counts done/open/skipped and computes completion percentage", () => {
    const mk = (status: PlaybookTask["status"]): PlaybookTask => ({
      id: status, title: "t", description: "", status, priority: "medium", source: "custom", order: 0, createdAt: NOW, updatedAt: NOW,
    });
    const stats = playbookStats([mk("done"), mk("done"), mk("todo"), mk("in_progress"), mk("skipped")]);
    expect(stats).toMatchObject({ total: 5, done: 2, skipped: 1, inProgress: 1, open: 2, completionPct: 40 });
  });

  it("is 0% for an empty playbook", () => {
    expect(playbookStats([]).completionPct).toBe(0);
  });
});

describe("sortPlaybookTasks", () => {
  it("orders by `order` then createdAt", () => {
    const t = (id: string, order: number, createdAt: string): PlaybookTask => ({
      id, title: id, description: "", status: "todo", priority: "medium", source: "custom", order, createdAt, updatedAt: createdAt,
    });
    const sorted = sortPlaybookTasks([t("b", 1, NOW), t("a", 0, NOW), t("c", 1, "2026-06-09T00:00:00.000Z")]);
    expect(sorted.map((x) => x.id)).toEqual(["a", "c", "b"]);
  });
});
