import { describe, it, expect } from "vitest";
import { emptyState, type Finding, type NextStep } from "../../src/analysis/stateTypes.js";
import {
  derivePlaybookTasks,
  mergePlaybook,
  playbookStats,
  sortPlaybookTasks,
  validateDependsOn,
  withBlockedState,
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

  it("dedup: a next step whose pointer cites a finding already covered by its own auto-task is folded in, not duplicated", () => {
    const state = {
      ...emptyState("c1"),
      findings: [finding({ id: "f10", severity: "Critical", title: "PUA installer executed" })],
      nextSteps: [nextStep({ id: "ns1", action: "Analyze the PUA binary", rationale: "confirm malicious", pointer: "finding f10; host ALClient07" })],
    };
    const seeds = derivePlaybookTasks(state);
    // No separate next_step seed — only the finding's own task remains.
    expect(seeds.map((s) => s.sourceKey)).toEqual(["finding:f10"]);
    expect(seeds[0].description).toContain("confirm malicious");
    expect(seeds[0].description).toContain("finding f10; host ALClient07");
  });

  it("dedup: folds into the 'investigate' phase when templates are on", () => {
    const state = {
      ...emptyState("c1"),
      findings: [finding({ id: "f10", severity: "Critical" })],
      nextSteps: [nextStep({ id: "ns1", action: "Analyze the PUA binary", rationale: "confirm malicious", pointer: "finding f10" })],
    };
    const seeds = derivePlaybookTasks(state, { useTemplates: true });
    expect(seeds.map((s) => s.sourceKey)).toEqual([
      "finding:f10:contain", "finding:f10:investigate", "finding:f10:eradicate", "finding:f10:recover",
    ]);
    const investigate = seeds.find((s) => s.sourceKey === "finding:f10:investigate")!;
    expect(investigate.description).toContain("confirm malicious");
  });

  it("does NOT dedup a next step pointing at a finding that ISN'T Critical/High (no auto-task to fold into)", () => {
    const state = {
      ...emptyState("c1"),
      findings: [finding({ id: "f10", severity: "Medium" })],
      nextSteps: [nextStep({ id: "ns1", pointer: "finding f10" })],
    };
    const seeds = derivePlaybookTasks(state);
    expect(seeds.map((s) => s.sourceKey)).toEqual(["next_step:ns1"]);
    expect(seeds[0].relatedFindingId).toBe("f10");
  });

  it("does NOT dedup when the pointer text doesn't cite a real finding id", () => {
    const state = {
      ...emptyState("c1"),
      findings: [finding({ id: "f10", severity: "Critical" })],
      nextSteps: [nextStep({ id: "ns1", pointer: "ALClient07" })],
    };
    const seeds = derivePlaybookTasks(state);
    expect(seeds.map((s) => s.sourceKey)).toEqual(["next_step:ns1", "finding:f10"]);
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

  it("prunes a PRISTINE auto-task whose seed disappeared", () => {
    const seeds0 = derivePlaybookTasks({ ...emptyState("c1"), nextSteps: [nextStep()] });
    const base = mergePlaybook([], seeds0, NOW).tasks;          // pristine (status todo, no edits)
    const { tasks, changed } = mergePlaybook(base, [], NOW);
    expect(changed).toBe(true);
    expect(tasks).toHaveLength(0);
  });

  it("KEEPS a touched auto-task whose seed disappeared (never loses analyst work)", () => {
    const seeds0 = derivePlaybookTasks({ ...emptyState("c1"), nextSteps: [nextStep()] });
    const base = mergePlaybook([], seeds0, NOW).tasks.map((t) => ({ ...t, status: "in_progress" as const }));
    const { tasks } = mergePlaybook(base, [], NOW);
    expect(tasks).toHaveLength(1);
    expect(tasks[0].status).toBe("in_progress");
  });

  it("leaves custom tasks untouched", () => {
    const custom: PlaybookTask = {
      id: "custom:1", title: "Call client", description: "", status: "todo", priority: "medium",
      source: "custom", order: 0, createdAt: NOW, updatedAt: NOW,
    };
    const seeds = derivePlaybookTasks({ ...emptyState("c1"), nextSteps: [nextStep()] });
    const { tasks } = mergePlaybook([custom], seeds, NOW);
    // The custom fields are left intact; merge only backfills a sequential shortId (T001 first).
    expect(tasks.find((t) => t.id === "custom:1")).toEqual({ ...custom, shortId: "T001" });
    expect(tasks).toHaveLength(2);
  });
});

describe("derivePlaybookTasks with severity templates (Phase 2)", () => {
  it("expands a Critical finding into the full IR cycle (contain/investigate/eradicate/recover)", () => {
    const state = { ...emptyState("c1"), findings: [finding({ id: "fa", severity: "Critical", mitreTechniques: ["T1486"] })] };
    const seeds = derivePlaybookTasks(state, { useTemplates: true });
    expect(seeds.map((s) => s.sourceKey)).toEqual([
      "finding:fa:contain", "finding:fa:investigate", "finding:fa:eradicate", "finding:fa:recover",
    ]);
    expect(seeds.map((s) => s.title)).toEqual([
      "Contain: Ransomware staged", "Investigate: Ransomware staged", "Eradicate: Ransomware staged", "Recover: Ransomware staged",
    ]);
    expect(seeds.every((s) => s.relatedFindingId === "fa")).toBe(true);
  });

  it("expands a High finding into investigate + contain only", () => {
    const state = { ...emptyState("c1"), findings: [finding({ id: "fb", severity: "High", title: "Persistence" })] };
    const seeds = derivePlaybookTasks(state, { useTemplates: true });
    expect(seeds.map((s) => s.sourceKey)).toEqual(["finding:fb:investigate", "finding:fb:contain"]);
  });

  it("tailors the investigate step to the finding's ATT&CK tactic and lists its techniques", () => {
    const state = { ...emptyState("c1"), findings: [finding({ id: "fa", severity: "Critical", mitreTechniques: ["T1486"] })] };
    const investigate = derivePlaybookTasks(state, { useTemplates: true }).find((s) => s.sourceKey === "finding:fa:investigate");
    expect(investigate!.description).toContain("Impact");      // T1486 → Impact tactic
    expect(investigate!.description).toContain("T1486");
  });

  it("templates off (default) still yields one task per finding", () => {
    const state = { ...emptyState("c1"), findings: [finding({ id: "fa", severity: "Critical" })] };
    expect(derivePlaybookTasks(state).map((s) => s.sourceKey)).toEqual(["finding:fa"]);
  });

  it("switching templates on prunes the pristine single finding task and adds the phases", () => {
    const state = { ...emptyState("c1"), findings: [finding({ id: "fa", severity: "Critical" })] };
    const off = mergePlaybook([], derivePlaybookTasks(state), NOW).tasks;
    expect(off.map((t) => t.id)).toEqual(["finding:fa"]);
    const on = mergePlaybook(off, derivePlaybookTasks(state, { useTemplates: true }), NOW).tasks;
    expect(on.map((t) => t.id)).toEqual(["finding:fa:contain", "finding:fa:investigate", "finding:fa:eradicate", "finding:fa:recover"]);
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

describe("dependency graph (issue #81)", () => {
  const mk = (id: string, over: Partial<PlaybookTask> = {}): PlaybookTask => ({
    id, title: id, description: "", status: "todo", priority: "medium", source: "custom", order: 0, createdAt: NOW, updatedAt: NOW, ...over,
  });

  describe("withBlockedState", () => {
    it("is not blocked when it has no dependencies", () => {
      const [t] = withBlockedState([mk("a")]);
      expect(t).toMatchObject({ blocked: false, blockedBy: [] });
    });

    it("is blocked while a dependency is not done", () => {
      const tasks = [mk("a"), mk("b", { dependsOn: ["a"] })];
      const [, b] = withBlockedState(tasks);
      expect(b).toMatchObject({ blocked: true, blockedBy: ["a"] });
    });

    it("unblocks once every dependency is done", () => {
      const tasks = [mk("a", { status: "done" }), mk("b", { dependsOn: ["a"] })];
      const [, b] = withBlockedState(tasks);
      expect(b).toMatchObject({ blocked: false, blockedBy: [] });
    });

    it("a skipped dependency still blocks (analyst must revisit it)", () => {
      const tasks = [mk("a", { status: "skipped" }), mk("b", { dependsOn: ["a"] })];
      const [, b] = withBlockedState(tasks);
      expect(b.blocked).toBe(true);
    });

    it("a dangling dependency (task no longer exists) never blocks", () => {
      const [b] = withBlockedState([mk("b", { dependsOn: ["ghost"] })]);
      expect(b).toMatchObject({ blocked: false, blockedBy: [] });
    });

    it.each(["done", "skipped"] as const)(
      "a %s task is never itself reported blocked, however unmet its dependencies are",
      (status) => {
        // "blocked" means "you cannot start this yet" — meaningless once the work is finished or
        // waived. A completed task still flying a red `blocked` badge devalues the badge everywhere.
        const tasks = [mk("a", { status: "todo" }), mk("b", { status, dependsOn: ["a"] })];
        const [, b] = withBlockedState(tasks);
        expect(b.blocked).toBe(false);
        expect(b.blockedBy).toEqual(["a"]);   // still inspectable — only the flag is suppressed
      },
    );
  });

  describe("validateDependsOn", () => {
    it("accepts a valid edge to an existing task", () => {
      const tasks = [mk("a"), mk("b")];
      expect(validateDependsOn(tasks, "b", ["a"])).toEqual({ ok: true, dependsOn: ["a"] });
    });

    it("rejects an unknown task id", () => {
      const r = validateDependsOn([mk("a")], "a", ["nope"]);
      expect(r.ok).toBe(false);
      expect(r.error).toMatch(/unknown task id/);
    });

    it("drops a self-reference as a harmless no-op rather than rejecting it", () => {
      const tasks = [mk("a")];
      expect(validateDependsOn(tasks, "a", ["a"])).toEqual({ ok: true, dependsOn: [] });
    });

    it("rejects a direct 2-cycle (a depends on b, b would depend on a)", () => {
      const tasks = [mk("a", { dependsOn: ["b"] }), mk("b")];
      const r = validateDependsOn(tasks, "b", ["a"]);
      expect(r.ok).toBe(false);
      expect(r.error).toMatch(/cycle/);
    });

    it("rejects an indirect cycle through a longer chain", () => {
      const tasks = [mk("a", { dependsOn: ["b"] }), mk("b", { dependsOn: ["c"] }), mk("c")];
      const r = validateDependsOn(tasks, "c", ["a"]);
      expect(r.ok).toBe(false);
    });

    it("dedups repeated ids", () => {
      const tasks = [mk("a"), mk("b")];
      expect(validateDependsOn(tasks, "b", ["a", "a"])).toEqual({ ok: true, dependsOn: ["a"] });
    });
  });

  describe("mergePlaybook + dependsOn", () => {
    it("preserves dependsOn edges across a re-derive (auto-task id is a stable sourceKey)", () => {
      const seeds = derivePlaybookTasks({ ...emptyState("c1"), nextSteps: [nextStep(), nextStep({ id: "ns2", action: "Isolate host" })] });
      const base = mergePlaybook([], seeds, NOW).tasks.map((t) =>
        t.id === "next_step:ns2" ? { ...t, dependsOn: ["next_step:ns1"] } : t,
      );
      const { tasks } = mergePlaybook(base, seeds, "2026-06-12T00:00:00.000Z");
      expect(tasks.find((t) => t.id === "next_step:ns2")!.dependsOn).toEqual(["next_step:ns1"]);
    });

    it("does NOT prune a pristine auto-task that carries a dependency edge", () => {
      const seeds = derivePlaybookTasks({ ...emptyState("c1"), nextSteps: [nextStep()] });
      const base = mergePlaybook([], seeds, NOW).tasks.map((t) => ({ ...t, dependsOn: ["custom:1"] }));
      const { tasks } = mergePlaybook(base, [], NOW);   // seed disappeared, but the task has an edge
      expect(tasks).toHaveLength(1);
    });
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
