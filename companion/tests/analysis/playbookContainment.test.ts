import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { PlaybookStore, type NewPlaybookTask } from "../../src/analysis/playbookStore.js";
import { mergePlaybook, playbookSchema } from "../../src/analysis/playbook.js";
import {
  containmentAttributionSchema,
  containmentDuplicate,
  type ContainmentAttribution,
} from "../../src/analysis/playbookContainment.js";
import { emptyState, type InvestigationState } from "../../src/analysis/stateTypes.js";

// #1925: a Playbook task added from a Jev containment check carries its attribution (which rule,
// which model, which answers) on disk, survives sync/merge, and is never added twice for one step.

function attribution(over: Partial<ContainmentAttribution> = {}): ContainmentAttribution {
  return {
    kind: "jev-containment",
    rule: "containment-v1",
    model: "typesafe/jev-1.13",
    checkedAt: "2026-10-02T10:00:00.000Z",
    findingId: "f3",
    stepId: "block-destination-org",
    basis: ["attacker_traffic", "reach"],
    answers: [
      {
        id: "attacker_traffic",
        label: "data/command traffic to attacker destination",
        kind: "yesno",
        value: 0.91,
        verdict: "yes",
        checkManually: false,
      },
      {
        id: "reach",
        label: "reach",
        kind: "choice",
        value: 0.72,
        verdict: "whole organization",
        checkManually: false,
      },
    ],
    inProgressCaveat: false,
    ...over,
  };
}

function containmentInput(stepId: string, findingId = "f3"): NewPlaybookTask {
  return {
    title: `Step ${stepId}`,
    priority: "high",
    relatedFindingId: findingId,
    containmentCheck: attribution({ stepId, findingId }),
  };
}

function stateWith(over: Partial<InvestigationState>): InvestigationState {
  return { ...emptyState("c1"), ...over };
}

describe("containmentAttributionSchema", () => {
  it("accepts a full attribution", () => {
    const a = attribution();
    expect(containmentAttributionSchema.parse(a)).toEqual(a);
  });

  it("rejects a wrong kind", () => {
    expect(containmentAttributionSchema.safeParse({ ...attribution(), kind: "other" }).success).toBe(false);
  });
});

describe("containmentDuplicate", () => {
  const existing = {
    relatedFindingId: "f3",
    containmentCheck: attribution({ stepId: "isolate-host" }),
  };

  it("matches the same finding and step", () => {
    expect(containmentDuplicate(existing, containmentInput("isolate-host"))).toBe(true);
  });

  it("does not match another step or another finding", () => {
    expect(containmentDuplicate(existing, containmentInput("kill-process"))).toBe(false);
    expect(containmentDuplicate(existing, containmentInput("isolate-host", "f9"))).toBe(false);
  });

  it("does not match when either side has no containmentCheck", () => {
    expect(containmentDuplicate({ relatedFindingId: "f3" }, containmentInput("isolate-host"))).toBe(false);
    const plain: NewPlaybookTask = { title: "x", relatedFindingId: "f3" };
    expect(containmentDuplicate(existing, plain)).toBe(false);
  });
});

describe("playbook task schema — containmentCheck", () => {
  const base = {
    id: "custom:1",
    title: "t",
    description: "",
    status: "todo",
    priority: "high",
    source: "custom",
    order: 0,
    createdAt: "2026-10-02T00:00:00Z",
    updatedAt: "2026-10-02T00:00:00Z",
  };

  it("drops a damaged containmentCheck without wiping the list", () => {
    const parsed = playbookSchema.parse([
      { ...base, id: "custom:1", containmentCheck: { kind: "jev-containment", rule: 7 } },
      { ...base, id: "custom:2", containmentCheck: attribution() },
    ]);
    expect(parsed).toHaveLength(2);
    expect(parsed[0].containmentCheck).toBeUndefined();
    expect(parsed[1].containmentCheck).toEqual(attribution());
  });

  it("mergePlaybook keeps the field and never prunes the task", () => {
    const [task] = playbookSchema.parse([{ ...base, containmentCheck: attribution() }]);
    const { tasks } = mergePlaybook([task], [], "2026-10-02T01:00:00Z");
    expect(tasks).toHaveLength(1);
    expect(tasks[0].containmentCheck).toEqual(attribution());
  });
});

describe("PlaybookStore — containment tasks", () => {
  let store: PlaybookStore;
  let cases: CaseStore;
  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-pb-contain-"));
    cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    store = new PlaybookStore(cases);
  });

  it("round-trips the attribution through save and load", async () => {
    const t = await store.add("c1", containmentInput("isolate-host"));
    expect(t.containmentCheck).toEqual(attribution({ stepId: "isolate-host" }));
    const [loaded] = await store.load("c1");
    expect(loaded.containmentCheck).toEqual(attribution({ stepId: "isolate-host" }));
    expect(loaded.relatedFindingId).toBe("f3");
  });

  it("a damaged field on disk is dropped, the other tasks stay", async () => {
    await store.add("c1", containmentInput("isolate-host"));
    await store.add("c1", { title: "plain" });
    const path = join(cases.stateDir("c1"), "playbook.json");
    const raw = JSON.parse(await readFile(path, "utf8"));
    raw[0].containmentCheck = { kind: "jev-containment", answers: "broken" };
    await writeFile(path, JSON.stringify(raw));
    const loaded = await store.load("c1");
    expect(loaded).toHaveLength(2);
    expect(loaded.find((t) => t.title === "Step isolate-host")!.containmentCheck).toBeUndefined();
  });

  it("generic add without the field is unchanged", async () => {
    const t = await store.add("c1", { title: "plain", priority: "low" });
    expect(t).not.toHaveProperty("containmentCheck");
    const [loaded] = await store.load("c1");
    expect(loaded).not.toHaveProperty("containmentCheck");
  });

  it("sync never prunes a containment task", async () => {
    await store.add("c1", containmentInput("isolate-host"));
    const state = stateWith({
      nextSteps: [{ id: "ns1", priority: "high", action: "Pull logs", rationale: "r", pointer: "host" }],
    });
    await store.sync("c1", state);
    const out = await store.sync("c1", stateWith({}));
    const kept = out.find((t) => t.containmentCheck);
    expect(kept?.containmentCheck).toEqual(attribution({ stepId: "isolate-host" }));
  });

  it("addMany adds new steps and skips duplicates, including a skipped-status task", async () => {
    const first = await store.add("c1", containmentInput("isolate-host"));
    await store.update("c1", first.id, { status: "skipped" });
    const r = await store.addMany(
      "c1",
      [containmentInput("isolate-host"), containmentInput("kill-process")],
      containmentDuplicate,
    );
    expect(r.added.map((t) => t.containmentCheck?.stepId)).toEqual(["kill-process"]);
    expect(r.skipped.map((t) => t.containmentCheck?.stepId)).toEqual(["isolate-host"]);
    const all = await store.load("c1");
    expect(all).toHaveLength(2);
    expect(new Set(all.map((t) => t.shortId)).size).toBe(2);
  });

  it("addMany skips a duplicate inside the same batch", async () => {
    const r = await store.addMany(
      "c1",
      [containmentInput("isolate-host"), containmentInput("isolate-host")],
      containmentDuplicate,
    );
    expect(r.added).toHaveLength(1);
    expect(r.skipped).toHaveLength(1);
  });

  it("two concurrent addMany calls add each step once", async () => {
    const inputs = [containmentInput("isolate-host"), containmentInput("kill-process")];
    const [a, b] = await Promise.all([
      store.addMany("c1", inputs, containmentDuplicate),
      store.addMany("c1", inputs, containmentDuplicate),
    ]);
    expect(a.added.length + b.added.length).toBe(2);
    expect(a.skipped.length + b.skipped.length).toBe(2);
    const all = await store.load("c1");
    expect(all.map((t) => t.containmentCheck?.stepId).sort()).toEqual(["isolate-host", "kill-process"]);
  });

  it("a removed containment task can be added again", async () => {
    const t = await store.add("c1", containmentInput("isolate-host"));
    await store.remove("c1", t.id);
    const r = await store.addMany("c1", [containmentInput("isolate-host")], containmentDuplicate);
    expect(r.added).toHaveLength(1);
  });
});
