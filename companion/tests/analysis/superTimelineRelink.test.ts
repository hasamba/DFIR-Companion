import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { TagsStore } from "../../src/analysis/tags.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";

// #2619 — after an import Undo and a re-import, the re-imported row lands in the forensic timeline
// under a new id, while the super-timeline's content dedup keeps the OLD row (old id, not in the
// forensic timeline), so the raw record never shows it as Promoted. The store relinks such a row to
// the id the forensic timeline now holds.

function ev(p: Partial<ForensicEvent> & { id: string }): ForensicEvent {
  return {
    timestamp: "2026-06-01T10:00:00Z",
    description: "ntds.dit copied",
    asset: "DC01",
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...p,
  };
}

describe("SuperTimelineStore relink (#2619)", () => {
  let cases: CaseStore;
  let store: SuperTimelineStore;
  let state: StateStore;
  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-super-relink-"));
    cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    store = new SuperTimelineStore(cases, 100000);
    state = new StateStore(cases);
  });

  const forensic = async (events: ForensicEvent[]): Promise<void> => {
    await state.save({ ...emptyState("c1"), forensicTimeline: events });
  };

  it("reports a content-deduped row whose stored id is not in the forensic timeline as a relink candidate", async () => {
    await store.append("c1", [ev({ id: "1e1" })]);
    await forensic([ev({ id: "2e1" })]);
    const result = await store.appendReporting("c1", [ev({ id: "2e1" })], { relinkCandidates: true });
    expect(result.retained).toBe(0);
    expect(result.relinkCandidates).toEqual([{ id: "2e1", storedId: "1e1" }]);
  });

  it("reports no candidate when the stored row is itself in the forensic timeline", async () => {
    await store.append("c1", [ev({ id: "1e1" })]);
    await forensic([ev({ id: "1e1" }), ev({ id: "2e1" })]);
    const result = await store.appendReporting("c1", [ev({ id: "2e1" })], { relinkCandidates: true });
    expect(result.relinkCandidates).toEqual([]);
  });

  it("reports nothing unless asked", async () => {
    await store.append("c1", [ev({ id: "1e1" })]);
    const result = await store.appendReporting("c1", [ev({ id: "2e1" })]);
    expect(result.relinkCandidates).toBeUndefined();
  });

  it("relinks the stored row to the forensic id and grade, keeps its content, and carries tags across", async () => {
    await store.append("c1", [ev({ id: "1e1" })]);
    const tags = new TagsStore(cases, store);
    await tags.add("c1", { targetType: "event", targetId: "1e1", label: "keep-me", author: "analyst" });
    await store.setLabels("c1", "1e1", ["lbl"]);
    await forensic([ev({ id: "2e1", severity: "High" })]);
    const before = await store.meta("c1");

    const n = await store.relink("c1", [{ fromId: "1e1", toId: "2e1", severity: "High" }]);
    expect(n).toBe(1);

    const page = await store.query("c1", { limit: 10 });
    expect(page.total).toBe(1);
    expect(page.events[0]).toMatchObject({ id: "2e1", severity: "High", description: "ntds.dit copied" });
    expect(await store.get("c1", "1e1")).toBeNull();
    const moved = await tags.load("c1");
    expect(moved.map((t) => [t.targetId, t.label])).toEqual([["2e1", "keep-me"]]);
    expect(await store.protectedIds("c1")).toEqual(["2e1"]);
    expect((await store.meta("c1")).version).not.toBe(before.version);

    // The content key is unchanged, so a later re-import still dedups against the relinked row.
    expect(await store.append("c1", [ev({ id: "3e1" })])).toBe(0);
  });

  it("refuses a relink whose stored id is in the forensic timeline or whose new id is not", async () => {
    await store.append("c1", [ev({ id: "1e1" }), ev({ id: "1e2", description: "other" })]);
    await forensic([ev({ id: "1e1" })]);
    const n = await store.relink("c1", [
      { fromId: "1e1", toId: "2e1", severity: "High" },
      { fromId: "1e2", toId: "2e2", severity: "High" },
    ]);
    expect(n).toBe(0);
    expect((await store.query("c1", { limit: 10 })).events.map((e) => e.id).sort()).toEqual(["1e1", "1e2"]);
  });

  it("refuses a relink onto an id the store already holds", async () => {
    await store.append("c1", [ev({ id: "1e1" }), ev({ id: "2e1", description: "other" })]);
    await forensic([ev({ id: "2e1" })]);
    expect(await store.relink("c1", [{ fromId: "1e1", toId: "2e1", severity: "High" }])).toBe(0);
  });
});
