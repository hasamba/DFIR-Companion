import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

function ev(p: Partial<ForensicEvent> & { id: string; timestamp: string }): ForensicEvent {
  return { description: "d", severity: "Info", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], ...p };
}

describe("SuperTimelineStore", () => {
  let cases: CaseStore;
  let store: SuperTimelineStore;
  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-super-"));
    cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    store = new SuperTimelineStore(cases, 100000);
  });

  it("query on an empty case returns an empty result", async () => {
    const r = await store.query("c1", {});
    expect(r).toEqual({ events: [], total: 0, origins: [], labelsAvailable: [] });
  });

  it("append persists events; query returns them; re-append dedups by id", async () => {
    await store.append("c1", [ev({ id: "e1", timestamp: "2026-06-01T00:00:00Z", artifactName: "Windows.NTFS.MFT" })]);
    await store.append("c1", [ev({ id: "e1", timestamp: "2026-06-01T00:00:00Z" }), ev({ id: "e2", timestamp: "2026-06-02T00:00:00Z" })]);
    const r = await store.query("c1", {});
    expect(r.total).toBe(2);
    expect(r.events.map((e) => e.id)).toEqual(["e1", "e2"]);
  });

  it("enforces the cap, keeping the newest events", async () => {
    const small = new SuperTimelineStore(cases, 2);
    await small.append("c1", [
      ev({ id: "old", timestamp: "2026-06-01T00:00:00Z" }),
      ev({ id: "mid", timestamp: "2026-06-02T00:00:00Z" }),
      ev({ id: "new", timestamp: "2026-06-03T00:00:00Z" }),
    ]);
    const r = await small.query("c1", {});
    expect(r.total).toBe(2);
    expect(new Set(r.events.map((e) => e.id))).toEqual(new Set(["mid", "new"]));
  });

  it("prunes labels for events evicted by the cap", async () => {
    const small = new SuperTimelineStore(cases, 1);
    await small.append("c1", [ev({ id: "old", timestamp: "2026-06-01T00:00:00Z" })]);
    await small.setLabels("c1", "old", ["key-evidence"]);
    // Appending past the cap evicts "old"; its orphaned label entry must be pruned, not left to leak.
    await small.append("c1", [ev({ id: "new", timestamp: "2026-06-03T00:00:00Z" })]);
    const r = await small.query("c1", {});
    expect(new Set(r.events.map((e) => e.id))).toEqual(new Set(["new"]));
    // The evicted event's label is gone (nothing carries it), so it no longer facets or filters.
    expect(r.labelsAvailable).toEqual([]);
    const filtered = await small.query("c1", { labels: ["key-evidence"] });
    expect(filtered.total).toBe(0);
  });

  it("keeps labels for events retained after a cap append", async () => {
    const small = new SuperTimelineStore(cases, 2);
    await small.append("c1", [ev({ id: "a", timestamp: "2026-06-02T00:00:00Z" })]);
    await small.setLabels("c1", "a", ["keep"]);
    await small.append("c1", [ev({ id: "b", timestamp: "2026-06-03T00:00:00Z" })]);   // "a" still retained under cap 2
    const r = await small.query("c1", { labels: ["keep"] });
    expect(r.events.map((e) => e.id)).toEqual(["a"]);
  });

  it("get returns one event by id or null", async () => {
    await store.append("c1", [ev({ id: "e1", timestamp: "2026-06-01T00:00:00Z" })]);
    expect((await store.get("c1", "e1"))?.id).toBe("e1");
    expect(await store.get("c1", "nope")).toBeNull();
  });

  it("setLabels persists labels; query filters by them", async () => {
    await store.append("c1", [ev({ id: "e1", timestamp: "2026-06-01T00:00:00Z" }), ev({ id: "e2", timestamp: "2026-06-02T00:00:00Z" })]);
    await store.setLabels("c1", "e2", ["key-evidence"]);
    const r = await store.query("c1", { labels: ["key-evidence"] });
    expect(r.events.map((e) => e.id)).toEqual(["e2"]);
    const all = await store.query("c1", {});
    expect(all.labelsAvailable).toEqual(["key-evidence"]);
  });

  it("tolerates a malformed events file (returns empty rather than throwing)", async () => {
    await store.append("c1", [ev({ id: "e1", timestamp: "2026-06-01T00:00:00Z" })]);
    await writeFile(join(cases.stateDir("c1"), "super-timeline.json"), "{ not json", "utf8");
    const r = await store.query("c1", {});
    expect(r.total).toBe(0);
  });
});
