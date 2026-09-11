import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

function ev(p: Partial<ForensicEvent> & { id: string; timestamp: string }): ForensicEvent {
  return {
    description: "d",
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...p,
  };
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
    expect(r).toEqual({ events: [], total: 0, origins: [], hosts: [], labelsAvailable: [] });
  });

  it("append persists events; query returns them; re-append dedups by id", async () => {
    await store.append("c1", [
      ev({ id: "e1", timestamp: "2026-06-01T00:00:00Z", artifactName: "Windows.NTFS.MFT" }),
    ]);
    await store.append("c1", [
      ev({ id: "e1", timestamp: "2026-06-01T00:00:00Z" }),
      ev({ id: "e2", timestamp: "2026-06-02T00:00:00Z" }),
    ]);
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

  // #932 item 12 — undated rows sort LAST, and the cap evicts in INSERTION order.
  //
  // Before: `coalesce(timestamp_ms, MIN)` put every undated row FIRST in every read (page one of
  // any query was the rows with no clock) and evicted them first at the cap, so an undated import
  // was the first thing the case forgot. Flipping the sentinel alone would let undated rows pin the
  // cap (they would count as the newest rows forever and every later dated row would be evicted on
  // arrival), so retention is insertion order: no class of row is "newest" by construction.
  it("sorts undated rows after every dated row, in insertion order among themselves", async () => {
    await store.append("c1", [
      ev({ id: "u1", timestamp: "", description: "undated one" }),
      ev({ id: "d2", timestamp: "2026-06-02T00:00:00Z" }),
      ev({ id: "u2", timestamp: "", description: "undated two" }),
      ev({ id: "d1", timestamp: "2026-06-01T00:00:00Z" }),
    ]);
    const r = await store.query("c1", {});
    expect(r.events.map((e) => e.id)).toEqual(["d1", "d2", "u1", "u2"]);
  });

  it("keeps undated rows inside a time window, after the dated ones", async () => {
    await store.append("c1", [
      ev({ id: "u1", timestamp: "", description: "undated" }),
      ev({ id: "d1", timestamp: "2026-06-01T00:00:00Z" }),
      ev({ id: "d9", timestamp: "2026-09-01T00:00:00Z" }),
    ]);
    const r = await store.query("c1", { from: "2026-05-01T00:00:00Z", to: "2026-07-01T00:00:00Z" });
    expect(r.events.map((e) => e.id)).toEqual(["d1", "u1"]);
  });

  it("pages across the dated→undated boundary without a repeat or a skip", async () => {
    const dated = [1, 2, 3].map((n) => ev({ id: `d${n}`, timestamp: `2026-06-0${n}T00:00:00Z` }));
    const undated = [1, 2, 3].map((n) => ev({ id: `u${n}`, timestamp: "", description: `undated ${n}` }));
    await store.append("c1", [...undated, ...dated]);
    const seen: string[] = [];
    for await (const batch of store.eventBatches("c1", 2)) seen.push(...batch.map((e) => e.id));
    expect(seen).toEqual(["d1", "d2", "d3", "u1", "u2", "u3"]);
  });

  it("evicts the oldest-IMPORTED row at the cap, not the oldest-dated one", async () => {
    const small = new SuperTimelineStore(cases, 2);
    // Inserted newest-dated first: date order says "new" should go, insertion order says "new" stays.
    await small.append("c1", [
      ev({ id: "new", timestamp: "2026-06-03T00:00:00Z" }),
      ev({ id: "mid", timestamp: "2026-06-02T00:00:00Z" }),
    ]);
    await small.append("c1", [ev({ id: "old", timestamp: "2026-06-01T00:00:00Z" })]);
    const r = await small.query("c1", {});
    expect(new Set(r.events.map((e) => e.id))).toEqual(new Set(["mid", "old"]));
  });

  it("does not evict an undated row for being undated", async () => {
    const small = new SuperTimelineStore(cases, 2);
    await small.append("c1", [
      ev({ id: "d1", timestamp: "2026-06-01T00:00:00Z" }),
      ev({ id: "d2", timestamp: "2026-06-02T00:00:00Z" }),
    ]);
    const retained = await small.append("c1", [ev({ id: "u1", timestamp: "", description: "undated" })]);
    expect(retained).toBe(1);
    const r = await small.query("c1", {});
    expect(r.events.map((e) => e.id)).toEqual(["d2", "u1"]); // d1 was imported first, so d1 went
  });

  it("reports the rows RETAINED after eviction, never the rows inserted", async () => {
    const small = new SuperTimelineStore(cases, 4);
    await small.append("c1", [
      ev({ id: "a", timestamp: "2026-06-01T00:00:00Z" }),
      ev({ id: "b", timestamp: "2026-06-02T00:00:00Z" }),
    ]);
    // Five more against a cap of four: the two old rows go, and so does the first of this batch.
    const retained = await small.append(
      "c1",
      [1, 2, 3, 4, 5].map((n) => ev({ id: `n${n}`, timestamp: `2026-07-0${n}T00:00:00Z` })),
    );
    expect(retained).toBe(4);
    const r = await small.query("c1", {});
    expect(r.total).toBe(4);
    expect(r.events.map((e) => e.id)).toEqual(["n2", "n3", "n4", "n5"]);
    // A batch that is entirely a re-import inserts nothing and reports nothing.
    expect(await small.append("c1", [ev({ id: "n5", timestamp: "2026-07-05T00:00:00Z" })])).toBe(0);
  });

  it("keeps labels for events retained after a cap append", async () => {
    const small = new SuperTimelineStore(cases, 2);
    await small.append("c1", [ev({ id: "a", timestamp: "2026-06-02T00:00:00Z" })]);
    await small.setLabels("c1", "a", ["keep"]);
    await small.append("c1", [ev({ id: "b", timestamp: "2026-06-03T00:00:00Z" })]); // "a" still retained under cap 2
    const r = await small.query("c1", { labels: ["keep"] });
    expect(r.events.map((e) => e.id)).toEqual(["a"]);
  });

  it("get returns one event by id or null", async () => {
    await store.append("c1", [ev({ id: "e1", timestamp: "2026-06-01T00:00:00Z" })]);
    expect((await store.get("c1", "e1"))?.id).toBe("e1");
    expect(await store.get("c1", "nope")).toBeNull();
  });

  it("setLabels persists labels; query filters by them", async () => {
    await store.append("c1", [
      ev({ id: "e1", timestamp: "2026-06-01T00:00:00Z" }),
      ev({ id: "e2", timestamp: "2026-06-02T00:00:00Z" }),
    ]);
    await store.setLabels("c1", "e2", ["key-evidence"]);
    const r = await store.query("c1", { labels: ["key-evidence"] });
    expect(r.events.map((e) => e.id)).toEqual(["e2"]);
    const all = await store.query("c1", {});
    expect(all.labelsAvailable).toEqual(["key-evidence"]);
  });

  // Regression: append() is a read-modify-write (load -> merge -> atomicWrite). The import route
  // fires it once per imported file, so two imports finishing close together used to read the same
  // base array and the second write clobbered the first — rows vanished silently. atomicWrite makes
  // each write crash-safe, not serialized; only a per-case lock makes concurrent appends additive.
  it("serializes concurrent appends so no batch is clobbered", async () => {
    const batches = Array.from({ length: 12 }, (_, b) =>
      Array.from({ length: 5 }, (_, i) =>
        ev({
          id: `b${b}e${i}`,
          timestamp: `2026-06-0${(b % 9) + 1}T00:0${i}:00Z`,
          description: `batch ${b} event ${i}`,
        }),
      ),
    );
    await Promise.all(batches.map((batch) => store.append("c1", batch)));
    const r = await store.query("c1", {});
    expect(r.total).toBe(60);
    // Every batch must be represented — a clobber shows up as whole batches missing, not stray rows.
    for (let b = 0; b < 12; b++) {
      expect(r.events.filter((e) => e.id.startsWith(`b${b}e`))).toHaveLength(5);
    }
  });

  it("serializes concurrent setLabels so no label is clobbered", async () => {
    await store.append(
      "c1",
      Array.from({ length: 6 }, (_, i) => ev({ id: `L${i}`, timestamp: `2026-06-0${i + 1}T00:00:00Z` })),
    );
    await Promise.all(Array.from({ length: 6 }, (_, i) => store.setLabels("c1", `L${i}`, [`tag${i}`])));
    const r = await store.query("c1", {});
    expect(r.labelsAvailable.sort()).toEqual(["tag0", "tag1", "tag2", "tag3", "tag4", "tag5"]);
  });

  it("keeps SQLite authoritative when the retained legacy file is later damaged", async () => {
    await store.append("c1", [ev({ id: "e1", timestamp: "2026-06-01T00:00:00Z" })]);
    await writeFile(join(cases.stateDir("c1"), "super-timeline.json"), "{ not json", "utf8");
    const r = await store.query("c1", {});
    expect(r.total).toBe(1);
    expect(r.events[0].id).toBe("e1");
  });

  it("migrates legacy events and labels before the first indexed query", async () => {
    await writeFile(
      join(cases.stateDir("c1"), "super-timeline.json"),
      JSON.stringify([
        ev({ id: "legacy", timestamp: "2026-06-01T00:00:00Z", artifactName: "Windows.Events" }),
      ]),
    );
    await writeFile(
      join(cases.stateDir("c1"), "super-timeline-labels.json"),
      JSON.stringify({
        legacy: ["key-evidence"],
      }),
    );

    const r = await store.query("c1", { labels: ["key-evidence"] });
    expect(r.events.map((event) => event.id)).toEqual(["legacy"]);
    expect(r.labelsAvailable).toEqual(["key-evidence"]);
  });

  it("gives migrated legacy rows the retention age the old store implied: oldest-dated goes first", async () => {
    // The old JSON cap re-sorted the array newest-first, so array position is not append age. A
    // migrated store must not evict the NEWEST legacy row on the next append past the cap.
    await writeFile(
      join(cases.stateDir("c1"), "super-timeline.json"),
      JSON.stringify([
        ev({ id: "newest", timestamp: "2026-06-03T00:00:00Z" }),
        ev({ id: "undated", timestamp: "" }),
        ev({ id: "oldest", timestamp: "2026-06-01T00:00:00Z" }),
      ]),
    );
    const small = new SuperTimelineStore(cases, 3);
    await small.append("c1", [ev({ id: "fresh", timestamp: "2026-06-02T00:00:00Z" })]);
    const r = await small.query("c1", {});
    expect(new Set(r.events.map((e) => e.id))).toEqual(new Set(["newest", "undated", "fresh"]));
  });

  it("caps one query page while cursor batches cover the complete store", async () => {
    const events = Array.from({ length: 650 }, (_, i) =>
      ev({ id: `e${i}`, timestamp: new Date(Date.UTC(2026, 0, 1, 0, 0, i)).toISOString() }),
    );
    await store.append("c1", events);

    const page = await store.query("c1", {});
    expect(page.total).toBe(650);
    expect(page.events).toHaveLength(500);
    let batched = 0;
    for await (const batch of store.eventBatches("c1", 73)) batched += batch.length;
    expect(batched).toBe(650);
  });
});
