import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";
import { SPAWNED_CHILD_NOTE } from "../../src/analysis/collectorChildren.js";
import { loadDatabaseSync } from "../../src/analysis/sqliteRuntime.js";

const DatabaseSync = loadDatabaseSync();

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

  // #1535 — a row a NAMED rule deliberately graded Info is evidence the case set aside, and an Info
  // row lives ONLY here. It goes behind ordinary telemetry in the eviction order. "Behind", not
  // "never", and not unboundedly: the tests below pin all three clauses.
  describe("set-aside rows are evicted last", () => {
    const aside = (id: string, timestamp: string) =>
      ev({ id, timestamp, description: `${id}: net.exe users${SPAWNED_CHILD_NOTE}` });

    it("evicts ordinary Info first and keeps the set-aside row behind it", async () => {
      const small = new SuperTimelineStore(cases, 2);
      await small.append("c1", [
        ev({ id: "bulk1", timestamp: "2026-06-01T00:00:00Z", description: "b1" }),
        aside("kept", "2026-06-02T00:00:00Z"),
        ev({ id: "bulk2", timestamp: "2026-06-03T00:00:00Z", description: "b2" }),
        ev({ id: "bulk3", timestamp: "2026-06-04T00:00:00Z", description: "b3" }),
      ]);
      const r = await small.query("c1", {});
      expect(new Set(r.events.map((e) => e.id))).toEqual(new Set(["kept", "bulk3"]));
    });

    it("evicts a set-aside row once they fill the tier — evicted last, not never", async () => {
      const small = new SuperTimelineStore(cases, 2);
      await small.append("c1", [
        aside("aside-old", "2026-06-01T00:00:00Z"),
        aside("aside-new", "2026-06-02T00:00:00Z"),
        ev({ id: "bulk", timestamp: "2026-06-03T00:00:00Z", description: "b" }),
      ]);
      const r = await small.query("c1", {});
      // A cap of 2 reserves one row of headroom, so the tier holds one; the earlier-imported
      // set-aside row went with the ordinary rows.
      expect(new Set(r.events.map((e) => e.id))).toEqual(new Set(["aside-new", "bulk"]));
    });

    it("never lets set-aside rows freeze the store against new telemetry", async () => {
      const small = new SuperTimelineStore(cases, 4);
      await small.append(
        "c1",
        [1, 2, 3, 4].map((n) => aside(`a${n}`, `2026-06-0${n}T00:00:00Z`)),
      );
      // The cap is full of set-aside rows. A fresh ordinary row must still land.
      const retained = await small.append("c1", [
        ev({ id: "fresh", timestamp: "2026-07-01T00:00:00Z", description: "fresh" }),
      ]);
      expect(retained).toBe(1);
      expect((await small.query("c1", {})).events.map((e) => e.id)).toContain("fresh");
    });

    it("gives a Low-or-above copy no priority: its original is in the forensic timeline", async () => {
      const small = new SuperTimelineStore(cases, 2);
      await small.append("c1", [
        ev({ id: "graded", timestamp: "2026-06-01T00:00:00Z", severity: "High", description: "g" }),
        aside("kept", "2026-06-02T00:00:00Z"),
        ev({ id: "bulk", timestamp: "2026-06-03T00:00:00Z", description: "b" }),
      ]);
      expect(new Set((await small.query("c1", {})).events.map((e) => e.id))).toEqual(
        new Set(["kept", "bulk"]),
      );
    });

    it("refuses a row that carries the note but was never demoted (Critical keeps its grade)", async () => {
      const small = new SuperTimelineStore(cases, 2);
      await small.append("c1", [
        ev({
          id: "critical-note",
          timestamp: "2026-06-01T00:00:00Z",
          severity: "Critical",
          description: `crit${SPAWNED_CHILD_NOTE}`,
        }),
        ev({ id: "bulk1", timestamp: "2026-06-02T00:00:00Z", description: "b1" }),
        ev({ id: "bulk2", timestamp: "2026-06-03T00:00:00Z", description: "b2" }),
      ]);
      expect(new Set((await small.query("c1", {})).events.map((e) => e.id))).toEqual(
        new Set(["bulk1", "bulk2"]),
      );
    });

    it("reads the DESCRIPTION, not the whole payload — a marker in the raw message buys nothing", async () => {
      const small = new SuperTimelineStore(cases, 2);
      await small.append("c1", [
        ev({
          id: "quoted",
          timestamp: "2026-06-01T00:00:00Z",
          description: "q",
          message: `raw${SPAWNED_CHILD_NOTE}`,
        }),
        ev({ id: "bulk1", timestamp: "2026-06-02T00:00:00Z", description: "b1" }),
        ev({ id: "bulk2", timestamp: "2026-06-03T00:00:00Z", description: "b2" }),
      ]);
      expect(new Set((await small.query("c1", {})).events.map((e) => e.id))).toEqual(
        new Set(["bulk1", "bulk2"]),
      );
    });

    it("derives the relation before a protection reconcile can enforce the cap on upgrade", async () => {
      // The open that upgrades a case runs both reconciles. Protection's enforces the cap as soon
      // as it releases a row, so if set-aside membership were derived after it, the legacy rows the
      // backfill is about to claim would already be gone.
      const big = new SuperTimelineStore(cases, 10);
      await big.append("c1", [
        aside("legacy", "2026-06-01T00:00:00Z"),
        ev({ id: "bulk1", timestamp: "2026-06-02T00:00:00Z", description: "b1" }),
        ev({ id: "bulk2", timestamp: "2026-06-03T00:00:00Z", description: "b2" }),
      ]);
      // Star two rows, then rewind the case: the relation and both sync stamps go, so the next open
      // re-derives protection (releasing the stars, which enforces the cap) and set-aside together.
      expect(await big.protect("c1", "bulk1")).toBe(true);
      const db = new DatabaseSync(join(cases.stateDir("c1"), "investigation.sqlite"));
      db.exec(
        "DELETE FROM super_set_aside; DELETE FROM super_protected; " +
          "DELETE FROM storage_meta WHERE key IN ('super_set_aside_sync','super_protected_sync');",
      );
      db.close();
      const small = new SuperTimelineStore(cases, 2);
      expect(await small.query("c1", { limit: 0 })).toBeTruthy(); // one read is enough to migrate
      expect((await small.query("c1", {})).events.map((e) => e.id)).toContain("legacy");
    });

    it("re-derives the relation for rows a case already held when the registry changes", async () => {
      const big = new SuperTimelineStore(cases, 10);
      await big.append("c1", [
        aside("legacy", "2026-06-01T00:00:00Z"),
        ev({ id: "bulk1", timestamp: "2026-06-02T00:00:00Z", description: "b1" }),
      ]);
      // Rewind the case to how it looks before a new demoter ships: the relation is empty and the
      // registry fingerprint is gone, exactly as an upgraded case opens.
      const db = new DatabaseSync(join(cases.stateDir("c1"), "investigation.sqlite"));
      db.exec("DELETE FROM super_set_aside; DELETE FROM storage_meta WHERE key='super_set_aside_sync';");
      db.close();
      const small = new SuperTimelineStore(cases, 2);
      await small.append("c1", [ev({ id: "bulk2", timestamp: "2026-06-03T00:00:00Z", description: "b2" })]);
      // Without the re-derive "legacy" is the oldest row and goes first; with it, bulk1 goes.
      expect(new Set((await small.query("c1", {})).events.map((e) => e.id))).toEqual(
        new Set(["legacy", "bulk2"]),
      );
    });

    it("a protected set-aside row does not consume the tier", async () => {
      const small = new SuperTimelineStore(cases, 2);
      await small.append("c1", [aside("starred-aside", "2026-06-01T00:00:00Z")]);
      expect(await small.protect("c1", "starred-aside")).toBe(true);
      // The tier holds one row and the protected one must not be it: the unprotected set-aside row
      // still outranks the ordinary rows.
      await small.append("c1", [
        aside("kept", "2026-06-02T00:00:00Z"),
        ev({ id: "bulk1", timestamp: "2026-06-03T00:00:00Z", description: "b1" }),
        ev({ id: "bulk2", timestamp: "2026-06-04T00:00:00Z", description: "b2" }),
      ]);
      const ids = new Set((await small.query("c1", {})).events.map((e) => e.id));
      expect(ids).toEqual(new Set(["starred-aside", "kept", "bulk2"]));
    });

    it("a starred row still outranks a set-aside row", async () => {
      const small = new SuperTimelineStore(cases, 2);
      await small.append("c1", [ev({ id: "starred", timestamp: "2026-06-01T00:00:00Z", description: "s" })]);
      expect(await small.protect("c1", "starred")).toBe(true);
      await small.append("c1", [
        aside("aside", "2026-06-02T00:00:00Z"),
        ev({ id: "bulk1", timestamp: "2026-06-03T00:00:00Z", description: "b1" }),
        ev({ id: "bulk2", timestamp: "2026-06-04T00:00:00Z", description: "b2" }),
      ]);
      const ids = new Set((await small.query("c1", {})).events.map((e) => e.id));
      expect(ids).toEqual(new Set(["starred", "aside", "bulk2"]));
    });
  });

  describe("the cap says what it dropped", () => {
    const aside = (id: string, timestamp: string) =>
      ev({ id, timestamp, description: `${id}: net.exe users${SPAWNED_CHILD_NOTE}` });

    it("append still returns only the retained count", async () => {
      const small = new SuperTimelineStore(cases, 2);
      const retained = await small.append("c1", [
        ev({ id: "a", timestamp: "2026-06-01T00:00:00Z", description: "a" }),
        ev({ id: "b", timestamp: "2026-06-02T00:00:00Z", description: "b" }),
        ev({ id: "c", timestamp: "2026-06-03T00:00:00Z", description: "c" }),
      ]);
      expect(retained).toBe(2);
    });

    it("appendReporting reports the count, the set-aside share and the evicted event-time span", async () => {
      const small = new SuperTimelineStore(cases, 2);
      await small.append("c1", [aside("x1", "2026-06-01T00:00:00Z"), aside("x2", "2026-06-05T00:00:00Z")]);
      const result = await small.appendReporting("c1", [aside("x3", "2026-06-09T00:00:00Z")]);
      expect(result.retained).toBe(1);
      expect(result.evicted.count).toBe(1);
      // It lost the tier to the headroom, but it is still a row a rule set aside, and the analyst
      // is told that. Reporting the ORDERING flag would have called this loss ordinary telemetry.
      expect(result.evicted.setAside).toBe(1);
      expect(result.evicted.from).toBe("2026-06-01T00:00:00Z");
      expect(result.evicted.to).toBe("2026-06-01T00:00:00Z");
    });

    it("counts the set-aside rows the cap had to take", async () => {
      const small = new SuperTimelineStore(cases, 2);
      await small.append("c1", [aside("x1", "2026-06-01T00:00:00Z"), aside("x2", "2026-06-05T00:00:00Z")]);
      // Two fresh ordinary rows plus the two above is four against a cap of two: one ordinary row
      // and one over-share set-aside row go.
      const result = await small.appendReporting("c1", [
        ev({ id: "n1", timestamp: "2026-06-09T00:00:00Z", description: "n1" }),
        ev({ id: "n2", timestamp: "2026-06-10T00:00:00Z", description: "n2" }),
      ]);
      expect(result.evicted.count).toBe(2);
      expect(result.evicted.setAside).toBe(1);
      expect(result.evicted.from).toBe("2026-06-01T00:00:00Z");
      expect(result.evicted.to).toBe("2026-06-09T00:00:00Z");
    });

    it("reports no eviction when the cap took nothing", async () => {
      const result = await store.appendReporting("c1", [ev({ id: "a", timestamp: "2026-06-01T00:00:00Z" })]);
      expect(result.evicted).toEqual({ count: 0, setAside: 0, from: "", to: "" });
    });

    it("keeps a durable per-case total that survives the append it came from", async () => {
      const small = new SuperTimelineStore(cases, 1);
      await small.append("c1", [
        ev({ id: "a", timestamp: "2026-06-01T00:00:00Z", description: "a" }),
        ev({ id: "b", timestamp: "2026-06-02T00:00:00Z", description: "b" }),
      ]);
      await small.append("c1", [ev({ id: "c", timestamp: "2026-06-03T00:00:00Z", description: "c" })]);
      const meta = await small.meta("c1");
      expect(meta.evictedTotal).toBe(2);
      expect(meta.lastEviction?.count).toBe(1);
      expect(meta.lastEviction?.at).toMatch(/^\d{4}-/);
    });

    it("reports an all-undated eviction as a count with no span", async () => {
      const small = new SuperTimelineStore(cases, 1);
      await small.append("c1", [ev({ id: "u1", timestamp: "", description: "u1" })]);
      const result = await small.appendReporting("c1", [ev({ id: "u2", timestamp: "", description: "u2" })]);
      expect(result.evicted.count).toBe(1);
      expect(result.evicted.from).toBe("");
      expect(result.evicted.to).toBe("");
    });
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

  // #1429. query() used to answer every page by scanning and JSON-parsing the whole store — count,
  // facets and page all came out of one pass over every row — and the scan's cursor defeated the
  // time index, so each 1,000-row page re-sorted the whole table. 100k rows: 92 s for a first page
  // of 100; 446k rows: never. The count, the facets and the page now come out of SQL when no text
  // filter is set. These pin that the SQL path answers exactly what the scan path answered.
  describe("the indexed query path (#1429)", () => {
    // Dated and undated rows, three origins (one row with no origin at all → "Unknown"), two hosts
    // plus a host-less row, a sidecar label, a tag-derived label that OVERRIDES the sidecar for one
    // event, and a star.
    async function seed() {
      await store.append("c1", [
        ev({
          id: "d1",
          timestamp: "2026-06-01T00:00:00Z",
          artifactName: "Windows.NTFS.MFT",
          asset: "HOST-A",
        }),
        ev({
          id: "d2",
          timestamp: "2026-06-02T00:00:00Z",
          artifactName: "Windows.NTFS.MFT",
          asset: "HOST-B",
        }),
        ev({ id: "d3", timestamp: "2026-06-03T00:00:00Z", sources: ["Sysmon"], asset: "HOST-A" }),
        ev({ id: "d4", timestamp: "2026-09-01T00:00:00Z", artifactName: "Windows.Registry.UserAssist" }),
        ev({
          id: "u1",
          timestamp: "",
          description: "undated one",
          artifactName: "Windows.NTFS.MFT",
          asset: "HOST-A",
        }),
        ev({ id: "u2", timestamp: "", description: "undated two" }),
      ]);
      await store.setLabels("c1", "d2", ["key-evidence"]);
      await store.setLabels("c1", "u1", ["noise", "starred"]);
    }
    // The route's tag-derived map: d3 gains a label the sidecar never had, and u1's sidecar labels
    // are replaced (an id present in the map uses the map's labels, nothing else).
    const labelMap = { d3: ["key-evidence"], u1: ["from-tags"] };

    // Forcing the scan path: an exclude term that matches nothing changes no result, but it does
    // switch query() onto the row-by-row path. Every query below is answered both ways and must agree.
    async function both(q: Parameters<typeof store.query>[1], map?: Record<string, string[]>) {
      const fast = await store.query("c1", q, map);
      const scanned = await store.query("c1", { ...q, excludeText: ["zzz-matches-nothing"] }, map);
      expect(scanned).toEqual(fast);
      return fast;
    }

    it("orders dated rows first, then undated in insertion order, with an offset that crosses the boundary", async () => {
      await seed();
      expect((await both({})).events.map((e) => e.id)).toEqual(["d1", "d2", "d3", "d4", "u1", "u2"]);
      expect((await both({ offset: 3, limit: 2 })).events.map((e) => e.id)).toEqual(["d4", "u1"]);
      expect((await both({ offset: 5, limit: 2 })).events.map((e) => e.id)).toEqual(["u2"]);
      expect((await both({ offset: 9, limit: 2 })).events).toEqual([]);
      expect((await both({ offset: 3, limit: 2 })).total).toBe(6);
    });

    it("facets come from the time window alone, not from the origin/host/label selection", async () => {
      await seed();
      const r = await both({ origins: ["Sysmon"] });
      expect(r.events.map((e) => e.id)).toEqual(["d3"]);
      expect(r.total).toBe(1);
      expect(r.origins).toEqual(["Sysmon", "Unknown", "Windows.NTFS.MFT", "Windows.Registry.UserAssist"]);
      expect(r.hosts).toEqual(["(no host)", "HOST-A", "HOST-B"]);
      expect(r.labelsAvailable).toEqual(["key-evidence", "noise"]); // the star is never a facet
    });

    it("a time window narrows the facets, keeps undated rows, and counts only what it keeps", async () => {
      await seed();
      const r = await both({ from: "2026-05-01T00:00:00Z", to: "2026-07-01T00:00:00Z" });
      expect(r.events.map((e) => e.id)).toEqual(["d1", "d2", "d3", "u1", "u2"]);
      expect(r.total).toBe(5);
      expect(r.origins).toEqual(["Sysmon", "Unknown", "Windows.NTFS.MFT"]);
    });

    it("filters by origin, excluded origin and excluded host on the stored columns", async () => {
      await seed();
      expect((await both({ origins: ["Windows.NTFS.MFT", "Unknown"] })).events.map((e) => e.id)).toEqual([
        "d1",
        "d2",
        "u1",
        "u2",
      ]);
      expect((await both({ exclude: ["Windows.NTFS.MFT"] })).events.map((e) => e.id)).toEqual([
        "d3",
        "d4",
        "u2",
      ]);
      expect((await both({ excludeHosts: ["HOST-A"] })).events.map((e) => e.id)).toEqual(["d2", "d4", "u2"]);
      expect((await both({ excludeHosts: ["(no host)"] })).events.map((e) => e.id)).toEqual([
        "d1",
        "d2",
        "d3",
        "u1",
      ]);
    });

    it("filters by label, tagged-only and starred from the sidecar", async () => {
      await seed();
      expect((await both({ labels: ["key-evidence"] })).events.map((e) => e.id)).toEqual(["d2"]);
      expect((await both({ labels: ["noise", "key-evidence"] })).events.map((e) => e.id)).toEqual([
        "d2",
        "u1",
      ]);
      expect((await both({ taggedOnly: true })).events.map((e) => e.id)).toEqual(["d2", "u1"]);
      expect((await both({ starred: true })).events.map((e) => e.id)).toEqual(["u1"]);
      expect(
        (await both({ starred: true, taggedOnly: true, labels: ["noise"] })).events.map((e) => e.id),
      ).toEqual(["u1"]);
    });

    it("an id in the tag map uses the map's labels instead of the sidecar; every other id keeps the sidecar", async () => {
      await seed();
      const r = await both({ labels: ["key-evidence"] }, labelMap);
      expect(r.events.map((e) => e.id)).toEqual(["d2", "d3"]);
      expect(r.labelsAvailable).toEqual(["from-tags", "key-evidence"]); // u1's sidecar "noise" is gone
      expect((await both({ starred: true }, labelMap)).events).toEqual([]); // u1's star lived in the sidecar
      expect((await both({ taggedOnly: true }, labelMap)).events.map((e) => e.id)).toEqual([
        "d2",
        "d3",
        "u1",
      ]);
      expect(
        (await both({ labels: ["from-tags"], from: "2026-08-01T00:00:00Z" }, labelMap)).events.map(
          (e) => e.id,
        ),
      ).toEqual(["u1"]);
    });

    it("text search and exclude keep their row-by-row semantics on top of the column filters", async () => {
      await seed();
      const r = await store.query("c1", { search: "undated", exclude: ["Unknown"] });
      expect(r.events.map((e) => e.id)).toEqual(["u1"]);
      expect(r.total).toBe(1);
      expect((await store.query("c1", { excludeText: ["undated"] })).events.map((e) => e.id)).toEqual([
        "d1",
        "d2",
        "d3",
        "d4",
      ]);
    });

    it("answers the first page of a large store in bounded time", async () => {
      // 50,000 rows shaped like a real MFT/UserAssist import: mostly undated, ~1 KB payloads. The
      // pre-#1429 path took ~25 s here and grew quadratically (92 s at 100k); the bound is generous
      // so a slow CI runner passes, and a return to the scan-everything shape still fails it.
      const pad = "x".repeat(900);
      for (let b = 0; b < 50000; b += 5000) {
        await store.append(
          "c1",
          Array.from({ length: 5000 }, (_, i) => {
            const n = b + i;
            return ev({
              id: `big-${n}`,
              timestamp: n % 4 === 0 ? new Date(Date.UTC(2026, 0, 1, 0, 0, 0) + n * 1000).toISOString() : "",
              description: `row ${n} ${pad}`,
              artifactName: `Windows.Art${n % 5}`,
              asset: n % 3 === 0 ? "HOST-A" : "HOST-B",
            });
          }),
        );
      }
      const started = performance.now();
      const r = await store.query("c1", { offset: 0, limit: 100 });
      const elapsed = performance.now() - started;
      expect(r.total).toBe(50000);
      expect(r.events).toHaveLength(100);
      expect(r.origins).toHaveLength(5);
      expect(elapsed, `first page took ${Math.round(elapsed)} ms`).toBeLessThan(3000);
    }, 240_000);
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

describe("SuperTimelineStore.collect (#1444)", () => {
  let cases: CaseStore;
  let store: SuperTimelineStore;
  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-super-collect-"));
    cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    store = new SuperTimelineStore(cases, 100000);
  });

  it("keeps only what `pick` returns, across page boundaries, dated and undated", async () => {
    const dated = Array.from({ length: 7 }, (_, i) =>
      ev({ id: `d${i}`, timestamp: `2026-06-0${i + 1}T00:00:00Z`, asset: i % 2 ? "odd" : "even" }),
    );
    const undated = [
      ev({ id: "u1", timestamp: "", asset: "odd" }),
      ev({ id: "u2", timestamp: "", asset: "even" }),
    ];
    await store.append("c1", [...undated, ...dated]);
    const odd = await store.collect("c1", (e) => (e.asset === "odd" ? e.id : undefined), 3);
    expect(odd).toEqual(["d1", "d3", "d5", "u1"]);
  });

  it("returns an empty array for an empty case and never materializes the events", async () => {
    let seen = 0;
    const out = await store.collect("c1", () => {
      seen += 1;
      return undefined;
    });
    expect(out).toEqual([]);
    expect(seen).toBe(0);
  });

  it("has no whole-timeline read: `all` is gone so no route can load a capped case at once", () => {
    expect((store as unknown as Record<string, unknown>).all).toBeUndefined();
  });
});

// #1508. A learned hostname rename re-homes the forensic rows at the settle seam, but the
// super-timeline holds its own copies (dual-written, or Info rows that live only here) and nothing
// rewrote them: the raw record kept showing the former name beside the current one. `rehome`
// rewrites a stored row in place — payload, host column and content key together — so the host
// facet, `get` and the content dedup all follow the new name.
describe("SuperTimelineStore.rehome (#1508)", () => {
  const OLD = "WS-OLD";
  const NEW = "WS-NEW";
  const TS = "2026-06-01T00:00:00Z";
  let cases: CaseStore;
  let store: SuperTimelineStore;
  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-super-rehome-"));
    cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    store = new SuperTimelineStore(cases, 100000);
  });

  const stored = () => [
    ev({ id: "e1", timestamp: TS, description: "logon", asset: OLD, assetRecord: OLD }),
    ev({ id: "e2", timestamp: TS, description: "service start", asset: OLD, assetRecord: OLD }),
    ev({ id: "other", timestamp: TS, description: "zeek", asset: "WS-THIRD" }),
  ];
  const rehomed = (e: ForensicEvent): ForensicEvent => ({
    ...e,
    asset: NEW,
    description: `${e.description} [logged under former hostname ${OLD}]`,
  });

  it("rewrites the payload, the host facet and the content key of the rows it is given", async () => {
    await store.append("c1", stored());
    const before = await store.meta("c1");
    const updated = await store.rehome("c1", stored().slice(0, 2).map(rehomed));
    expect(updated).toBe(2);

    const r = await store.query("c1", {});
    expect(r.hosts).toEqual([NEW, "WS-THIRD"]);
    expect(r.total).toBe(3);
    expect((await store.get("c1", "e1"))?.asset).toBe(NEW);
    expect((await store.get("c1", "e1"))?.description).toBe(`logon [logged under former hostname ${OLD}]`);
    const meta = await store.meta("c1", { hosts: 10 });
    expect(meta.hosts).toEqual([NEW, "WS-THIRD"]);
    expect(meta.generation).toBeGreaterThan(before.generation); // live views refresh
    // The content key follows: a later row with the re-homed content is a duplicate, and one under
    // the former name no longer collides with anything.
    expect(await store.append("c1", [ev({ ...rehomed(stored()[0]), id: "dup" })])).toBe(0);
    expect(await store.append("c1", [ev({ ...stored()[0], id: "under-old" })])).toBe(1);
    // The typed read path sees the new host too.
    const byHost = await store.queryIndexed("c1", { host: NEW });
    expect(byHost.entities.map((e) => e.id).sort()).toEqual(["e1", "e2"]);
  });

  it("skips an id the store does not hold, and leaves the generation alone when nothing changed", async () => {
    await store.append("c1", stored());
    const before = await store.meta("c1");
    expect(await store.rehome("c1", [rehomed(ev({ id: "ghost", timestamp: TS, asset: OLD }))])).toBe(0);
    expect(await store.rehome("c1", [])).toBe(0);
    expect((await store.meta("c1")).generation).toBe(before.generation);
    expect((await store.get("c1", "e1"))?.asset).toBe(OLD);
  });
});
