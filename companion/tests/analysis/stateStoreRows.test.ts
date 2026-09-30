import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadDatabaseSync } from "../../src/analysis/sqliteRuntime.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";

// #1874: the targeted row ops an import's settle phase writes through. Each must touch only the
// rows it names, keep the timeline's order (no renumbering), and keep the value index, the FTS term
// index and the stored count consistent — exactly what a full save of the same content would leave.

function ev(id: string, timestamp: string, p: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id,
    timestamp,
    description: `row ${id} ran C:\\Windows\\Temp\\${id}.exe`,
    severity: "Low",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...p,
  };
}

const DatabaseSync = loadDatabaseSync();
type Db = InstanceType<typeof DatabaseSync>;
let dir: string;
let store: StateStore;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "dfir-rows-"));
  const cases = new CaseStore(dir);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  store = new StateStore(cases);
  await store.save({
    ...emptyState("c1"),
    forensicTimeline: [
      ev("a", "2026-01-01T00:00:00Z"),
      ev("b", "2026-01-02T00:00:00Z", { severity: "Info" }),
      ev("c", "2026-01-03T00:00:00Z", { dstIp: "10.0.0.9" }),
    ],
    iocs: [{ id: "i1", type: "ip", value: "10.0.0.9" } as never],
  });
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

function db(): Db {
  return new DatabaseSync(store.databasePath("c1"), { readOnly: true });
}

function rows(): Array<{ row_id: number; entity_id: string; ordinal: number; severity: string }> {
  const d = db();
  try {
    return d
      .prepare(
        "SELECT row_id, entity_id, ordinal, severity FROM entities WHERE kind='forensicTimeline' ORDER BY ordinal",
      )
      .all() as never;
  } finally {
    d.close();
  }
}

describe("targeted forensic row ops (#1874)", () => {
  it("updates a row in place: same row id and ordinal, new payload, index columns and terms follow", async () => {
    const before = rows();
    const [b] = await store.forensicRowsById("c1", ["b"]);
    const r = await store.updateForensicRows("c1", [
      { ...b, event: { ...b.event, severity: "High", description: "now mimikatz.exe" } },
    ]);
    expect(r).toEqual({ updated: 1, missing: [], conflicts: [] });
    const after = rows();
    expect(after.map((x) => [x.row_id, x.ordinal])).toEqual(before.map((x) => [x.row_id, x.ordinal]));
    expect(after.find((x) => x.entity_id === "b")?.severity).toBe("High");
    const loaded = await store.load("c1");
    expect(loaded.forensicTimeline.map((e) => e.id)).toEqual(["a", "b", "c"]);
    expect(loaded.forensicTimeline[1].description).toBe("now mimikatz.exe");
    const d = db();
    try {
      const hit = d
        .prepare("SELECT rowid FROM event_terms WHERE event_terms MATCH ?")
        .all('"mimikatz.exe"') as Array<{ rowid: number }>;
      expect(hit.map((h) => Number(h.rowid))).toEqual([b.rowId]);
    } finally {
      d.close();
    }
  });

  it("a change that leaves every indexed value and term alone keeps the value index and term index", async () => {
    const [c] = await store.forensicRowsById("c1", ["c"]);
    await store.updateForensicRows("c1", [
      { ...c, event: { ...c.event, severity: "High", importedAt: "2026-09-29T00:00:00Z" } },
    ]);
    expect((await store.queryForensicTimeline("c1", { ioc: "10.0.0.9" })).entities.map((e) => e.id)).toEqual([
      "c",
    ]);
    expect((await store.queryForensicTimeline("c1", { severity: "High" })).entities.map((e) => e.id)).toEqual(
      ["c"],
    );
    const d = db();
    try {
      const hit = d
        .prepare("SELECT rowid FROM event_terms WHERE event_terms MATCH ?")
        .all('"10.0.0.9"') as Array<{
        rowid: number;
      }>;
      expect(hit.map((h) => Number(h.rowid))).toEqual([c.rowId]);
    } finally {
      d.close();
    }
  });

  it("refuses a row whose version moved since it was read, and never re-inserts a missing row", async () => {
    const [a] = await store.forensicRowsById("c1", ["a"]);
    await store.updateForensicRows("c1", [{ ...a, event: { ...a.event, severity: "Medium" } }]);
    const stale = await store.updateForensicRows("c1", [{ ...a, event: { ...a.event, severity: "High" } }]);
    expect(stale.conflicts).toEqual([a.rowId]);
    expect((await store.forensicRowsById("c1", ["a"]))[0].event.severity).toBe("Medium");
    const gone = await store.updateForensicRows("c1", [
      { rowId: 999, version: 1, event: ev("z", "2026-01-09T00:00:00Z") },
    ]);
    expect(gone.missing).toEqual([999]);
    expect((await store.load("c1")).forensicTimeline).toHaveLength(3);
  });

  it("refuses an update that would move the row in time", async () => {
    const [a] = await store.forensicRowsById("c1", ["a"]);
    const r = await store.updateForensicRows("c1", [
      { ...a, event: { ...a.event, timestamp: "2027-01-01T00:00:00Z" } },
    ]);
    expect(r.conflicts).toEqual([a.rowId]);
  });

  it("deletes by row id and keeps the count, the value index and the term index consistent", async () => {
    const [c] = await store.forensicRowsById("c1", ["c"]);
    expect(await store.deleteForensicRows("c1", [c.rowId])).toBe(1);
    const page = await store.queryForensicTimeline("c1", { limit: 10 });
    expect(page.total).toBe(2);
    expect(page.entities.map((e) => e.id)).toEqual(["a", "b"]);
    expect((await store.queryForensicTimeline("c1", { ioc: "10.0.0.9" })).entities).toHaveLength(0);
    const d = db();
    try {
      expect(d.prepare("SELECT count(*) AS n FROM event_terms WHERE rowid=?").get(c.rowId)).toEqual({ n: 0 });
    } finally {
      d.close();
    }
  });

  it("reads rows outside the kept severities in timeline order, and the outline in timeline order", async () => {
    const out = await store.forensicRowsOutsideSeverities("c1", ["Low", "Medium", "High", "Critical"]);
    expect(out.map((r) => r.event.id)).toEqual(["b"]);
    const outline = await store.forensicOutline("c1");
    expect(outline.ids).toEqual(["a", "b", "c"]);
    expect(outline.severities).toEqual(["Low", "Info", "Low"]);
    expect(outline.timestamps[0]).toBe("2026-01-01T00:00:00Z");
  });

  it("saves the overview without touching the forensic timeline", async () => {
    const overview = await store.loadOverview("c1");
    await store.saveOverview({ ...overview, iocs: [], summary: "changed" } as never);
    const loaded = await store.load("c1");
    expect(loaded.forensicTimeline.map((e) => e.id)).toEqual(["a", "b", "c"]);
    expect(loaded.iocs).toEqual([]);
    expect((loaded as unknown as { summary: string }).summary).toBe("changed");
  });

  it("patches case metadata without touching any row", async () => {
    await store.patchStateMeta("c1", { updatedAt: "2026-09-29T00:00:00Z" });
    const loaded = await store.load("c1");
    expect(loaded.updatedAt).toBe("2026-09-29T00:00:00Z");
    expect(loaded.forensicTimeline).toHaveLength(3);
  });

  it("journals the pre-image of each forensic row changed or deleted while armed, and nothing else", async () => {
    const captured = await store.captureImportBaseline("c1", "t1");
    expect(captured?.outline.ids).toEqual(["a", "b", "c"]);
    const [a, c] = await store.forensicRowsById("c1", ["a", "c"]);
    await store.updateForensicRows("c1", [{ ...a, event: { ...a.event, severity: "High" } }]);
    await store.updateForensicRows("c1", [
      { ...a, version: a.version + 1, event: { ...a.event, severity: "Critical" } },
    ]);
    await store.deleteForensicRows("c1", [c.rowId]);
    const journal = await store.readImportJournal("c1", "t1");
    expect(journal?.map((j) => [j.entityId, j.event.severity])).toEqual([
      ["a", "Low"], // the FIRST pre-image, not the intermediate one
      ["c", "Low"],
    ]);
    expect(await store.readImportJournal("c1", "other")).toBeNull();
    // A stale token cannot disarm a newer section's journal.
    await store.disarmImportJournal("c1", "other");
    expect(await store.readImportJournal("c1", "t1")).not.toBeNull();
    await store.disarmImportJournal("c1", "t1");
    expect(await store.readImportJournal("c1", "t1")).toBeNull();
    // Disarmed: a later change is not journaled.
    await store.captureImportBaseline("c1", "t2");
    await store.disarmImportJournal("c1", "t2");
    const [b] = await store.forensicRowsById("c1", ["b"]);
    await store.updateForensicRows("c1", [{ ...b, event: { ...b.event, severity: "Low" } }]);
    const d = db();
    try {
      expect(d.prepare("SELECT count(*) AS n FROM import_journal").get()).toEqual({ n: 0 });
    } finally {
      d.close();
    }
  });
});
