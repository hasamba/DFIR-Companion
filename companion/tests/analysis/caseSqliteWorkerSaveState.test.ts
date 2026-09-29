// A full-state save reconciles each array kind's rows by entity id (#1874). The timeline is kept
// in time order, so an import of earlier evidence inserts rows at the FRONT: matching by position
// made every later row look changed, and each save rewrote the payload, the value index and the
// term index of the whole case. Matching by id moves those rows instead and leaves them otherwise
// untouched, so a row keeps its row_id — and its term-index entry — for as long as it exists.
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { caseSqliteWorker } from "../../src/analysis/caseSqliteWorker.js";
import { loadDatabaseSync } from "../../src/analysis/sqliteRuntime.js";
import { emptyState, type ForensicEvent, type InvestigationState } from "../../src/analysis/stateTypes.js";

interface Row {
  row_id: number;
  entity_id: string | null;
  ordinal: number;
  version: number;
  payload: string;
}

function event(id: string, day: number, extra: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id,
    timestamp: `2026-07-${String(day).padStart(2, "0")}T10:00:00.000Z`,
    description: `row ${id} C:\\Temp\\${id}.exe`,
    path: `C:\\Temp\\${id}.exe`,
    severity: "Medium",
    sources: ["test"],
    ...extra,
  } as ForensicEvent;
}

function state(
  forensicTimeline: ForensicEvent[],
  extra: Partial<InvestigationState> = {},
): InvestigationState {
  return { ...emptyState("c"), forensicTimeline, ...extra };
}

function withDb<T>(dbPath: string, fn: (db: InstanceType<ReturnType<typeof loadDatabaseSync>>) => T): T {
  const DatabaseSync = loadDatabaseSync();
  const db = new DatabaseSync(dbPath);
  try {
    return fn(db);
  } finally {
    db.close();
  }
}

function rows(dbPath: string, kind: string): Row[] {
  return withDb(
    dbPath,
    (db) =>
      db
        .prepare(
          "SELECT row_id, entity_id, ordinal, version, payload FROM entities WHERE kind=? ORDER BY ordinal",
        )
        .all(kind) as unknown as Row[],
  );
}

function valueOrdinals(dbPath: string, rowId: number): number[] {
  return withDb(dbPath, (db) =>
    (db.prepare("SELECT ordinal FROM entity_values WHERE row_id=?").all(rowId) as { ordinal: number }[]).map(
      (r) => r.ordinal,
    ),
  );
}

function termRows(dbPath: string, term: string): number[] {
  return withDb(dbPath, (db) =>
    (
      db.prepare("SELECT rowid FROM event_terms WHERE event_terms MATCH ?").all(`"${term}"`) as {
        rowid: number;
      }[]
    ).map((r) => r.rowid),
  );
}

const save = (dbPath: string, s: InvestigationState) =>
  caseSqliteWorker.request<void>({ op: "saveState", dbPath, state: s });
const load = (dbPath: string) =>
  caseSqliteWorker.request<InvestigationState>({ op: "loadState", dbPath, excludedKinds: [] });

describe("saveState reconciles rows by entity id (#1874)", () => {
  let dir: string;
  let dbPath: string;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "save-state-"));
    dbPath = join(dir, "investigation.sqlite");
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("moves existing rows when events are inserted at the front, without rewriting them", async () => {
    await save(dbPath, state([event("a", 10), event("b", 11), event("c", 12)]));
    const before = rows(dbPath, "forensicTimeline");

    await save(dbPath, state([event("x", 1), event("y", 2), event("a", 10), event("b", 11), event("c", 12)]));
    const after = rows(dbPath, "forensicTimeline");

    expect(after.map((r) => r.entity_id)).toEqual(["x", "y", "a", "b", "c"]);
    expect(after.map((r) => r.ordinal)).toEqual([0, 1, 2, 3, 4]);
    for (const id of ["a", "b", "c"]) {
      const was = before.find((r) => r.entity_id === id)!;
      const now = after.find((r) => r.entity_id === id)!;
      expect(now.row_id).toBe(was.row_id); // same row, moved
      expect(now.version).toBe(was.version); // not rewritten
      expect(now.payload).toBe(was.payload);
      const ordinals = valueOrdinals(dbPath, now.row_id);
      expect(ordinals.length).toBeGreaterThan(0); // the path is an indexed value
      expect(ordinals.every((o) => o === now.ordinal)).toBe(true);
    }
    expect((await load(dbPath)).forensicTimeline.map((e) => e.id)).toEqual(["x", "y", "a", "b", "c"]);
  });

  it("keeps a moved row's term-index entry on the same row", async () => {
    await save(dbPath, state([event("a", 10)]));
    const rowA = rows(dbPath, "forensicTimeline")[0].row_id;
    await save(dbPath, state([event("x", 1), event("a", 10)]));
    expect(termRows(dbPath, "c:\\temp\\a.exe")).toEqual([rowA]);
    expect(termRows(dbPath, "c:\\temp\\x.exe")).toHaveLength(1);
  });

  it("re-indexes a moved row whose text changed, on the same row", async () => {
    await save(dbPath, state([event("a", 10)]));
    const rowA = rows(dbPath, "forensicTimeline")[0].row_id;
    await save(dbPath, state([event("x", 1), event("a", 10, { description: "row a C:\\Other\\moved.exe" })]));
    expect(termRows(dbPath, "c:\\temp\\a.exe")).toEqual([rowA]); // still the path value
    expect(termRows(dbPath, "c:\\other\\moved.exe")).toEqual([rowA]);
    const a = rows(dbPath, "forensicTimeline").find((r) => r.entity_id === "a")!;
    expect(a.ordinal).toBe(1);
    expect(valueOrdinals(dbPath, rowA).every((o) => o === 1)).toBe(true);
  });

  it("keeps each unchanged duplicate on its own row when another duplicate is inserted before it", async () => {
    const dA = event("d", 10, { description: "d first" });
    const dB = event("d", 11, { description: "d second" });
    await save(dbPath, state([dA, dB]));
    const [rowA, rowB] = rows(dbPath, "forensicTimeline").map((r) => r.row_id);
    await save(dbPath, state([event("d", 1, { description: "d new" }), dA, dB]));
    const after = rows(dbPath, "forensicTimeline");
    expect(after.map((r) => JSON.parse(r.payload).description)).toEqual(["d new", "d first", "d second"]);
    expect(after[1].row_id).toBe(rowA);
    expect(after[2].row_id).toBe(rowB);
    expect(after[1].version).toBe(1);
    expect(after[2].version).toBe(1);
  });

  it("rewrites a row whose payload changed and deletes rows no longer in the list", async () => {
    await save(dbPath, state([event("a", 10), event("b", 11), event("c", 12)]));
    const rowB = rows(dbPath, "forensicTimeline").find((r) => r.entity_id === "b")!;

    await save(dbPath, state([event("b", 11, { severity: "High" }), event("d", 13)]));
    const after = rows(dbPath, "forensicTimeline");

    expect(after.map((r) => r.entity_id)).toEqual(["b", "d"]);
    const b = after.find((r) => r.entity_id === "b")!;
    expect(b.row_id).toBe(rowB.row_id);
    expect(b.version).toBe(rowB.version + 1);
    expect(JSON.parse(b.payload).severity).toBe("High");
    expect(termRows(dbPath, "c:\\temp\\a.exe")).toEqual([]); // the delete trigger took it
    expect(
      withDb(dbPath, (db) =>
        Number(
          (
            db.prepare("SELECT count FROM entity_counts WHERE kind='forensicTimeline'").get() as {
              count: number;
            }
          ).count,
        ),
      ),
    ).toBe(2);
  });

  it("reverses the order of every row without a unique-ordinal conflict", async () => {
    const list = Array.from({ length: 50 }, (_, i) => event(`e${i}`, 1 + (i % 28)));
    await save(dbPath, state(list));
    const reversed = [...list].reverse();
    await save(dbPath, state(reversed));
    expect((await load(dbPath)).forensicTimeline.map((e) => e.id)).toEqual(reversed.map((e) => e.id));
  });

  it("keeps duplicate ids as separate rows, matched in order", async () => {
    await save(dbPath, state([event("d", 10), event("d", 11, { description: "second d" })]));
    await save(dbPath, state([event("x", 1), event("d", 10), event("d", 11, { description: "second d" })]));
    const loaded = (await load(dbPath)).forensicTimeline;
    expect(loaded.map((e) => e.id)).toEqual(["x", "d", "d"]);
    expect(loaded[2].description).toBe("second d");
  });

  it("matches id-less entries by position, as before", async () => {
    const t = (text: string) => ({ timestamp: "2026-07-01T00:00:00Z", text }) as never;
    await save(dbPath, state([], { timeline: [t("one"), t("two")] }));
    const before = rows(dbPath, "timeline");
    await save(dbPath, state([], { timeline: [t("one"), t("TWO")] }));
    const after = rows(dbPath, "timeline");
    expect(after[0].row_id).toBe(before[0].row_id);
    expect(after[0].version).toBe(before[0].version); // unchanged entry is not rewritten
    expect(JSON.parse(after[1].payload).text).toBe("TWO");
    await save(dbPath, state([], { timeline: [t("one")] }));
    expect(rows(dbPath, "timeline").map((r) => JSON.parse(r.payload).text)).toEqual(["one"]);
  });
});
