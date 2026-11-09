// #2445 (same defect as #2377): a DELETE from the contentless_delete FTS5 term index writes a
// tombstone page into event_terms_data at rowid 2^53 + segid * 2^37, and SQLite leaves that value
// in the connection's last-insert-rowid. Node releases that range-check StatementSync.run() then
// throw ERR_OUT_OF_RANGE on the next run() — the case-state save fails with a 500. The worker
// guards run() results (caseSqliteWorkerRunGuard.ts); these tests pin the hazard and the guard.
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CASE_SQLITE_WORKER_SOURCE } from "../../src/analysis/caseSqliteWorker.js";
import { CaseSqliteWorkerPool } from "../../src/analysis/caseSqliteWorkerPool.js";
import { CASE_SQLITE_SCHEMA_SQL } from "../../src/analysis/caseSqliteSchema.js";
import { loadDatabaseSync } from "../../src/analysis/sqliteRuntime.js";
import { emptyState, type ForensicEvent, type InvestigationState } from "../../src/analysis/stateTypes.js";

// Emulates a Node release whose run() refuses a lastInsertRowid outside the safe-integer range.
const STRICT_RUN_PREAMBLE = String.raw`
const __strictProto = process.getBuiltinModule("node:sqlite").StatementSync.prototype;
const __strictRun = __strictProto.run;
__strictProto.run = function (...args) {
  const result = __strictRun.apply(this, args);
  if (typeof result.lastInsertRowid === "number" && result.lastInsertRowid > Number.MAX_SAFE_INTEGER) {
    const error = new RangeError("Value is too large to be represented as a JavaScript number: " + result.lastInsertRowid);
    error.code = "ERR_OUT_OF_RANGE";
    throw error;
  }
  return result;
};
`;

function event(id: string, description: string): ForensicEvent {
  return {
    id,
    timestamp: "2026-07-01T10:00:00.000Z",
    description,
    severity: "Medium",
    sources: ["test"],
  } as ForensicEvent;
}

function state(forensicTimeline: ForensicEvent[]): InvestigationState {
  return { ...emptyState("c"), forensicTimeline };
}

describe("FTS5 tombstone rowid leak (#2445)", () => {
  it("T1: a contentless_delete DELETE leaves a last-insert-rowid above 2^53", () => {
    // If SQLite ever stops leaking the tombstone rowid, the guard is merely redundant and this
    // assertion may be relaxed.
    const DatabaseSync = loadDatabaseSync();
    const db = new DatabaseSync(":memory:");
    try {
      db.exec(CASE_SQLITE_SCHEMA_SQL);
      const insert = db.prepare("INSERT INTO event_terms(rowid, terms) VALUES (?, ?)");
      let rowid = 1;
      for (let batch = 0; batch < 3; batch++) {
        db.exec("BEGIN");
        for (let i = 0; i < 5; i++, rowid++) insert.run(rowid, `term${rowid} shared${batch}`);
        db.exec("COMMIT");
      }
      // The first DELETE from a flushed segment creates its tombstone page and then rewrites the
      // structure record (rowid 10), so last-insert-rowid looks harmless. The second DELETE from
      // the same segment rewrites only the tombstone page, and that rowid is what leaks. get()
      // never range-checks lastInsertRowid, so neither DELETE can throw here.
      const remove = db.prepare("DELETE FROM event_terms WHERE rowid = ?");
      remove.get(1);
      remove.get(4);
      // setReadBigInts is missing from the bundled node:sqlite typings.
      const probe = db.prepare("SELECT last_insert_rowid() AS r") as ReturnType<typeof db.prepare> & {
        setReadBigInts(enabled: boolean): void;
      };
      probe.setReadBigInts(true);
      const { r } = probe.get() as { r: bigint };
      expect(r > BigInt(Number.MAX_SAFE_INTEGER)).toBe(true);
    } finally {
      db.close();
    }
  });

  describe("T2: the case worker under a range-checking run()", () => {
    let dir: string;
    let dbPath: string;
    const pool = new CaseSqliteWorkerPool(STRICT_RUN_PREAMBLE + CASE_SQLITE_WORKER_SOURCE);
    const save = (s: InvestigationState) => pool.request<void>({ op: "saveState", dbPath, state: s });
    const load = () => pool.request<InvestigationState>({ op: "loadState", dbPath, excludedKinds: [] });

    beforeEach(async () => {
      dir = await mkdtemp(join(tmpdir(), "dfir-rowid-leak-"));
      dbPath = join(dir, "case.sqlite");
    });

    afterEach(async () => {
      await rm(dir, { recursive: true, force: true });
    });

    it("keeps saving when a terms DELETE leaks a tombstone rowid", async () => {
      // 20 rows: the term index flushes one segment per row and its crisis-merge folds them into
      // ONE shared segment, so the later DELETEs below hit the same segment.
      const rows = Array.from({ length: 20 }, (_, i) =>
        event(`m${i}`, `row${i} tool${i}.exe C:\\Temp\\m${i}.bin`),
      );
      const withChanges = (changes: Record<number, string>): ForensicEvent[] =>
        rows.map((row, i) => (i in changes ? { ...row, description: changes[i] } : row));
      await save(state(rows));
      // Re-indexing m3 writes the shared segment's first tombstone page (no leak yet).
      const first = { 3: "row3 changed mshta.exe C:\\Temp\\m3.hta" };
      await save(state(withChanges(first)));
      // m4's terms DELETE hits that segment again and leaks the tombstone rowid. Its new
      // description yields no terms, so no INSERT resets the leak before m5's UPDATE runs.
      const second = { ...first, 4: "x", 5: "row5 changed regsvr32.exe C:\\Temp\\m5.sct" };
      await save(state(withChanges(second)));

      const loaded = await load();
      expect(loaded.forensicTimeline.map((row) => row.description)).toEqual(
        withChanges(second).map((row) => row.description),
      );
    });
  });
});
