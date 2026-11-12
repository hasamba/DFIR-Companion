import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore, INVESTIGATION_DB_FILENAME } from "../../src/analysis/stateStore.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import { caseSqliteWorker } from "../../src/analysis/caseSqliteWorker.js";
import { loadDatabaseSync } from "../../src/analysis/sqliteRuntime.js";
import { ENTITY_ROWS_SQL } from "../../src/analysis/caseSqliteWorkerRows.js";
import { CLOUD_INACTIVE_BATCHES_SQL } from "../../src/analysis/caseSqliteWorkerCloud.js";

// #2584: every cloud import looks up its records in the cloud-record ledger and reads the batches an
// Undo forgot. Both reads walked one row per record (or per imported file) the case ever held, so a
// 3,872-file drop got slower with every file. Each must be an index probe of the rows it asks for.

let root: string;
let cases: CaseStore;
let dbPath: string;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "dfir-entityrows-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
  await new StateStore(cases).save(emptyState("c1"));
  dbPath = join(cases.stateDir("c1"), INVESTIGATION_DB_FILENAME);
  await caseSqliteWorker.request({ op: "ensureDatabase", dbPath }); // the writer creates the indexes
});

afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

function planOf(sql: string, ...params: unknown[]): string {
  const db = new (loadDatabaseSync())(dbPath);
  try {
    return (db.prepare("EXPLAIN QUERY PLAN " + sql).all(...params) as { detail: string }[])
      .map((x) => x.detail)
      .join(" | ");
  } finally {
    db.close();
  }
}

/** Ledger-shaped rows: `n` of `kind`, ordinals descending so ordinal order is not row order. */
function seed(kind: string, n: number): void {
  const db = new (loadDatabaseSync())(dbPath);
  try {
    const insert = db.prepare(
      "INSERT INTO entities (kind, entity_id, ordinal, version, payload) VALUES (?, ?, ?, 1, ?)",
    );
    for (let i = 0; i < n; i++) insert.run(kind, `id-${i}`, 10_000 - i, JSON.stringify({ id: `id-${i}`, i }));
  } finally {
    db.close();
  }
}

describe("per-import ledger reads are index probes (#2584)", () => {
  it("looks rows up by id through the (kind, entity_id) index, not a walk of the kind", () => {
    const plan = planOf(ENTITY_ROWS_SQL.byId, "cloudRecord", "[]");
    expect(plan).toContain("entities_id_idx (kind=? AND entity_id=?)");
    expect(plan).not.toContain("sqlite_autoindex_entities_1");
  });

  it("looks rows up by row id through the primary key, not a walk of the kind", () => {
    const plan = planOf(ENTITY_ROWS_SQL.byRowId, "cloudRecord", "[]");
    expect(plan).toContain("INTEGER PRIMARY KEY (rowid=?)");
    expect(plan).not.toContain("sqlite_autoindex_entities_1");
  });

  it("reads the forgotten batches from their partial index", () => {
    expect(planOf(CLOUD_INACTIVE_BATCHES_SQL)).toContain("entities_cloud_inactive_idx");
  });

  it("adds the forgotten-batch index to a case database created before it existed", async () => {
    const db = new (loadDatabaseSync())(dbPath);
    try {
      db.exec("DROP INDEX entities_cloud_inactive_idx");
    } finally {
      db.close();
    }
    expect(planOf(CLOUD_INACTIVE_BATCHES_SQL)).not.toContain("entities_cloud_inactive_idx");
    await caseSqliteWorker.request({ op: "ensureDatabase", dbPath }); // the next open by the writer
    expect(planOf(CLOUD_INACTIVE_BATCHES_SQL)).toContain("entities_cloud_inactive_idx");
  });

  it("returns exactly the asked rows of the kind, in ordinal order", async () => {
    seed("cloudRecord", 50);
    seed("cloudOther", 5);
    const byId = await caseSqliteWorker.request<Array<{ rowId: number; entity: { i: number } }>>({
      op: "entityRows",
      dbPath,
      kind: "cloudRecord",
      ids: ["id-3", "id-40", "id-7", "missing", "id-3"],
    });
    expect(byId.map((r) => r.entity.i)).toEqual([40, 7, 3]);
    const byRowId = await caseSqliteWorker.request<Array<{ rowId: number; entity: { i: number } }>>({
      op: "entityRows",
      dbPath,
      kind: "cloudRecord",
      rowIds: [...byId.map((r) => r.rowId)].reverse(),
    });
    expect(byRowId.map((r) => r.entity.i)).toEqual([40, 7, 3]);
    const otherKind = await caseSqliteWorker.request<unknown[]>({
      op: "entityRows",
      dbPath,
      kind: "cloudOther",
      rowIds: byId.map((r) => r.rowId),
    });
    expect(otherKind).toEqual([]);
  });

  it("still lists a batch an Undo forgot, and drops it again on Redo", async () => {
    const db = new (loadDatabaseSync())(dbPath);
    try {
      const insert = db.prepare(
        "INSERT INTO entities (kind, entity_id, ordinal, version, host, payload) VALUES ('cloudRecordBatch', ?, ?, 1, ?, ?)",
      );
      for (let i = 0; i < 20; i++) insert.run(`b${i}`, i, `f${i}.json.gz`, JSON.stringify({ id: `b${i}` }));
    } finally {
      db.close();
    }
    const inactive = () => caseSqliteWorker.request<string[]>({ op: "cloudInactiveBatches", dbPath });
    expect(await inactive()).toEqual([]);
    await caseSqliteWorker.request({
      op: "cloudBatchesSetInactive",
      dbPath,
      batches: ["b4", "b9"],
      inactive: true,
    });
    expect([...(await inactive())].sort()).toEqual(["b4", "b9"]);
    await caseSqliteWorker.request({
      op: "cloudBatchesSetInactive",
      dbPath,
      batches: ["b4"],
      inactive: false,
    });
    expect(await inactive()).toEqual(["b9"]);
  });
});
