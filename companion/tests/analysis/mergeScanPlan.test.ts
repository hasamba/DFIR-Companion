import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore, INVESTIGATION_DB_FILENAME } from "../../src/analysis/stateStore.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import { caseSqliteWorker } from "../../src/analysis/caseSqliteWorker.js";
import { loadDatabaseSync } from "../../src/analysis/sqliteRuntime.js";
import { MERGE_EARLIEST_CLOUD_SQL, MERGE_SCAN_SQL } from "../../src/analysis/caseSqliteWorkerMerge.js";

// #1887: the importer merge walks every forensic row on every import (the snapshot's counts, the
// stale list, the year counts, the placement scan). Reading a row's version from the table touched
// the page holding its full payload, so each walk read the whole case. Every walk must be answered
// from entities_merge_order_idx and merge_rows' key alone: no payload page, no sort of the timeline.

let root: string;
let cases: CaseStore;
let store: StateStore;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "dfir-mergescan-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
  store = new StateStore(cases);
});

afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

describe("importer merge scans (#1887)", () => {
  it("answer every per-import walk over the forensic rows from the covering index", async () => {
    await store.save(emptyState("c1"));
    const dbPath = join(cases.stateDir("c1"), INVESTIGATION_DB_FILENAME);
    // Opening through the writer creates the indexes.
    await caseSqliteWorker.request({ op: "ensureDatabase", dbPath });
    const db = new (loadDatabaseSync())(dbPath);
    try {
      for (const [name, sql] of Object.entries(MERGE_SCAN_SQL)) {
        const params = (sql.match(/\?/g) ?? []).map(() => 0);
        const plan = (db.prepare("EXPLAIN QUERY PLAN " + sql).all(...params) as { detail: string }[])
          .map((x) => x.detail)
          .join(" | ");
        expect(plan, name).toContain("COVERING INDEX entities_merge_order_idx");
        expect(plan, name).not.toContain("TEMP B-TREE FOR ORDER BY"); // a GROUP BY year is a few rows
        expect(plan, name).not.toMatch(/SCAN e\b/);
      }
    } finally {
      db.close();
    }
  });

  // #2504: the cloud coverage row's time, read on every cloud-only import, walks the partial index of
  // the cloud-audit rows by time: no scan of the case, no sort.
  it("finds the earliest cloud-audit row from its partial index", async () => {
    await store.save(emptyState("c1"));
    const dbPath = join(cases.stateDir("c1"), INVESTIGATION_DB_FILENAME);
    await caseSqliteWorker.request({ op: "ensureDatabase", dbPath });
    const db = new (loadDatabaseSync())(dbPath);
    try {
      for (const [name, sql] of Object.entries(MERGE_EARLIEST_CLOUD_SQL)) {
        const params = (sql.match(/\?/g) ?? []).map((_, i) => (i === 0 ? "[]" : 0));
        const plan = (db.prepare("EXPLAIN QUERY PLAN " + sql).all(...params) as { detail: string }[])
          .map((x) => x.detail)
          .join(" | ");
        expect(plan, name).toContain("merge_rows_cloud_time_idx");
        // The row query sorts only the rows at one instant (time_ms=?), never the timeline.
        if (name === "time") expect(plan, name).not.toContain("TEMP B-TREE");
        else expect(plan, name).toContain("(time_ms=?)");
        expect(plan, name).not.toMatch(/SCAN (e|m)\b/);
      }
    } finally {
      db.close();
    }
  });
});
