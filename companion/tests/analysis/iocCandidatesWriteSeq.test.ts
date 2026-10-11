// #2131: StateStore.iocProvenanceCandidates posted the writer op `iocCandidates` on every call, and
// the pool counts every writer op as a write at submission. So each GET of /ioc-provenance and
// /ioc-provenance-chain (both fired on every case open) moved the case write sequence even when the
// term index was already current, and defeated the case-open share (#2126) and the report-lite
// cache (#2057). The store now asks a READ op first and posts the writer op only when the index is
// missing or stale — the #2129 superMigrateNeeded pattern.
import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { caseSqliteWorker } from "../../src/analysis/caseSqliteWorker.js";
import { loadDatabaseSync } from "../../src/analysis/sqliteRuntime.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";

const DatabaseSync = loadDatabaseSync();
const CASE = "c1";

function ev(id: string, description: string): ForensicEvent {
  return {
    id,
    timestamp: "2026-06-01T00:00:00Z",
    description,
    severity: "High",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
  };
}

function withDb(dbPath: string, run: (db: InstanceType<typeof DatabaseSync>) => void): void {
  const db = new DatabaseSync(dbPath);
  try {
    run(db);
  } finally {
    db.close();
  }
}

function termsVersion(dbPath: string): string | null {
  let value: string | null = null;
  withDb(dbPath, (db) => {
    const row = db.prepare("SELECT value FROM storage_meta WHERE key='event_terms_version'").get() as
      { value: string } | undefined;
    value = row ? row.value : null;
  });
  return value;
}

const ids = (events: readonly { id: string }[]) => events.map((e) => e.id);

describe("a settled IOC-candidates read keeps the case write sequence (#2131)", () => {
  let cases: CaseStore;
  let stateStore: StateStore;
  let dbPath: string;

  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-2131-"));
    cases = new CaseStore(root);
    await cases.createCase({ caseId: CASE, name: "n", investigator: "i", aiProvider: null });
    stateStore = new StateStore(cases);
    dbPath = stateStore.databasePath(CASE);
  });

  async function seed(): Promise<void> {
    await stateStore.save({
      ...emptyState(CASE),
      forensicTimeline: [ev("f1", "needle in forensic"), ev("f2", "hay")],
    });
    await new SuperTimelineStore(cases).append(CASE, [ev("s1", "needle in super")]);
  }

  const read = () => stateStore.iocProvenanceCandidates(CASE, ["needle"], []);

  it("repeat reads of a settled case never move the write sequence", async () => {
    await seed();
    const first = await read();
    expect(ids(first.forensic)).toEqual(["f1"]);
    expect(ids(first.super)).toEqual(["s1"]);
    const before = caseSqliteWorker.writeSequence(dbPath);
    expect(await read()).toEqual(first);
    expect(await read()).toEqual(first);
    expect(caseSqliteWorker.writeSequence(dbPath)).toBe(before);
  });

  it("a stale term-index version takes the writer, rebuilds and re-stamps", async () => {
    await seed();
    const first = await read();
    withDb(dbPath, (db) => db.exec("DELETE FROM storage_meta WHERE key='event_terms_version'"));
    const before = caseSqliteWorker.writeSequence(dbPath);
    expect(await read()).toEqual(first);
    expect(caseSqliteWorker.writeSequence(dbPath)).toBeGreaterThan(before);
    expect(termsVersion(dbPath)).toBe("1");
    const settled = caseSqliteWorker.writeSequence(dbPath);
    expect(await read()).toEqual(first);
    expect(caseSqliteWorker.writeSequence(dbPath)).toBe(settled);
  });

  // A malformed stamp (an imported or restored database) reads back as NaN. The writer rebuilds on
  // NaN, so the read op must too — otherwise an incomplete index silently drops matches.
  it("a malformed term-index version takes the writer and recovers missing candidates", async () => {
    await seed();
    const first = await read();
    withDb(dbPath, (db) => {
      db.exec("DELETE FROM event_terms");
      db.exec("UPDATE storage_meta SET value='garbage' WHERE key='event_terms_version'");
    });
    const before = caseSqliteWorker.writeSequence(dbPath);
    expect(await read()).toEqual(first);
    expect(caseSqliteWorker.writeSequence(dbPath)).toBeGreaterThan(before);
    expect(termsVersion(dbPath)).toBe("1");
  });

  it("a database from before the term index (no event_terms table) does not throw", async () => {
    await seed();
    const first = await read();
    withDb(dbPath, (db) => {
      db.exec("DROP TRIGGER IF EXISTS entities_terms_delete");
      db.exec("DROP TABLE IF EXISTS event_terms");
      db.exec("DELETE FROM storage_meta WHERE key='event_terms_version'");
    });
    const before = caseSqliteWorker.writeSequence(dbPath);
    expect(await read()).toEqual(first);
    expect(caseSqliteWorker.writeSequence(dbPath)).toBeGreaterThan(before);
    expect(termsVersion(dbPath)).toBe("1");
  });

  // No write-sequence assertion here: with no database, ensureMigrated posts migrateState (the legacy
  // JSON migration attempt, a writer op) before any IOC op is reached. That is not a settled case.
  it("a case with no database answers empty", async () => {
    expect(await read()).toEqual({ forensic: [], super: [], candidates: 0 });
  });
});
