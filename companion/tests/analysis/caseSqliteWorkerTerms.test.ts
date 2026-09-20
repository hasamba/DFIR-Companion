// The event_terms FTS5 index behind the IOC-provenance reads (#1452). Drives the case SQLite worker
// directly on a temp database: a terms row follows every forensic/super row through insert, update
// and the three delete paths, and `iocCandidates` returns a SUPERSET of what the builders in
// iocProvenance.ts / iocProvenanceChain.ts would match, in the order eventBatches() feeds them.
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { caseSqliteWorker } from "../../src/analysis/caseSqliteWorker.js";
import { loadDatabaseSync } from "../../src/analysis/sqliteRuntime.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

interface Candidates {
  forensic: ForensicEvent[];
  super: ForensicEvent[];
  candidates: number;
}

function event(p: Partial<ForensicEvent> & { id: string }): ForensicEvent {
  return {
    timestamp: "2026-01-01T00:00:00Z",
    description: "",
    severity: "Info",
    sources: ["test"],
    ...p,
  } as ForensicEvent;
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

function termsRowIds(dbPath: string, key: string): number[] {
  return withDb(dbPath, (db) =>
    db
      .prepare("SELECT rowid AS id FROM event_terms WHERE event_terms MATCH ? ORDER BY rowid")
      .all('"' + key.replace(/"/g, '""') + '"')
      .map((row) => Number((row as { id: number }).id)),
  );
}

function rowIdOf(dbPath: string, kind: string, entityId: string): number {
  return withDb(dbPath, (db) => {
    const row = db
      .prepare("SELECT row_id AS id FROM entities WHERE kind=? AND entity_id=?")
      .get(kind, entityId) as { id: number } | undefined;
    if (!row) throw new Error(`no ${kind} row for ${entityId}`);
    return Number(row.id);
  });
}

function metaValue(dbPath: string, key: string): string | null {
  return withDb(dbPath, (db) => {
    const row = db.prepare("SELECT value FROM storage_meta WHERE key=?").get(key) as
      { value: string } | undefined;
    return row ? row.value : null;
  });
}

async function saveForensic(dbPath: string, forensicTimeline: ForensicEvent[]): Promise<void> {
  await caseSqliteWorker.request({ op: "saveState", dbPath, state: { caseId: "c1", forensicTimeline } });
}

async function appendSuper(dbPath: string, events: ForensicEvent[], max = 100000): Promise<number> {
  return caseSqliteWorker.request<number>({ op: "appendSuper", dbPath, events, max });
}

async function candidates(dbPath: string, keys: string[], ids: string[] = []): Promise<Candidates> {
  return caseSqliteWorker.request<Candidates>({ op: "iocCandidates", dbPath, keys, ids });
}

const ids = (rows: ForensicEvent[]): string[] => rows.map((e) => e.id);

describe("case SQLite worker: event_terms index", () => {
  let root: string;
  let dbPath: string;
  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "dfir-terms-"));
    dbPath = join(root, "case.sqlite");
  });
  afterEach(async () => {
    await rm(root, { recursive: true, force: true });
  });

  describe("write hook", () => {
    it("a forensic row saved through saveState gets a terms row for its tokens and fields", async () => {
      await saveForensic(dbPath, [
        event({
          id: "f1",
          description: "Dropped Evil.EXE to disk",
          path: "C:\\Windows\\Temp\\payload.ps1",
          sha256: "AbCdEf0123456789",
        }),
      ]);
      const id = rowIdOf(dbPath, "forensicTimeline", "f1");
      expect(termsRowIds(dbPath, "evil.exe")).toEqual([id]);
      expect(termsRowIds(dbPath, "c:\\windows\\temp\\payload.ps1")).toEqual([id]);
      expect(termsRowIds(dbPath, "abcdef0123456789")).toEqual([id]);
      expect(termsRowIds(dbPath, "nothere")).toEqual([]);
    });

    it("a super row appended through appendSuper gets a terms row", async () => {
      await appendSuper(dbPath, [event({ id: "s1", description: "beacon to 203.0.113.9:443" })]);
      const id = rowIdOf(dbPath, "superTimeline", "s1");
      expect(termsRowIds(dbPath, "203.0.113.9:443")).toEqual([id]);
    });

    it("a non-timeline kind gets no terms row", async () => {
      await caseSqliteWorker.request({
        op: "saveState",
        dbPath,
        state: { caseId: "c1", findings: [{ id: "x1", title: "finding evil.exe", description: "evil.exe" }] },
      });
      expect(termsRowIds(dbPath, "evil.exe")).toEqual([]);
    });

    it("the terms row is gone after a saveState tail trim", async () => {
      await saveForensic(dbPath, [
        event({ id: "f1", description: "keepme" }),
        event({ id: "f2", description: "trimme" }),
      ]);
      expect(termsRowIds(dbPath, "trimme")).toHaveLength(1);
      await saveForensic(dbPath, [event({ id: "f1", description: "keepme" })]);
      expect(termsRowIds(dbPath, "trimme")).toEqual([]);
      expect(termsRowIds(dbPath, "keepme")).toHaveLength(1);
    });

    it("the terms row is gone after pruneEntitiesBefore", async () => {
      await appendSuper(dbPath, [
        event({ id: "old", timestamp: "2020-01-01T00:00:00Z", description: "ancient" }),
        event({ id: "new", timestamp: "2026-01-01T00:00:00Z", description: "recent" }),
      ]);
      await caseSqliteWorker.request({
        op: "pruneEntitiesBefore",
        dbPath,
        kind: "superTimeline",
        beforeMs: Date.parse("2025-01-01T00:00:00Z"),
      });
      expect(termsRowIds(dbPath, "ancient")).toEqual([]);
      expect(termsRowIds(dbPath, "recent")).toHaveLength(1);
    });

    it("the terms row is gone after cap eviction", async () => {
      await appendSuper(dbPath, [event({ id: "s1", description: "firstin" })], 1);
      await appendSuper(dbPath, [event({ id: "s2", description: "secondin" })], 1);
      expect(termsRowIds(dbPath, "firstin")).toEqual([]);
      expect(termsRowIds(dbPath, "secondin")).toHaveLength(1);
    });

    it("an update replaces the terms row in place", async () => {
      await saveForensic(dbPath, [event({ id: "f1", description: "before-text" })]);
      const id = rowIdOf(dbPath, "forensicTimeline", "f1");
      await saveForensic(dbPath, [event({ id: "f1", description: "after-text" })]);
      expect(rowIdOf(dbPath, "forensicTimeline", "f1")).toBe(id);
      expect(termsRowIds(dbPath, "before-text")).toEqual([]);
      expect(termsRowIds(dbPath, "after-text")).toEqual([id]);
    });
  });

  describe("iocCandidates", () => {
    it("a missing database yields an empty result", async () => {
      const out = await candidates(join(root, "absent.sqlite"), ["evil.exe"]);
      expect(out).toEqual({ forensic: [], super: [], candidates: 0 });
    });

    it("a whole description token is a candidate, case-insensitively", async () => {
      await saveForensic(dbPath, [
        event({ id: "hit", description: "Ran EVIL.exe from temp" }),
        event({ id: "miss", description: "nothing here" }),
      ]);
      const out = await candidates(dbPath, ["evil.exe"]);
      expect(ids(out.forensic)).toEqual(["hit"]);
      expect(out.super).toEqual([]);
      expect(out.candidates).toBe(1);
    });

    it("a structured sha256 or path is a candidate without appearing in the description", async () => {
      await saveForensic(dbPath, [
        event({ id: "hash", description: "file written", sha256: "DEADBEEF00" }),
        event({ id: "path", description: "file written", path: "C:\\Users\\bob\\evil.dll" }),
        event({ id: "miss", description: "file written" }),
      ]);
      const out = await candidates(dbPath, ["deadbeef00", "c:\\users\\bob\\evil.dll"]);
      expect(ids(out.forensic)).toEqual(["hash", "path"]);
    });

    it("a path with spaces (a structured value that tokenizes to several terms) is a candidate", async () => {
      await appendSuper(dbPath, [
        event({ id: "hit", description: "exec", path: "C:\\Program Files\\Tool\\run me.exe" }),
        event({ id: "miss", description: "exec", path: "C:\\Program Files\\Other\\x.exe" }),
      ]);
      const out = await candidates(dbPath, ["c:\\program files\\tool\\run me.exe"]);
      expect(ids(out.super)).toEqual(["hit"]);
    });

    it("an authoritative id is a candidate with no value hit at all", async () => {
      await saveForensic(dbPath, [event({ id: "linked", description: "unrelated words" })]);
      await appendSuper(dbPath, [event({ id: "slinked", description: "also unrelated" })]);
      const out = await candidates(dbPath, ["zzz-no-such-value"], ["linked", "slinked", "ghost"]);
      expect(ids(out.forensic)).toEqual(["linked"]);
      expect(ids(out.super)).toEqual(["slinked"]);
      expect(out.candidates).toBe(2);
    });

    it("a key that is only a substring of a longer token is NOT a candidate", async () => {
      await saveForensic(dbPath, [
        event({ id: "longer", description: "saw evil.exe today" }),
        event({ id: "field", description: "x", path: "evilexe" }),
      ]);
      const out = await candidates(dbPath, ["evil"]);
      expect(out.forensic).toEqual([]);
      expect(out.candidates).toBe(0);
    });

    it("a key containing a double quote is escaped, not a syntax error", async () => {
      await saveForensic(dbPath, [
        event({ id: "quoted", description: "x", path: 'C:\\odd"name\\tool.exe' }),
        event({ id: "plain", description: "x" }),
      ]);
      const out = await candidates(dbPath, ['c:\\odd"name\\tool.exe']);
      expect(ids(out.forensic)).toEqual(["quoted"]);
    });

    it("a key of separator characters only is skipped, not an error", async () => {
      await saveForensic(dbPath, [event({ id: "f1", description: "words" })]);
      const out = await candidates(dbPath, ["***", "   ", "words"]);
      expect(ids(out.forensic)).toEqual(["f1"]);
    });

    it("keys the caller did not give never widen the result", async () => {
      await saveForensic(dbPath, [event({ id: "f1", description: "alpha beta" })]);
      const out = await candidates(dbPath, [], []);
      expect(out).toEqual({ forensic: [], super: [], candidates: 0 });
    });

    it("forensic rows come back by ordinal, super rows by timestamp then row_id with undated last", async () => {
      await saveForensic(dbPath, [
        event({ id: "f0", timestamp: "2026-03-01T00:00:00Z", description: "needle" }),
        event({ id: "f1", timestamp: "2026-01-01T00:00:00Z", description: "needle" }),
        event({ id: "f2", timestamp: "2026-02-01T00:00:00Z", description: "needle" }),
      ]);
      await appendSuper(dbPath, [
        event({ id: "undated", timestamp: "", description: "needle" }),
        event({ id: "late", timestamp: "2026-05-01T00:00:00Z", description: "needle" }),
        event({ id: "early-a", timestamp: "2026-04-01T00:00:00Z", description: "needle on host a" }),
        event({ id: "early-b", timestamp: "2026-04-01T00:00:00Z", description: "needle on host b" }),
      ]);
      const out = await candidates(dbPath, ["needle"]);
      expect(ids(out.forensic)).toEqual(["f0", "f1", "f2"]);
      expect(ids(out.super)).toEqual(["early-a", "early-b", "late", "undated"]);
      expect(out.candidates).toBe(7);
    });

    it("payloads come back whole, and a row hit by several keys is counted once", async () => {
      await saveForensic(dbPath, [
        event({ id: "f1", description: "both alpha and beta", sha256: "aa11", asset: "HOST-1" }),
      ]);
      const out = await candidates(dbPath, ["alpha", "beta", "aa11"]);
      expect(out.candidates).toBe(1);
      expect(out.forensic[0]).toMatchObject({ id: "f1", sha256: "aa11", asset: "HOST-1" });
    });
  });

  describe("backfill", () => {
    it("a new database is stamped with the terms version up front", async () => {
      await saveForensic(dbPath, []);
      expect(metaValue(dbPath, "event_terms_version")).toBe("1");
    });

    it("a database built before the index is rebuilt on the first iocCandidates call", async () => {
      await saveForensic(dbPath, [
        event({ id: "f1", description: "needle in forensic" }),
        event({ id: "f2", description: "hay" }),
      ]);
      await appendSuper(dbPath, [event({ id: "s1", description: "needle in super", sha256: "beef" })]);
      const before = await candidates(dbPath, ["needle", "beef"]);
      expect(ids(before.forensic)).toEqual(["f1"]);
      expect(ids(before.super)).toEqual(["s1"]);

      // Strip everything the new schema adds, as a case from before #1452 would have it.
      withDb(dbPath, (db) => {
        db.exec("DROP TRIGGER IF EXISTS entities_terms_delete");
        db.exec("DROP TABLE IF EXISTS event_terms");
        db.exec("DELETE FROM storage_meta WHERE key='event_terms_version'");
      });
      expect(metaValue(dbPath, "event_terms_version")).toBeNull();

      const after = await candidates(dbPath, ["needle", "beef"]);
      expect(after).toEqual(before);
      expect(metaValue(dbPath, "event_terms_version")).toBe("1");
      expect(termsRowIds(dbPath, "hay")).toEqual([rowIdOf(dbPath, "forensicTimeline", "f2")]);
    });

    it("a stale version rebuilds and re-stamps; a current one does not touch the index", async () => {
      await saveForensic(dbPath, [event({ id: "f1", description: "needle" })]);
      withDb(dbPath, (db) => {
        db.exec("INSERT INTO event_terms(event_terms) VALUES('delete-all')");
        db.exec("UPDATE storage_meta SET value='0' WHERE key='event_terms_version'");
      });
      expect(termsRowIds(dbPath, "needle")).toEqual([]);
      const rebuilt = await candidates(dbPath, ["needle"]);
      expect(ids(rebuilt.forensic)).toEqual(["f1"]);
      expect(metaValue(dbPath, "event_terms_version")).toBe("1");

      withDb(dbPath, (db) => db.exec("INSERT INTO event_terms(event_terms) VALUES('delete-all')"));
      const untouched = await candidates(dbPath, ["needle"]);
      expect(untouched.forensic).toEqual([]);
    });
  });
});
