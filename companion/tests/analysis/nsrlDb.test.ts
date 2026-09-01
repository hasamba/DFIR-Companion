import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadDatabaseSync } from "../../src/analysis/sqliteRuntime.js";
import { NsrlDb, loadNsrlDbPath, saveNsrlDbPath, removeNsrlDbPath } from "../../src/analysis/nsrlDb.js";

const DatabaseSync = loadDatabaseSync();

const MD5 = "d41d8cd98f00b204e9800998ecf8427e";
const SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

// Build an NSRL-RDS-shaped SQLite DB: METADATA base table + a FILE view over it, hashes UPPERCASE
// (the RDS convention). Optionally a sha256 index (mirrors the documented setup).
async function buildRds(opts?: { lower?: boolean; sha1Only?: boolean }): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "dfir-nsrldb-"));
  const file = join(dir, "rds.db");
  const db = new DatabaseSync(file);
  if (opts?.sha1Only) {
    db.exec("CREATE TABLE METADATA(package_id INTEGER, sha1 TEXT, file_name TEXT)");
    db.prepare("INSERT INTO METADATA(sha1) VALUES(?)").run("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709");
  } else {
    db.exec("CREATE TABLE METADATA(package_id INTEGER, sha256 TEXT, sha1 TEXT, md5 TEXT, file_name TEXT)");
    db.exec("CREATE VIEW FILE AS SELECT * FROM METADATA");
    const cast = (h: string): string => (opts?.lower ? h.toLowerCase() : h.toUpperCase());
    db.prepare("INSERT INTO METADATA(sha256, md5) VALUES(?, ?)").run(cast(SHA256), cast(MD5));
    db.exec("CREATE INDEX idx_sha256 ON METADATA(sha256)");
  }
  db.close();
  return file;
}

describe("NsrlDb", () => {
  it("opens a modern RDS, picks the METADATA base table, and reports its hash columns", async () => {
    const db = NsrlDb.open(await buildRds());
    expect(db.table).toBe("METADATA"); // the table, not the FILE view
    expect(db.columns.sort()).toEqual(["md5", "sha256"]);
    db.close();
  });

  it("matches sha256 + md5 known-good hashes, case-insensitively, and misses unknowns", async () => {
    const db = NsrlDb.open(await buildRds());
    expect(db.has(SHA256)).toBe(true); // normalized (lowercase) input vs uppercase-stored
    expect(db.has(MD5)).toBe(true);
    expect(db.has("f".repeat(64))).toBe(false);
    expect(db.has("a".repeat(32))).toBe(false);
    expect(db.has("da39a3ee5e6b4b0d3255bfef95601890afd80709")).toBe(false); // sha1 length → no column, not matched
    db.close();
  });

  it("works when the RDS stores hashes lowercase too", async () => {
    const db = NsrlDb.open(await buildRds({ lower: true }));
    expect(db.has(SHA256)).toBe(true);
    expect(db.has(MD5)).toBe(true);
    db.close();
  });

  it("throws a clear error when there is no sha256/md5 column", async () => {
    await expect(async () => NsrlDb.open(await buildRds({ sha1Only: true }))).rejects.toThrow(
      /sha256 or md5/,
    );
  });

  it("throws when the file can't be opened", async () => {
    await expect(async () =>
      NsrlDb.open(join(tmpdir(), "does-not-exist-" + process.pid + ".db")),
    ).rejects.toThrow();
  });

  // #761 — the table name comes from the analyst-selected file's sqlite_master, so a hostile "NSRL
  // export" can name a table with an embedded double quote and break out of the quoted identifier.
  // The payload below turns the lookup into `... FROM "M" WHERE 1=1 UNION SELECT 1 AS x FROM "M"
  // WHERE "sha256" = ? LIMIT 1`, which returns a row for EVERY hash — silently auto-marking every
  // hashed event and IOC in the case as a false positive. Escaping the identifier keeps the name a
  // name, so the lookup finds nothing.
  it("does not let a hostile table name inject SQL into the hash lookup", async () => {
    const dir = await mkdtemp(join(tmpdir(), "dfir-nsrldb-inject-"));
    const file = join(dir, "hostile.db");
    const hostile = 'M" WHERE 1=1 UNION SELECT 1 AS x FROM "M';
    const db = new DatabaseSync(file);
    // Created first so detectHashTable reaches it before the decoy (both rank equally).
    db.exec(`CREATE TABLE "${hostile.replace(/"/g, '""')}"(sha256 TEXT, md5 TEXT)`);
    db.exec("CREATE TABLE M(sha256 TEXT, md5 TEXT)");
    db.prepare("INSERT INTO M(sha256, md5) VALUES(?, ?)").run(SHA256.toUpperCase(), MD5.toUpperCase());
    db.close();

    const nsrl = NsrlDb.open(file);
    try {
      expect(nsrl.table).toBe(hostile); // the poisoned table IS the one selected
      expect(nsrl.has("f".repeat(64))).toBe(false); // no injected UNION → unknown stays unknown
      expect(nsrl.has("a".repeat(32))).toBe(false);
      expect(nsrl.has(SHA256)).toBe(false); // the hostile table itself holds no rows
    } finally {
      nsrl.close();
    }
  });

  // A quote in a hash COLUMN name can't reach the query today (hashColumnsOf only returns case
  // variants of sha256/md5), but the same escaping must hold if that filter ever loosens.
  it("keeps working when the hash columns use the RDS's own casing", async () => {
    const dir = await mkdtemp(join(tmpdir(), "dfir-nsrldb-case-"));
    const file = join(dir, "cased.db");
    const db = new DatabaseSync(file);
    db.exec('CREATE TABLE METADATA("SHA256" TEXT, "MD5" TEXT)');
    db.prepare("INSERT INTO METADATA VALUES(?, ?)").run(SHA256.toUpperCase(), MD5.toUpperCase());
    db.close();

    const nsrl = NsrlDb.open(file);
    try {
      expect(nsrl.columns.sort()).toEqual(["md5", "sha256"]);
      expect(nsrl.has(SHA256)).toBe(true);
      expect(nsrl.has(MD5)).toBe(true);
      expect(nsrl.has("f".repeat(64))).toBe(false);
    } finally {
      nsrl.close();
    }
  });
});

describe("NSRL DB path persistence", () => {
  it("saves, loads, and removes the configured DB path", async () => {
    const dir = await mkdtemp(join(tmpdir(), "dfir-nsrldbcfg-"));
    const file = join(dir, "nsrl", "db-path.txt"); // nested dir created on save
    expect(loadNsrlDbPath(file)).toBe("");
    await saveNsrlDbPath(file, "D:\\NSRL\\RDS.db");
    expect(loadNsrlDbPath(file)).toBe("D:\\NSRL\\RDS.db");
    await removeNsrlDbPath(file);
    expect(loadNsrlDbPath(file)).toBe("");
    await removeNsrlDbPath(file); // idempotent
  });
});
