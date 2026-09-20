import { describe, it, expect } from "vitest";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import {
  INVESTIGATION_DB_BASENAME,
  isTransientCasePath,
  SQLITE_TEMP_VERBS,
} from "../../src/analysis/caseTransientPaths.js";
import { INVESTIGATION_DB_FILENAME } from "../../src/analysis/stateStore.js";

const WORKER_SOURCE_FILE = join(
  import.meta.dirname,
  "..",
  "..",
  "src",
  "analysis",
  "caseSqliteWorker.js",
).replace(/\.js$/, ".ts");

describe("isTransientCasePath — SQLite worker temporaries", () => {
  // The verbs live inside caseSqliteWorker's String.raw source, which cannot import anything, so
  // caseTransientPaths.ts keeps a copy. Nothing but this test stops the two from drifting: a fourth
  // "<db>.<verb>-<uuid>" temp added to the worker without being listed there would put the export
  // straight back to dying mid-write, which is how this reached an analyst the first time.
  it("knows every temp name the worker actually writes", async () => {
    const source = await readFile(WORKER_SOURCE_FILE, "utf8");
    const verbs = [
      ...new Set([...source.matchAll(/\.(\w+)-"\s*\+\s*randomUUID\(\)/g)].map((m) => m[1])),
    ].sort();

    // Both directions. A verb the worker writes but the list omits lets a temp file break the
    // export; a verb the list keeps after the worker drops it is dead code that hides the next
    // real one. Equality is what keeps this test from passing vacuously.
    expect(verbs).toEqual([...SQLITE_TEMP_VERBS].sort());

    for (const verb of verbs) {
      const path = `state/investigation.sqlite.${verb}-3fe4927a-44f6-4c7b-9972-8592d781cbd7`;
      expect(isTransientCasePath(path), `the worker writes ".${verb}-<uuid>" but the export keeps it`).toBe(
        true,
      );
      // SQLite puts a rollback journal beside whichever database it has open, temps included.
      expect(isTransientCasePath(`${path}-journal`), `the journal beside a ${verb} temp is kept`).toBe(true);
    }
  });

  // The rollback journal holds pages to UNDO an open write and is deleted on commit, so it races
  // the export and is never where committed data lives. The database itself must stay.
  it("skips the live database's rollback journal but keeps the database", () => {
    expect(isTransientCasePath("state/investigation.sqlite-journal")).toBe(true);
    expect(isTransientCasePath("state/investigation.sqlite")).toBe(false);
  });

  // #1454: journal_mode=WAL. Committed pages DO live in the -wal file until a checkpoint folds them
  // in, so a raw copy of the database alone can be stale — which is why both archive writers copy a
  // VACUUM INTO snapshot instead of the live file. The sidecars themselves are never case content.
  it("skips the live database's WAL and shared-memory sidecars", () => {
    expect(isTransientCasePath("state/investigation.sqlite-wal")).toBe(true);
    expect(isTransientCasePath("state/investigation.sqlite-shm")).toBe(true);
    expect(isTransientCasePath("investigation.sqlite-wal")).toBe(true);
    for (const verb of SQLITE_TEMP_VERBS) {
      const temp = `investigation.sqlite.${verb}-3fe4927a-44f6-4c7b-9972-8592d781cbd7`;
      expect(isTransientCasePath(`${temp}-wal`)).toBe(true);
      expect(isTransientCasePath(`${temp}-shm`)).toBe(true);
    }
  });

  // BackupManager snapshots the database to `<manifest>.investigation.sqlite` under state/backups/,
  // through the same worker temp; its temp and sidecars are as transient as the live database's.
  it("covers the backup sidecar's temp and journal too", () => {
    const sidecar = "2026-09-20T10-00-00-000Z_auto.investigation.sqlite";
    expect(isTransientCasePath(sidecar)).toBe(false);
    expect(isTransientCasePath(`${sidecar}.snapshot-3fe4927a-44f6-4c7b-9972-8592d781cbd7`)).toBe(true);
    expect(isTransientCasePath(`${sidecar}-journal`)).toBe(true);
    expect(isTransientCasePath(`${sidecar}-wal`)).toBe(true);
  });

  // The rule is anchored on the one database name the worker writes. The sidecar suffixes alone
  // must not classify a file: an analyst can import a collected SQLite database with its WAL.
  it("matches only the case database's own name, never an imported one", () => {
    expect(INVESTIGATION_DB_BASENAME).toBe(INVESTIGATION_DB_FILENAME);
    for (const path of [
      "imports/evidence.sqlite-journal",
      "imports/evidence.sqlite-wal",
      "imports/evidence.sqlite-shm",
      "imports/history.sqlite.migrating-3fe4927a-44f6-4c7b-9972-8592d781cbd7",
      "imports/xinvestigation.sqlite-wal",
      "imports/evidence-investigation.sqlite-wal",
      "imports/investigation.sqlite.bak-wal",
    ]) {
      expect(isTransientCasePath(path), `${path} is case content and must be exported`).toBe(false);
    }
  });
});

describe("isTransientCasePath — atomicWrite temporaries", () => {
  it("skips the uuid-suffixed temp atomicWrite renames away", () => {
    expect(isTransientCasePath("state/notebook.json.3f2504e0-4f89-41d3-9a0c-0305e82c3301.tmp")).toBe(true);
  });
});

// The failure this must never allow is the quiet one: an archive that omits a file an analyst
// imported and still presents itself as complete. Every pattern matches a full generated shape, so
// evidence that merely resembles one by extension stays in the export.
describe("isTransientCasePath — never mistakes evidence for a temp file", () => {
  it("keeps analyst files whose names look transient", () => {
    for (const path of [
      "imports/payload.tmp",
      "imports/case-journal",
      "imports/notes-journal",
      "imports/migrating-notes.txt",
      "screenshots/shot.tmp.webp",
      "state/notebook.json",
      "state/notebook.json.not-a-uuid.tmp",
      "imports/evidence.sqlite",
      "imports/evidence.sqlite.migrating-not-a-uuid",
    ]) {
      expect(isTransientCasePath(path), `${path} is case content and must be exported`).toBe(false);
    }
  });
});
