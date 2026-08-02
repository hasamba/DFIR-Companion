import { describe, it, expect } from "vitest";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { isTransientCasePath, SQLITE_TEMP_VERBS } from "../../src/analysis/caseTransientPaths.js";

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

  // journal_mode=DELETE: the journal holds pages to UNDO an open write and is deleted on commit, so
  // it races the export and is never where committed data lives. The database itself must stay.
  it("skips the live database's rollback journal but keeps the database", () => {
    expect(isTransientCasePath("state/investigation.sqlite-journal")).toBe(true);
    expect(isTransientCasePath("state/investigation.sqlite")).toBe(false);
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
