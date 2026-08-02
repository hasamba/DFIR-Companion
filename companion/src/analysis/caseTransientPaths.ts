import { isAtomicWriteTempPath } from "../storage/atomicWrite.js";

// Which files inside a case directory are a write IN PROGRESS rather than case content.
//
// The whole-case export walks the case directory while the rest of the app is still writing to it,
// so it has to tell the two apart. It could not, and that cost an analyst a working export: a
// dashboard load on a seeded case fires the legacy JSON -> SQLite migration and a burst of sidecar
// saves, every one of which creates a uniquely-named file and renames it away microseconds later.
// readdir listed those names, the per-file lstat came back ENOENT, and the whole export died with a
// raw 500 — while a freshly created case, which writes almost nothing, exported fine. That is what
// made the bug look content-dependent instead of like the race it is.
//
// Two rules govern what belongs here, and they pull in opposite directions:
//
//   1. Nothing that could be evidence. A case directory holds files an analyst imported, and a
//      malware sample named "payload.tmp" or "notes-journal" is entirely ordinary. Dropping one
//      from an archive because of its extension is silent evidence loss — the single outcome a
//      forensic export must never produce. So every pattern below matches a full generated shape
//      (a uuid, a known database name), never a bare extension.
//   2. Nothing whose absence loses committed data. See the journal note in SQLITE_TRANSIENT below.
//
// Anything that vanishes and is NOT matched here still fails the export loudly, with a message
// naming the file — see caseExportArchive.ts. Skipping is the exception, not the fallback.

const UUID = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";

// The three "<db path>.<verb>-<uuid>" temp databases caseSqliteWorker.ts builds and then renames
// over the real one — the legacy-JSON migration, the backup snapshot, and the restore. They live in
// that worker's String.raw source, which cannot import anything, so this list is a copy; the drift
// test in tests/analysis/caseTransientPaths.test.ts reads that source and fails if a fourth verb
// appears without being added here.
export const SQLITE_TEMP_VERBS = ["migrating", "snapshot", "restoring"];

// A SQLite rollback journal, beside either the real database or one of the temps above.
//
// Safe to skip ONLY because openDatabase sets `PRAGMA journal_mode=DELETE`: the journal holds the
// pages needed to UNDO an open write and is deleted on commit, so committed data is always in the
// .sqlite file itself. It also has no business in an archive — restoring a database next to a stale
// journal invites SQLite to roll the copy back. DELETE mode is why there is no -wal/-shm here; if
// that pragma ever becomes WAL, committed data WOULD live beside the database and this exclusion
// must be reconsidered rather than widened.
const SQLITE_TRANSIENT = new RegExp(
  `\\.sqlite(?:\\.(?:${SQLITE_TEMP_VERBS.join("|")})-${UUID})?-journal$` +
    `|\\.sqlite\\.(?:${SQLITE_TEMP_VERBS.join("|")})-${UUID}$`,
  "i",
);

/**
 * True when `path` names a write in flight inside a case directory — an atomicWrite temp, a SQLite
 * worker temp database, or a rollback journal — rather than part of the case itself.
 */
export function isTransientCasePath(path: string): boolean {
  return isAtomicWriteTempPath(path) || SQLITE_TRANSIENT.test(path);
}
