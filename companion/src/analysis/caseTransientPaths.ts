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

// The one database name the worker writes. stateStore.ts owns INVESTIGATION_DB_FILENAME; this is a
// copy for the same reason the verbs are (the drift test compares the two). Anchoring on it is what
// keeps the rule from ever classifying an imported database — `imports/evidence.sqlite-wal` is
// evidence an analyst collected and stays in every archive. The name may follow a path separator
// or a dot: BackupManager's binary sidecar is `<manifest>.investigation.sqlite` and its snapshot
// temp and journal sit beside it under state/backups/.
export const INVESTIGATION_DB_BASENAME = "investigation.sqlite";
const DB_NAME_PATTERN = `(?:^|[\\/.])${INVESTIGATION_DB_BASENAME.replace(".", "\\.")}`;

// SQLite's sidecars beside the real database or one of the temps above: the rollback journal, and
// since #1454 (journal_mode=WAL) the write-ahead log and its shared-memory index.
//
// The journal holds the pages needed to UNDO an open write and is deleted on commit, so it is never
// where committed data lives. The WAL is the opposite — committed pages sit in it until a checkpoint
// folds them into the .sqlite file — which is why NEITHER archive writer copies the live database:
// both substitute a `VACUUM INTO` snapshot (caseExportArchive.ts, caseArchive.ts), a consistent
// single file that needs no sidecar. The sidecars themselves would only ever be stale or
// mid-write in an archive, and restoring a database next to one invites SQLite to replay it.
const SQLITE_TRANSIENT = new RegExp(
  `${DB_NAME_PATTERN}(?:\\.(?:${SQLITE_TEMP_VERBS.join("|")})-${UUID})?(?:-journal|-wal|-shm)$` +
    `|${DB_NAME_PATTERN}\\.(?:${SQLITE_TEMP_VERBS.join("|")})-${UUID}$`,
  "i",
);

/**
 * True when `path` names a write in flight inside a case directory — an atomicWrite temp, a SQLite
 * worker temp database, or a SQLite sidecar of the case database — rather than part of the case.
 */
export function isTransientCasePath(path: string): boolean {
  return isAtomicWriteTempPath(path) || SQLITE_TRANSIENT.test(path);
}
