import { join } from "node:path";
import { caseSqliteWorker } from "./caseSqliteWorker.js";
import { INVESTIGATION_DB_BASENAME } from "./caseTransientPaths.js";

// Where a case's tags are stored (#1874), and the backup side of that storage. TagsStore (tags.ts)
// owns the tag rules; this storage-level module holds what BackupManager also needs, so storage never
// imports the findings layer. The tags live in the case database (worker ops in
// caseSqliteWorkerTags.ts), migrated once from state/tags.json.

// The migration source, and the name a backup bundle carries the list under.
export const TAGS_FILENAME = "tags.json";

// A stored tag as the worker returns it (tags.ts `Tag`; kept structural so this layer stays below it).
export interface StoredTag {
  id: string;
  targetType: string;
  targetId: string;
  label: string;
  author: string;
  createdAt: string;
}

// The two case files the tag ops need: the database, and tags.json for its one-time migration.
export function tagPaths(stateDir: string): { dbPath: string; tagsPath: string } {
  return { dbPath: join(stateDir, INVESTIGATION_DB_BASENAME), tagsPath: join(stateDir, TAGS_FILENAME) };
}

// The case's list once its tags are migrated (on the writer, so it cannot interleave with a
// migration); null while they are still only in tags.json.
async function migratedTags(stateDir: string): Promise<StoredTag[] | null> {
  const { dbPath, tagsPath } = tagPaths(stateDir);
  const snapshot = await caseSqliteWorker.request<{ tags?: StoredTag[] }>({
    op: "tagsBackup",
    dbPath,
    tagsPath,
  });
  return snapshot.tags ?? null;
}

// A bundle's "tags.json" entry: the database's list once the case's tags are migrated, else what the
// old file holds, read by `readFile` exactly as before (raw JSON, malformed or not; ENOENT → no entry).
export async function tagsForBackup(
  stateDir: string,
  readFile: (path: string) => Promise<string>,
): Promise<{ present: true; value: unknown } | { present: false }> {
  const tags = await migratedTags(stateDir);
  if (tags) return { present: true, value: tags };
  try {
    return { present: true, value: JSON.parse(await readFile(tagPaths(stateDir).tagsPath)) as unknown };
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return { present: false };
    throw err;
  }
}

// Read BEFORE a restore that carries no "tags.json" replaces the database: the case's current list,
// or null when its tags were never migrated (they are still in tags.json, which the restore keeps).
export function tagsToCarry(stateDir: string): Promise<StoredTag[] | null> {
  return migratedTags(stateDir);
}

// AFTER a restore: a bundle "tags.json" (already written back) replaces the table's list — a legacy
// investigation.json restore never touches the table, and a restored database may hold another list;
// otherwise the carried list goes back into the replaced database.
export async function restoreTagsAfterBackup(
  stateDir: string,
  bundleHadTags: boolean,
  carried: StoredTag[] | null,
): Promise<void> {
  const { dbPath, tagsPath } = tagPaths(stateDir);
  if (bundleHadTags) await caseSqliteWorker.request<boolean>({ op: "tagsRestore", dbPath, tagsPath });
  else if (carried) await caseSqliteWorker.request<boolean>({ op: "tagsReplace", dbPath, tags: carried });
}
