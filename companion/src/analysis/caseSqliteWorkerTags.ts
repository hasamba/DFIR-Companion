import { TAGGER_PREFIX_SQL } from "./caseSqliteSchema.js";

// Tag storage ops (#1874): the case's tags live in the case database (tables in caseSqliteSchema.ts),
// migrated once from state/tags.json. Spliced into caseSqliteWorker.ts's WORKER_SOURCE as plain text;
// runs inside the worker thread with that file's helpers in scope. Keep it backtick-free.
//
// analysis/tags.ts (TagsStore) is the only caller of the list and write ops; the super-timeline
// fragment calls ensureTagsMigrated and reads the table for its protection (caseSqliteWorkerSuper.ts);
// BackupManager uses tagsBackup / tagsRestore, and restoreDatabase calls settleRestoredTags. Every op
// that reads or writes tags first migrates tags.json when the database has no 'tags_migrated' marker.
// The marker is set only when a file was migrated or a tag was written, so "marker set" means what "tags.json exists" meant: the
// case has a tag list of its own. The file is never renamed or deleted; once the marker is set the
// database is the authority and the file is a stale migration source, like investigation.json.
export const TAGS_WORKER_SOURCE =
  String.raw`
const TAGS_TAGGER_PREFIX = ` +
  JSON.stringify(TAGGER_PREFIX_SQL) +
  String.raw`;
// The writer thread that planned an in-flight analyst event tag (tags_protect_pending).
const TAGS_WORKER_BOOT = randomUUID();
const TAG_FIELDS = ["id", "targetType", "targetId", "label", "author", "createdAt"];
const TAG_SELECT = "SELECT id, target_type, target_id, label, author, created_at FROM tags";
const TAG_ANALYST_EVENT_SQL = "target_type = 'event' AND substr(author, 1, " + TAGS_TAGGER_PREFIX.length + ") <> '" + TAGS_TAGGER_PREFIX + "'";

// The zod key order of tagSchema (analysis/tags.ts), so a listed tag is the object load() returned.
function tagFromRow(row) {
  return {
    id: row.id, targetType: row.target_type, targetId: row.target_id,
    label: row.label, author: row.author, createdAt: row.created_at,
  };
}

function tagIsAnalystEvent(tag) {
  return tag.targetType === "event" && !String(tag.author).startsWith(TAGS_TAGGER_PREFIX);
}

function tagsMarkerSet(db) {
  return !!db.prepare("SELECT 1 AS x FROM storage_meta WHERE key='tags_migrated'").get();
}

function setTagsMarker(db) {
  db.prepare("INSERT OR IGNORE INTO storage_meta(key, value) VALUES('tags_migrated', '1')").run();
}

// The file's parsed JSON, or undefined when there is no file. A parse error throws, as the file-based
// load() did.
function readTagsFile(tagsPath) {
  let text;
  try {
    text = readFileSync(tagsPath, "utf8");
  } catch (error) {
    if (error && error.code === "ENOENT") return undefined;
    throw error;
  }
  return JSON.parse(text);
}

// Exactly z.array(tagSchema).catch([]): anything but an array of objects whose six fields are all
// strings is an empty list; other keys are stripped.
function tagsFromFileValue(parsed) {
  if (!Array.isArray(parsed)) return [];
  const out = [];
  for (const item of parsed) {
    if (!item || typeof item !== "object" || Array.isArray(item)) return [];
    const tag = {};
    for (const key of TAG_FIELDS) {
      if (typeof item[key] !== "string") return [];
      tag[key] = item[key];
    }
    out.push(tag);
  }
  return out;
}

function insertTagRows(db, tags) {
  const insert = db.prepare("INSERT INTO tags(id, target_type, target_id, label, author, created_at) VALUES (?, ?, ?, ?, ?, ?)");
  for (const tag of tags) insert.run(tag.id, tag.targetType, tag.targetId, tag.label, tag.author, tag.createdAt);
}

// Inside a transaction, marker absent: migrate the file when there is one.
function migrateTagsFile(db, tagsPath) {
  const parsed = readTagsFile(tagsPath);
  if (parsed === undefined) return;
  insertTagRows(db, tagsFromFileValue(parsed));
  setTagsMarker(db);
}

// Writer only, outside any transaction.
function ensureTagsMigrated(db, tagsPath) {
  if (tagsMarkerSet(db)) return;
  withTransaction(db, () => {
    if (!tagsMarkerSet(db)) migrateTagsFile(db, tagsPath);
  });
}

function hasTagsTable(db) {
  return !!db.prepare("SELECT 1 AS x FROM sqlite_master WHERE type='table' AND name='tags'").get();
}

function listTagRows(db) {
  return db.prepare(TAG_SELECT + " ORDER BY seq").all().map(tagFromRow);
}

// Read op: the list, or { migrate: true } when the writer must migrate tags.json first.
function tagsList(dbPath, tagsPath) {
  if (!existsSync(dbPath)) return existsSync(tagsPath) ? { migrate: true } : [];
  const db = openDatabase(dbPath);
  try {
    if (!hasTagsTable(db)) return { migrate: true };
    if (!tagsMarkerSet(db) && existsSync(tagsPath)) return { migrate: true };
    return listTagRows(db);
  } finally {
    db.close();
  }
}

// #2059: the reads that never hand back the whole table. On an auto-tagged case the tagger's event
// tags are nearly all of it (one per matched event and label), so they are read only as a page or
// for named rows. q.scope:
//   "analyst"   — every tag except the tagger's event tags, plus the tagger version (count:max seq —
//                 seq is AUTOINCREMENT, so any add or removal of a tagger tag changes it)
//   "tagger"    — a page of the tagger's event tags (q.offset, q.limit) and their total
//   "taggerFor" — the tagger's event tags naming q.targetIds
// Same migrate answer as tagsList.
const TAG_TAGGER_EVENT_SQL = "target_type = 'event' AND substr(author, 1, " + TAGS_TAGGER_PREFIX.length + ") = '" + TAGS_TAGGER_PREFIX + "'";

function taggerVersion(db) {
  const row = db.prepare("SELECT count(*) AS n, coalesce(max(seq), 0) AS s FROM tags WHERE " + TAG_TAGGER_EVENT_SQL).get();
  return row.n + ":" + row.s;
}

function tagsQueryRows(db, q) {
  if (q.scope === "analyst") {
    const tags = db.prepare(TAG_SELECT + " WHERE NOT (" + TAG_TAGGER_EVENT_SQL + ") ORDER BY seq").all().map(tagFromRow);
    return { tags, version: taggerVersion(db) };
  }
  if (q.scope === "tagger") {
    const total = db.prepare("SELECT count(*) AS n FROM tags WHERE " + TAG_TAGGER_EVENT_SQL).get().n;
    const tags = db.prepare(TAG_SELECT + " WHERE " + TAG_TAGGER_EVENT_SQL + " ORDER BY seq LIMIT ? OFFSET ?")
      .all(Math.max(0, Number(q.limit) || 0), Math.max(0, Number(q.offset) || 0)).map(tagFromRow);
    return { tags, total };
  }
  if (q.scope === "taggerFor") {
    const tags = db.prepare(TAG_SELECT + " WHERE target_type = 'event' AND target_id IN (SELECT value FROM json_each(?)) AND " +
      TAG_TAGGER_EVENT_SQL + " ORDER BY seq").all(JSON.stringify(q.targetIds || [])).map(tagFromRow);
    return { tags };
  }
  throw new Error("unknown tags query scope: " + q.scope);
}

function tagsQuery(dbPath, tagsPath, q) {
  if (!existsSync(dbPath)) return existsSync(tagsPath) ? { migrate: true } : { tags: [], total: 0, version: "0:0" };
  const db = openDatabase(dbPath);
  try {
    if (!hasTagsTable(db)) return { migrate: true };
    if (!tagsMarkerSet(db) && existsSync(tagsPath)) return { migrate: true };
    return tagsQueryRows(db, q || {});
  } finally {
    db.close();
  }
}

// The writer's connection with the tags migrated. Null when the case has neither a database nor a
// tags file and create is false: there is nothing to read or remove, and nothing is created for it.
function openTagsDatabase(dbPath, tagsPath, create) {
  if (!create && !existsSync(dbPath) && !existsSync(tagsPath)) return null;
  const db = openDatabase(dbPath);
  try {
    ensureTagsMigrated(db, tagsPath);
    return db;
  } catch (error) {
    db.close();
    throw error;
  }
}

function tagsEnsure(dbPath, tagsPath) {
  const db = openTagsDatabase(dbPath, tagsPath, false);
  if (db) db.close();
}

function findTagStatement(db) {
  return db.prepare(TAG_SELECT + " WHERE target_type = ? AND target_id = ? AND label = ? ORDER BY seq LIMIT 1");
}

// Which inputs are new: not stored yet and not an earlier input of the same batch (first wins).
// first is the stored tag for input 0 when it is not new (add() returns it). When the new ones
// include an analyst event tag that TagsStore will protect, the protect generation moves and the
// targets are recorded as in flight, in this same transaction, before the protect call.
function tagsPlan(dbPath, tagsPath, inputs, protecting) {
  const db = openTagsDatabase(dbPath, tagsPath, true);
  try {
    return withTransaction(db, () => {
      const find = findTagStatement(db);
      const seen = new Set();
      const fresh = [];
      const guarded = [];
      let first = null;
      (inputs || []).forEach((input, index) => {
        const key = JSON.stringify([input.targetType, input.targetId, input.label]);
        if (seen.has(key)) return;
        seen.add(key);
        const row = find.get(input.targetType, input.targetId, input.label);
        if (row) {
          if (index === 0) first = tagFromRow(row);
          return;
        }
        fresh.push(index);
        if (protecting && tagIsAnalystEvent(input)) guarded.push(input.targetId);
      });
      if (guarded.length) {
        db.prepare("UPDATE tags_protect_gen SET n = n + 1 WHERE id = 1").run();
        const pending = db.prepare("INSERT OR IGNORE INTO tags_protect_pending(target_id, boot) VALUES (?, ?)");
        for (const targetId of guarded) pending.run(targetId, TAGS_WORKER_BOOT);
      }
      return { fresh, first };
    });
  } finally {
    db.close();
  }
}

function clearPending(db, targetIds) {
  db.prepare("DELETE FROM tags_protect_pending WHERE boot = ? AND target_id IN (SELECT value FROM json_each(?))")
    .run(TAGS_WORKER_BOOT, JSON.stringify(targetIds));
}

// Insert the planned tags in order. A (target, label) another store wrote since the plan is not
// inserted twice: it is reported as skipped with the stored tag. Sets the marker and clears the
// in-flight record of these targets.
function tagsInsert(dbPath, tagsPath, tags) {
  const db = openTagsDatabase(dbPath, tagsPath, true);
  try {
    return withTransaction(db, () => {
      const find = findTagStatement(db);
      const skipped = [];
      const fresh = [];
      (tags || []).forEach((tag, index) => {
        const row = find.get(tag.targetType, tag.targetId, tag.label);
        if (row) skipped.push({ index, tag: tagFromRow(row) });
        else fresh.push(tag);
      });
      insertTagRows(db, fresh);
      setTagsMarker(db);
      clearPending(db, (tags || []).map((tag) => tag.targetId));
      return { skipped };
    });
  } finally {
    db.close();
  }
}

function tagsPendingClear(dbPath, targetIds) {
  if (!existsSync(dbPath)) return;
  const db = openDatabase(dbPath);
  try {
    withTransaction(db, () => clearPending(db, targetIds || []));
  } finally {
    db.close();
  }
}

// Of these analyst event targets (in order, distinct), the ones no remaining analyst event tag names.
function unreferencedTargets(db, targetIds) {
  const held = db.prepare("SELECT 1 AS x FROM tags WHERE target_type = 'event' AND target_id = ? AND " + TAG_ANALYST_EVENT_SQL + " LIMIT 1");
  return [...new Set(targetIds)].filter((targetId) => !held.get(targetId));
}

// The first tag with this id (list order), and the removal of every tag with it. release names the
// first tag's target when it was an analyst event tag no remaining one names.
function tagsRemove(dbPath, tagsPath, tagId) {
  const db = openTagsDatabase(dbPath, tagsPath, false);
  if (!db) return { removed: null, release: [] };
  try {
    return withTransaction(db, () => {
      const row = db.prepare(TAG_SELECT + " WHERE id = ? ORDER BY seq LIMIT 1").get(tagId);
      if (!row) return { removed: null, release: [] };
      const removed = tagFromRow(row);
      db.prepare("DELETE FROM tags WHERE id = ?").run(tagId);
      return { removed, release: tagIsAnalystEvent(removed) ? unreferencedTargets(db, [removed.targetId]) : [] };
    });
  } finally {
    db.close();
  }
}

// The tagger's event tags on these targets. Tagger tags never protect, so nothing is released.
function tagsRemoveTaggerFor(dbPath, tagsPath, targetIds) {
  const db = openTagsDatabase(dbPath, tagsPath, false);
  if (!db) return 0;
  try {
    return withTransaction(db, () => Number(db.prepare(
      "DELETE FROM tags WHERE target_type = 'event' AND target_id IN (SELECT value FROM json_each(?)) " +
      "AND substr(author, 1, " + TAGS_TAGGER_PREFIX.length + ") = ?"
    ).run(JSON.stringify(targetIds || []), TAGS_TAGGER_PREFIX).changes));
  } finally {
    db.close();
  }
}

// Every tag whose author starts with prefix (case-sensitive, like startsWith; LIKE is not).
function tagsRemoveByPrefix(dbPath, tagsPath, prefix) {
  const db = openTagsDatabase(dbPath, tagsPath, false);
  if (!db) return { count: 0, release: [] };
  try {
    return withTransaction(db, () => {
      const match = "substr(author, 1, length(?1)) = ?1";
      const targets = db.prepare("SELECT target_id FROM tags WHERE " + match + " AND " + TAG_ANALYST_EVENT_SQL + " ORDER BY seq")
        .all(prefix).map((row) => row.target_id);
      const count = Number(db.prepare("DELETE FROM tags WHERE " + match).run(prefix).changes);
      return { count, release: count ? unreferencedTargets(db, targets) : [] };
    });
  } finally {
    db.close();
  }
}

// BackupManager's "tags.json" entry, on the writer so it cannot interleave with a migration: the
// database's list once the marker is set, else { file: true } (the caller reads the file as before).
function tagsBackup(dbPath) {
  if (!existsSync(dbPath)) return { file: true };
  const db = openDatabase(dbPath);
  try {
    return tagsMarkerSet(db) ? { tags: listTagRows(db) } : { file: true };
  } finally {
    db.close();
  }
}

// A restored database's in-flight protection records belong to requests that will never finish in it:
// dropped, and protection re-derived from the tag table on the next super-timeline call.
function dropRestoredPending(db) {
  if (!db.prepare("SELECT 1 AS x FROM tags_protect_pending LIMIT 1").get()) return;
  db.prepare("DELETE FROM tags_protect_pending").run();
  db.prepare("DELETE FROM storage_meta WHERE key='super_protected_sync'").run();
}

// Inside restoreDatabase, on the checked copy BEFORE it replaces the live file, so the restore and the
// case's final tag list go live together (#1874). tags.bundle: the bundle's "tags.json" value becomes
// the list (as a migration of that file would make it). tags.carry: the live database's list is kept
// (a bundle without tags.json leaves the tags alone, as it left the file alone) — read here, inside the
// exclusive op, so no tag write can fall between the read and the swap. A live database whose tags were
// never migrated has none to carry: they are still in tags.json, which the restore keeps.
function settleRestoredTags(db, livePath, tags) {
  withTransaction(db, () => {
    dropRestoredPending(db);
    if (!tags || typeof tags !== "object") return;
    let list = null;
    if (Object.prototype.hasOwnProperty.call(tags, "bundle")) list = tagsFromFileValue(tags.bundle);
    else if (tags.carry && existsSync(livePath)) {
      const live = openDatabase(livePath);
      try { if (hasTagsTable(live) && tagsMarkerSet(live)) list = listTagRows(live); } finally { live.close(); }
    }
    if (!list) return;
    db.prepare("DELETE FROM tags").run();
    insertTagRows(db, list);
    setTagsMarker(db);
  });
}

// After a restore that wrote tags.json: the table becomes that file's list, whatever the (restored or
// kept) database held.
function tagsRestore(dbPath, tagsPath) {
  if (!existsSync(dbPath)) return false;
  const db = openDatabase(dbPath);
  try {
    withTransaction(db, () => {
      dropRestoredPending(db);
      db.prepare("DELETE FROM tags").run();
      db.prepare("DELETE FROM storage_meta WHERE key='tags_migrated'").run();
      migrateTagsFile(db, tagsPath);
    });
    return true;
  } finally {
    db.close();
  }
}

function dispatchTags(message) {
  switch (message.op) {
    case "tagsList": return tagsList(message.dbPath, message.tagsPath);
    case "tagsQuery": return tagsQuery(message.dbPath, message.tagsPath, message.query);
    case "tagsEnsure": return tagsEnsure(message.dbPath, message.tagsPath);
    case "tagsPlan": return tagsPlan(message.dbPath, message.tagsPath, message.inputs, message.protecting);
    case "tagsInsert": return tagsInsert(message.dbPath, message.tagsPath, message.tags);
    case "tagsPendingClear": return tagsPendingClear(message.dbPath, message.targetIds);
    case "tagsRemove": return tagsRemove(message.dbPath, message.tagsPath, message.tagId);
    case "tagsRemoveTaggerFor": return tagsRemoveTaggerFor(message.dbPath, message.tagsPath, message.targetIds);
    case "tagsRemoveByPrefix": return tagsRemoveByPrefix(message.dbPath, message.tagsPath, message.prefix);
    case "tagsBackup": return tagsBackup(message.dbPath);
    case "tagsRestore": return tagsRestore(message.dbPath, message.tagsPath);
    default: throw new Error("unknown SQLite worker operation: " + message.op);
  }
}
`;
