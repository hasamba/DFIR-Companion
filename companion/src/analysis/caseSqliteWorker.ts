import { CaseSqliteWorkerPool } from "./caseSqliteWorkerPool.js";
import { CASE_SQLITE_SCHEMA_SQL } from "./caseSqliteSchema.js";
import { SUPER_WORKER_SOURCE } from "./caseSqliteWorkerSuper.js";
import { SUPER_QUERY_WORKER_SOURCE } from "./caseSqliteWorkerSuperQuery.js";
import { TERMS_WORKER_SOURCE } from "./caseSqliteWorkerTerms.js";

// node:sqlite is synchronous. Keeping the entire database lifecycle in worker threads prevents a
// checkpoint, migration, large import, or integrity check from pinning Express/WebSocket work on
// the main event loop. A worker opens a database only for one transaction/query and closes it
// before replying.
//
// #1454: the same source runs as ONE writer and a small pool of read-only readers (see
// caseSqliteWorkerPool.ts, which owns the routing). The database runs in WAL mode so a reader
// never waits for the writer's transaction and the writer never waits for a reader. A reader opens
// read-only, runs no schema DDL, and wraps its statements in one deferred transaction so a
// multi-statement read describes one database version; `close()` rolls that transaction back.
// It refuses a database the writer has not initialised (still in rollback-journal mode or on an
// older schema) with DFIR_SQLITE_NEEDS_INIT, and the pool then runs `ensureDatabase` on the writer
// and retries — that is how a restored, imported, or pre-WAL case file is converted exactly once.
const WORKER_SOURCE =
  String.raw`
const { parentPort, workerData } = require("node:worker_threads");
const { copyFileSync, existsSync, mkdirSync, readFileSync, renameSync, rmSync, statSync } = require("node:fs");
const { dirname } = require("node:path");
const { randomUUID } = require("node:crypto");

const DatabaseSync = process.getBuiltinModule("node:sqlite").DatabaseSync;
const READ_ONLY = !!(workerData && workerData.role === "read");
const ARRAY_KINDS = [
  "findings", "iocs", "openThreads", "timeline", "forensicTimeline", "mitreTechniques",
  "keyQuestions", "nextSteps", "uncertainties", "iocExcludeRules"
];
const SCHEMA_VERSION = 1;
// After a checkpoint a WAL that grew behind a long read shrinks back to this size (bytes).
const JOURNAL_SIZE_LIMIT = 64 * 1024 * 1024;

function openDatabase(path) {
  if (READ_ONLY) return openReadOnlyDatabase(path);
  mkdirSync(dirname(path), { recursive: true });
  const db = new DatabaseSync(path, { enableForeignKeyConstraints: true });
  db.exec("PRAGMA busy_timeout=10000; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; " +
    "PRAGMA journal_size_limit=" + JOURNAL_SIZE_LIMIT + ";");
  db.exec(${JSON.stringify(CASE_SQLITE_SCHEMA_SQL)} + "PRAGMA user_version=" + SCHEMA_VERSION + ";");
  stampEventTermsOnNewDatabase(db); // #1452: a new file never backfills the term index
  return db;
}

function openReadOnlyDatabase(path) {
  const db = new DatabaseSync(path, { readOnly: true });
  try {
    db.exec("PRAGMA busy_timeout=10000");
    const mode = String(db.prepare("PRAGMA journal_mode").get().journal_mode);
    const version = Number(db.prepare("PRAGMA user_version").get().user_version);
    if (mode !== "wal" || version !== SCHEMA_VERSION) {
      const error = new Error("case database is not initialised for concurrent reads (" + mode + ", v" + version + ")");
      error.code = "DFIR_SQLITE_NEEDS_INIT";
      throw error;
    }
    db.exec("BEGIN");
    return db;
  } catch (error) {
    db.close();
    throw error;
  }
}

// Writer-only: open and close once so the schema, user_version, term stamp and WAL conversion are
// applied before the read pool touches the file. False when there is no database to initialise.
function ensureDatabase(dbPath) {
  if (!existsSync(dbPath)) return false;
  openDatabase(dbPath).close();
  return true;
}

function withTransaction(db, fn) {
  db.exec("BEGIN IMMEDIATE");
  try {
    const value = fn();
    db.exec("COMMIT");
    return value;
  } catch (error) {
    try { db.exec("ROLLBACK"); } catch {}
    throw error;
  }
}

function scalarText(value) {
  return typeof value === "string" && value.length ? value : null;
}

function timestampMs(value) {
  if (typeof value !== "string" || !value) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function indexValues(kind, entity) {
  const out = [];
  const add = (name, value) => {
    if (typeof value === "string" && value) out.push([name, value]);
  };
  add("entity", entity && entity.id);
  if (kind === "iocs") {
    add("ioc", entity && entity.value);
    for (const alias of (entity && entity.aliasValues) || []) add("ioc", alias);
  }
  if (kind === "forensicTimeline" || kind === "superTimeline") {
    for (const key of ["srcIp", "dstIp", "srcDomain", "dstDomain", "sha256", "md5", "path"]) {
      add("ioc", entity && entity[key]);
    }
  }
  for (const technique of (entity && entity.mitreTechniques) || []) add("technique", technique);
  return out;
}

function entityProjection(kind, entity, ordinal, contentKey) {
  const sources = Array.isArray(entity && entity.sources) ? entity.sources : [];
  const entityId = scalarText(entity && (entity.id || (kind === "iocs" ? entity.value : null)));
  const timestamp = scalarText(entity && (entity.timestamp || entity.firstSeen || entity.openedAt));
  return {
    kind,
    entityId,
    ordinal,
    timestamp,
    timestampMs: timestampMs(timestamp),
    host: scalarText(entity && entity.asset),
    source: scalarText(entity && (entity.artifactName || sources[0])),
    severity: scalarText(entity && entity.severity),
    contentKey: contentKey || null,
    payload: JSON.stringify(entity),
  };
}

function createEntityWriter(db) {
  const insertStatement = db.prepare(
    "INSERT INTO entities " +
    "(kind, entity_id, ordinal, version, timestamp, timestamp_ms, host, source, severity, content_key, payload) " +
    "VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?)"
  );
  const valueStatement = db.prepare(
    "INSERT OR IGNORE INTO entity_values (row_id, name, value, kind, host, ordinal) " +
    "VALUES (?, ?, ?, ?, ?, ?)"
  );
  const updateStatement = db.prepare(
    "UPDATE entities SET entity_id=?, version=version+1, timestamp=?, timestamp_ms=?, host=?, " +
    "source=?, severity=?, content_key=?, payload=? WHERE row_id=?"
  );
  const deleteValuesStatement = db.prepare("DELETE FROM entity_values WHERE row_id=?");
  const terms = createTermsWriter(db); // #1452: the term index follows every timeline row
  return {
    insert(projection, entity) {
      const result = insertStatement.run(
        projection.kind, projection.entityId, projection.ordinal, projection.timestamp,
        projection.timestampMs, projection.host, projection.source, projection.severity,
        projection.contentKey, projection.payload
      );
      const rowId = Number(result.lastInsertRowid);
      for (const [name, value] of indexValues(projection.kind, entity)) {
        valueStatement.run(
          rowId, name, value, projection.kind, projection.host, projection.ordinal
        );
      }
      terms.insert(projection.kind, rowId, entity);
      return rowId;
    },
    update(rowId, projection, entity) {
      updateStatement.run(
        projection.entityId, projection.timestamp, projection.timestampMs, projection.host,
        projection.source, projection.severity, projection.contentKey, projection.payload, rowId
      );
      deleteValuesStatement.run(rowId);
      for (const [name, value] of indexValues(projection.kind, entity)) {
        valueStatement.run(
          rowId, name, value, projection.kind, projection.host, projection.ordinal
        );
      }
      terms.update(projection.kind, rowId, entity);
    },
  };
}

function writeState(db, state) {
  return withTransaction(db, () => {
    const writer = createEntityWriter(db);
    const meta = {};
    for (const [key, value] of Object.entries(state || {})) {
      if (!ARRAY_KINDS.includes(key)) meta[key] = value;
    }
    db.prepare(
      "INSERT INTO storage_meta(key, value) VALUES('investigation', ?) " +
      "ON CONFLICT(key) DO UPDATE SET value=excluded.value"
    ).run(JSON.stringify(meta));
    for (const kind of ARRAY_KINDS) {
      const values = Array.isArray(state && state[kind]) ? state[kind] : [];
      const existing = new Map(db.prepare(
        "SELECT row_id, ordinal, payload FROM entities WHERE kind=? ORDER BY ordinal"
      ).all(kind).map((row) => [row.ordinal, row]));
      for (let ordinal = 0; ordinal < values.length; ordinal++) {
        const projection = entityProjection(kind, values[ordinal], ordinal);
        const prior = existing.get(ordinal);
        if (!prior) writer.insert(projection, values[ordinal]);
        else if (prior.payload !== projection.payload) writer.update(prior.row_id, projection, values[ordinal]);
      }
      db.prepare("DELETE FROM entities WHERE kind=? AND ordinal>=?").run(kind, values.length);
      db.prepare(
        "INSERT INTO entity_counts(kind, count) VALUES(?, ?) " +
        "ON CONFLICT(kind) DO UPDATE SET count=excluded.count"
      ).run(kind, values.length);
    }
    db.prepare(
      "INSERT INTO storage_meta(key, value) VALUES('schema_version', ?) " +
      "ON CONFLICT(key) DO UPDATE SET value=excluded.value"
    ).run(String(SCHEMA_VERSION));
  });
}

function readState(db, excludedKinds) {
  const row = db.prepare("SELECT value FROM storage_meta WHERE key='investigation'").get();
  if (!row) return null;
  const state = JSON.parse(row.value);
  for (const kind of ARRAY_KINDS) {
    state[kind] = (excludedKinds || []).includes(kind)
      ? []
      : db.prepare("SELECT payload FROM entities WHERE kind=? ORDER BY ordinal")
        .all(kind).map((item) => JSON.parse(item.payload));
  }
  return state;
}

function migrateState(dbPath, jsonPath) {
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(jsonPath, "utf8"));
  } catch (error) {
    if (error && error.code === "ENOENT") return false;
    throw error;
  }

  if (existsSync(dbPath)) {
    const db = openDatabase(dbPath);
    try {
      if (!db.prepare("SELECT 1 AS x FROM storage_meta WHERE key='investigation'").get()) writeState(db, parsed);
      return true;
    } finally {
      db.close();
    }
  }

  const temporary = dbPath + ".migrating-" + randomUUID();
  try {
    const db = openDatabase(temporary);
    try {
      writeState(db, parsed);
      const check = db.prepare("PRAGMA integrity_check").get();
      if (!check || check.integrity_check !== "ok") throw new Error("SQLite integrity check failed during migration");
    } finally {
      db.close();
    }
    renameSync(temporary, dbPath);
    return true;
  } catch (error) {
    try { rmSync(temporary, { force: true }); } catch {}
    throw error;
  }
}

function stateExists(dbPath) {
  if (!existsSync(dbPath)) return false;
  const db = openDatabase(dbPath);
  try {
    return !!db.prepare("SELECT 1 AS x FROM storage_meta WHERE key='investigation'").get();
  } finally {
    db.close();
  }
}

function loadState(dbPath, excludedKinds) {
  if (!existsSync(dbPath)) return null;
  const db = openDatabase(dbPath);
  try { return readState(db, excludedKinds); } finally { db.close(); }
}

function saveState(dbPath, state) {
  const db = openDatabase(dbPath);
  try { writeState(db, state); } finally { db.close(); }
}

function setStateCaseId(dbPath, caseId) {
  if (!existsSync(dbPath)) return;
  const db = openDatabase(dbPath);
  try {
    withTransaction(db, () => {
      const row = db.prepare("SELECT value FROM storage_meta WHERE key='investigation'").get();
      if (!row) return;
      const meta = JSON.parse(row.value);
      meta.caseId = caseId;
      db.prepare("UPDATE storage_meta SET value=? WHERE key='investigation'").run(JSON.stringify(meta));
    });
  } finally {
    db.close();
  }
}

function queryEntities(dbPath, kind, query) {
  if (!existsSync(dbPath)) return { entities: [], nextCursor: null, total: 0 };
  const db = openDatabase(dbPath);
  try {
    const hasIndex = !!(query && typeof query.indexName === "string" &&
      typeof query.indexValue === "string");
    const fromClause = hasIndex
      ? "entity_values indexed_value JOIN entities ON entities.row_id=indexed_value.row_id"
      : "entities";
    const where = [];
    const params = [];
    if (hasIndex) {
      where.push("indexed_value.name=?", "indexed_value.value=?", "indexed_value.kind=?");
      params.push(query.indexName, query.indexValue, kind);
    } else {
      where.push("entities.kind=?");
      params.push(kind);
    }
    for (const [field, column] of [
      ["host", hasIndex ? "indexed_value.host" : "entities.host"],
      ["source", "entities.source"],
      ["severity", "entities.severity"],
      ["entityId", "entities.entity_id"],
    ]) {
      if (query && typeof query[field] === "string" && query[field]) {
        where.push(column + "=?");
        params.push(query[field]);
      }
    }
    const validFrom = query && typeof query.from === "string" && Number.isFinite(Date.parse(query.from));
    const validTo = query && typeof query.to === "string" && Number.isFinite(Date.parse(query.to));
    if (validFrom) {
      where.push("(entities.timestamp_ms IS NULL OR entities.timestamp_ms>=?)");
      params.push(Date.parse(query.from));
    }
    if (validTo) {
      where.push("(entities.timestamp_ms IS NULL OR entities.timestamp_ms<=?)");
      params.push(Date.parse(query.to));
    }
    // #928 search prefilter. Two clauses, and analysis/forensicSearch.ts documents why both are
    // needed: LIKE folds case for ASCII only, so the GLOB keeps every row holding a non-ASCII
    // character as a candidate rather than losing it.
    if (query && query.searchPrefilter) {
      const clauses = [];
      if (typeof query.searchLike === "string" && query.searchLike) {
        clauses.push("entities.payload LIKE ? ESCAPE '\\'");
        params.push(query.searchLike);
      }
      clauses.push("entities.payload GLOB '*[^ -~]*'");
      where.push("(" + clauses.join(" OR ") + ")");
    }
    const totalClause = where.join(" AND ");
    let total = -1;
    if (!(query && query.includeTotal === false)) {
      const hasEntityOnlyFilters = !!(
        (query && typeof query.source === "string" && query.source) ||
        (query && typeof query.severity === "string" && query.severity) ||
        (query && typeof query.entityId === "string" && query.entityId) ||
        validFrom || validTo || (query && query.searchPrefilter)
      );
      const hasAnyFilter = hasIndex || hasEntityOnlyFilters ||
        !!(query && typeof query.host === "string" && query.host);
      if (!hasAnyFilter) {
        const countRow = db.prepare("SELECT count AS n FROM entity_counts WHERE kind=?").get(kind);
        total = countRow
          ? Number(countRow.n)
          : Number(db.prepare("SELECT count(*) AS n FROM entities WHERE kind=?").get(kind).n);
      } else if (hasIndex && !hasEntityOnlyFilters) {
        // The covering value index answers indicator/technique + host counts without touching the
        // multi-gigabyte payload table. Only the returned page joins back to parse complete JSON.
        total = Number(db.prepare(
          "SELECT count(*) AS n FROM entity_values indexed_value WHERE " + totalClause
        ).get(...params).n);
      } else {
        total = Number(db.prepare(
          "SELECT count(*) AS n FROM " + fromClause + " WHERE " + totalClause
        ).get(...params).n);
      }
    }
    const pageWhere = [...where];
    const pageParams = [...params];
    const ordinalColumn = hasIndex ? "indexed_value.ordinal" : "entities.ordinal";
    if (query && Number.isFinite(query.afterOrdinal)) {
      pageWhere.push(ordinalColumn + ">?");
      pageParams.push(Math.floor(query.afterOrdinal));
    }
    const pageClause = pageWhere.join(" AND ");
    const requestedLimit = query && Number.isFinite(query.limit) ? query.limit : 500;
    const limit = Math.max(0, Math.min(10000, Math.floor(requestedLimit)));
    const rows = db.prepare(
      "SELECT entities.ordinal, entities.payload FROM " + fromClause +
      " WHERE " + pageClause + " ORDER BY " + ordinalColumn + " LIMIT ?"
    ).all(...pageParams, limit + 1);
    const hasMore = rows.length > limit;
    const pageRows = hasMore ? rows.slice(0, limit) : rows;
    const entities = pageRows.map((row) => JSON.parse(row.payload));
    return {
      entities,
      // Parallel to entities: a post-filtering caller resumes from the row it stopped on (#928).
      ordinals: pageRows.map((row) => row.ordinal),
      nextCursor: hasMore && pageRows.length ? pageRows[pageRows.length - 1].ordinal : null,
      total,
    };
  } finally {
    db.close();
  }
}

function hasEntityIds(dbPath, kind, ids) {
  if (!existsSync(dbPath) || !Array.isArray(ids) || !ids.length) return [];
  const db = openDatabase(dbPath);
  try {
    return db.prepare(
      "SELECT DISTINCT entity_id FROM entities " +
      "WHERE kind=? AND entity_id IN (SELECT value FROM json_each(?))"
    ).all(kind, JSON.stringify(ids)).map((row) => row.entity_id);
  } finally {
    db.close();
  }
}

function entityCounts(dbPath, kinds) {
  if (!existsSync(dbPath)) return null;
  const db = openDatabase(dbPath);
  try {
    const out = {};
    const countStatement = db.prepare("SELECT count AS n FROM entity_counts WHERE kind=?");
    const fallbackStatement = db.prepare("SELECT count(*) AS n FROM entities WHERE kind=?");
    for (const kind of kinds || []) {
      const row = countStatement.get(kind);
      out[kind] = Number(row ? row.n : fallbackStatement.get(kind).n);
    }
    return out;
  } finally {
    db.close();
  }
}

function appendEntities(dbPath, kind, entities) {
  const db = openDatabase(dbPath);
  try {
    return withTransaction(db, () => {
      const writer = createEntityWriter(db);
      let ordinal = Number(db.prepare(
        "SELECT coalesce(max(ordinal), -1) AS n FROM entities WHERE kind=?"
      ).get(kind).n) + 1;
      for (const entity of entities || []) {
        writer.insert(entityProjection(kind, entity, ordinal++), entity);
      }
      const added = (entities || []).length;
      db.prepare(
        "INSERT INTO entity_counts(kind, count) VALUES(?, ?) " +
        "ON CONFLICT(kind) DO UPDATE SET count=entity_counts.count+excluded.count"
      ).run(kind, added);
      return added;
    });
  } finally {
    db.close();
  }
}

// #1104 (cross-upload password-spray detection). Deliberately its own op, not a parameter on the
// shared queryEntities: that function is load-bearing for forensicTimeline/superTimeline with many
// callers, and reordering its ordinal-ascending cursor for one new caller is disproportionate risk
// for a single-pass review. Newest-first (DESC) so a capped window keeps the observations nearest
// in time to the CURRENT import, not the oldest ones in the window.
function queryAuthObservationsWindow(dbPath, sinceMs, limit) {
  if (!existsSync(dbPath)) return { entities: [], truncated: false };
  const db = openDatabase(dbPath);
  try {
    const boundedLimit = Math.max(0, Math.min(200000, Math.floor(limit)));
    const countRow = db.prepare(
      "SELECT count(*) AS n FROM entities WHERE kind='authObservation' AND timestamp_ms>=?"
    ).get(sinceMs);
    const total = Number(countRow ? countRow.n : 0);
    const rows = db.prepare(
      "SELECT payload FROM entities WHERE kind='authObservation' AND timestamp_ms>=? " +
      "ORDER BY timestamp_ms DESC, row_id DESC LIMIT ?"
    ).all(sinceMs, boundedLimit);
    return {
      entities: rows.map((row) => JSON.parse(row.payload)),
      truncated: total > boundedLimit,
    };
  } finally {
    db.close();
  }
}

// #1104. Bounds a kind's stored row count to a rolling window instead of the life of the case.
// entity_values cascades on DELETE (schema FK); only entity_counts needs an explicit decrement,
// by the statement's own reported change count — never assumed from the caller's candidate count.
function pruneEntitiesBefore(dbPath, kind, beforeMs) {
  if (!existsSync(dbPath)) return 0;
  const db = openDatabase(dbPath);
  try {
    return withTransaction(db, () => {
      const result = db.prepare(
        "DELETE FROM entities WHERE kind=? AND timestamp_ms IS NOT NULL AND timestamp_ms<?"
      ).run(kind, beforeMs);
      const deleted = Number(result.changes || 0);
      if (deleted > 0) {
        db.prepare("UPDATE entity_counts SET count=max(count-?, 0) WHERE kind=?").run(deleted, kind);
      }
      return deleted;
    });
  } finally {
    db.close();
  }
}
` +
  SUPER_WORKER_SOURCE +
  SUPER_QUERY_WORKER_SOURCE +
  TERMS_WORKER_SOURCE +
  String.raw`

function integrity(dbPath) {
  if (!existsSync(dbPath)) return { ok: true, message: "missing" };
  const db = new DatabaseSync(dbPath, { readOnly: true });
  try {
    const row = db.prepare("PRAGMA integrity_check").get();
    const message = String((row && row.integrity_check) || "unknown");
    return { ok: message === "ok", message };
  } finally {
    db.close();
  }
}

function backupDatabase(dbPath, targetPath) {
  if (!existsSync(dbPath)) return false;
  mkdirSync(dirname(targetPath), { recursive: true });
  const temporary = targetPath + ".snapshot-" + randomUUID();
  try {
    rmSync(temporary, { force: true });
    const db = openDatabase(dbPath);
    try {
      const sourceCheck = db.prepare("PRAGMA quick_check").get();
      if (!sourceCheck || sourceCheck.quick_check !== "ok") {
        throw new Error("refusing to back up a case database that failed SQLite quick_check");
      }
      // VACUUM INTO produces a transactionally consistent, compact standalone database even when
      // a writer commits while the snapshot is running.
      db.prepare("VACUUM INTO ?").run(temporary);
    } finally {
      db.close();
    }
    const snapshot = new DatabaseSync(temporary, { readOnly: true });
    try {
      const snapshotCheck = snapshot.prepare("PRAGMA integrity_check").get();
      if (!snapshotCheck || snapshotCheck.integrity_check !== "ok") {
        throw new Error("SQLite backup failed integrity_check");
      }
    } finally {
      snapshot.close();
    }
    renameSync(temporary, targetPath);
    return true;
  } catch (error) {
    try { rmSync(temporary, { force: true }); } catch {}
    throw error;
  }
}

// #1454. A "-wal" beside a database nobody has open holds committed pages of THAT file (a read-only
// connection cannot checkpoint on close, and a crash skips it). Replaying it onto a different file
// renamed into place would corrupt the restore, so the old file absorbs it: opening and closing the
// old database checkpoints and deletes the sidecars. Only an old file that will not open leaves
// them to be removed by hand — by then the old file is already beyond recovery.
function foldLeftoverWal(targetPath) {
  const sidecars = [targetPath + "-wal", targetPath + "-shm"];
  if (!sidecars.some((path) => existsSync(path))) return;
  try {
    const old = new DatabaseSync(targetPath);
    try { old.exec("PRAGMA wal_checkpoint(TRUNCATE)"); } finally { old.close(); }
  } catch {}
  for (const path of sidecars) {
    try { rmSync(path, { force: true }); } catch {}
  }
}

function restoreDatabase(sourcePath, targetPath) {
  if (!existsSync(sourcePath)) {
    const error = new Error("backup database does not exist");
    error.code = "ENOENT";
    throw error;
  }
  mkdirSync(dirname(targetPath), { recursive: true });
  const temporary = targetPath + ".restoring-" + randomUUID();
  try {
    const sourceCheck = integrity(sourcePath);
    if (!sourceCheck.ok) {
      throw new Error("backup database failed integrity_check: " + sourceCheck.message);
    }
    copyFileSync(sourcePath, temporary);
    const copyCheck = integrity(temporary);
    if (!copyCheck.ok) {
      throw new Error("restored database copy failed integrity_check: " + copyCheck.message);
    }
    // The pool runs this op exclusively (no reader holds the file), so renaming the checked copy
    // over the destination makes the authoritative file switch atomic without loading it into V8
    // memory. Any WAL beside the destination belongs to the OLD file and is folded in first.
    foldLeftoverWal(targetPath);
    renameSync(temporary, targetPath);
    return true;
  } catch (error) {
    try { rmSync(temporary, { force: true }); } catch {}
    throw error;
  }
}

async function dispatch(message) {
  switch (message.op) {
    case "ensureDatabase": return ensureDatabase(message.dbPath);
    case "stateExists": return stateExists(message.dbPath);
    case "migrateState": return migrateState(message.dbPath, message.jsonPath);
    case "loadState": return loadState(message.dbPath, message.excludedKinds);
    case "saveState": return saveState(message.dbPath, message.state);
    case "setStateCaseId": return setStateCaseId(message.dbPath, message.caseId);
    case "queryEntities": return queryEntities(message.dbPath, message.kind, message.query || {});
    case "hasEntityIds": return hasEntityIds(message.dbPath, message.kind, message.ids);
    case "entityCounts": return entityCounts(message.dbPath, message.kinds);
    case "appendEntities": return appendEntities(message.dbPath, message.kind, message.entities);
    case "queryAuthObservationsWindow": return queryAuthObservationsWindow(message.dbPath, message.sinceMs, message.limit);
    case "pruneEntitiesBefore": return pruneEntitiesBefore(message.dbPath, message.kind, message.beforeMs);
    case "migrateSuper": return migrateSuper(message.dbPath, message.eventsPath, message.labelsPath, message.tagsPath, message.excludeAuthorPrefix, message.max);
    case "appendSuper": return appendSuper(message.dbPath, message.events, message.max);
    case "scanSuper": return scanSuper(message.dbPath, message.query || {});
    case "querySuper": return querySuper(message.dbPath, message.query || {});
    case "getSuper": return getSuper(message.dbPath, message.id);
    case "setSuperLabels": return setSuperLabels(message.dbPath, message.eventId, message.labels);
    case "protectSuper": return protectSuper(message.dbPath, message.eventId);
    case "unprotectSuper": return unprotectSuper(message.dbPath, message.eventId, message.max);
    case "listSuperProtected": return listSuperProtected(message.dbPath);
    case "superMeta": return superMeta(message.dbPath, message.hosts);
    case "iocCandidates": return iocCandidates(message.dbPath, message.keys, message.ids);
    case "integrity": return integrity(message.dbPath);
    case "backupDatabase": return backupDatabase(message.dbPath, message.targetPath);
    case "restoreDatabase": return restoreDatabase(message.sourcePath, message.targetPath);
    default: throw new Error("unknown SQLite worker operation: " + message.op);
  }
}

parentPort.on("message", async (message) => {
  try {
    parentPort.postMessage({ requestId: message.requestId, value: await dispatch(message) });
  } catch (error) {
    parentPort.postMessage({
      requestId: message.requestId,
      error: {
        name: error && error.name ? error.name : "Error",
        message: error && error.message ? error.message : String(error),
        code: error && error.code,
        stack: error && error.stack,
      },
    });
  }
});
`;

export const caseSqliteWorker = new CaseSqliteWorkerPool(WORKER_SOURCE);
