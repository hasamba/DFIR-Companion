import { Worker } from "node:worker_threads";
import { loadDatabaseSync } from "./sqliteRuntime.js";

// node:sqlite is synchronous. Keeping the entire database lifecycle in this worker prevents a
// checkpoint, migration, large import, or integrity check from pinning Express/WebSocket work on
// the main event loop. The worker opens a database only for one transaction/query and closes it
// before replying, which also leaves a checkpointed single-file database for backups and exports.
const WORKER_SOURCE = String.raw`
const { parentPort } = require("node:worker_threads");
const { copyFileSync, existsSync, mkdirSync, readFileSync, renameSync, rmSync } = require("node:fs");
const { dirname } = require("node:path");
const { randomUUID } = require("node:crypto");

const DatabaseSync = process.getBuiltinModule("node:sqlite").DatabaseSync;
const ARRAY_KINDS = [
  "findings", "iocs", "openThreads", "timeline", "forensicTimeline", "mitreTechniques",
  "keyQuestions", "nextSteps", "uncertainties", "iocExcludeRules"
];
const SCHEMA_VERSION = 1;

function openDatabase(path) {
  mkdirSync(dirname(path), { recursive: true });
  const db = new DatabaseSync(path, { enableForeignKeyConstraints: true });
  db.exec("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=10000;");
  db.exec(
    "CREATE TABLE IF NOT EXISTS storage_meta (" +
      "key TEXT PRIMARY KEY, value TEXT NOT NULL" +
    ");" +
    "CREATE TABLE IF NOT EXISTS entities (" +
      "row_id INTEGER PRIMARY KEY," +
      "kind TEXT NOT NULL," +
      "entity_id TEXT," +
      "ordinal INTEGER NOT NULL," +
      "version INTEGER NOT NULL DEFAULT 1," +
      "timestamp TEXT," +
      "timestamp_ms INTEGER," +
      "host TEXT," +
      "source TEXT," +
      "severity TEXT," +
      "content_key TEXT," +
      "payload TEXT NOT NULL," +
      "UNIQUE(kind, ordinal)" +
    ");" +
    "CREATE INDEX IF NOT EXISTS entities_time_idx ON entities(kind, timestamp_ms, row_id);" +
    "CREATE INDEX IF NOT EXISTS entities_host_idx ON entities(kind, host);" +
    "CREATE INDEX IF NOT EXISTS entities_source_idx ON entities(kind, source);" +
    "CREATE INDEX IF NOT EXISTS entities_severity_idx ON entities(kind, severity);" +
    "CREATE INDEX IF NOT EXISTS entities_id_idx ON entities(kind, entity_id);" +
    "CREATE INDEX IF NOT EXISTS entities_content_idx ON entities(kind, content_key);" +
    "CREATE TABLE IF NOT EXISTS entity_counts (" +
      "kind TEXT PRIMARY KEY," +
      "count INTEGER NOT NULL" +
    ");" +
    "CREATE TABLE IF NOT EXISTS entity_values (" +
      "row_id INTEGER NOT NULL REFERENCES entities(row_id) ON DELETE CASCADE," +
      "name TEXT NOT NULL," +
      "value TEXT NOT NULL," +
      "kind TEXT NOT NULL," +
      "host TEXT," +
      "ordinal INTEGER NOT NULL," +
      "PRIMARY KEY(row_id, name, value)" +
    ");" +
    "CREATE INDEX IF NOT EXISTS entity_values_lookup_idx " +
      "ON entity_values(name, value, kind, ordinal, row_id);" +
    "CREATE INDEX IF NOT EXISTS entity_values_host_lookup_idx " +
      "ON entity_values(name, value, kind, host, ordinal, row_id);" +
    "CREATE TABLE IF NOT EXISTS super_labels (" +
      "event_id TEXT NOT NULL," +
      "label TEXT NOT NULL," +
      "PRIMARY KEY(event_id, label)" +
    ");" +
    "PRAGMA user_version=" + SCHEMA_VERSION + ";"
  );
  return db;
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
    const totalClause = where.join(" AND ");
    let total = -1;
    if (!(query && query.includeTotal === false)) {
      const hasEntityOnlyFilters = !!(
        (query && typeof query.source === "string" && query.source) ||
        (query && typeof query.severity === "string" && query.severity) ||
        (query && typeof query.entityId === "string" && query.entityId) ||
        validFrom || validTo
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

function superContentKey(event) {
  const description = String((event && event.description) || "")
    .replace(/\s*\[corroborated by \d+ sources?:[^\]]*\]\s*$/i, "").trim();
  const host = (event && event.asset) || "(no host)";
  return String((event && event.timestamp) || "") + " " + description + " " + host;
}

function writeSuperEvents(db, events, max) {
  return withTransaction(db, () => {
    const writer = createEntityWriter(db);
    const incoming = events || [];
    const incomingIds = [...new Set(incoming.map((event) => scalarText(event && event.id)).filter(Boolean))];
    const incomingContent = [...new Set(incoming.map(superContentKey))];
    const existingIds = incomingIds.length
      ? new Set(db.prepare(
        "SELECT entity_id FROM entities WHERE kind='superTimeline' " +
        "AND entity_id IN (SELECT value FROM json_each(?))"
      ).all(JSON.stringify(incomingIds)).map((row) => row.entity_id))
      : new Set();
    const existingContent = incomingContent.length
      ? new Set(db.prepare(
        "SELECT content_key FROM entities WHERE kind='superTimeline' " +
        "AND content_key IN (SELECT value FROM json_each(?))"
      ).all(JSON.stringify(incomingContent)).map((row) => row.content_key))
      : new Set();
    let ordinal = Number(db.prepare(
      "SELECT coalesce(max(ordinal), -1) AS n FROM entities WHERE kind='superTimeline'"
    ).get().n) + 1;
    let added = 0;
    const seenIds = new Set();
    const seenContent = new Set();
    for (const event of incoming) {
      const id = scalarText(event && event.id);
      const contentKey = superContentKey(event);
      if ((id && (seenIds.has(id) || existingIds.has(id))) ||
          seenContent.has(contentKey) || existingContent.has(contentKey)) continue;
      if (id) seenIds.add(id);
      seenContent.add(contentKey);
      writer.insert(entityProjection("superTimeline", event, ordinal++, contentKey), event);
      added++;
    }
    const cap = Number.isFinite(max) ? Math.max(0, Math.floor(max)) : 100000;
    const count = Number(db.prepare("SELECT count(*) AS n FROM entities WHERE kind='superTimeline'").get().n);
    if (count > cap) {
      const remove = count - cap;
      db.prepare(
        "DELETE FROM entities WHERE row_id IN (" +
          "SELECT row_id FROM entities WHERE kind='superTimeline' " +
          "ORDER BY coalesce(timestamp_ms, -9007199254740991), row_id LIMIT ?" +
        ")"
      ).run(remove);
      db.prepare(
        "DELETE FROM super_labels WHERE event_id NOT IN " +
        "(SELECT entity_id FROM entities WHERE kind='superTimeline' AND entity_id IS NOT NULL)"
      ).run();
    }
    db.prepare(
      "INSERT INTO entity_counts(kind, count) VALUES('superTimeline', ?) " +
      "ON CONFLICT(kind) DO UPDATE SET count=excluded.count"
    ).run(Math.min(count, cap));
    return added;
  });
}

function migrateSuper(dbPath, eventsPath, labelsPath, max) {
  const db = openDatabase(dbPath);
  try {
    if (db.prepare("SELECT 1 AS x FROM storage_meta WHERE key='super_migrated'").get()) return;
    let events = [];
    let labels = {};
    try {
      const parsed = JSON.parse(readFileSync(eventsPath, "utf8"));
      if (Array.isArray(parsed)) events = parsed;
    } catch {}
    try {
      const parsed = JSON.parse(readFileSync(labelsPath, "utf8"));
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) labels = parsed;
    } catch {}
    writeSuperEvents(db, events, max);
    withTransaction(db, () => {
      const labelStatement = db.prepare("INSERT OR IGNORE INTO super_labels(event_id, label) VALUES(?, ?)");
      for (const [id, values] of Object.entries(labels)) {
        for (const label of Array.isArray(values) ? values : []) {
          if (typeof label === "string" && label.trim()) labelStatement.run(id, label.trim());
        }
      }
      db.prepare("INSERT INTO storage_meta(key,value) VALUES('super_migrated','1')").run();
    });
  } finally {
    db.close();
  }
}

function appendSuper(dbPath, events, max) {
  const db = openDatabase(dbPath);
  try { return writeSuperEvents(db, events, max); } finally { db.close(); }
}

function scanSuper(dbPath, query) {
  if (!existsSync(dbPath)) return { rows: [], nextCursor: null };
  const db = openDatabase(dbPath);
  try {
    const where = ["e.kind='superTimeline'"];
    const params = [];
    if (query && typeof query.from === "string" && Number.isFinite(Date.parse(query.from))) {
      where.push("(e.timestamp_ms IS NULL OR e.timestamp_ms>=?)");
      params.push(Date.parse(query.from));
    }
    if (query && typeof query.to === "string" && Number.isFinite(Date.parse(query.to))) {
      where.push("(e.timestamp_ms IS NULL OR e.timestamp_ms<=?)");
      params.push(Date.parse(query.to));
    }
    const afterMs = query && Number.isFinite(query.afterMs) ? query.afterMs : -9007199254740992;
    const afterRowId = query && Number.isFinite(query.afterRowId) ? query.afterRowId : 0;
    where.push("(coalesce(e.timestamp_ms, -9007199254740991)>? OR " +
      "(coalesce(e.timestamp_ms, -9007199254740991)=? AND e.row_id>?))");
    params.push(afterMs, afterMs, afterRowId);
    const limit = Math.max(1, Math.min(10000, Math.floor((query && query.limit) || 1000)));
    const rows = db.prepare(
      "SELECT e.row_id, coalesce(e.timestamp_ms, -9007199254740991) AS sort_ms, e.payload, " +
      "CASE WHEN count(l.label)=0 THEN '[]' ELSE json_group_array(l.label) END AS labels " +
      "FROM entities e LEFT JOIN super_labels l ON l.event_id=e.entity_id " +
      "WHERE " + where.join(" AND ") + " GROUP BY e.row_id " +
      "ORDER BY sort_ms, e.row_id LIMIT ?"
    ).all(...params, limit + 1);
    const hasMore = rows.length > limit;
    const pageRows = hasMore ? rows.slice(0, limit) : rows;
    const mapped = pageRows.map((row) => ({
      event: JSON.parse(row.payload),
      labels: JSON.parse(row.labels),
      rowId: row.row_id,
      sortMs: row.sort_ms,
    }));
    return {
      rows: mapped,
      nextCursor: hasMore && mapped.length
        ? { afterMs: mapped[mapped.length - 1].sortMs, afterRowId: mapped[mapped.length - 1].rowId }
        : null,
    };
  } finally {
    db.close();
  }
}

function getSuper(dbPath, id) {
  if (!existsSync(dbPath)) return null;
  const db = openDatabase(dbPath);
  try {
    const row = db.prepare(
      "SELECT payload FROM entities WHERE kind='superTimeline' AND entity_id=? ORDER BY ordinal LIMIT 1"
    ).get(id);
    return row ? JSON.parse(row.payload) : null;
  } finally {
    db.close();
  }
}

function setSuperLabels(dbPath, eventId, labels) {
  const db = openDatabase(dbPath);
  try {
    withTransaction(db, () => {
      db.prepare("DELETE FROM super_labels WHERE event_id=?").run(eventId);
      const statement = db.prepare("INSERT OR IGNORE INTO super_labels(event_id,label) VALUES(?,?)");
      for (const label of [...new Set((labels || []).map((value) => String(value).trim()).filter(Boolean))]) {
        statement.run(eventId, label);
      }
    });
  } finally {
    db.close();
  }
}

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
    // The worker serializes all case-database operations. Renaming the checked copy over the
    // destination makes the authoritative file switch atomic without loading it into V8 memory.
    renameSync(temporary, targetPath);
    return true;
  } catch (error) {
    try { rmSync(temporary, { force: true }); } catch {}
    throw error;
  }
}

async function dispatch(message) {
  switch (message.op) {
    case "stateExists": return stateExists(message.dbPath);
    case "migrateState": return migrateState(message.dbPath, message.jsonPath);
    case "loadState": return loadState(message.dbPath, message.excludedKinds);
    case "saveState": return saveState(message.dbPath, message.state);
    case "setStateCaseId": return setStateCaseId(message.dbPath, message.caseId);
    case "queryEntities": return queryEntities(message.dbPath, message.kind, message.query || {});
    case "hasEntityIds": return hasEntityIds(message.dbPath, message.kind, message.ids);
    case "entityCounts": return entityCounts(message.dbPath, message.kinds);
    case "appendEntities": return appendEntities(message.dbPath, message.kind, message.entities);
    case "migrateSuper": return migrateSuper(message.dbPath, message.eventsPath, message.labelsPath, message.max);
    case "appendSuper": return appendSuper(message.dbPath, message.events, message.max);
    case "scanSuper": return scanSuper(message.dbPath, message.query || {});
    case "getSuper": return getSuper(message.dbPath, message.id);
    case "setSuperLabels": return setSuperLabels(message.dbPath, message.eventId, message.labels);
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

interface WorkerError {
  name: string;
  message: string;
  code?: string;
  stack?: string;
}

interface WorkerReply<T> {
  requestId: number;
  value?: T;
  error?: WorkerError;
}

type PendingRequest = {
  resolve: (value: unknown) => void;
  reject: (error: Error) => void;
};

class CaseSqliteWorker {
  private worker: Worker | null = null;
  private nextId = 1;
  private readonly pending = new Map<number, PendingRequest>();

  request<T>(message: Record<string, unknown>): Promise<T> {
    const worker = this.ensureWorker();
    const id = this.nextId++;
    worker.ref();
    return new Promise<T>((resolve, reject) => {
      this.pending.set(id, {
        resolve: (value) => resolve(value as T),
        reject,
      });
      worker.postMessage({ ...message, requestId: id });
    });
  }

  private ensureWorker(): Worker {
    if (this.worker) return this.worker;
    // Validate through the shared runtime accessor before constructing the worker. This keeps the
    // startup error actionable and preserves the bundler/SEA-safe node:sqlite loading seam.
    loadDatabaseSync();
    const worker = new Worker(WORKER_SOURCE, { eval: true });
    worker.on("message", (reply: WorkerReply<unknown>) => this.onReply(reply));
    worker.on("error", (error) => this.failAll(error));
    worker.on("exit", (code) => {
      if (code !== 0) this.failAll(new Error(`SQLite worker exited with code ${code}`));
      this.worker = null;
    });
    worker.unref();
    this.worker = worker;
    return worker;
  }

  private onReply(reply: WorkerReply<unknown>): void {
    const pending = this.pending.get(reply.requestId);
    if (!pending) return;
    this.pending.delete(reply.requestId);
    if (reply.error) {
      const error = new Error(reply.error.message);
      error.name = reply.error.name;
      if (reply.error.code) (error as NodeJS.ErrnoException).code = reply.error.code;
      if (reply.error.stack) error.stack = reply.error.stack;
      pending.reject(error);
    } else {
      pending.resolve(reply.value);
    }
    if (this.pending.size === 0) this.worker?.unref();
  }

  private failAll(error: Error): void {
    for (const pending of this.pending.values()) pending.reject(error);
    this.pending.clear();
  }
}

export const caseSqliteWorker = new CaseSqliteWorker();
