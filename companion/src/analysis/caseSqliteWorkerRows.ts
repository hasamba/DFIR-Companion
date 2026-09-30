// Targeted row operations of the case SQLite worker (#1874). Spliced into caseSqliteWorker.ts's
// WORKER_SOURCE as plain text, so everything here runs inside the worker thread with that file's
// helpers in scope (openDatabase, withTransaction, readState, entityProjection, createEntityWriter,
// existsSync). Keep it backtick-free: the fragment is a String.raw template.
//
// An import's settle phase used to load the whole case, change a few rows, and save the whole case
// again, five or six times per import. These ops let it read and write only the rows it changes:
//
//  - an UPDATE keeps the row's row_id and ordinal (a settle step never moves a row in time), and
//    goes through the same writer as a full save, so entity_values and the FTS term index follow;
//  - it is refused for a row whose version moved since it was read (a writer that does not share
//    the state lock changed it) or whose id no longer matches, so it never overwrites what it did
//    not read;
//  - a DELETE is by row id, so a duplicate id elsewhere in the table is never touched; entity_values
//    cascade and the FTS row goes with the delete trigger; entity_counts drops by what was deleted.
//
// The import journal (tables and triggers in caseSqliteSchema.ts) records the pre-import image of
// every forensic row an UPDATE or DELETE touches while an import section holds it armed. That is
// what the undo checkpoint and "which old rows did this import touch" are computed from, instead of
// a full copy of the case held for the whole import.
export const ROWS_WORKER_SOURCE = String.raw`
// One multi-path json_extract returns the three fields as a JSON array, so each keeps its JSON type
// (a string stays a string, an object an object) exactly as a full load would parse it. A missing
// field and a JSON null both read as null. Without keys, only ids and row ids are read.
function outlineRows(db, withKeys) {
  const out = { rowIds: [], ids: [], timestamps: [], descriptions: [], severities: [] };
  const sql = withKeys
    ? "SELECT row_id, entity_id, json_extract(payload, '$.timestamp', '$.description', '$.severity') AS k " +
      "FROM entities WHERE kind='forensicTimeline' ORDER BY ordinal"
    : "SELECT row_id, entity_id FROM entities WHERE kind='forensicTimeline' ORDER BY ordinal";
  for (const row of db.prepare(sql).iterate()) {
    out.rowIds.push(Number(row.row_id));
    out.ids.push(row.entity_id);
    if (!withKeys) continue;
    const k = JSON.parse(row.k);
    out.timestamps.push(k[0]);
    out.descriptions.push(k[1]);
    out.severities.push(k[2]);
  }
  return out;
}

function forensicOutline(dbPath, withKeys) {
  if (!existsSync(dbPath)) return null;
  const db = openDatabase(dbPath);
  try { return outlineRows(db, withKeys !== false); } finally { db.close(); }
}

// One transaction: arm the journal (when a token is given), then read the overview and the
// outline, so no write can land between the snapshot and the start of journaling.
function captureImportBaseline(dbPath, token) {
  if (!existsSync(dbPath)) return null;
  const db = openDatabase(dbPath);
  try {
    return withTransaction(db, () => {
      if (typeof token === "string" && token) {
        db.exec("DELETE FROM import_journal; DELETE FROM import_journal_arm;");
        db.prepare("INSERT INTO import_journal_arm(token) VALUES (?)").run(token);
      }
      const overview = readState(db, ["forensicTimeline"]);
      return { overview, outline: outlineRows(db, true) };
    });
  } finally {
    db.close();
  }
}

function armedToken(db) {
  const row = db.prepare("SELECT token FROM import_journal_arm LIMIT 1").get();
  return row ? row.token : null;
}

function readImportJournal(dbPath, token) {
  if (!existsSync(dbPath)) return null;
  const db = openDatabase(dbPath);
  try {
    if (armedToken(db) !== token) return null;
    return db.prepare("SELECT row_id, entity_id, payload FROM import_journal ORDER BY row_id").all()
      .map((row) => ({ rowId: Number(row.row_id), entityId: row.entity_id, payload: JSON.parse(row.payload) }));
  } finally {
    db.close();
  }
}

function disarmImportJournal(dbPath, token) {
  if (!existsSync(dbPath)) return false;
  const db = openDatabase(dbPath);
  try {
    return withTransaction(db, () => {
      if (armedToken(db) !== token) return false;
      db.exec("DELETE FROM import_journal_arm; DELETE FROM import_journal;");
      return true;
    });
  } finally {
    db.close();
  }
}

function toRow(row) {
  return { rowId: Number(row.row_id), version: Number(row.version), entity: JSON.parse(row.payload) };
}

function entityRows(dbPath, kind, ids, rowIds) {
  if (!existsSync(dbPath)) return [];
  const db = openDatabase(dbPath);
  try {
    if (Array.isArray(rowIds)) {
      return db.prepare(
        "SELECT row_id, version, payload FROM entities WHERE kind=? " +
        "AND row_id IN (SELECT value FROM json_each(?)) ORDER BY ordinal"
      ).all(kind, JSON.stringify(rowIds)).map(toRow);
    }
    return db.prepare(
      "SELECT row_id, version, payload FROM entities WHERE kind=? " +
      "AND entity_id IN (SELECT value FROM json_each(?)) ORDER BY ordinal"
    ).all(kind, JSON.stringify(Array.isArray(ids) ? ids : [])).map(toRow);
  } finally {
    db.close();
  }
}

// Rows whose severity is missing or outside the kept set, in timeline order. The severity index
// answers the filter; only the matching rows' payloads are read.
function forensicRowsOutsideSeverities(dbPath, keep) {
  if (!existsSync(dbPath)) return [];
  const db = openDatabase(dbPath);
  try {
    return db.prepare(
      "SELECT row_id, version, payload FROM entities WHERE kind='forensicTimeline' " +
      "AND (severity IS NULL OR severity NOT IN (SELECT value FROM json_each(?))) ORDER BY ordinal"
    ).all(JSON.stringify(Array.isArray(keep) ? keep : [])).map(toRow);
  } finally {
    db.close();
  }
}

function distinctHosts(dbPath, kind) {
  if (!existsSync(dbPath)) return [];
  const db = openDatabase(dbPath);
  try {
    return db.prepare("SELECT DISTINCT host FROM entities WHERE kind=? AND host IS NOT NULL")
      .all(kind).map((row) => row.host);
  } finally {
    db.close();
  }
}

function updateEntityRows(dbPath, kind, rows) {
  const out = { updated: 0, missing: [], conflicts: [] };
  if (!existsSync(dbPath)) {
    for (const row of rows || []) out.missing.push(row.rowId);
    return out;
  }
  const db = openDatabase(dbPath);
  try {
    return withTransaction(db, () => {
      const writer = createEntityWriter(db);
      const read = db.prepare(
        "SELECT entity_id, ordinal, version, timestamp, host, payload FROM entities WHERE row_id=? AND kind=?"
      );
      const rewriteRow = db.prepare(
        "UPDATE entities SET version=version+1, source=?, severity=?, content_key=?, payload=? WHERE row_id=?"
      );
      for (const row of rows || []) {
        const stored = read.get(row.rowId, kind);
        if (!stored) { out.missing.push(row.rowId); continue; }
        const projection = entityProjection(kind, row.entity, Number(stored.ordinal));
        // A version that moved, an id that changed, or a new timestamp (the row would belong at a
        // different ordinal) is refused: the caller re-reads, or leaves the row alone.
        if ((Number.isFinite(row.version) && Number(stored.version) !== row.version) ||
            stored.entity_id !== projection.entityId || stored.timestamp !== projection.timestamp) {
          out.conflicts.push(row.rowId);
          continue;
        }
        if (stored.payload === projection.payload) continue;
        // A settle change (a stamp, a grade) usually leaves every indexed value and every term as
        // it was: then only the row itself is rewritten, not its value-index and FTS entries.
        const prior = JSON.parse(stored.payload);
        if (stored.host === projection.host &&
            JSON.stringify(indexValues(kind, prior)) === JSON.stringify(indexValues(kind, row.entity)) &&
            (!indexesTerms(kind) || eventTermsText(prior) === eventTermsText(row.entity))) {
          rewriteRow.run(projection.source, projection.severity, projection.contentKey, projection.payload, row.rowId);
        } else {
          writer.update(row.rowId, projection, row.entity);
        }
        out.updated++;
      }
      return out;
    });
  } finally {
    db.close();
  }
}

function deleteEntityRows(dbPath, kind, rowIds) {
  if (!existsSync(dbPath) || !Array.isArray(rowIds) || !rowIds.length) return 0;
  const db = openDatabase(dbPath);
  try {
    return withTransaction(db, () => {
      const deleted = Number(db.prepare(
        "DELETE FROM entities WHERE kind=? AND row_id IN (SELECT value FROM json_each(?))"
      ).run(kind, JSON.stringify(rowIds)).changes || 0);
      if (deleted > 0) {
        db.prepare("UPDATE entity_counts SET count=max(count-?, 0) WHERE kind=?").run(deleted, kind);
      }
      return deleted;
    });
  } finally {
    db.close();
  }
}

// Merge top-level fields into the stored case metadata. Never touches an array kind.
function patchStateMeta(dbPath, patch) {
  if (!existsSync(dbPath)) return false;
  const db = openDatabase(dbPath);
  try {
    return withTransaction(db, () => {
      const row = db.prepare("SELECT value FROM storage_meta WHERE key='investigation'").get();
      if (!row) return false;
      const meta = JSON.parse(row.value);
      for (const [key, value] of Object.entries(patch || {})) {
        if (!ARRAY_KINDS.includes(key)) meta[key] = value;
      }
      db.prepare("UPDATE storage_meta SET value=? WHERE key='investigation'").run(JSON.stringify(meta));
      return true;
    });
  } finally {
    db.close();
  }
}

function dispatchRows(message) {
  switch (message.op) {
    case "forensicOutline": return forensicOutline(message.dbPath, message.withKeys);
    case "captureImportBaseline": return captureImportBaseline(message.dbPath, message.token);
    case "readImportJournal": return readImportJournal(message.dbPath, message.token);
    case "disarmImportJournal": return disarmImportJournal(message.dbPath, message.token);
    case "entityRows": return entityRows(message.dbPath, message.kind, message.ids, message.rowIds);
    case "forensicRowsOutsideSeverities": return forensicRowsOutsideSeverities(message.dbPath, message.keep);
    case "distinctHosts": return distinctHosts(message.dbPath, message.kind);
    case "updateEntityRows": return updateEntityRows(message.dbPath, message.kind, message.rows);
    case "deleteEntityRows": return deleteEntityRows(message.dbPath, message.kind, message.rowIds);
    case "patchStateMeta": return patchStateMeta(message.dbPath, message.patch);
    default: throw new Error("unknown SQLite worker operation: " + message.op);
  }
}
`;
