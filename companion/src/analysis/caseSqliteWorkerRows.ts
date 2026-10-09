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
// field and a JSON null both read as null. Without keys, only ids and row ids are read. Array rows
// ([row_id, entity_id, k]), not objects: about twice as fast on a 20k-row timeline (#1887).
function outlineRows(db, withKeys) {
  const out = { rowIds: [], ids: [], timestamps: [], descriptions: [], severities: [] };
  const sql = withKeys
    ? "SELECT row_id, entity_id, json_extract(payload, '$.timestamp', '$.description', '$.severity') AS k " +
      "FROM entities WHERE kind='forensicTimeline' ORDER BY ordinal"
    : "SELECT row_id, entity_id FROM entities WHERE kind='forensicTimeline' ORDER BY ordinal";
  const stmt = db.prepare(sql);
  stmt.setReturnArrays(true);
  for (const row of stmt.iterate()) {
    out.rowIds.push(Number(row[0]));
    out.ids.push(row[1]);
    if (!withKeys) continue;
    const k = JSON.parse(row[2]);
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
// outline, so no write can land between the snapshot and the start of journaling. With a facts
// stamp (#1874) the outline is ids only and the forensic rows whose facts are unknown come with it
// (null: every row) — the settle's timeline diff reads keys for only those and the rows the import
// changed (routes/importSettleDiff.ts).
function captureImportBaseline(dbPath, token, factsStamp) {
  if (!existsSync(dbPath)) return null;
  const db = openDatabase(dbPath);
  try {
    return withTransaction(db, () => {
      if (typeof token === "string" && token) {
        db.exec("DELETE FROM import_journal; DELETE FROM import_journal_ioc; DELETE FROM import_journal_arm;");
        db.prepare("INSERT INTO import_journal_arm(token) VALUES (?)").run(token);
      }
      if (typeof factsStamp !== "string") {
        return { overview: readState(db, ["forensicTimeline"]), outline: outlineRows(db, true) };
      }
      // Every row the case holds now has a row id at most this; a journaled row above it is one the
      // import inserted, which no reader of the journal wants (a pre-import row is what they compare).
      const fence = Number(db.prepare("SELECT COALESCE(MAX(row_id), 0) AS m FROM entities").get().m);
      // The IOCs as ids in order, not the list (#1874): the IOC journal holds what the import changes.
      const overview = readState(db, ["forensicTimeline", "iocs"]);
      const outline = outlineRows(db, false);
      return { overview, outline, unfresh: factsUnfresh(db, factsStamp), fence, iocOutline: iocOutlineRows(db) };
    });
  } finally {
    db.close();
  }
}

function armedToken(db) {
  const row = db.prepare("SELECT token FROM import_journal_arm LIMIT 1").get();
  return row ? row.token : null;
}

function readImportJournal(dbPath, token, fence) {
  if (!existsSync(dbPath)) return null;
  const db = openDatabase(dbPath);
  try {
    if (armedToken(db) !== token) return null;
    const upTo = typeof fence === "number" ? fence : Number.MAX_SAFE_INTEGER;
    return db.prepare("SELECT row_id, entity_id, payload FROM import_journal WHERE row_id <= ? ORDER BY row_id").all(upTo)
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
      db.exec("DELETE FROM import_journal_arm; DELETE FROM import_journal; DELETE FROM import_journal_ioc;");
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

// Each distinct forensic host with the ordinal of its first row, in that order (#1874): what the
// host-duplicate check needs, from the (kind, host, ordinal) index instead of every row.
function forensicHostsInOrder(dbPath) {
  if (!existsSync(dbPath)) return [];
  const db = openDatabase(dbPath);
  try {
    return db.prepare(
      "SELECT host, MIN(ordinal) AS first FROM entities WHERE kind='forensicTimeline' AND host IS NOT NULL " +
      "GROUP BY host ORDER BY first"
    ).all().map((row) => row.host);
  } finally {
    db.close();
  }
}

function updateEntityRows(dbPath, kind, rows) {
  refuseSuperRows("updateEntityRows", kind);
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
        if (kind === "forensicTimeline") carryMergeIndex(db, row.rowId, Number(stored.version), stored.payload, prior, row.entity);
        out.updated++;
      }
      return out;
    });
  } finally {
    db.close();
  }
}

// Super-timeline rows change only through the super ops (caseSqliteWorkerSuper.ts), which write the
// content stamp a cached full-scan result depends on (#1881).
function refuseSuperRows(op, kind) {
  if (kind === "superTimeline") throw new Error(op + " does not write superTimeline rows; use the super-timeline ops");
}

function deleteEntityRows(dbPath, kind, rowIds) {
  refuseSuperRows("deleteEntityRows", kind);
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

// #2060: one forensic row placed where a stable sort by event time (forensicSort.byEventTime) puts
// it, in one transaction, instead of a whole-case load, sort and save. A parseable time goes after
// the last row at or before it (ties keep the existing rows first); an unparseable one goes last.
// The neighbours come from the time index and the (kind, ordinal) key. With no free ordinal
// between them, the timeline is spread ORDINAL_GAP times wider, set-based as the merge does. Returns false
// when the case has no stored state yet, so the caller can create it.
function forensicInsertAfter(db, timeMs) {
  if (timeMs === null) {
    return Number(db.prepare("SELECT coalesce(max(ordinal), -1) AS n FROM entities WHERE kind='forensicTimeline'").get().n);
  }
  const last = db.prepare(
    "SELECT timestamp_ms AS t FROM entities WHERE kind='forensicTimeline' AND timestamp_ms<=? " +
    "ORDER BY timestamp_ms DESC LIMIT 1"
  ).get(timeMs);
  if (!last) return -1;
  return Number(db.prepare(
    "SELECT max(ordinal) AS n FROM entities WHERE kind='forensicTimeline' AND timestamp_ms=?"
  ).get(last.t).n);
}

function forensicInsertOrdinal(db, timeMs) {
  const prev = forensicInsertAfter(db, timeMs);
  const next = db.prepare("SELECT min(ordinal) AS n FROM entities WHERE kind='forensicTimeline' AND ordinal>?").get(prev).n;
  if (next === null || next === undefined) return prev < 0 ? 0 : prev + ORDINAL_GAP;
  return Number(next) - prev >= 2 ? Math.floor((prev + Number(next)) / 2) : null;
}

function spreadForensicOrdinals(db) {
  const top = Number(db.prepare("SELECT coalesce(max(ordinal), 0) AS n FROM entities WHERE kind='forensicTimeline'").get().n);
  // (o + 1) * ORDINAL_GAP, not o * ORDINAL_GAP: a row at ordinal 0 must get room in front of it too.
  if ((top + 2) * ORDINAL_GAP <= ORDINAL_MAX) {
    db.prepare("UPDATE entities SET ordinal=-ordinal-1 WHERE kind='forensicTimeline'").run();
    db.prepare("UPDATE entities SET ordinal=(-ordinal)*? WHERE kind='forensicTimeline'").run(ORDINAL_GAP);
    db.prepare("UPDATE entity_values SET ordinal=(ordinal+1)*? WHERE kind='forensicTimeline'").run(ORDINAL_GAP);
    return;
  }
  // Too wide to spread: renumber every row (i + 1) * ORDINAL_GAP, in its current order.
  const rows = db.prepare("SELECT row_id FROM entities WHERE kind='forensicTimeline' ORDER BY ordinal").all();
  db.prepare("UPDATE entities SET ordinal=-ordinal-1 WHERE kind='forensicTimeline'").run();
  const setRow = db.prepare("UPDATE entities SET ordinal=? WHERE row_id=?");
  const setValues = db.prepare("UPDATE entity_values SET ordinal=? WHERE row_id=?");
  rows.forEach((row, i) => {
    setRow.run((i + 1) * ORDINAL_GAP, row.row_id);
    setValues.run((i + 1) * ORDINAL_GAP, row.row_id);
  });
}

function insertForensicInOrder(dbPath, entity, updatedAt) {
  if (!existsSync(dbPath)) return false;
  const db = openDatabase(dbPath);
  try {
    return withTransaction(db, () => {
      const metaRow = db.prepare("SELECT value FROM storage_meta WHERE key='investigation'").get();
      if (!metaRow) return false;
      const timeMs = entityProjection("forensicTimeline", entity, 0).timestampMs;
      let ordinal = forensicInsertOrdinal(db, timeMs);
      if (ordinal === null) {
        spreadForensicOrdinals(db);
        ordinal = forensicInsertOrdinal(db, timeMs);
      }
      createEntityWriter(db).insert(entityProjection("forensicTimeline", entity, ordinal), entity);
      db.prepare(
        "INSERT INTO entity_counts(kind, count) VALUES('forensicTimeline', 1) " +
        "ON CONFLICT(kind) DO UPDATE SET count=entity_counts.count+1"
      ).run();
      if (typeof updatedAt === "string") {
        const meta = JSON.parse(metaRow.value);
        meta.updatedAt = updatedAt;
        db.prepare("UPDATE storage_meta SET value=? WHERE key='investigation'").run(JSON.stringify(meta));
      }
      return true;
    });
  } finally {
    db.close();
  }
}

function dispatchRows(message) {
  switch (message.op) {
    case "forensicOutline": return forensicOutline(message.dbPath, message.withKeys);
    case "captureImportBaseline": return captureImportBaseline(message.dbPath, message.token, message.factsStamp);
    case "readImportJournal": return readImportJournal(message.dbPath, message.token, message.fence);
    case "disarmImportJournal": return disarmImportJournal(message.dbPath, message.token);
    case "entityRows": return entityRows(message.dbPath, message.kind, message.ids, message.rowIds);
    case "forensicRowsOutsideSeverities": return forensicRowsOutsideSeverities(message.dbPath, message.keep);
    case "distinctHosts": return distinctHosts(message.dbPath, message.kind);
    case "forensicHostsInOrder": return forensicHostsInOrder(message.dbPath);
    case "updateEntityRows": return updateEntityRows(message.dbPath, message.kind, message.rows);
    case "deleteEntityRows": return deleteEntityRows(message.dbPath, message.kind, message.rowIds);
    case "patchStateMeta": return patchStateMeta(message.dbPath, message.patch);
    case "insertForensicInOrder": return insertForensicInOrder(message.dbPath, message.entity, message.updatedAt);
    default: return dispatchFacts(message); // caseSqliteWorkerFacts.ts
  }
}
`;
