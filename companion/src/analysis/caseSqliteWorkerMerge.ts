// The incremental merge's worker ops (#1874). Spliced into caseSqliteWorker.ts's WORKER_SOURCE as
// plain text, so everything here runs inside the worker thread with that file's helpers in scope
// (openDatabase, withTransaction, writeStateBody, entityProjection, createEntityWriter, existsSync).
// Keep it backtick-free and free of dollar-brace: the fragment is a String.raw template.
//
// The merge index (tables in caseSqliteSchema.ts) is one row per forensic row the importer merge
// wrote: its version, its time and year, its correlation bucket keys and its activity flags. A row is
// CLEAN while that version equals the stored row's version, i.e. nobody wrote the row since the merge
// that indexed it. Everything else is STALE and the merge reads it in full. These ops let the merge
// read only the rows a delta needs, and write only the rows it changed, in one checked transaction.
//
// merge_generation is bumped by triggers on every write to a forensic row, an IOC or the case
// metadata. The apply op refuses to write when it moved since the merge's first read, so a writer
// that does not share the state lock can never have its change overwritten by a merge that did not
// see it.
export const MERGE_WORKER_SOURCE = String.raw`
function mergeGeneration(db) {
  const row = db.prepare("SELECT n FROM merge_generation WHERE id=1").get();
  return row ? Number(row.n) : 0;
}

function readMergeMeta(db) {
  const row = db.prepare("SELECT value FROM storage_meta WHERE key='merge_index'").get();
  if (!row) return null;
  try { return JSON.parse(row.value); } catch { return null; }
}

function mergeFail(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

// Clean rows only: the index row's version is the stored row's version.
const CLEAN_JOIN = "JOIN merge_rows m ON m.row_id=e.row_id AND m.version=e.version";

// One read of everything the merge decides on before it fetches a payload.
function mergeSnapshot(dbPath) {
  if (!existsSync(dbPath)) return null;
  const db = openDatabase(dbPath);
  try {
    db.exec("BEGIN");
    try {
      if (!db.prepare("SELECT 1 AS x FROM storage_meta WHERE key='investigation'").get()) return null;
      const counts = db.prepare(
        "SELECT count(*) AS n, total((m.flags & 1) <> 0) AS t, total((m.flags & 2) <> 0) AS p, " +
        "total((m.flags & 4) <> 0) AS c, total((m.flags & 8) <> 0) AS l FROM entities e " + CLEAN_JOIN +
        " WHERE e.kind='forensicTimeline'"
      ).get();
      return {
        generation: mergeGeneration(db),
        meta: readMergeMeta(db),
        rowCount: Number(db.prepare(
          "SELECT count(*) AS n FROM entities WHERE kind='forensicTimeline'"
        ).get().n),
        stale: db.prepare(
          "SELECT e.row_id FROM entities e LEFT JOIN merge_rows m ON m.row_id=e.row_id " +
          "WHERE e.kind='forensicTimeline' AND (m.row_id IS NULL OR m.version<>e.version) ORDER BY e.ordinal"
        ).all().map((r) => Number(r.row_id)),
        clean: {
          rows: Number(counts.n), trigger: Number(counts.t), process: Number(counts.p),
          cloud: Number(counts.c), load: Number(counts.l),
        },
        years: db.prepare(
          "SELECT m.year AS year, count(*) AS n FROM entities e " + CLEAN_JOIN +
          " WHERE e.kind='forensicTimeline' AND m.year IS NOT NULL GROUP BY m.year"
        ).all().map((r) => [Number(r.year), Number(r.n)]),
        dirtyKeys: db.prepare("SELECT key FROM merge_dirty_keys").all().map((r) => r.key),
      };
    } finally {
      db.exec("ROLLBACK");
    }
  } finally {
    db.close();
  }
}

// The rows as the merge reads them, each with its index (one query for the index rows, one for the
// keys, whatever the number of rows).
function mergeRowsOut(db, rows) {
  if (!rows.length) return [];
  const ids = JSON.stringify(rows.map((row) => Number(row.row_id)));
  const index = new Map();
  for (const m of db.prepare(
    "SELECT row_id, version, time_ms, year, year_inferred, flags FROM merge_rows WHERE row_id IN (SELECT value FROM json_each(?))"
  ).iterate(ids)) {
    index.set(Number(m.row_id), {
      version: Number(m.version),
      timeMs: m.time_ms === null ? null : Number(m.time_ms),
      year: m.year === null ? null : Number(m.year),
      yearInferred: Number(m.year_inferred) === 1,
      flags: Number(m.flags),
      keys: [],
    });
  }
  for (const k of db.prepare(
    "SELECT row_id, key FROM merge_keys WHERE row_id IN (SELECT value FROM json_each(?))"
  ).iterate(ids)) {
    const entry = index.get(Number(k.row_id));
    if (entry) entry.keys.push(k.key);
  }
  return rows.map((row) => ({
    rowId: Number(row.row_id),
    ordinal: Number(row.ordinal),
    version: Number(row.version),
    payload: row.payload,
    index: index.get(Number(row.row_id)) || null,
  }));
}

// Forensic rows by row id, event id, bucket key, index flag (clean rows carrying one of the bits),
// or clamp year (clean rows on a guessed year other than the dominant one), in timeline order,
// never the rows named in excludeRowIds.
function mergeRows(dbPath, select) {
  if (!existsSync(dbPath)) return [];
  const db = openDatabase(dbPath);
  try {
    const cols = "SELECT e.row_id, e.ordinal, e.version, e.payload FROM entities e ";
    let rows = [];
    if (Array.isArray(select.rowIds)) {
      rows = db.prepare(cols + "WHERE e.kind='forensicTimeline' AND e.row_id IN (SELECT value FROM json_each(?)) ORDER BY e.ordinal")
        .all(JSON.stringify(select.rowIds));
    } else if (Array.isArray(select.ids)) {
      rows = db.prepare(cols + "WHERE e.kind='forensicTimeline' AND e.entity_id IN (SELECT value FROM json_each(?)) ORDER BY e.ordinal")
        .all(JSON.stringify(select.ids));
    } else if (Array.isArray(select.keys)) {
      rows = db.prepare(cols + "WHERE e.kind='forensicTimeline' AND e.row_id IN " +
        "(SELECT row_id FROM merge_keys WHERE key IN (SELECT value FROM json_each(?))) ORDER BY e.ordinal")
        .all(JSON.stringify(select.keys));
    } else if (typeof select.flagMask === "number") {
      rows = db.prepare(cols + CLEAN_JOIN + " WHERE e.kind='forensicTimeline' AND (m.flags & ?) <> 0 ORDER BY e.ordinal")
        .all(select.flagMask);
    } else if (typeof select.clampYear === "number") {
      rows = db.prepare(cols + CLEAN_JOIN + " WHERE e.kind='forensicTimeline' AND m.year_inferred=1 " +
        "AND m.year IS NOT NULL AND m.year<>? ORDER BY e.ordinal").all(select.clampYear);
    }
    const exclude = new Set(Array.isArray(select.excludeRowIds) ? select.excludeRowIds : []);
    return mergeRowsOut(db, rows.filter((row) => !exclude.has(Number(row.row_id))));
  } finally {
    db.close();
  }
}

// How many forensic rows carry each of these event ids.
function mergeIdCounts(dbPath, ids) {
  if (!existsSync(dbPath)) return {};
  const db = openDatabase(dbPath);
  try {
    const out = {};
    for (const row of db.prepare(
      "SELECT entity_id, count(*) AS n FROM entities WHERE kind='forensicTimeline' " +
      "AND entity_id IN (SELECT value FROM json_each(?)) GROUP BY entity_id"
    ).all(JSON.stringify(ids || []))) out[row.entity_id] = Number(row.n);
    return out;
  } finally {
    db.close();
  }
}

// The IOCs a delta's values could match (case-insensitively, or by alias-target id), in list order,
// plus the next canonical i### sequence over EVERY IOC. SQLite's lower() folds ASCII only, so every
// stored value with a character outside printable ASCII (or not a string at all) is returned too; the
// merge applies the exact test. Each branch reads one index (#1874; IOC indexes in caseSqliteSchema.ts,
// named because the planner would scan every IOC without ANALYZE statistics): an IOC whose id is a
// non-empty string has it as entity_id, and every other IOC is in the bad-id index.
function mergeIocCandidates(dbPath, lowered, aliasIds) {
  if (!existsSync(dbPath)) return { rows: [], nextSeq: 1 };
  const db = openDatabase(dbPath);
  try {
    const columns = "SELECT row_id, ordinal, version, payload FROM entities ";
    const byId = "json_extract(payload, '$.id') IN (SELECT value FROM json_each(?1))";
    const rows = db.prepare(
      columns + "INDEXED BY entities_id_idx WHERE kind='iocs' AND entity_id IN (SELECT value FROM json_each(?1)) AND " + byId +
      " UNION " + columns + "INDEXED BY entities_ioc_badid_idx WHERE " + IOC_BAD_ID_WHERE + " AND " + byId +
      " UNION " + columns + "INDEXED BY entities_ioc_value_idx WHERE kind='iocs' AND " +
      "lower(json_extract(payload, '$.value')) IN (SELECT value FROM json_each(?2))" +
      " UNION " + columns + "INDEXED BY entities_ioc_odd_idx WHERE " + IOC_ODD_VALUE_WHERE +
      " ORDER BY ordinal"
    ).all(JSON.stringify(aliasIds || []), JSON.stringify(lowered || []));
    return {
      rows: rows.map((r) => ({ rowId: Number(r.row_id), ordinal: Number(r.ordinal), version: Number(r.version), payload: r.payload })),
      nextSeq: nextIocSeq(db) + 1,
    };
  } finally {
    db.close();
  }
}

// The highest i<digits> IOC id, as a scan of every id with /^i(\d+)$/ and parseInt finds it. The seq
// index holds every IOC whose entity_id has that shape, highest number first; the first whose payload
// id is that entity_id (not a value standing in for a missing id) is the answer. A number past 2^53
// sorts first (SQLite's CAST saturates at 2^63) and sends it to the scan, where parseInt decides.
function nextIocSeq(db) {
  for (const row of db.prepare(
    "SELECT entity_id, json_extract(payload, '$.id') AS id " +
    "FROM entities INDEXED BY entities_ioc_seq_idx WHERE " + IOC_SEQ_WHERE + " ORDER BY CAST(substr(entity_id, 2) AS INTEGER) DESC"
  ).iterate()) {
    if (row.id !== row.entity_id) continue;
    const n = parseInt(row.id.slice(1), 10);
    if (Number.isSafeInteger(n)) return n;
    return fullIocSeqScan(db);
  }
  return 0;
}

function fullIocSeqScan(db) {
  let max = 0;
  for (const row of db.prepare("SELECT json_extract(payload, '$.id') AS id FROM entities WHERE kind='iocs'").iterate()) {
    const m = /^i(\d+)$/.exec(row.id);
    if (m) max = Math.max(max, parseInt(m[1], 10));
  }
  return max;
}

// IOCs whose extractedFrom cites one of these event ids, in list order.
function mergeIocsCiting(dbPath, eventIds) {
  if (!existsSync(dbPath)) return [];
  const db = openDatabase(dbPath);
  try {
    return db.prepare(
      "SELECT DISTINCT e.row_id, e.ordinal, e.version, e.payload FROM entities e, json_each(e.payload, '$.extractedFrom') j " +
      "WHERE e.kind='iocs' AND json_type(e.payload, '$.extractedFrom')='array' " +
      "AND j.value IN (SELECT value FROM json_each(?)) ORDER BY e.ordinal"
    ).all(JSON.stringify(eventIds || [])).map((r) => ({
      rowId: Number(r.row_id), ordinal: Number(r.ordinal), version: Number(r.version), payload: r.payload,
    }));
  } finally {
    db.close();
  }
}

// Index rows, in three set-based statements: entries are { rowId, index } with index.clean saying
// whether the row is written at its current version (clean) or at -1 (read again by every merge).
function writeMergeIndex(db, entries) {
  if (!entries.length) return;
  const json = JSON.stringify(entries.map((e) => ({
    rowId: e.rowId, clean: e.index.clean ? 1 : 0, timeMs: e.index.timeMs, year: e.index.year,
    yearInferred: e.index.yearInferred ? 1 : 0, flags: e.index.flags, keys: e.index.keys,
  })));
  db.prepare(
    "DELETE FROM merge_keys WHERE row_id IN (SELECT json_extract(value, '$.rowId') FROM json_each(?))"
  ).run(json);
  db.prepare(
    "INSERT INTO merge_rows(row_id, version, time_ms, year, year_inferred, flags) " +
    "SELECT json_extract(j.value, '$.rowId'), CASE WHEN json_extract(j.value, '$.clean') = 1 THEN e.version ELSE -1 END, " +
    "json_extract(j.value, '$.timeMs'), json_extract(j.value, '$.year'), json_extract(j.value, '$.yearInferred'), " +
    "json_extract(j.value, '$.flags') FROM json_each(?) j JOIN entities e ON e.row_id = json_extract(j.value, '$.rowId') WHERE true " +
    "ON CONFLICT(row_id) DO UPDATE SET version=excluded.version, time_ms=excluded.time_ms, year=excluded.year, " +
    "year_inferred=excluded.year_inferred, flags=excluded.flags"
  ).run(json);
  db.prepare(
    "INSERT OR IGNORE INTO merge_keys(key, row_id) SELECT k.value, json_extract(j.value, '$.rowId') " +
    "FROM json_each(?) j, json_each(j.value, '$.keys') k"
  ).run(json);
}

// Fields the merge never reads: no correlation pass, bucket key or flag looks at them. Settle stamps
// them on every row an import added, right after the merge wrote those rows.
const MERGE_UNREAD_FIELDS = ["importedAt", "importBatchId"];

function withoutUnreadFields(entity) {
  const copy = Object.assign({}, entity);
  for (const field of MERGE_UNREAD_FIELDS) delete copy[field];
  return JSON.stringify(copy);
}

// A targeted row write (settle, caseSqliteWorkerRows.ts) that changed only fields the merge never
// reads keeps the row's merge index current, so the next merge need not read the row again.
function carryMergeIndex(db, rowId, priorVersion, priorPayload, prior, next) {
  const index = db.prepare("SELECT version FROM merge_rows WHERE row_id=?").get(rowId);
  if (!index || Number(index.version) !== priorVersion) return;
  // A stored payload is JSON.stringify output, so without the fields it is already its own text.
  const unread = MERGE_UNREAD_FIELDS.some((field) => Object.prototype.hasOwnProperty.call(prior, field));
  if ((unread ? withoutUnreadFields(prior) : priorPayload) !== withoutUnreadFields(next)) return;
  db.prepare("UPDATE merge_rows SET version=(SELECT version FROM entities WHERE row_id=?) WHERE row_id=?").run(rowId, rowId);
}

// The stored rows may fold again on the next merge: that merge takes the full path, which writes
// the flag again. The stamp is kept, so an index from another build is still rebuilt whole.
function unsettleMergeIndex(db) {
  db.prepare(
    "UPDATE storage_meta SET value=json_set(value, '$.stable', json('false')) WHERE key='merge_index'"
  ).run();
}

function writeMergeMeta(db, meta) {
  db.prepare(
    "INSERT INTO storage_meta(key, value) VALUES('merge_index', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value"
  ).run(JSON.stringify(meta));
}

// Byte-for-byte the comparison byEventTime makes: a missing time sorts last, equal times keep order.
function mergeTimeCompare(a, b) {
  if (a === null && b === null) return 0;
  if (a === null) return 1;
  if (b === null) return -1;
  return a - b;
}

// Place the merge's rows among the rows it did not touch. Untouched rows keep their relative order
// (they are verified to be in time order: otherwise today's merge would re-sort them, and the merge
// refuses so the caller takes the full path). A placed row goes before an untouched one when its time
// is earlier, or equal with an earlier first appearance (the untouched row's is its ordinal) — the
// stable sort's rule. Untouched rows keep their ordinals, and the placed rows take free ordinals in the
// gaps between them; only when a gap is too small is the whole timeline respaced, with room left
// between every two rows, so an import into a large case moves no row it did not write. Ordinals are
// only ever an order (every reader sorts or pages by them), never a position.
function mergePlace(db, placed, deletedRowIds) {
  const placedIds = new Set();
  for (const p of placed) if (p.rowId !== undefined) placedIds.add(p.rowId);
  const untouched = [];
  let prev = undefined;
  for (const row of db.prepare(
    "SELECT e.row_id, e.ordinal, e.version, m.version AS mv, m.time_ms FROM entities e " +
    "LEFT JOIN merge_rows m ON m.row_id=e.row_id WHERE e.kind='forensicTimeline' ORDER BY e.ordinal"
  ).iterate()) {
    const rowId = Number(row.row_id);
    if (placedIds.has(rowId) || deletedRowIds.has(rowId)) continue;
    if (row.mv === null || Number(row.mv) !== Number(row.version)) {
      throw mergeFail("DFIR_MERGE_CONFLICT", "an untouched forensic row is not indexed");
    }
    const timeMs = row.time_ms === null ? null : Number(row.time_ms);
    if (prev !== undefined && mergeTimeCompare(prev, timeMs) > 0) {
      throw mergeFail("DFIR_MERGE_UNSORTED", "the stored forensic timeline is not in time order");
    }
    prev = timeMs;
    untouched.push({ rowId, ordinal: Number(row.ordinal), timeMs });
  }
  const sequence = [];
  let u = 0;
  for (const p of placed) {
    while (u < untouched.length) {
      const c = mergeTimeCompare(p.timeMs, untouched[u].timeMs);
      if (c < 0 || (c === 0 && p.pre < untouched[u].ordinal)) break;
      sequence.push(untouched[u++]);
    }
    sequence.push(p);
  }
  while (u < untouched.length) sequence.push(untouched[u++]);
  // A row's current ordinal: an untouched row carries it, a placed stored row is read back, a new
  // row has none.
  const readOrdinal = db.prepare("SELECT ordinal FROM entities WHERE row_id=?");
  const own = sequence.map((item) =>
    item.pre === undefined ? item.ordinal
      : item.rowId !== undefined ? Number(readOrdinal.get(item.rowId).ordinal) : undefined);
  // The next UNTOUCHED row's ordinal after each position: a placed row may keep its ordinal only
  // below it, so untouched rows never move unless the case must be respaced.
  const nextUntouched = new Array(sequence.length);
  let upcoming = undefined;
  for (let i = sequence.length - 1; i >= 0; i--) {
    nextUntouched[i] = upcoming;
    if (sequence[i].pre === undefined) upcoming = own[i];
  }
  // Anchors keep their ordinal; the rows between two anchors are spread over the gap between them
  // (fillOrdinalGaps, caseSqliteWorkerSaveState.ts), or the timeline is respaced when one is full.
  const assigned = new Array(sequence.length);
  const anchor = new Array(sequence.length).fill(false);
  let lastKept = -1;
  for (let i = 0; i < sequence.length; i++) {
    const o = own[i];
    if (o === undefined || o <= lastKept) continue;
    if (sequence[i].pre !== undefined && nextUntouched[i] !== undefined && o >= nextUntouched[i]) continue;
    anchor[i] = true;
    assigned[i] = o;
    lastKept = o;
  }
  if (!fillOrdinalGaps(assigned, anchor)) {
    // No room somewhere: spread the whole timeline ORDINAL_GAP times wider in two set-based updates
    // (no per-row work), then place again; only if that cannot fit either is every row renumbered.
    const top = Number(db.prepare(
      "SELECT coalesce(max(ordinal), 0) AS n FROM entities WHERE kind='forensicTimeline'"
    ).get().n);
    if ((top + 1) * ORDINAL_GAP <= ORDINAL_MAX) {
      db.prepare("UPDATE entities SET ordinal=-ordinal-1 WHERE kind='forensicTimeline'").run();
      db.prepare("UPDATE entities SET ordinal=(-ordinal-1)*? WHERE kind='forensicTimeline'").run(ORDINAL_GAP);
      db.prepare("UPDATE entity_values SET ordinal=ordinal*? WHERE kind='forensicTimeline'").run(ORDINAL_GAP);
      for (let i = 0; i < sequence.length; i++) {
        if (own[i] === undefined) continue;
        own[i] *= ORDINAL_GAP;
        if (sequence[i].pre === undefined) sequence[i].ordinal = own[i];
        if (anchor[i]) assigned[i] = own[i];
      }
    }
    if (!fillOrdinalGaps(assigned, anchor)) respaceOrdinals(assigned);
  }
  return { sequence, assigned };
}

function mergeApply(dbPath, plan) {
  const db = openDatabase(dbPath);
  try {
    return withTransaction(db, () => {
      if (mergeGeneration(db) !== plan.generation) {
        throw mergeFail("DFIR_MERGE_CONFLICT", "the case changed while the merge was computed");
      }
      const readVersion = db.prepare("SELECT version, kind FROM entities WHERE row_id=?");
      const expect = (rowId, version, kind) => {
        const row = readVersion.get(rowId);
        if (!row || row.kind !== kind || Number(row.version) !== version) {
          throw mergeFail("DFIR_MERGE_CONFLICT", "a row the merge read has changed");
        }
      };
      for (const d of plan.forensic.deletes) expect(d.rowId, d.version, "forensicTimeline");
      for (const p of plan.forensic.placed) if (p.rowId !== undefined) expect(p.rowId, p.version, "forensicTimeline");
      for (const i of plan.iocs.updates) expect(i.rowId, i.version, "iocs");
      const writer = createEntityWriter(db);
      writeStateBody(db, writer, plan.overview, ["forensicTimeline", "iocs"]);
      // IOCs: rewritten in place, new ones appended.
      const readRow = db.prepare("SELECT ordinal, payload FROM entities WHERE row_id=?");
      for (const i of plan.iocs.updates) {
        const stored = readRow.get(i.rowId);
        const projection = entityProjection("iocs", i.entity, Number(stored.ordinal));
        if (projection.payload !== stored.payload) writer.update(i.rowId, projection, i.entity);
      }
      let iocOrdinal = Number(db.prepare(
        "SELECT coalesce(max(ordinal), -1) AS n FROM entities WHERE kind='iocs'"
      ).get().n) + 1;
      for (const entity of plan.iocs.inserts) writer.insert(entityProjection("iocs", entity, iocOrdinal++), entity);
      if (plan.iocs.inserts.length) {
        db.prepare(
          "INSERT INTO entity_counts(kind, count) VALUES('iocs', ?) ON CONFLICT(kind) DO UPDATE SET count=entity_counts.count+excluded.count"
        ).run(plan.iocs.inserts.length);
      }
      // Forensic rows: folded-away rows go, then every placed row takes its position.
      const deleted = new Set(plan.forensic.deletes.map((d) => d.rowId));
      const removeRow = db.prepare("DELETE FROM entities WHERE row_id=?");
      for (const rowId of deleted) removeRow.run(rowId);
      const { sequence, assigned } = mergePlace(db, plan.forensic.placed, deleted);
      const setOrdinal = db.prepare("UPDATE entities SET ordinal=? WHERE row_id=?");
      const setValueOrdinal = db.prepare("UPDATE entity_values SET ordinal=? WHERE row_id=?");
      const moves = [];
      const ordinalOf = db.prepare("SELECT ordinal FROM entities WHERE row_id=?");
      for (let i = 0; i < sequence.length; i++) {
        const item = sequence[i];
        if (item.rowId === undefined) continue;
        const now = Number(ordinalOf.get(item.rowId).ordinal);
        if (now !== assigned[i]) moves.push([item.rowId, assigned[i]]);
      }
      for (const [rowId] of moves) setOrdinal.run(-rowId, rowId);
      for (const [rowId, ordinal] of moves) {
        setOrdinal.run(ordinal, rowId);
        setValueOrdinal.run(ordinal, rowId);
      }
      let inserted = 0;
      const indexEntries = [];
      for (let i = 0; i < sequence.length; i++) {
        const item = sequence[i];
        if (item.pre === undefined) continue; // an untouched row
        let rowId = item.rowId;
        if (rowId === undefined) {
          rowId = writer.insert(entityProjection("forensicTimeline", item.entity, assigned[i]), item.entity);
          inserted++;
        } else if (item.entity) {
          const stored = readRow.get(rowId);
          const projection = entityProjection("forensicTimeline", item.entity, assigned[i]);
          if (projection.payload !== stored.payload) writer.update(rowId, projection, item.entity);
        }
        if (item.index) indexEntries.push({ rowId, index: item.index });
      }
      const change = inserted - deleted.size;
      if (change !== 0) {
        db.prepare(
          "INSERT INTO entity_counts(kind, count) VALUES('forensicTimeline', ?) " +
          "ON CONFLICT(kind) DO UPDATE SET count=max(entity_counts.count+excluded.count, 0)"
        ).run(change);
      }
      writeMergeIndex(db, indexEntries);
      db.exec("DELETE FROM merge_dirty_keys");
      writeMergeMeta(db, plan.meta);
      return { inserted, deleted: deleted.size, moved: moves.length };
    });
  } finally {
    db.close();
  }
}

// After a full save: the positions (0-based, in timeline order) of the forensic rows whose index is
// missing or stale — every row, when the index was written by another build — and the generation to
// write it under.
function mergeStalePositions(dbPath, stamp) {
  if (!existsSync(dbPath)) return null;
  const db = openDatabase(dbPath);
  try {
    const meta = readMergeMeta(db);
    const all = !meta || meta.stamp !== stamp;
    const positions = [];
    let at = 0;
    for (const row of db.prepare(
      "SELECT e.version, m.version AS mv FROM entities e LEFT JOIN merge_rows m ON m.row_id=e.row_id " +
      "WHERE e.kind='forensicTimeline' ORDER BY e.ordinal"
    ).iterate()) {
      if (all || row.mv === null || Number(row.mv) !== Number(row.version)) positions.push(at);
      at++;
    }
    return { generation: mergeGeneration(db), rowCount: at, positions };
  } finally {
    db.close();
  }
}

// Index the rows a full save wrote, by position, and record the index stamp.
function mergeIndexWrite(dbPath, generation, entries, meta) {
  const db = openDatabase(dbPath);
  try {
    return withTransaction(db, () => {
      if (mergeGeneration(db) !== generation) {
        throw mergeFail("DFIR_MERGE_CONFLICT", "the case changed before its merge index was written");
      }
      const rowIds = db.prepare("SELECT row_id FROM entities WHERE kind='forensicTimeline' ORDER BY ordinal")
        .all().map((r) => Number(r.row_id));
      for (const entry of entries) {
        if (entry.position < 0 || entry.position >= rowIds.length) {
          throw mergeFail("DFIR_MERGE_CONFLICT", "a forensic row moved before it was indexed");
        }
      }
      writeMergeIndex(db, entries.map((entry) => ({ rowId: rowIds[entry.position], index: entry.index })));
      db.exec("DELETE FROM merge_dirty_keys");
      writeMergeMeta(db, meta);
      return entries.length;
    });
  } finally {
    db.close();
  }
}

function dispatchMerge(message) {
  switch (message.op) {
    case "mergeSnapshot": return mergeSnapshot(message.dbPath);
    case "mergeRows": return mergeRows(message.dbPath, message.select || {});
    case "mergeIdCounts": return mergeIdCounts(message.dbPath, message.ids);
    case "mergeIocCandidates": return mergeIocCandidates(message.dbPath, message.lowered, message.aliasIds);
    case "mergeIocsCiting": return mergeIocsCiting(message.dbPath, message.eventIds);
    case "mergeApply": return mergeApply(message.dbPath, message.plan);
    case "mergeStalePositions": return mergeStalePositions(message.dbPath, message.stamp);
    case "mergeIndexWrite": return mergeIndexWrite(message.dbPath, message.generation, message.entries, message.meta);
    default: return dispatchRows(message);
  }
}
`;

/** The per-row merge index (analysis/mergeIndex.ts computes it; this is its stored shape). */
export interface MergeIndexRecord {
  timeMs: number | null;
  year: number | null;
  yearInferred: boolean;
  keys: string[];
  flags: number;
}

/** What mergeSnapshot reads before the merge fetches any payload. */
export interface MergeSnapshot {
  generation: number;
  meta: { stamp?: unknown; stable?: unknown } | null;
  rowCount: number;
  /** Forensic rows with no index, or written since it was taken, in timeline order. */
  stale: number[];
  /** Clean rows, and how many of them carry each flag. */
  clean: { rows: number; trigger: number; process: number; cloud: number; load: number };
  /** [year, clean rows dated in it]. */
  years: [number, number][];
  dirtyKeys: string[];
}

/** A stored forensic or IOC row as the merge reads it: raw payload, and the index when it has one. */
export interface MergeStoredRow {
  rowId: number;
  ordinal: number;
  version: number;
  payload: string;
  index?: (MergeIndexRecord & { version: number }) | null;
}

/** One row the merge places: a stored row (rowId + version read) or a new one, with its sort key. */
export interface MergePlacedRow {
  rowId?: number;
  version?: number;
  /** The row to store (the full save's stored form); the worker writes it only if it differs. */
  entity: unknown;
  timeMs: number | null;
  /** First appearance in the pre-sort timeline: the stored ordinal, or past every ordinal for new rows. */
  pre: number;
  /** Absent: the row keeps the index it has. */
  index?: MergeIndexRecord & { clean: boolean };
}

export interface MergeApplyPlan {
  generation: number;
  overview: Record<string, unknown>;
  iocs: { updates: { rowId: number; version: number; entity: unknown }[]; inserts: unknown[] };
  forensic: { deletes: { rowId: number; version: number }[]; placed: MergePlacedRow[] };
  meta: { stamp: string; stable: boolean };
}
