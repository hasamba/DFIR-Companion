import { IOC_BAD_ID_WHERE, IOC_ODD_VALUE_WHERE, IOC_SEQ_WHERE } from "./caseSqliteSchema.js";

// The IOC side of an import's journal and the indexed IOC reads (#1874). Spliced into
// caseSqliteWorker.ts's WORKER_SOURCE as plain text, like caseSqliteWorkerRows.ts: everything here
// runs inside the worker thread with that file's helpers in scope (openDatabase, existsSync,
// armedToken). Keep it backtick-free.
//
// An import used to read the whole IOC list three times — at capture, for the settle's IOC diff and
// for the undo checkpoint. With the IOC journal (caseSqliteSchema.ts) holding the stored image of
// every IOC row the import wrote or deleted, those reads shrink to: the IOC ids in order (an
// index-only read), the journaled rows, the rows the import inserted, and the untouched rows that
// share a value with one of them. analysis/iocJournal.ts turns these into the same diff and undo
// delta the full lists gave. Every query on a partial IOC index names it (INDEXED BY): without
// ANALYZE statistics SQLite's planner would otherwise scan every IOC.
export const IOC_WORKER_SOURCE =
  String.raw`
const IOC_BAD_ID_WHERE = ` +
  JSON.stringify(IOC_BAD_ID_WHERE) +
  String.raw`;
const IOC_ODD_VALUE_WHERE = ` +
  JSON.stringify(IOC_ODD_VALUE_WHERE) +
  String.raw`;
const IOC_SEQ_WHERE = ` +
  JSON.stringify(IOC_SEQ_WHERE) +
  String.raw`;

// The IOC ids in list order. For an IOC whose id is a non-empty string, entity_id IS that id
// (entityIdOf); the few whose id is anything else are read from their payload, so ids[i] is exactly
// iocs[i].id of a full load. objects counts IOCs whose value is an object or array: diffIocs keys by
// identity, so such a value never matches itself across two loads and only the full lists say what
// the diff reports.
function iocOutlineRows(db) {
  const rowIds = [];
  const ids = [];
  const at = new Map();
  for (const row of db.prepare(
    "SELECT row_id, entity_id FROM entities INDEXED BY entities_order_idx WHERE kind='iocs' ORDER BY ordinal"
  ).iterate()) {
    at.set(Number(row.row_id), ids.length);
    rowIds.push(Number(row.row_id));
    ids.push(row.entity_id);
  }
  for (const row of db.prepare(
    "SELECT row_id, payload FROM entities INDEXED BY entities_ioc_badid_idx WHERE " + IOC_BAD_ID_WHERE
  ).iterate()) {
    const i = at.get(Number(row.row_id));
    if (i !== undefined) ids[i] = JSON.parse(row.payload).id;
  }
  const objects = Number(db.prepare(
    "SELECT count(*) AS n FROM entities INDEXED BY entities_ioc_odd_idx WHERE " + IOC_ODD_VALUE_WHERE +
    " AND json_type(payload, '$.value') IN ('object', 'array')"
  ).get().n);
  return { rowIds, ids, objects };
}

// The journaled IOC images at or below the fence (the baseline's rows); null when token no longer
// holds the journal. A baseline with no journal (the case was empty) has no images.
function iocJournalRows(db, token, fence) {
  if (typeof token !== "string") return [];
  if (armedToken(db) !== token) return null;
  const upTo = typeof fence === "number" ? fence : Number.MAX_SAFE_INTEGER;
  return db.prepare("SELECT row_id, payload FROM import_journal_ioc WHERE row_id <= ? ORDER BY row_id").all(upTo)
    .map((row) => ({ rowId: Number(row.row_id), payload: JSON.parse(row.payload) }));
}

function iocRowsWhere(db, where, list) {
  if (!list.length) return [];
  return db.prepare("SELECT row_id, payload FROM entities WHERE kind='iocs' AND " + where + " IN (SELECT value FROM json_each(?))")
    .all(JSON.stringify(list)).map((row) => ({ rowId: Number(row.row_id), payload: JSON.parse(row.payload) }));
}

// Values held by IOC rows NOT in skip: every row whose value lower-cases (SQLite lower(), the index's
// own function) like one of the string values, and, when a value is not a string, every row whose
// value is not text. A superset: the caller applies the exact test.
function iocValueHolders(db, values, skip) {
  const strings = values.filter((v) => typeof v === "string");
  const out = [];
  if (strings.length) {
    for (const row of db.prepare(
      "SELECT row_id, json_extract(payload, '$.value') AS v FROM entities INDEXED BY entities_ioc_value_idx " +
      "WHERE kind='iocs' AND lower(json_extract(payload, '$.value')) IN (SELECT lower(value) FROM json_each(?))"
    ).iterate(JSON.stringify(strings))) {
      if (!skip.has(Number(row.row_id))) out.push(row.v);
    }
  }
  if (values.some((v) => typeof v !== "string")) {
    for (const row of db.prepare(
      "SELECT row_id, payload FROM entities INDEXED BY entities_ioc_odd_idx WHERE " + IOC_ODD_VALUE_WHERE
    ).iterate()) {
      if (!skip.has(Number(row.row_id))) out.push(JSON.parse(row.payload).value);
    }
  }
  return out;
}

const iocValueOf = (payload) => (payload && typeof payload === "object" ? payload.value : undefined);

// One read snapshot on the writer's connection for a multi-query op.
function readSnapshot(dbPath, fn) {
  if (!existsSync(dbPath)) return null;
  const db = openDatabase(dbPath);
  try {
    db.exec("BEGIN");
    try { return fn(db); } finally { db.exec("COMMIT"); }
  } finally {
    db.close();
  }
}

// Everything the settle's IOC diff reads: the IOC outline now, the journaled images of baseline rows,
// the current rows that are journaled or new (not a baseline row), and the values untouched rows hold
// among theirs. Null when the journal is gone.
function iocDiffInputs(dbPath, token, fence, baselineRowIds) {
  return readSnapshot(dbPath, (db) => {
    const baseline = new Set(baselineRowIds);
    const images = iocJournalRows(db, token, fence);
    if (!images) return null;
    const own = images.filter((j) => baseline.has(j.rowId));
    const journaled = new Set(own.map((j) => j.rowId));
    const after = iocOutlineRows(db);
    const touched = after.rowIds.filter((r) => journaled.has(r) || !baseline.has(r));
    const current = iocRowsWhere(db, "row_id", touched);
    const values = [...own, ...current].map((r) => iocValueOf(r.payload)).filter((v) => v);
    const skip = new Set([...journaled, ...touched]);
    const holders = values.length ? iocValueHolders(db, [...new Set(values)], skip) : [];
    return { after, images: own, current, holders };
  });
}

// What the undo checkpoint's IOC delta reads: the IOC outline now, the journaled images of baseline
// rows, and the current rows carrying those images' ids (an IOC whose id is a non-empty string has it
// as entity_id). Null when the journal is gone.
function iocUndoInputs(dbPath, token, fence, baselineRowIds) {
  return readSnapshot(dbPath, (db) => {
    const baseline = new Set(baselineRowIds);
    const images = iocJournalRows(db, token, fence);
    if (!images) return null;
    const own = images.filter((j) => baseline.has(j.rowId));
    const ids = own.map((j) => j.payload && j.payload.id).filter((id) => typeof id === "string" && id);
    return { after: iocOutlineRows(db), images: own, current: iocRowsWhere(db, "entity_id", ids) };
  });
}

// The whole IOC list before (untouched rows as they are now, journaled rows as their images) and after,
// for the diffs and deltas the targeted inputs cannot prove equal. Null when the journal is gone or a
// baseline row left no trace.
function iocFullLists(dbPath, token, fence, baselineRowIds) {
  return readSnapshot(dbPath, (db) => {
    const images = iocJournalRows(db, token, fence);
    if (!images) return null;
    const image = new Map(images.map((j) => [j.rowId, j.payload]));
    const byRow = new Map();
    const after = [];
    for (const row of db.prepare("SELECT row_id, payload FROM entities WHERE kind='iocs' ORDER BY ordinal").iterate()) {
      const payload = JSON.parse(row.payload);
      byRow.set(Number(row.row_id), payload);
      after.push(payload);
    }
    const before = [];
    for (const rowId of baselineRowIds) {
      if (image.has(rowId)) before.push(image.get(rowId));
      else if (byRow.has(rowId)) before.push(JSON.parse(JSON.stringify(byRow.get(rowId))));
      else return null;
    }
    return { before, after };
  });
}

function iocOutline(dbPath) {
  return readSnapshot(dbPath, iocOutlineRows);
}

function dispatchIoc(message) {
  const rows = message.baselineRowIds || [];
  switch (message.op) {
    case "iocOutline": return iocOutline(message.dbPath);
    case "iocDiffInputs": return iocDiffInputs(message.dbPath, message.token, message.fence, rows);
    case "iocUndoInputs": return iocUndoInputs(message.dbPath, message.token, message.fence, rows);
    case "iocFullLists": return iocFullLists(message.dbPath, message.token, message.fence, rows);
    default: return dispatchTags(message); // caseSqliteWorkerTags.ts
  }
}
`;
