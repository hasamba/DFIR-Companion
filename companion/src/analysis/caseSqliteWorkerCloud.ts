// The cloud-record reads of the case SQLite worker (#2301). Spliced into caseSqliteWorker.ts's
// WORKER_SOURCE as plain text, like caseSqliteWorkerRows.ts: everything here runs inside the worker
// thread with that file's helpers in scope (openDatabase, existsSync, withTransaction). Keep it
// backtick-free.
//
// All three stores live in the generic kind-based entities table, so no schema change:
//  - cloudRecordMember: one row per (aggregated event group, source record). The group key is the
//    projected host column, so a page is one (kind, host, row_id) index range — never a scan, and
//    never the whole member list in memory, however many records one event stands for.
//  - authObservation: paged by evidence time, with optional tenant/account filters, on a
//    (timestamp_ms, row_id) keyset so no fixed cap can silently hide a row.
//  - pruneEntitiesBeforeNewest: retention measured against the kind's NEWEST stored evidence time,
//    not the wall clock, so an export of last year's activity is not pruned on arrival.
export const CLOUD_WORKER_SOURCE = String.raw`
const CLOUD_PAGE_MAX = 5000;

function cloudPageLimit(limit) {
  const n = Math.floor(Number(limit));
  return Number.isFinite(n) && n > 0 ? Math.min(CLOUD_PAGE_MAX, n) : 500;
}

function cloudMembersPage(dbPath, group, afterRowId, limit) {
  if (!existsSync(dbPath) || typeof group !== "string" || !group) return { members: [], next: null, total: 0 };
  const db = openDatabase(dbPath);
  try {
    const bounded = cloudPageLimit(limit);
    const after = Number.isFinite(Number(afterRowId)) ? Number(afterRowId) : 0;
    const rows = db.prepare(
      "SELECT row_id, payload FROM entities INDEXED BY entities_host_idx " +
      "WHERE kind='cloudRecordMember' AND host=? AND row_id>? ORDER BY row_id LIMIT ?"
    ).all(group, after, bounded + 1);
    const total = Number(db.prepare(
      "SELECT count(*) AS n FROM entities INDEXED BY entities_host_idx WHERE kind='cloudRecordMember' AND host=?"
    ).get(group).n);
    const page = rows.slice(0, bounded);
    const members = page.map((row) => {
      const p = JSON.parse(row.payload);
      return { ref: p.ref, ...(p.locator ? { locator: p.locator } : {}) };
    });
    const next = rows.length > bounded ? Number(page[page.length - 1].row_id) : null;
    return { members, next, total };
  } finally {
    db.close();
  }
}

function authObservationsPage(dbPath, query) {
  if (!existsSync(dbPath)) return { observations: [], next: null };
  const db = openDatabase(dbPath);
  try {
    const q = query || {};
    const where = ["kind='authObservation'", "timestamp_ms>=?", "timestamp_ms<=?"];
    const params = [Number(q.sinceMs) || 0, Number.isFinite(Number(q.untilMs)) ? Number(q.untilMs) : 8.64e15];
    if (typeof q.tenant === "string" && q.tenant) {
      where.push("json_extract(payload, '$.hostOrTenant')=?");
      params.push(q.tenant);
    }
    if (typeof q.account === "string" && q.account) {
      where.push("lower(json_extract(payload, '$.account'))=?");
      params.push(q.account.trim().toLowerCase());
    }
    if (q.after && Number.isFinite(Number(q.after.ms)) && Number.isFinite(Number(q.after.rowId))) {
      where.push("(timestamp_ms>? OR (timestamp_ms=? AND row_id>?))");
      params.push(Number(q.after.ms), Number(q.after.ms), Number(q.after.rowId));
    }
    const bounded = cloudPageLimit(q.limit);
    const rows = db.prepare(
      "SELECT row_id, timestamp_ms, payload FROM entities INDEXED BY entities_time_idx WHERE " +
      where.join(" AND ") + " ORDER BY timestamp_ms, row_id LIMIT ?"
    ).all(...params, bounded + 1);
    const page = rows.slice(0, bounded);
    const last = page[page.length - 1];
    return {
      observations: page.map((row) => JSON.parse(row.payload)),
      next: rows.length > bounded ? { ms: Number(last.timestamp_ms), rowId: Number(last.row_id) } : null,
    };
  } finally {
    db.close();
  }
}

function pruneEntitiesBeforeNewest(dbPath, kind, spanMs) {
  if (!existsSync(dbPath)) return 0;
  const db = openDatabase(dbPath);
  try {
    return withTransaction(db, () => {
      const newest = db.prepare("SELECT max(timestamp_ms) AS n FROM entities WHERE kind=?").get(kind).n;
      if (newest === null || newest === undefined) return 0;
      const result = db.prepare(
        "DELETE FROM entities WHERE kind=? AND timestamp_ms IS NOT NULL AND timestamp_ms<?"
      ).run(kind, Number(newest) - Number(spanMs));
      const deleted = Number(result.changes || 0);
      if (deleted > 0) db.prepare("UPDATE entity_counts SET count=max(count-?, 0) WHERE kind=?").run(deleted, kind);
      return deleted;
    });
  } finally {
    db.close();
  }
}

function dispatchCloud(message) {
  switch (message.op) {
    case "cloudMembersPage": return cloudMembersPage(message.dbPath, message.group, message.afterRowId, message.limit);
    case "authObservationsPage": return authObservationsPage(message.dbPath, message.query);
    case "pruneEntitiesBeforeNewest": return pruneEntitiesBeforeNewest(message.dbPath, message.kind, message.spanMs);
    default: throw new Error("unknown SQLite worker operation: " + message.op);
  }
}
`;
