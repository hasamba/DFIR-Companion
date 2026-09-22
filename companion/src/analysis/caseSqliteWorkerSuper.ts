// The super-timeline half of the case SQLite worker: the raw record's dedup, cap, protection
// (#958), migration, scan and legacy labels. Spliced into caseSqliteWorker.ts's WORKER_SOURCE as
// plain text, so everything here runs inside the worker thread with that file's helpers in scope
// (openDatabase, withTransaction, createEntityWriter, entityProjection, scalarText, readFileSync,
// existsSync). Keep it backtick-free: the fragment is a String.raw template.
export const SUPER_WORKER_SOURCE = String.raw`
function superContentKey(event) {
  const description = String((event && event.description) || "")
    .replace(/\s*\[corroborated by \d+ sources?:[^\]]*\]\s*$/i, "").trim();
  const host = (event && event.asset) || "(no host)";
  return String((event && event.timestamp) || "") + " " + description + " " + host;
}

// Protect the given ids (#958): a row is protected only when it exists, so the relation never names an
// evicted or unknown id. An id the batch carried but content-dedup dropped transfers its
// protection to the retained row with the same content key — that row now stands for the evidence.
function protectSuperRows(db, ids, incomingById) {
  const exists = db.prepare("SELECT 1 AS x FROM entities WHERE kind='superTimeline' AND entity_id=? LIMIT 1");
  const byContent = db.prepare(
    "SELECT entity_id FROM entities WHERE kind='superTimeline' AND content_key=? AND entity_id IS NOT NULL ORDER BY row_id LIMIT 1"
  );
  const insert = db.prepare("INSERT OR IGNORE INTO super_protected(event_id) VALUES(?)");
  let protectedCount = 0;
  for (const id of ids || []) {
    if (typeof id !== "string" || !id) continue;
    let target = exists.get(id) ? id : null;
    if (!target && incomingById && incomingById.has(id)) {
      const row = byContent.get(superContentKey(incomingById.get(id)));
      target = row ? row.entity_id : null;
    }
    if (!target) continue;
    insert.run(target);
    protectedCount++;
  }
  return protectedCount;
}

// A row a NAMED rule deliberately graded Info (#1535), decided from the STORED row: the projected
// severity column first, then the stated reason in the row's own description. The description, not
// the whole payload — a raw message or a command line that happens to quote the phrase must not buy
// a row retention priority. analysis/setAsideRows.ts owns the marker list and hands it in.
function setAsideMatchSql(markers) {
  const list = (markers || []).filter((m) => typeof m === "string" && m);
  if (!list.length) return null;
  const tests = list.map(() => "instr(json_extract(e.payload,'$.description'), ?)>0").join(" OR ");
  return { sql: "e.severity='Info' AND (" + tests + ")", params: list };
}

// Claim the qualifying rows in scope — a fromRowId for the batch just inserted, an id list for the
// rows a rehome rewrote, or null for the whole store (a re-derive). INSERT OR IGNORE: the relation
// is a set, so re-running it over rows already claimed costs nothing and changes nothing.
function markSetAsideRows(db, markers, scope) {
  const match = setAsideMatchSql(markers);
  if (!match) return 0;
  let bound = "";
  let params = match.params;
  if (scope && Number.isFinite(scope.fromRowId)) {
    bound = " AND e.row_id>=?";
    params = [...match.params, scope.fromRowId];
  } else if (scope && Array.isArray(scope.ids)) {
    if (!scope.ids.length) return 0;
    bound = " AND e.entity_id IN (SELECT value FROM json_each(?))";
    params = [...match.params, JSON.stringify(scope.ids)];
  }
  return db.prepare(
    "INSERT OR IGNORE INTO super_set_aside(event_id) SELECT e.entity_id FROM entities e " +
    "WHERE e.kind='superTimeline' AND e.entity_id IS NOT NULL AND (" + match.sql + ")" + bound
  ).run(...params).changes;
}

// Re-derive the whole relation when the marker registry changed — which is what makes a demoter
// shipped TODAY claim rows a case imported yesterday, instead of only helping future imports. One
// pass over the store's descriptions, once per registry version, guarded by storage_meta.
function reconcileSetAside(db, markers, version) {
  if (!setAsideMatchSql(markers) || typeof version !== "string" || !version) return;
  const synced = db.prepare("SELECT value FROM storage_meta WHERE key='super_set_aside_sync'").get();
  if (synced && synced.value === version) return;
  withTransaction(db, () => {
    db.prepare("DELETE FROM super_set_aside").run();
    markSetAsideRows(db, markers, null);
    db.prepare("INSERT INTO storage_meta(key,value) VALUES('super_set_aside_sync',?) " +
      "ON CONFLICT(key) DO UPDATE SET value=excluded.value").run(version);
  });
}

// The cap bounds UNPROTECTED rows; every protected row is kept (#958). Runs inside the caller's
// transaction after anything that adds rows or drops protection, so the store never rests above
// the cap. NOT EXISTS, not NOT IN: a row with no entity_id must stay evictable, and
// NULL NOT IN (...) is never true. Stores the exact post-delete total in entity_counts.
function enforceSuperCap(db, max) {
  const cap = Number.isFinite(max) ? Math.max(0, Math.floor(max)) : 100000;
  const count = Number(db.prepare("SELECT count(*) AS n FROM entities WHERE kind='superTimeline'").get().n);
  const protectedCount = Number(db.prepare(
    "SELECT count(*) AS n FROM entities e WHERE e.kind='superTimeline' " +
    "AND EXISTS (SELECT 1 FROM super_protected p WHERE p.event_id=e.entity_id)"
  ).get().n);
  const excess = Math.max(0, count - protectedCount - cap);
  let deleted = 0; // eviction policy: superTimelineStore.ts "Retention"
  let evicted = { count: 0, setAside: 0, from: "", to: "" };
  if (excess > 0) {
    // The doomed rows, in eviction order: ordinary rows by insertion age first, set-aside rows
    // behind every one of them, protected rows not at all (#1535). Unlike protection, the
    // set-aside tier is BOUNDED (superSetAsideFloor): a store whose cap filled with set-aside rows
    // would otherwise evict every newly imported row on arrival and quietly stop taking evidence.
    const floorRowId = superSetAsideFloor(db, cap);
    // "member" is what the analyst is told — a set-aside row the cap took is a set-aside row the
    // cap took, whether or not it still had the tier. "aside" is only the ORDER, and is the one the
    // headroom bounds. Summing the ordering flag would have reported an over-headroom loss as
    // ordinary telemetry.
    const doomed =
      "SELECT e.row_id AS row_id, e.timestamp AS ts, " +
      "(CASE WHEN EXISTS(SELECT 1 FROM super_set_aside s WHERE s.event_id=e.entity_id) THEN 1 ELSE 0 END) AS member, " +
      "(CASE WHEN e.row_id>=? AND EXISTS(SELECT 1 FROM super_set_aside s WHERE s.event_id=e.entity_id) THEN 1 ELSE 0 END) AS aside " +
      "FROM entities e WHERE e.kind='superTimeline' " +
      "AND NOT EXISTS (SELECT 1 FROM super_protected p WHERE p.event_id=e.entity_id) " +
      "ORDER BY aside ASC, e.row_id ASC LIMIT ?";
    // Summarized with one aggregate over the same ordered subquery rather than by reading the ids
    // back: a bulk import can evict hundreds of thousands of rows, and none of them is materialized.
    const summary = db.prepare(
      "SELECT count(*) AS n, coalesce(sum(member),0) AS asides, min(nullif(ts,'')) AS t0, max(nullif(ts,'')) AS t1 " +
      "FROM (" + doomed + ")"
    ).get(floorRowId, excess);
    deleted = db.prepare("DELETE FROM entities WHERE row_id IN (SELECT row_id FROM (" + doomed + "))").run(floorRowId, excess).changes;
    db.prepare("DELETE FROM super_labels WHERE event_id NOT IN " +
      "(SELECT entity_id FROM entities WHERE kind='superTimeline' AND entity_id IS NOT NULL)").run();
    db.prepare("DELETE FROM super_set_aside WHERE event_id NOT IN " +
      "(SELECT entity_id FROM entities WHERE kind='superTimeline' AND entity_id IS NOT NULL)").run();
    evicted = {
      count: deleted,
      setAside: Number(summary.asides || 0),
      from: summary.t0 ? String(summary.t0) : "",
      to: summary.t1 ? String(summary.t1) : "",
    };
    recordSuperEviction(db, evicted);
  }
  db.prepare(
    "INSERT INTO entity_counts(kind, count) VALUES('superTimeline', ?) " +
    "ON CONFLICT(kind) DO UPDATE SET count=excluded.count"
  ).run(count - deleted);
  bumpSuperGeneration(db);
  return evicted;
}

// The one thing the set-aside tier may NOT do: stop the store taking new evidence (#1535).
//
// Protection cannot cause this — a protected row does not count against the cap at all, so the
// store simply grows. A set-aside row does count, so a store whose cap had filled with them would
// put every newly imported ordinary row at the head of the eviction order and evict it on arrival.
// An analyst stars rows one at a time; a rule demotes them by the thousand, and a future rule could
// demote a whole provisioning window.
//
// So the tier stops at cap minus this headroom — a tenth of the cap, at least one row. At the
// default cap that is 90,000 rows of priority and 10,000 rows of guaranteed forward progress; the
// oldest set-aside rows past it evict with everything else, oldest first. superTimelineStore.ts's
// RETENTION header states it as part of the contract.
const SET_ASIDE_HEADROOM_SHARE = 0.1;

// The oldest set-aside row that still gets the tier, as a row_id. Returns 0 — every set-aside row
// qualifies — when the store holds fewer than the headroom allows, and MAX when the cap is too
// small to reserve anything. Protected rows are excluded: they are outside the cap the headroom
// protects, so counting them would silently shrink the tier.
function superSetAsideFloor(db, cap) {
  const keep = cap - Math.max(1, Math.ceil(cap * SET_ASIDE_HEADROOM_SHARE));
  if (keep <= 0) return Number.MAX_SAFE_INTEGER;
  const row = db.prepare(
    "SELECT e.row_id AS row_id FROM entities e WHERE e.kind='superTimeline' " +
    "AND EXISTS(SELECT 1 FROM super_set_aside s WHERE s.event_id=e.entity_id) " +
    "AND NOT EXISTS(SELECT 1 FROM super_protected p WHERE p.event_id=e.entity_id) " +
    "ORDER BY e.row_id DESC LIMIT 1 OFFSET ?"
  ).get(keep - 1);
  return row ? Number(row.row_id) : 0;
}

// The case's durable record of what the cap dropped (#1535). Written HERE, not at the append site,
// because the cap also runs when an analyst unstars a row or when protection is reconciled from the
// tags file — an eviction the import summary never sees. A caller that reports per-import numbers
// reads the atomic result of its own append; this is the complete total.
function recordSuperEviction(db, evicted) {
  if (!evicted || !evicted.count) return;
  db.prepare(
    "INSERT INTO storage_meta(key, value) VALUES('super_evicted_total', ?) " +
    "ON CONFLICT(key) DO UPDATE SET value=CAST(CAST(value AS INTEGER)+? AS TEXT)"
  ).run(String(evicted.count), evicted.count);
  db.prepare(
    "INSERT INTO storage_meta(key, value) VALUES('super_evicted_last', ?) " +
    "ON CONFLICT(key) DO UPDATE SET value=excluded.value"
  ).run(JSON.stringify({ at: new Date().toISOString(), ...evicted }));
}

// The store's mutation generation (#969): bumped on every append, eviction and migration, since
// each of them runs the cap above — and on a bulk-import rollback (#1480), which deletes rows the
// cap never saw. A row count and a latest timestamp cannot tell an append-with-eviction at the cap
// from no change; a reader that captured the generation can.
function bumpSuperGeneration(db) {
  db.prepare(
    "INSERT INTO storage_meta(key, value) VALUES('super_generation', '1') " +
    "ON CONFLICT(key) DO UPDATE SET value=CAST(CAST(value AS INTEGER)+1 AS TEXT)"
  ).run();
}

// The store's row count and mutation generation, and its distinct host spellings as stored —
// index-only reads (entities_host_idx), never a scan of the payloads (#969).
function superMeta(dbPath, hostLimit) {
  if (!existsSync(dbPath)) return { rows: 0, generation: 0, hosts: [], hostsTruncated: false, evictedTotal: 0, lastEviction: null };
  const db = openDatabase(dbPath);
  try {
    const countRow = db.prepare("SELECT count AS n FROM entity_counts WHERE kind='superTimeline'").get();
    const rows = countRow ? Number(countRow.n) : Number(db.prepare("SELECT count(*) AS n FROM entities WHERE kind='superTimeline'").get().n);
    const genRow = db.prepare("SELECT value FROM storage_meta WHERE key='super_generation'").get();
    // Hosts only when asked, and bounded: one more than the limit is read so the caller can tell
    // "exactly the limit" from "more than it".
    const limit = Number.isFinite(hostLimit) ? Math.max(0, Math.floor(hostLimit)) : 0;
    const hosts = limit
      ? db.prepare("SELECT DISTINCT host FROM entities WHERE kind='superTimeline' AND host IS NOT NULL AND host<>'' ORDER BY host LIMIT ?").all(limit + 1).map((row) => String(row.host))
      : [];
    // What the cap has dropped from this case, over its whole life and from EVERY path — append,
    // unstar, a protection reconcile (#1535). Two storage_meta reads; nothing is scanned.
    const totalRow = db.prepare("SELECT value FROM storage_meta WHERE key='super_evicted_total'").get();
    const lastRow = db.prepare("SELECT value FROM storage_meta WHERE key='super_evicted_last'").get();
    let lastEviction = null;
    try { lastEviction = lastRow ? JSON.parse(lastRow.value) : null; } catch { lastEviction = null; }
    return {
      rows, generation: genRow ? Number(genRow.value) : 0, hosts: hosts.slice(0, limit),
      hostsTruncated: hosts.length > limit,
      evictedTotal: totalRow ? Number(totalRow.value) || 0 : 0,
      lastEviction,
    };
  } finally {
    db.close();
  }
}

function writeSuperEvents(db, events, max, protectIds, setAsideMarkers) {
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
    let firstRowId = null; // batch rows have the highest row_ids: survivors are one range count
    const seenIds = new Set();
    const seenContent = new Set();
    for (const event of incoming) {
      const id = scalarText(event && event.id);
      const contentKey = superContentKey(event);
      if ((id && (seenIds.has(id) || existingIds.has(id))) ||
          seenContent.has(contentKey) || existingContent.has(contentKey)) continue;
      if (id) seenIds.add(id);
      seenContent.add(contentKey);
      const rowId = writer.insert(entityProjection("superTimeline", event, ordinal++, contentKey), event);
      if (firstRowId === null) firstRowId = rowId;
      added++;
    }
    if (protectIds && protectIds.length) {
      protectSuperRows(db, protectIds, new Map(incoming.filter((event) => scalarText(event && event.id)).map((event) => [event.id, event])));
    }
    // Claim this batch's set-aside rows BEFORE the cap runs, so the rows it just inserted are
    // already behind ordinary telemetry in the eviction order rather than one append too late.
    // A row that content-dedups against one the store already holds inserts nothing and needs
    // nothing: the content key is timestamp + description + host, so the retained row carries the
    // same stated reason and was claimed on its own append.
    if (firstRowId !== null) markSetAsideRows(db, setAsideMarkers, { fromRowId: firstRowId });
    const evicted = enforceSuperCap(db, max);
    // retained, not inserted: a batch past the cap loses its own head
    const retained = firstRowId === null ? 0 : Number(db.prepare("SELECT count(*) AS n FROM entities WHERE kind='superTimeline' AND row_id>=?").get(firstRowId).n);
    return { retained, evicted };
  });
}

// Analyst-authored event tags in the tags side file (#958). Automatic tagger tags are excluded:
// they can cover most rows, and a protected majority would leave the cap nothing to bound.
function readProtectedTagIds(tagsPath, excludeAuthorPrefix) {
  let tags = [];
  try {
    const parsed = JSON.parse(readFileSync(tagsPath, "utf8"));
    if (Array.isArray(parsed)) tags = parsed;
  } catch {}
  const ids = new Set();
  for (const tag of tags) {
    if (!tag || tag.targetType !== "event" || typeof tag.targetId !== "string" || !tag.targetId) continue;
    if (excludeAuthorPrefix && typeof tag.author === "string" && tag.author.startsWith(excludeAuthorPrefix)) continue;
    ids.add(tag.targetId);
  }
  return [...ids];
}

// The tags file as the worker last saw it. Size and mtime, not content: a stat per store call is
// cheap, a read is not, and TagsStore's own protect/unprotect calls cover a same-size rewrite
// inside one mtime tick.
function tagsFingerprint(tagsPath) {
  try {
    const stat = statSync(tagsPath);
    return stat.size + ":" + stat.mtimeMs;
  } catch {
    return "absent";
  }
}

// The tags file is the authority for protection, and it is written and snapshotted apart from the
// case database: a restore, an export, or a crash between the two writes can leave a star in one
// file and not the other. So the relation is re-derived from the file whenever the file changed
// since the last sync (or was never synced — a case indexed before #958): the exact analyst set
// is protected, everything else released, and the cap enforced over what was released.
function reconcileSuperProtection(db, tagsPath, excludeAuthorPrefix, max) {
  const fingerprint = tagsFingerprint(tagsPath);
  const synced = db.prepare("SELECT value FROM storage_meta WHERE key='super_protected_sync'").get();
  if (synced && synced.value === fingerprint) return;
  withTransaction(db, () => {
    const ids = readProtectedTagIds(tagsPath, excludeAuthorPrefix);
    db.prepare("DELETE FROM super_protected WHERE event_id NOT IN (SELECT value FROM json_each(?))").run(JSON.stringify(ids));
    protectSuperRows(db, ids, null);
    enforceSuperCap(db, max);
    db.prepare("INSERT INTO storage_meta(key,value) VALUES('super_protected_sync',?) " +
      "ON CONFLICT(key) DO UPDATE SET value=excluded.value").run(fingerprint);
  });
}

function migrateSuper(dbPath, eventsPath, labelsPath, tagsPath, excludeAuthorPrefix, max, setAsideMarkers, setAsideVersion) {
  const db = openDatabase(dbPath);
  try {
    if (db.prepare("SELECT 1 AS x FROM storage_meta WHERE key='super_migrated'").get()) {
      // Set-aside FIRST. Protection reconciliation enforces the cap as soon as it releases a row,
      // and on the open that upgrades a case the relation is still empty — the legacy rows the
      // backfill is about to claim would be evicted as ordinary telemetry before it ever ran.
      reconcileSetAside(db, setAsideMarkers, setAsideVersion);
      reconcileSuperProtection(db, tagsPath, excludeAuthorPrefix, max);
      return;
    }
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
    const legacyMs = (e) => { const t = Date.parse(e && e.timestamp); return Number.isNaN(t) ? Number.MAX_SAFE_INTEGER : t; }; // row_id is retention age; a legacy array has none
    writeSuperEvents(db, events.map((e, i) => [legacyMs(e), i, e]).sort((a, b) => a[0] - b[0] || a[1] - b[1]).map((x) => x[2]), max,
      readProtectedTagIds(tagsPath, excludeAuthorPrefix), setAsideMarkers); // protected BEFORE the cap is enforced
    withTransaction(db, () => {
      const labelStatement = db.prepare("INSERT OR IGNORE INTO super_labels(event_id, label) VALUES(?, ?)");
      for (const [id, values] of Object.entries(labels)) {
        for (const label of Array.isArray(values) ? values : []) {
          if (typeof label === "string" && label.trim()) labelStatement.run(id, label.trim());
        }
      }
      db.prepare("INSERT INTO storage_meta(key,value) VALUES('super_migrated','1')").run();
      db.prepare("INSERT INTO storage_meta(key,value) VALUES('super_protected_sync',?)").run(tagsFingerprint(tagsPath));
      if (typeof setAsideVersion === "string" && setAsideVersion) {
        db.prepare("INSERT INTO storage_meta(key,value) VALUES('super_set_aside_sync',?) " +
          "ON CONFLICT(key) DO UPDATE SET value=excluded.value").run(setAsideVersion);
      }
    });
  } finally {
    db.close();
  }
}

// Returns { retained, evicted } so a caller that reports can have BOTH from one atomic call.
// SuperTimelineStore.append still hands its callers the retained number and nothing else.
function appendSuper(dbPath, events, max, setAsideMarkers) {
  const db = openDatabase(dbPath);
  try { return writeSuperEvents(db, events, max, null, setAsideMarkers); } finally { db.close(); }
}

// Rewrite stored rows in place once the case learned a hostname rename (#1508): the payload, the
// host column the facet and the typed reads filter on, the content key the dedup compares, and the
// value/term indexes all follow, because the write goes through the entity writer's update. The
// row keeps its row_id and ordinal, so retention age and scan order do not move. An id the store
// does not hold is skipped — appendSuper would have skipped it the other way round. Returns the
// count rewritten; the generation is bumped only when that is non-zero, so live views refresh.
function rehomeSuper(dbPath, events, setAsideMarkers) {
  if (!existsSync(dbPath)) return 0;
  const db = openDatabase(dbPath);
  try {
    return withTransaction(db, () => {
      const writer = createEntityWriter(db);
      const find = db.prepare(
        "SELECT row_id, ordinal FROM entities WHERE kind='superTimeline' AND entity_id=? ORDER BY ordinal LIMIT 1"
      );
      let updated = 0;
      const rewritten = [];
      for (const event of events || []) {
        const id = scalarText(event && event.id);
        if (!id) continue;
        const row = find.get(id);
        if (!row) continue;
        writer.update(row.row_id, entityProjection("superTimeline", event, row.ordinal, superContentKey(event)), event);
        rewritten.push(id);
        updated++;
      }
      // The relation always follows the CURRENT payload (#1535): a rewritten row is released and
      // re-derived, so a rehome can neither strand a claim nor silently keep one it no longer earns.
      if (rewritten.length) {
        db.prepare("DELETE FROM super_set_aside WHERE event_id IN (SELECT value FROM json_each(?))")
          .run(JSON.stringify(rewritten));
        markSetAsideRows(db, setAsideMarkers, { ids: rewritten });
      }
      if (updated) bumpSuperGeneration(db);
      return updated;
    });
  } finally {
    db.close();
  }
}

// One page of the raw record in the store's order: dated rows by timestamp then row_id, undated
// rows after every dated one by row_id ("Ordering" in superTimelineStore.ts). Two phases, one per
// kind of row, so each page is a range read of entities_time_idx (kind, timestamp_ms, row_id).
// The cursor used to compare coalesce(timestamp_ms, MAX) in both WHERE and ORDER BY, which no
// index can serve: every 1,000-row page re-scanned and re-sorted the whole table, and a 446k-row
// store never finished a first page (#1429). The labels join runs over the page, not the table.
function superWindowClauses(query) {
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
  return { where, params };
}

function superPageWithLabels(db, pageSql, params) {
  return db.prepare(
    "SELECT p.row_id, p.sort_ms, p.payload, " +
    "CASE WHEN count(l.label)=0 THEN '[]' ELSE json_group_array(l.label) END AS labels " +
    "FROM (" + pageSql + ") p LEFT JOIN super_labels l ON l.event_id=p.entity_id " +
    "GROUP BY p.row_id ORDER BY p.sort_ms, p.row_id"
  ).all(...params);
}

function scanSuper(dbPath, query) {
  if (!existsSync(dbPath)) return { rows: [], nextCursor: null };
  const db = openDatabase(dbPath);
  try {
    const { where, params } = superWindowClauses(query);
    const limit = Math.max(1, Math.min(10000, Math.floor((query && query.limit) || 1000)));
    const phase = query && query.phase === "undated" ? "undated" : "dated";
    const afterRowId = query && Number.isFinite(query.afterRowId) ? query.afterRowId : 0;
    let rows;
    if (phase === "dated") {
      const afterMs = query && Number.isFinite(query.afterMs) ? query.afterMs : -9007199254740992;
      rows = superPageWithLabels(db,
        "SELECT e.row_id, e.entity_id, e.timestamp_ms AS sort_ms, e.payload FROM entities e WHERE " +
        where.concat(["e.timestamp_ms IS NOT NULL", "(e.timestamp_ms>? OR (e.timestamp_ms=? AND e.row_id>?))"]).join(" AND ") +
        " ORDER BY e.timestamp_ms, e.row_id LIMIT ?",
        params.concat([afterMs, afterMs, afterRowId, limit + 1]));
    } else {
      rows = superPageWithLabels(db,
        "SELECT e.row_id, e.entity_id, 9007199254740991 AS sort_ms, e.payload FROM entities e WHERE " +
        where.concat(["e.timestamp_ms IS NULL", "e.row_id>?"]).join(" AND ") +
        " ORDER BY e.row_id LIMIT ?",
        params.concat([afterRowId, limit + 1]));
    }
    const hasMore = rows.length > limit;
    const pageRows = hasMore ? rows.slice(0, limit) : rows;
    const mapped = pageRows.map((row) => ({
      event: JSON.parse(row.payload),
      labels: JSON.parse(row.labels),
      rowId: row.row_id,
      sortMs: row.sort_ms,
    }));
    const last = mapped.length ? mapped[mapped.length - 1] : null;
    let nextCursor = null;
    if (hasMore && last) nextCursor = { phase, afterMs: last.sortMs, afterRowId: last.rowId };
    else if (phase === "dated") nextCursor = { phase: "undated", afterMs: 0, afterRowId: 0 }; // the dated rows are done; the undated ones follow
    return { rows: mapped, nextCursor };
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

function protectSuper(dbPath, eventId) {
  const db = openDatabase(dbPath);
  try {
    return withTransaction(db, () => protectSuperRows(db, [eventId], null) === 1);
  } finally {
    db.close();
  }
}

// Releasing a row can put the unprotected population over the cap, so the cap runs here too.
function unprotectSuper(dbPath, eventId, max) {
  if (!existsSync(dbPath)) return;
  const db = openDatabase(dbPath);
  try {
    withTransaction(db, () => {
      db.prepare("DELETE FROM super_protected WHERE event_id=?").run(eventId);
      enforceSuperCap(db, max);
    });
  } finally {
    db.close();
  }
}

function listSuperProtected(dbPath) {
  if (!existsSync(dbPath)) return [];
  const db = openDatabase(dbPath);
  try {
    return db.prepare("SELECT event_id FROM super_protected ORDER BY event_id").all().map((row) => row.event_id);
  } finally {
    db.close();
  }
}

// Legacy label sidecar. Returns false — and writes nothing — when the row is not in the store (#958).
function setSuperLabels(dbPath, eventId, labels) {
  const db = openDatabase(dbPath);
  try {
    return withTransaction(db, () => {
      if (!db.prepare("SELECT 1 AS x FROM entities WHERE kind='superTimeline' AND entity_id=? LIMIT 1").get(eventId)) return false;
      db.prepare("DELETE FROM super_labels WHERE event_id=?").run(eventId);
      const statement = db.prepare("INSERT OR IGNORE INTO super_labels(event_id,label) VALUES(?,?)");
      for (const label of [...new Set((labels || []).map((value) => String(value).trim()).filter(Boolean))]) {
        statement.run(eventId, label);
      }
      return true;
    });
  } finally {
    db.close();
  }
}
`;
