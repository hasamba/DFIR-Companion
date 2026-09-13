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

function writeSuperEvents(db, events, max, protectIds) {
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
    const cap = Number.isFinite(max) ? Math.max(0, Math.floor(max)) : 100000;
    const count = Number(db.prepare("SELECT count(*) AS n FROM entities WHERE kind='superTimeline'").get().n);
    // The cap bounds UNPROTECTED rows; every protected row is kept (#958). NOT EXISTS, not NOT IN:
    // a row with no entity_id must stay evictable, and NULL NOT IN (...) is never true.
    const protectedCount = Number(db.prepare(
      "SELECT count(*) AS n FROM entities e WHERE e.kind='superTimeline' " +
      "AND EXISTS (SELECT 1 FROM super_protected p WHERE p.event_id=e.entity_id)"
    ).get().n);
    const excess = Math.max(0, count - protectedCount - cap);
    let deleted = 0; // eviction policy: superTimelineStore.ts "Retention"
    if (excess > 0) {
      deleted = db.prepare(
        "DELETE FROM entities WHERE row_id IN (SELECT e.row_id FROM entities e WHERE e.kind='superTimeline' " +
        "AND NOT EXISTS (SELECT 1 FROM super_protected p WHERE p.event_id=e.entity_id) ORDER BY e.row_id LIMIT ?)"
      ).run(excess).changes;
      db.prepare("DELETE FROM super_labels WHERE event_id NOT IN " +
        "(SELECT entity_id FROM entities WHERE kind='superTimeline' AND entity_id IS NOT NULL)").run();
    }
    db.prepare(
      "INSERT INTO entity_counts(kind, count) VALUES('superTimeline', ?) " +
      "ON CONFLICT(kind) DO UPDATE SET count=excluded.count"
    ).run(count - deleted);
    // retained, not inserted: a batch past the cap loses its own head
    return firstRowId === null ? 0 : Number(db.prepare("SELECT count(*) AS n FROM entities WHERE kind='superTimeline' AND row_id>=?").get(firstRowId).n);
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

function migrateSuper(dbPath, eventsPath, labelsPath, tagsPath, excludeAuthorPrefix, max) {
  const db = openDatabase(dbPath);
  try {
    const flagged = (key) => db.prepare("SELECT 1 AS x FROM storage_meta WHERE key=?").get(key);
    if (flagged("super_migrated")) {
      // A case indexed before #958 has rows but no protection: backfill it from the tags file once.
      if (flagged("super_protected_synced")) return;
      withTransaction(db, () => {
        protectSuperRows(db, readProtectedTagIds(tagsPath, excludeAuthorPrefix), null);
        db.prepare("INSERT INTO storage_meta(key,value) VALUES('super_protected_synced','1')").run();
      });
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
      readProtectedTagIds(tagsPath, excludeAuthorPrefix)); // protected BEFORE the cap is enforced
    withTransaction(db, () => {
      const labelStatement = db.prepare("INSERT OR IGNORE INTO super_labels(event_id, label) VALUES(?, ?)");
      for (const [id, values] of Object.entries(labels)) {
        for (const label of Array.isArray(values) ? values : []) {
          if (typeof label === "string" && label.trim()) labelStatement.run(id, label.trim());
        }
      }
      db.prepare("INSERT INTO storage_meta(key,value) VALUES('super_migrated','1')").run();
      db.prepare("INSERT INTO storage_meta(key,value) VALUES('super_protected_synced','1')").run();
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
    const afterRowId = query && Number.isFinite(query.afterRowId) ? query.afterRowId : 0; // undated sort LAST: superTimelineStore.ts "Ordering"
    where.push("(coalesce(e.timestamp_ms, 9007199254740991)>? OR " +
      "(coalesce(e.timestamp_ms, 9007199254740991)=? AND e.row_id>?))");
    params.push(afterMs, afterMs, afterRowId);
    const limit = Math.max(1, Math.min(10000, Math.floor((query && query.limit) || 1000)));
    const rows = db.prepare(
      "SELECT e.row_id, coalesce(e.timestamp_ms, 9007199254740991) AS sort_ms, e.payload, " +
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

function protectSuper(dbPath, eventId) {
  const db = openDatabase(dbPath);
  try {
    return withTransaction(db, () => protectSuperRows(db, [eventId], null) === 1);
  } finally {
    db.close();
  }
}

function unprotectSuper(dbPath, eventId) {
  if (!existsSync(dbPath)) return;
  const db = openDatabase(dbPath);
  try {
    db.prepare("DELETE FROM super_protected WHERE event_id=?").run(eventId);
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
