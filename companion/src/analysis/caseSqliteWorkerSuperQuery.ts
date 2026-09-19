// The super-timeline's indexed query (#1429): count, facets and one page straight from SQL.
// Spliced into caseSqliteWorker.ts's WORKER_SOURCE after SUPER_WORKER_SOURCE, so it runs inside
// the worker thread with that file's helpers (openDatabase, existsSync) and the super fragment's
// (superWindowClauses) in scope. Keep it backtick-free: the fragment is a String.raw template.
//
// Before this, SuperTimelineStore.query() answered every dashboard page by scanning the whole
// store — count, facets and page all fell out of one JSON-parsing pass over every row — so a
// first page of 100 rows cost 92 s at 100k rows and never returned at 446k. Everything here is
// answered from the entities columns the writer already projects (source = artifactName or the
// first source, host = asset, timestamp_ms) and the super_labels relation; only the page's own
// payloads are parsed. The JS predicates it mirrors live in superTimeline.ts (superOriginOf,
// superHostOf) and superTimelineStore.ts (query); tests/analysis/superTimelineStore.test.ts pins
// that the two paths agree on every filter.
export const SUPER_QUERY_WORKER_SOURCE = String.raw`
const SUPER_NO_HOST_FACET = "(no host)";
const SUPER_UNKNOWN_ORIGIN = "Unknown";
const SUPER_STARRED = "starred";

function superJsonList(values) {
  return JSON.stringify(Array.isArray(values) ? values.filter((v) => typeof v === "string") : []);
}

// The effective labels of a row are the tag map's when the map names its id, else the sidecar's.
// The map side is resolved in JS by the caller (ids that match, ids that are tagged, ids that
// are starred); the sidecar side is an EXISTS over super_labels. A row without an entity_id is
// never in the map and has no sidecar row, so it fails every label test — as the scan did.
function superLabelClause(where, params, mapIds, matchIds, sidecarCondition, sidecarParams) {
  where.push(
    "(e.entity_id IN (SELECT value FROM json_each(?)) OR " +
    "((e.entity_id IS NULL OR e.entity_id NOT IN (SELECT value FROM json_each(?))) AND " +
    "EXISTS (SELECT 1 FROM super_labels l WHERE l.event_id=e.entity_id AND " + sidecarCondition + ")))"
  );
  params.push(superJsonList(matchIds), superJsonList(mapIds), ...sidecarParams);
}

function superFilterClauses(query) {
  const { where, params } = superWindowClauses(query);
  const origins = Array.isArray(query.origins) ? query.origins : [];
  if (origins.length) {
    const named = origins.filter((o) => o !== SUPER_UNKNOWN_ORIGIN);
    const clauses = ["e.source IN (SELECT value FROM json_each(?))"];
    params.push(superJsonList(named));
    if (origins.includes(SUPER_UNKNOWN_ORIGIN)) clauses.push("e.source IS NULL", "e.source=''");
    where.push("(" + clauses.join(" OR ") + ")");
  }
  const exclude = Array.isArray(query.exclude) ? query.exclude : [];
  if (exclude.length) {
    const named = exclude.filter((o) => o !== SUPER_UNKNOWN_ORIGIN);
    if (exclude.includes(SUPER_UNKNOWN_ORIGIN)) where.push("e.source IS NOT NULL", "e.source<>''");
    // NULL NOT IN (...) is never true, so the unknown origin is kept explicitly.
    where.push("(e.source IS NULL OR e.source='' OR e.source NOT IN (SELECT value FROM json_each(?)))");
    params.push(superJsonList(named));
  }
  const excludeHosts = Array.isArray(query.excludeHosts) ? query.excludeHosts : [];
  if (excludeHosts.length) {
    const named = excludeHosts.filter((h) => h !== SUPER_NO_HOST_FACET);
    if (excludeHosts.includes(SUPER_NO_HOST_FACET)) where.push("e.host IS NOT NULL", "e.host<>''");
    where.push("(e.host IS NULL OR e.host='' OR e.host NOT IN (SELECT value FROM json_each(?)))");
    params.push(superJsonList(named));
  }
  const map = query.labelMap && typeof query.labelMap === "object" ? query.labelMap : {};
  const mapIds = Object.keys(map);
  const mapLabels = (id) => (Array.isArray(map[id]) ? map[id] : []);
  const labels = Array.isArray(query.labels) ? query.labels : [];
  if (labels.length) {
    superLabelClause(where, params, mapIds, mapIds.filter((id) => mapLabels(id).some((l) => labels.includes(l))),
      "l.label IN (SELECT value FROM json_each(?))", [superJsonList(labels)]);
  }
  if (query.taggedOnly) {
    superLabelClause(where, params, mapIds, mapIds.filter((id) => mapLabels(id).some((l) => l !== SUPER_STARRED)),
      "l.label<>?", [SUPER_STARRED]);
  }
  if (query.starred) {
    superLabelClause(where, params, mapIds, mapIds.filter((id) => mapLabels(id).includes(SUPER_STARRED)),
      "l.label=?", [SUPER_STARRED]);
  }
  return { where, params, map, mapIds };
}

// Facets keep the scan's semantics: the time window alone, never the origin/host/label selection.
function superFacets(db, query, map, mapIds) {
  const { where, params } = superWindowClauses(query);
  const windowSql = where.join(" AND ");
  const origins = new Set(db.prepare("SELECT DISTINCT e.source AS v FROM entities e WHERE " + windowSql)
    .all(...params).map((row) => (row.v === null || row.v === "" ? SUPER_UNKNOWN_ORIGIN : String(row.v))));
  const hosts = new Set(db.prepare("SELECT DISTINCT e.host AS v FROM entities e WHERE " + windowSql)
    .all(...params).map((row) => (row.v === null || row.v === "" ? SUPER_NO_HOST_FACET : String(row.v))));
  const labels = new Set(db.prepare(
    "SELECT DISTINCT l.label AS v FROM super_labels l JOIN entities e ON e.entity_id=l.event_id WHERE " +
    windowSql + " AND l.label<>? AND e.entity_id NOT IN (SELECT value FROM json_each(?))"
  ).all(...params, SUPER_STARRED, superJsonList(mapIds)).map((row) => String(row.v)));
  if (mapIds.length) {
    const present = db.prepare(
      "SELECT e.entity_id AS id FROM entities e WHERE " + windowSql + " AND e.entity_id IN (SELECT value FROM json_each(?))"
    ).all(...params, superJsonList(mapIds));
    for (const row of present) {
      for (const label of Array.isArray(map[row.id]) ? map[row.id] : []) if (label !== SUPER_STARRED) labels.add(label);
    }
  }
  return {
    origins: [...origins].sort(),
    hosts: [...hosts].sort(),
    labelsAvailable: [...labels].sort(),
  };
}

function querySuper(dbPath, query) {
  if (!existsSync(dbPath)) return { events: [], total: 0, origins: [], hosts: [], labelsAvailable: [] };
  const db = openDatabase(dbPath);
  try {
    const { where, params, map, mapIds } = superFilterClauses(query || {});
    const filterSql = where.join(" AND ");
    const count = (extra) => Number(db.prepare(
      "SELECT count(*) AS n FROM entities e WHERE " + filterSql + " AND " + extra
    ).get(...params).n);
    const dated = count("e.timestamp_ms IS NOT NULL");
    const undated = count("e.timestamp_ms IS NULL");
    const offset = Math.max(0, Math.floor(Number(query && query.offset) || 0));
    const limit = Math.max(0, Math.min(10000, Math.floor(Number(query && query.limit) || 0)));
    // The store's order across the two kinds of row: every dated row (timestamp, then row_id)
    // before every undated one (row_id). One page can straddle the boundary.
    const payloads = [];
    if (limit > 0 && offset < dated) {
      payloads.push(...db.prepare(
        "SELECT e.payload FROM entities e WHERE " + filterSql +
        " AND e.timestamp_ms IS NOT NULL ORDER BY e.timestamp_ms, e.row_id LIMIT ? OFFSET ?"
      ).all(...params, limit, offset).map((row) => row.payload));
    }
    if (limit > payloads.length && offset + payloads.length >= dated) {
      payloads.push(...db.prepare(
        "SELECT e.payload FROM entities e WHERE " + filterSql +
        " AND e.timestamp_ms IS NULL ORDER BY e.row_id LIMIT ? OFFSET ?"
      ).all(...params, limit - payloads.length, Math.max(0, offset - dated)).map((row) => row.payload));
    }
    const facets = superFacets(db, query || {}, map, mapIds);
    return {
      events: payloads.map((payload) => JSON.parse(payload)),
      total: dated + undated,
      origins: facets.origins,
      hosts: facets.hosts,
      labelsAvailable: facets.labelsAvailable,
    };
  } finally {
    db.close();
  }
}
`;
