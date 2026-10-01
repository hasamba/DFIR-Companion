// The forensic-timeline search prefilter of the case SQLite worker (#928, #1914). Spliced into
// caseSqliteWorker.ts's WORKER_SOURCE as plain text, so it runs inside the worker thread. Keep it
// backtick-free: the fragment is a String.raw template.
//
// The plan (which rows can match at all) is worked out from the term by analysis/searchFoldPrefilter.ts;
// this fragment only turns it into SQL. Candidates are rows the LIKE pattern accepts (ASCII folding,
// done in C), OR rows holding one of the few characters whose lowercase form reaches the term, which
// dfir_fold_contains then checks exactly. The function sees only rows that passed the cheap LIKE on
// one character: handing every payload to JavaScript costs ~0.6 s per 70,000 rows in marshalling alone.
export const SEARCH_WORKER_SOURCE = String.raw`
function foldContains(payload, needle) {
  if (typeof payload !== "string" || typeof needle !== "string") return 0;
  return payload.toLowerCase().replace(/ς/g, "σ").includes(needle) ? 1 : 0;
}

// Appends the prefilter's WHERE clause and parameters. A query with no prefilter, or a plan that
// scans every row, adds nothing.
function addSearchPrefilter(db, query, where, params) {
  if (!query || !query.searchPrefilter) return;
  const clauses = [];
  if (typeof query.searchLike === "string" && query.searchLike) {
    clauses.push("entities.payload LIKE ? ESCAPE '\\'");
    params.push(query.searchLike);
  }
  const chars = Array.isArray(query.searchFoldChars)
    ? query.searchFoldChars.filter((char) => typeof char === "string" && char)
    : [];
  if (chars.length && typeof query.searchFoldNeedle === "string") {
    db.function("dfir_fold_contains", { deterministic: true }, foldContains);
    clauses.push("((" + chars.map(() => "entities.payload LIKE ?").join(" OR ") +
      ") AND dfir_fold_contains(entities.payload, ?))");
    params.push(...chars.map((char) => "%" + char + "%"), query.searchFoldNeedle);
  }
  // Read-time upgrades add searchable text the stored JSON lacks (searchFoldPrefilter.ts): a row
  // with no canonical envelope gets one synthesised, and one with a source address may be
  // restamped "edge-observed". Exact JSON tests, so no row the matcher would see is lost.
  clauses.push("json_type(entities.payload, '$.canonical') IS NOT 'object'");
  if (query.searchEdgeObserved) {
    clauses.push("json_type(entities.payload, '$.canonical.network.source.address') IS NOT NULL");
  }
  where.push("(" + clauses.join(" OR ") + ")");
}
`;
