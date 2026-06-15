// Small pure helpers shared by the site adapters for digging result rows out of a parsed API
// response body. Kept dependency-free + side-effect-free so they're trivially unit-tested.

export function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Follow a dotted path (e.g. "result.rawResponse.hits.hits") through nested objects. */
export function getPath(root: unknown, path: string): unknown {
  let cur: unknown = root;
  for (const key of path.split(".")) {
    if (!isObject(cur)) return undefined;
    cur = cur[key];
  }
  return cur;
}

/** Return the value if it's a non-empty array, else null. */
export function asArray(v: unknown): unknown[] | null {
  return Array.isArray(v) && v.length > 0 ? v : null;
}

/**
 * Parse a captured response body string into one or more JSON values. Most tool APIs return a
 * single JSON document, but some stream NDJSON — one JSON object per line. Kibana's batched
 * `/internal/bsearch` is the important case: it streams `{"id":N,"result":{rawResponse:{…}}}`
 * per line, so a single `JSON.parse` of the whole body throws and the rows are lost. We try the
 * single-document fast path first, then fall back to parsing each non-empty line, returning every
 * value that parsed so the caller can run extractRows across all of them.
 */
export function parseResponseBodies(text: string): unknown[] {
  const trimmed = text.trim();
  if (!trimmed) return [];
  try { return [JSON.parse(trimmed)]; } catch { /* not a single document — try NDJSON */ }
  const out: unknown[] = [];
  for (const line of trimmed.split(/\r?\n/)) {
    const s = line.trim();
    if (!s) continue;
    try { out.push(JSON.parse(s)); } catch { /* skip a non-JSON line */ }
  }
  return out;
}

/**
 * Velociraptor / table-style envelope: { columns: string[], rows: [...] }. Each row's cells arrive
 * as a raw array, a { cell: [...] } wrapper, OR — the Velociraptor GUI's GetTable format —
 * { json: "<JSON-encoded array of cell values>" }. Zip the columns onto the cells to produce flat
 * objects. Returns null when the shape doesn't match.
 */
export function zipColumnsRows(body: unknown): unknown[] | null {
  if (!isObject(body)) return null;
  const columns = body.columns;
  const rows = body.rows;
  if (!Array.isArray(columns) || !Array.isArray(rows)) return null;
  const cols = columns.map((c) => String(c));
  return rows.map((row) => {
    const cells = rowCells(row);
    if (!cells) return isObject(row) ? row : { value: row };
    const obj: Record<string, unknown> = {};
    cols.forEach((c, i) => { obj[c] = cells[i]; });
    return obj;
  });
}

// Recover the ordered cell values from one table row across the shapes Velociraptor's API emits.
function rowCells(row: unknown): unknown[] | null {
  if (Array.isArray(row)) return row;
  if (!isObject(row)) return null;
  if (Array.isArray(row.cell)) return row.cell;
  // Velociraptor GUI GetTable: each row is { json: "[<cell>, <cell>, …]" } — a JSON-encoded array.
  if (typeof row.json === "string") {
    try {
      const parsed = JSON.parse(row.json);
      if (Array.isArray(parsed)) return parsed;
    } catch { /* not a JSON array — fall through */ }
  }
  return null;
}

/**
 * Expand dotted keys into nested objects: { "Detection.Name": x } → { Detection: { Name: x } }. The
 * Velociraptor GUI flattens nested VQL columns into dotted names, but the companion's importer reads
 * them nested (verdict object, System.*, FileInfo.* time keys). On a key collision (a leaf where a
 * branch is needed, or vice-versa) the original flat key is kept so nothing is silently dropped.
 */
export function unflattenDotted(row: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, val] of Object.entries(row)) {
    const parts = key.split(".");
    let cur = out;
    let ok = true;
    for (let i = 0; i < parts.length - 1; i++) {
      const next = cur[parts[i]];
      if (next === undefined) { const o: Record<string, unknown> = {}; cur[parts[i]] = o; cur = o; }
      else if (isObject(next)) { cur = next as Record<string, unknown>; }
      else { ok = false; break; } // collision — don't clobber an existing leaf
    }
    if (ok && !(parts[parts.length - 1] in cur && isObject(cur[parts[parts.length - 1]]))) {
      cur[parts[parts.length - 1]] = val;
    } else {
      out[key] = val; // keep the flat key on any collision
    }
  }
  return out;
}
