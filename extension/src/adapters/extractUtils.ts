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
 * Velociraptor / table-style envelope: { columns: string[], rows: [...] } where each row is either
 * a raw array of cells, a { cell: [...] } wrapper, or already an object. Zip the columns onto each
 * row to produce flat objects. Returns null when the shape doesn't match.
 */
export function zipColumnsRows(body: unknown): unknown[] | null {
  if (!isObject(body)) return null;
  const columns = body.columns;
  const rows = body.rows;
  if (!Array.isArray(columns) || !Array.isArray(rows)) return null;
  const cols = columns.map((c) => String(c));
  return rows.map((row) => {
    const cells = Array.isArray(row) ? row : isObject(row) && Array.isArray(row.cell) ? row.cell : null;
    if (!cells) return isObject(row) ? row : { value: row };
    const obj: Record<string, unknown> = {};
    cols.forEach((c, i) => { obj[c] = cells[i]; });
    return obj;
  });
}
