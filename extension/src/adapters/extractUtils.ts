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

const BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/;

/**
 * Inflate a base64-encoded, compressed JSON payload. Kibana's batched `/internal/bsearch` enables
 * **bfetch compression** for non-localhost connections (Elastic Cloud, remote self-hosted): each
 * NDJSON line is then `base64(deflate(JSON))` — NOT plain JSON — so a `JSON.parse` of the line throws
 * and the rows are silently lost. We decode it with the browser's `DecompressionStream` (zlib
 * `deflate` first, then `gzip`/`deflate-raw` to be robust to encoder differences). Returns the parsed
 * JSON value, or null when the string isn't base64 / doesn't inflate to JSON. Async (the stream API
 * is async); a no-op on plain-JSON deployments.
 */
export async function inflateBase64Json(raw: string): Promise<unknown | null> {
  const compact = raw.replace(/\s+/g, "");
  if (compact.length < 8 || !BASE64_RE.test(compact)) return null;
  let bytes: Uint8Array;
  try {
    const bin = atob(compact);
    bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  } catch { return null; }
  for (const format of ["deflate", "gzip", "deflate-raw"] as const) {
    try {
      const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream(format));
      const text = (await new Response(stream).text()).trim();
      if (text.startsWith("{") || text.startsWith("[")) {
        try { return JSON.parse(text); } catch { /* inflated but not JSON — try next format */ }
      }
    } catch { /* wrong format for these bytes — try the next */ }
  }
  return null;
}

/**
 * Decode a captured response body into JSON values, transparently handling the three shapes a DFIR
 * console's data API can emit: (1) a single JSON document, (2) streamed NDJSON (Kibana bsearch), and
 * (3) **compressed** bfetch — either a whole line that is `base64(deflate(JSON))`, or a JSON wrapper
 * `{ id, result: "<base64>" }` whose `result` is the compressed payload. The async superset of
 * `parseResponseBodies`; the capture path uses this so compression on remote Kibana doesn't drop rows.
 */
export async function decodeCapturedBodies(text: string): Promise<unknown[]> {
  const trimmed = text.trim();
  if (!trimmed) return [];
  // 1) Collect raw values — a single JSON document, or NDJSON lines (each plain JSON or compressed).
  const raw: unknown[] = [];
  const single = tryParseJson(trimmed);
  if (single !== undefined) {
    raw.push(single);
  } else {
    for (const line of trimmed.split(/\r?\n/)) {
      const s = line.trim();
      if (!s) continue;
      const parsed = tryParseJson(s);
      if (parsed !== undefined) raw.push(parsed);
      else { const inflated = await inflateBase64Json(s); if (inflated !== null) raw.push(inflated); }
    }
  }
  // 2) bfetch may also wrap the compressed payload as { id, result: "<base64>" } — inflate that
  //    string on whichever path produced the object (single or NDJSON).
  const out: unknown[] = [];
  for (let obj of raw) {
    if (isObject(obj) && typeof obj.result === "string") {
      const inner = await inflateBase64Json(obj.result);
      if (inner !== null) obj = { ...obj, result: inner };
    }
    out.push(obj);
  }
  return out;
}

function tryParseJson(s: string): unknown | undefined {
  try { return JSON.parse(s); } catch { return undefined; }
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
