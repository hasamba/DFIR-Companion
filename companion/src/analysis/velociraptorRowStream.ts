import { getCI, isObject } from "./siemImport.js";

/**
 * Row-at-a-time reader for the JSON shapes a Velociraptor export arrives in (#1439).
 *
 * `extractRows` parses the whole document with one `JSON.parse`, which for a 108 MB `Windows.NTFS.MFT`
 * artifact map is 100k row objects held at once — and every later stage (normalize, map, aggregate,
 * merge, save) holds its own copy on top. This reader walks the text with a depth/string scanner and
 * `JSON.parse`s ONE top-level element at a time, so the caller can process a batch of rows and let it
 * go before the next batch is read. The text itself stays one string; the expansion is what the OOM
 * was made of, not the text.
 *
 * Shapes handled, mirroring the whole-parse driver's rules so the two agree on what a row is:
 *   artifact map  {"Windows.NTFS.MFT":[{…},{…}], "Other.Artifact":[…]}  → `_Source` stamped per row
 *   bare array    [{…},{…}]                                              → Elastic `_source` unwrapped
 *   NDJSON        one object per line                                    → `_source` unwrapped, blank
 *                                                                          and malformed lines skipped
 * Anything else (CSV, a `{data:[…]}`/`{hits:…}` wrapper, a single object) returns null and the caller
 * falls back to the whole-parse path — the bulk driver only runs on inputs big enough that these
 * shapes do not occur.
 */

export type Row = Record<string, unknown>;

export type RowStreamFormat = "artifact-map" | "array" | "ndjson";

export interface RowStreamItem {
  row: Row;
  /** Byte offset just past this row — the driver reports it as import progress. */
  offset: number;
}

export interface VelociraptorRowStream {
  format: RowStreamFormat;
  rows: Generator<RowStreamItem, void, undefined>;
}

// Object keys the whole-parse driver treats as a generic wrapper, never as an artifact name.
// Kept in step with `WRAPPER_KEYS` in velociraptorImport.ts.
const WRAPPER_KEYS = new Set([
  "data",
  "hits",
  "events",
  "records",
  "results",
  "logs",
  "rows",
  "items",
  "alerts",
  "value",
]);

const WS = /\s/;

function skipWs(text: string, from: number): number {
  let i = from;
  while (i < text.length && WS.test(text[i])) i++;
  return i;
}

// Index just past the string literal that opens at `i` (text[i] === '"'). -1 when unterminated.
function skipString(text: string, i: number): number {
  for (let j = i + 1; j < text.length; j++) {
    const ch = text[j];
    if (ch === "\\") j++;
    else if (ch === '"') return j + 1;
  }
  return -1;
}

// Index just past the JSON value that opens at `i` — an object, array, string, or scalar. -1 when the
// text ends first. Objects and arrays are matched by depth with strings skipped whole, so a brace
// inside a string never counts.
function skipValue(text: string, i: number): number {
  const first = text[i];
  if (first === '"') return skipString(text, i);
  if (first !== "{" && first !== "[") {
    let j = i;
    while (j < text.length && !/[,\]}\s]/.test(text[j])) j++;
    return j;
  }
  let depth = 0;
  for (let j = i; j < text.length; j++) {
    const ch = text[j];
    if (ch === '"') {
      j = skipString(text, j);
      if (j === -1) return -1;
      j--; // the loop's own increment steps past the closing quote
    } else if (ch === "{" || ch === "[") depth++;
    else if (ch === "}" || ch === "]") {
      if (--depth === 0) return j + 1;
    }
  }
  return -1;
}

function unwrapSource(el: unknown): Row | null {
  if (!isObject(el)) return null;
  const src = getCI(el, "_source");
  return isObject(src) ? src : el;
}

function parseAt(text: string, start: number, end: number, ordinal: number): unknown {
  try {
    return JSON.parse(text.slice(start, end));
  } catch (err) {
    throw new Error(`row ${ordinal}: ${(err as Error).message}`);
  }
}

// Yield each object element of the array that opens at `i` (text[i] === '['). Returns the index just
// past the closing bracket. Non-object elements are skipped, as the whole-parse driver skips them.
function* arrayElements(
  text: string,
  i: number,
  stamp: ((row: Row) => Row) | null,
  counter: { n: number },
): Generator<RowStreamItem, number, undefined> {
  let pos = skipWs(text, i + 1);
  if (text[pos] === "]") return pos + 1;
  for (;;) {
    const end = skipValue(text, pos);
    if (end === -1) throw new Error(`row ${counter.n + 1}: unterminated array element`);
    counter.n++;
    if (text[pos] === "{") {
      const row = unwrapSource(parseAt(text, pos, end, counter.n));
      if (row) yield { row: stamp ? stamp(row) : row, offset: end };
    }
    pos = skipWs(text, end);
    if (text[pos] === ",") {
      pos = skipWs(text, pos + 1);
      continue;
    }
    if (text[pos] === "]") return pos + 1;
    throw new Error(`row ${counter.n}: expected ',' or ']' at offset ${pos}`);
  }
}

function* artifactMapRows(text: string, start: number): Generator<RowStreamItem, void, undefined> {
  const counter = { n: 0 };
  let pos = skipWs(text, start + 1);
  if (text[pos] === "}") return;
  for (;;) {
    if (text[pos] !== '"') throw new Error(`expected an artifact name at offset ${pos}`);
    const keyEnd = skipString(text, pos);
    if (keyEnd === -1) throw new Error(`unterminated artifact name at offset ${pos}`);
    const artifact = JSON.parse(text.slice(pos, keyEnd)) as string;
    pos = skipWs(text, keyEnd);
    if (text[pos] !== ":") throw new Error(`expected ':' at offset ${pos}`);
    pos = skipWs(text, pos + 1);
    if (text[pos] !== "[") throw new Error(`artifact "${artifact}" is not an array at offset ${pos}`);
    const stamp = (row: Row): Row =>
      getCI(row, "_Source") || getCI(row, "Artifact") ? row : { ...row, _Source: artifact };
    pos = yield* arrayElements(text, pos, stamp, counter);
    pos = skipWs(text, pos);
    if (text[pos] === ",") {
      pos = skipWs(text, pos + 1);
      continue;
    }
    if (text[pos] === "}") return;
    throw new Error(`expected ',' or '}' at offset ${pos}`);
  }
}

function* bareArrayRows(text: string, start: number): Generator<RowStreamItem, void, undefined> {
  yield* arrayElements(text, start, null, { n: 0 });
}

function* ndjsonRows(text: string): Generator<RowStreamItem, void, undefined> {
  let pos = 0;
  while (pos < text.length) {
    let nl = text.indexOf("\n", pos);
    if (nl === -1) nl = text.length;
    const line = text.slice(pos, nl).trim();
    pos = nl + 1;
    if (!line) continue;
    let obj: unknown;
    try {
      obj = JSON.parse(line);
    } catch {
      continue; // the whole-parse driver skips a malformed NDJSON line too
    }
    const row = unwrapSource(obj);
    if (row && Object.keys(row).length > 0) yield { row, offset: pos };
  }
}

// Every key of the root object must name an array, and none may be a generic wrapper key — the same
// test `extractRows` applies before it treats a root object as an artifact map. Scans keys only; the
// arrays are skipped whole, so this is one pass over the text with no allocation per row.
function looksLikeArtifactMap(text: string, start: number): boolean {
  let pos = skipWs(text, start + 1);
  if (text[pos] === "}") return false;
  let keys = 0;
  for (;;) {
    if (text[pos] !== '"') return false;
    const keyEnd = skipString(text, pos);
    if (keyEnd === -1) return false;
    let key: string;
    try {
      key = JSON.parse(text.slice(pos, keyEnd)) as string;
    } catch {
      return false;
    }
    if (WRAPPER_KEYS.has(key.toLowerCase())) return false;
    pos = skipWs(text, keyEnd);
    if (text[pos] !== ":") return false;
    pos = skipWs(text, pos + 1);
    if (text[pos] !== "[") return false;
    const end = skipValue(text, pos);
    if (end === -1) return false;
    keys++;
    pos = skipWs(text, end);
    if (text[pos] === ",") {
      pos = skipWs(text, pos + 1);
      continue;
    }
    return text[pos] === "}" && keys > 0;
  }
}

// NDJSON when the first line is a complete JSON object on its own and another non-blank line follows.
// A one-line artifact map has no second line; a pretty-printed one has a bare "{" first line.
function looksLikeNdjson(text: string): boolean {
  const nl = text.indexOf("\n");
  if (nl === -1) return false;
  const first = text.slice(0, nl).trim();
  if (!first.startsWith("{") || !first.endsWith("}")) return false;
  try {
    JSON.parse(first);
  } catch {
    return false;
  }
  return /\S/.test(text.slice(nl + 1));
}

/**
 * Probe the head of the text and return a row generator for it, or null when the shape is not one
 * the reader streams. The probe itself allocates nothing per row.
 */
export function openVelociraptorRowStream(text: string): VelociraptorRowStream | null {
  const start = skipWs(text, 0);
  if (start >= text.length) return null;
  const first = text[start];
  if (first === "[") return { format: "array", rows: bareArrayRows(text, start) };
  if (first !== "{") return null;
  if (looksLikeNdjson(text)) return { format: "ndjson", rows: ndjsonRows(text) };
  if (looksLikeArtifactMap(text, start))
    return { format: "artifact-map", rows: artifactMapRows(text, start) };
  return null;
}
