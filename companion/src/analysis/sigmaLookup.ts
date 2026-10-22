// Field lookup for the import-time Sigma engine (#2202): every value one Sigma field name reaches
// inside one raw record. Pure, deterministic, no I/O.
//
// A Sigma field is a dotted path, and a raw cloud record is nested JSON, so a path can cross
// objects (case-insensitively, as the importers already read them), arrays (any element may
// match) and JSON written as a string (Log Analytics and CSV exports stringify nested columns).
// A flattened export can also carry the whole dotted name as one key; both shapes are read.
//
// Imported records are adversary-influenced, so the walk is bounded. Hitting a bound does NOT
// answer "no match": it marks the lookup incomplete, and the evaluator carries that through the
// condition, so a truncated field can never turn `not filter` into a match (Codex plan review).

type Row = Record<string, unknown>;

/** Every value a field reached. Leaves are strings (numbers and booleans as their text, objects
 * and arrays as their JSON text) or null for a JSON null. `present` is false when no key on any
 * branch matched the path. */
export interface SigmaFieldLookup {
  present: boolean;
  values: readonly (string | null)[];
  incomplete: boolean;
}

/** Most leaves one field may yield before the lookup stops and is marked incomplete. */
export const SIGMA_LOOKUP_MAX_LEAVES = 10_000;
/** Longest JSON text the lookup parses or produces for one value. */
export const SIGMA_LOOKUP_MAX_JSON_CHARS = 1_000_000;

interface WalkState {
  present: boolean;
  leaves: (string | null)[];
  incomplete: boolean;
}

const isPlain = (v: unknown): v is Row => v !== null && typeof v === "object" && !Array.isArray(v);

/** Case-insensitive own-key lookup; an exact key wins over a case-folded one. */
function keyCI(row: Row, key: string): { found: boolean; value?: unknown } {
  if (Object.hasOwn(row, key)) return { found: true, value: row[key] };
  const lower = key.toLowerCase();
  for (const k of Object.keys(row)) if (k.toLowerCase() === lower) return { found: true, value: row[k] };
  return { found: false };
}

/** A value as the text Sigma compares, or null; undefined when it is too large to render. */
function leafText(v: unknown): string | null | undefined {
  if (v === null || v === undefined) return null;
  if (typeof v === "string") return v;
  if (typeof v === "number" || typeof v === "boolean" || typeof v === "bigint") return String(v);
  const text = JSON.stringify(v);
  return text.length > SIGMA_LOOKUP_MAX_JSON_CHARS ? undefined : text;
}

function pushLeaf(v: unknown, st: WalkState): void {
  const items = Array.isArray(v) ? v : [v];
  for (const item of items) {
    const text = leafText(item);
    if (text === undefined || st.leaves.length >= SIGMA_LOOKUP_MAX_LEAVES) {
      st.incomplete = true;
      return;
    }
    st.leaves.push(text);
  }
}

/** A string holding a JSON object or array, parsed; undefined when it is not one. */
function parseJsonContainer(s: string, st: WalkState): unknown {
  const t = s.trimStart();
  if (t[0] !== "{" && t[0] !== "[") return undefined;
  if (s.length > SIGMA_LOOKUP_MAX_JSON_CHARS) {
    st.incomplete = true;
    return undefined;
  }
  try {
    return JSON.parse(s) as unknown;
  } catch {
    return undefined;
  }
}

function walk(node: unknown, segs: readonly string[], st: WalkState): void {
  if (st.incomplete) return;
  if (segs.length === 0) {
    st.present = true;
    pushLeaf(node, st);
    return;
  }
  if (Array.isArray(node)) {
    for (const el of node) {
      walk(el, segs, st);
      if (st.incomplete) return;
    }
    return;
  }
  if (typeof node === "string") {
    const parsed = parseJsonContainer(node, st);
    if (parsed !== undefined) walk(parsed, segs, st);
    return;
  }
  if (!isPlain(node)) return;
  // A flattened export (CSV, some SIEM exports) keeps the rest of the path as one dotted key.
  if (segs.length > 1) {
    const flat = keyCI(node, segs.join("."));
    if (flat.found) walk(flat.value, [], st);
  }
  const hit = keyCI(node, segs[0]);
  if (hit.found) walk(hit.value, segs.slice(1), st);
}

/** Every value `path` reaches in `root`. */
export function lookupPath(root: unknown, path: string): SigmaFieldLookup {
  const st: WalkState = { present: false, leaves: [], incomplete: false };
  walk(root, path.split("."), st);
  return { present: st.present, values: st.leaves, incomplete: st.incomplete };
}

/** The whole record as one text, for Sigma keyword selections; undefined when too large. */
export function recordText(record: unknown): string | undefined {
  const text = JSON.stringify(record) ?? "";
  return text.length > SIGMA_LOOKUP_MAX_JSON_CHARS ? undefined : text;
}
