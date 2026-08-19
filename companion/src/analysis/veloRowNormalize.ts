// Reshape ONE raw row into the native Velociraptor form the classifier and mappers expect.
//
// Two independent distortions arrive here, and each one silently cost evidence:
//
//   • A source that streams a TEXT FILE back one line per row. It is a common artifact idiom —
//     read a file, split on newlines, emit `SELECT _value AS Line` — and
//     `Generic.Scanner.ThorZIP/ThorResultsJson` is exactly that. THOR's findings therefore arrive as
//     `{ "Line": "{\"time\":…,\"level\":\"Alert\",…}" }`: one JSON document per row, as a STRING.
//     Nothing downstream looks inside it, so a THOR Alert was mapped as an undated Info event with no
//     host and no detection, and the default Low forensic floor then dropped it — the scan imported
//     and still showed nothing.
//   • An Elasticsearch round-trip, when Velociraptor uploads to ES and the analyst pushes the Kibana
//     search back (see normalizeElasticRow below).
//
// Both are GATED on a shape test, so a native Velociraptor row passes through untouched.
// Its own module because analysis/velociraptorImport.ts is frozen by the file-size ledger (#384).
import { getCI, isObject, str } from "./siemImport.js";

type Row = Record<string, unknown>;

/** Un-wrap a `Line`-streamed payload, then reverse any Elastic reshaping. Order matters: the ES test
 *  reads the row's OWN columns, which only exist once the payload is out of its string. */
export function normalizeRow(row: Row): Row {
  return normalizeElasticRow(unwrapLineRow(row));
}

// Columns a source-qualified read adds AROUND the payload. They are kept when a row is unwrapped —
// `_Source` is what names the artifact for classification, and losing it would strip that context.
const WRAPPER_META = /^(_|Client(Id)?$|Fqdn$|Hostname$)/i;

/**
 * Replace a `{ Line: "<json object>" }` wrapper with the object it carries, keeping any collection
 * metadata alongside it. Every other row — a plain-text `Line`, a JSON array or scalar, a row with
 * real columns of its own — is returned UNCHANGED, so this can sit on the path every artifact takes.
 */
export function unwrapLineRow(row: Row): Row {
  if (!row || typeof row !== "object" || Array.isArray(row)) return row;
  const keys = Object.keys(row);
  // Exactly one payload column, and it must be `Line`. A row that has other real columns is already
  // structured — reshaping it would be guesswork, not un-wrapping.
  const payload = keys.filter((k) => !WRAPPER_META.test(k));
  if (payload.length !== 1 || payload[0].toLowerCase() !== "line") return row;
  const text = row[payload[0]];
  if (typeof text !== "string") return row;
  const trimmed = text.trim();
  if (!trimmed.startsWith("{") || !trimmed.endsWith("}")) return row; // cheap reject before parsing
  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    return row; // a line that merely looks like JSON stays the opaque text it is
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return row;
  const meta: Row = {};
  for (const k of keys) if (WRAPPER_META.test(k)) meta[k] = row[k];
  // Payload last: a field the record carries itself beats the collection's own metadata.
  return { ...meta, ...(parsed as Row) };
}

// ───────────────────────── Elastic-indexed Velociraptor normalization ─────────────────────────
//
// When Velociraptor uploads to Elasticsearch and the analyst pushes the Kibana search back, the rows
// arrive RESHAPED by ES, not in native VQL form: nested columns are flattened to dotted keys
// (`Detection.StringHit`), text fields gain `.keyword`/`.text` multi-fields, the artifact name lives
// in the `artifact_<name>` index, and ES doc metadata (`_id`/`_index`/`_version`) rides along. This
// reverses that so the classifier/mappers below see the native nested shape. It is GATED (only runs
// when a row has dotted keys or an `artifact_` index), so native Velociraptor JSON is untouched.

// These rows originate from an untrusted, page-forgeable browser push (POST /cases/:id/import), so
// their column names are attacker-controllable. A dotted key whose segments name __proto__/constructor/
// prototype would let the walk below bracket-assign into Object.prototype and pollute this Node.js
// process globally (CWE-1321) — the bare-`__proto__` case is already blocked by the `in out` guard, but
// the DOTTED form ("__proto__.<x>") walks a step in before writing, so every segment must be checked.
const DANGEROUS_SEGMENT = new Set(["__proto__", "constructor", "prototype"]);

// Assign an OWN data property without invoking a setter. Plain `obj[key] = val` on the key
// "__proto__" runs Object.prototype's prototype setter instead of storing anything, which hands an
// attacker control of `obj`'s prototype; for every other key the observable result is identical.
function safeSet(obj: Row, key: string, val: unknown): void {
  Object.defineProperty(obj, key, { value: val, writable: true, enumerable: true, configurable: true });
}

// Expand dotted keys into nested objects: { "Detection.StringHit": x } → { Detection: { StringHit: x } }.
// Collision-safe: a flat key is kept as-is when a needed branch already holds a leaf (or vice-versa).
function unflattenDotted(row: Row): Row {
  const out: Row = {};
  for (const [key, val] of Object.entries(row)) {
    if (!key.includes(".")) {
      if (!(key in out) || !isObject(out[key])) out[key] = val; // don't clobber an existing nested branch
      continue;
    }
    const parts = key.split(".");
    // Never walk INTO or write THROUGH a __proto__/constructor/prototype segment (would reach
    // Object.prototype). The dotted key can't equal a bare "__proto__", so keeping it flat is safe.
    if (parts.some((p) => DANGEROUS_SEGMENT.has(p))) {
      out[key] = val;
      continue;
    }
    let cur: Row = out;
    let ok = true;
    for (let i = 0; i < parts.length - 1; i++) {
      const next = cur[parts[i]];
      if (next === undefined) {
        const o: Row = {};
        cur[parts[i]] = o;
        cur = o;
      } else if (isObject(next)) {
        cur = next;
      } else {
        ok = false;
        break;
      } // collision — a leaf sits where a branch is needed
    }
    const leaf = parts[parts.length - 1];
    if (ok && !(leaf in cur && isObject(cur[leaf]))) cur[leaf] = val;
    else out[key] = val; // keep the flat key on any collision
  }
  return out;
}

function normalizeElasticRow(row: Row): Row {
  const idx = str(getCI(row, "_index"));
  const hasDotted = Object.keys(row).some((k) => k.includes("."));
  if (!hasDotted && !/^artifact[_-]/i.test(idx)) return row; // native Velociraptor row — leave it alone

  // 1) Collapse Elasticsearch multi-field suffixes: "Artifact.keyword" → "Artifact" (unless the bare
  //    field is already present).
  const collapsed: Row = {};
  for (const [k, v] of Object.entries(row)) {
    const bare = k.replace(/\.(keyword|text|raw)$/i, "");
    if (bare !== k) {
      if (!(bare in collapsed) && !(bare in row)) safeSet(collapsed, bare, v);
    } else safeSet(collapsed, k, v);
  }
  // 2) Un-flatten the remaining dotted keys to nested objects.
  const nested = unflattenDotted(collapsed);
  // 3) Synthesize the artifact source from the ES index name when the row carries no artifact field.
  if (!getCI(nested, "_Source") && !getCI(nested, "Artifact") && /^artifact[_-]/i.test(idx)) {
    nested._Source = idx.replace(/^artifact[_-]/i, "");
  }
  return nested;
}
