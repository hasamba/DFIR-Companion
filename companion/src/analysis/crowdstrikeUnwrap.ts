// Split a CrowdStrike Falcon LogScale / Next-Gen SIEM export into its Falcon rows and the third-party
// rows it wraps (#2592 Part 3). Pure; composition/crowdstrikeDispatch.ts sends each part to its importer.
//
// A LogScale export of third-party data wraps every log in LogScale metadata (`@timestamp`, `#repo`,
// `#type`, …). Two shapes:
//   - raw: the original log line in `@rawstring` (JSON for Okta / M365 / CloudTrail, or plain text);
//   - parsed: Next-Gen SIEM's parsed copy of the vendor record under `Vendor` — a nested object in JSON,
//     dotted `Vendor.protoPayload.methodName` / `Vendor.x[0].y` keys in a flattened or CSV export.
// Each wrapped row is classified ON ITS OWN (a file can mix Falcon sensor rows and several vendors):
// its inner record goes through detectImportKind (per row: detectors read values, not just keys). A vendor the companion
// has an importer for goes there and keeps that vendor's label, so the case's main source is the real
// tool. Anything else — plain text, a shape no importer claims — goes to the generic SIEM importer with
// the LogScale metadata reduced to its time and `#repo`/`#type` provenance.

import { detectImportKind, type ImportKind } from "./importDetect.js";
import { readCrowdstrikeRecords, isCrowdstrikeWrapper } from "./crowdstrikeImport.js";
import { field } from "./crowdstrikeFields.js";
import { crowdstrikeTimeOf } from "./crowdstrikeTime.js";

type Row = Record<string, unknown>;

const MAX_DEPTH = 16;
const MAX_INDEX = 999;
const FORBIDDEN = new Set(["__proto__", "constructor", "prototype"]);
const GENERIC: ReadonlySet<ImportKind> = new Set<ImportKind>(["siem", "csv", "log", "unknown"]);

const isObj = (v: unknown): v is Row => v !== null && typeof v === "object" && !Array.isArray(v);

// `protoPayload.response.spec.volumes[0].name` → ["protoPayload","response","spec","volumes",0,"name"],
// or null when a segment is forbidden, an index is out of bounds, or the path is too deep.
function pathOf(key: string): (string | number)[] | null {
  const out: (string | number)[] = [];
  for (const m of key.matchAll(/([^.[\]]+)|\[(\d+)\]/g)) {
    if (m[2] !== undefined) {
      const i = Number(m[2]);
      if (i > MAX_INDEX) return null;
      out.push(i);
    } else {
      if (FORBIDDEN.has(m[1])) return null;
      out.push(m[1]);
    }
  }
  return out.length > 0 && out.length <= MAX_DEPTH ? out : null;
}

// Set one dotted path in `root`. First scalar wins; a scalar is never replaced by a container.
function setPath(root: Row, path: (string | number)[], value: unknown): void {
  let cur: Record<string | number, unknown> = root;
  for (let i = 0; i < path.length; i++) {
    const seg = path[i];
    const existing = cur[seg];
    if (i === path.length - 1) {
      if (existing === undefined) cur[seg] = value;
      return;
    }
    if (existing === undefined) cur[seg] = typeof path[i + 1] === "number" ? [] : {};
    else if (existing === null || typeof existing !== "object") return;
    cur = cur[seg] as Record<string | number, unknown>;
  }
}

// Rebuild the nested vendor record from dotted `Vendor.…` keys. Null when no key survives.
function nestedFromDotted(rec: Row): Row | null {
  const root: Row = {};
  let any = false;
  for (const [k, v] of Object.entries(rec)) {
    if (!k.startsWith("Vendor.")) continue;
    const path = pathOf(k.slice("Vendor.".length));
    if (!path || typeof path[0] === "number") continue;
    setPath(root, path, v);
    any = true;
  }
  return any ? root : null;
}

function parseJsonObject(raw: string): Row | null {
  const t = raw.trim();
  if (t[0] !== "{") return null;
  try {
    const v: unknown = JSON.parse(t);
    return isObj(v) ? v : null;
  } catch {
    return null;
  }
}

/** The wrapped vendor record: `@rawstring` JSON > nested `Vendor` object > dotted `Vendor.…` keys. */
export function innerRecord(rec: Row): Row | null {
  const raw = parseJsonObject(field(rec, "@rawstring"));
  if (raw) return raw;
  const vendor = rec["Vendor"];
  return isObj(vendor) ? vendor : nestedFromDotted(rec);
}

/** The generic-SIEM record for a wrapped row no specific importer claims. */
export function fallbackRecord(rec: Row, inner: Row | null): Row {
  const out: Row = {};
  for (const [k, v] of Object.entries(rec)) {
    if (k[0] === "@" || k[0] === "#" || k === "Vendor" || k.startsWith("Vendor.")) continue;
    out[k] = v;
  }
  if (inner) Object.assign(out, inner);
  const raw = field(rec, "@rawstring");
  if (raw && !inner) out["message"] = raw;
  const time = crowdstrikeTimeOf(rec, ["@timestamp", "timestamp"]);
  if (time) out["@timestamp"] = time.iso;
  const repo = field(rec, "#repo");
  const type = field(rec, "#type");
  if (repo) out["LogScale_repo"] = repo;
  if (type) out["LogScale_type"] = type;
  return out;
}

export interface CrowdstrikeSplit {
  wrapped: number; // wrapped rows found; 0 = a plain Falcon file, import it unchanged
  falcon: Row[]; // Falcon sensor rows and alerts (plus any wrapped inner record that is Falcon itself)
  falconIndexes: number[]; // each Falcon row's record index in the ORIGINAL file (evidence locators)
  groups: Map<ImportKind, Row[]>; // routed third-party records, by the importer that reads them
}

/** Split a Falcon export row by row. Never routes the file by its first row. */
export function splitCrowdstrikeFile(text: string): CrowdstrikeSplit {
  const { records } = readCrowdstrikeRecords(text);
  const split: CrowdstrikeSplit = { wrapped: 0, falcon: [], falconIndexes: [], groups: new Map() };
  const push = (kind: ImportKind, row: Row): void => {
    const list = split.groups.get(kind);
    if (list) list.push(row);
    else split.groups.set(kind, [row]);
  };
  const pushFalcon = (row: Row, index: number): void => {
    split.falcon.push(row);
    split.falconIndexes.push(index);
  };
  for (const [index, rec] of records.entries()) {
    if (!isObj(rec)) continue;
    if (!isCrowdstrikeWrapper(rec)) {
      pushFalcon(rec, index);
      continue;
    }
    split.wrapped++;
    const inner = innerRecord(rec);
    if (!inner) {
      push("siem", fallbackRecord(rec, null));
      continue;
    }
    // Every row on its own: detectors read values and nested fields, so no shape cache is safe.
    const kind = detectImportKind("inner.json", JSON.stringify(inner));
    if (kind === "crowdstrike") pushFalcon(inner, index);
    else if (GENERIC.has(kind)) push("siem", fallbackRecord(rec, inner));
    else push(kind, inner);
  }
  return split;
}
