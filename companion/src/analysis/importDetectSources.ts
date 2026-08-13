import { getCI, isObject } from "./siemImport.js";

// Format detectors for the sources added alongside the identity/mobile/browser importers — Okta,
// Google Workspace, Hindsight, macOS and LEAPP.
//
// They live here rather than in importDetect.ts because that file sits at the 800-line limit, and
// the repo's rule when the size gate fails is to put the new code in its own module rather than
// raise the ceiling (CONTRIBUTING.md, "the file-size ratchet"). importDetect.ts keeps the dispatch
// order — which detector is asked first is a real contract between formats — and imports the
// predicates from here.

type Row = Record<string, unknown>;

// Local copy of importDetect's row picker: exporting it from there just to reach it here would
// widen that module's surface for one three-line helper.
function firstObj(arr: unknown[]): Row | null {
  for (const el of arr) if (isObject(el)) return el;
  return null;
}

// Okta System Log v1: eventType + published is the pair every record carries, and `outcome.result`
// or an `actor` object confirms it against another product that happens to use those two names.
export function isOkta(s: Row): boolean {
  if (!getCI(s, "eventType") || !getCI(s, "published")) return false;
  return !!getCI(s, "actor") || !!getCI(s, "outcome") || !!getCI(s, "legacyEventType");
}

// Google Workspace Admin SDK Reports activity: the id{time,applicationName} envelope plus an
// events array. Checked against the envelope, not `actor`, which other Google products also send.
export function isWorkspaceActivityRow(s: Row): boolean {
  const id = getCI(s, "id");
  if (!isObject(id)) return false;
  const row = id;
  if (!getCI(row, "time") || !getCI(row, "applicationName")) return false;
  return Array.isArray(getCI(s, "events")) || String(getCI(s, "kind") ?? "").includes("reports#activity");
}

// ROOT-AWARE ON PURPOSE. The Reports API wraps its rows in `{ items: [...] }`, and `items` is not in
// CONTAINER_KEYS — widening that list would change how every other format samples. Left unhandled
// the wrapper reads as an object whose values are arrays, which isVelociraptor claims as an artifact
// map, so the check looks at the envelope itself as well as the sampled row.
export function isGoogleWorkspace(s: Row, root: unknown): boolean {
  if (isWorkspaceActivityRow(s)) return true;
  if (!isObject(root)) return false;
  const items = getCI(root, "items");
  if (!Array.isArray(items)) return false;
  const first = firstObj(items);
  return !!first && isWorkspaceActivityRow(first);
}

// Hindsight browser artifacts: the (type + url + timestamp) triple with Hindsight's own
// `interpretation`/`profile folder` columns. Requires one of the Hindsight-specific columns so a
// generic proxy log with a url column is not claimed.
export function isHindsight(s: Row): boolean {
  if (!getCI(s, "url") && !getCI(s, "URL")) return false;
  if (!getCI(s, "timestamp") && !getCI(s, "date")) return false;
  return (
    getCI(s, "interpretation") != null ||
    getCI(s, "profile folder") != null ||
    getCI(s, "profile_folder") != null ||
    (getCI(s, "type") != null && getCI(s, "profile") != null)
  );
}

// macOS unified log (`log show --style json`): eventMessage plus one of the Apple-specific columns.
// traceID/machTimestamp/processImagePath are absent from every other JSON feed here.
export function isMacosUnifiedLog(s: Row): boolean {
  if (!getCI(s, "eventMessage") && !getCI(s, "composedMessage")) return false;
  return (
    getCI(s, "processImagePath") != null ||
    getCI(s, "senderImagePath") != null ||
    getCI(s, "machTimestamp") != null ||
    getCI(s, "traceID") != null
  );
}

// Hindsight CSV export: url + timestamp plus one of its own columns.
// LSQuarantine CSV dump — the column prefix is unmistakable.
export function macosQuarantineCsvSig(h: Set<string>): boolean {
  for (const k of h) if (k.startsWith("lsquarantine")) return true;
  return false;
}

export function hindsightCsvSig(h: Set<string>): boolean {
  const has = (k: string) => h.has(k);
  if (!has("url") || !(has("timestamp") || has("date"))) return false;
  return (
    has("interpretation") || has("profile folder") || has("profile_folder") || (has("type") && has("profile"))
  );
}
