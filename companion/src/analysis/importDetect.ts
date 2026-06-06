// Auto-detect which importer an uploaded file should route to, so the dashboard can offer a
// single "Import" button and the server picks the right deterministic/AI importer. Detection
// is a cheap sniff: structural (JSON object/array/NDJSON vs CSV vs plain log), then key/header
// signatures mirroring each importer's own classifier — ordered most-specific → most-generic.
//
// Returns a kind that maps 1:1 to a pipeline import method (see server `/cases/:id/import`).
// The detected kind is shown back to the analyst, so a mis-route is visible, not silent.

import { isObject, getCI, getPath, str } from "./siemImport.js";
import { parseCsv } from "./csvImport.js";

export type ImportKind =
  | "thor" | "siem" | "chainsaw" | "hayabusa" | "velociraptor" | "network"
  | "kape" | "cybertriage" | "m365" | "aws" | "cloud" | "plaso" | "sandbox" | "csv" | "log" | "unknown";

type Row = Record<string, unknown>;

const CONTAINER_KEYS = ["Records", "data", "events", "records", "results", "logs", "value", "alerts"];

function firstObj(arr: unknown[]): Row | null {
  for (const el of arr) if (isObject(el)) return el;
  return null;
}

// Parse the file as JSON (whole, or first NDJSON line) and unwrap one representative record.
function jsonSample(text: string): { root: unknown; sample: Row | null } {
  const t = text.trim();
  let root: unknown;
  if (t[0] === "{" || t[0] === "[") {
    try { root = JSON.parse(t); } catch { root = undefined; }
  }
  if (root === undefined) {
    // NDJSON: first parseable object line.
    for (const line of t.split(/\r\n|\r|\n/)) {
      const l = line.trim();
      if (!l || (l[0] !== "{" && l[0] !== "[")) continue;
      try { root = JSON.parse(l); break; } catch { /* keep scanning */ }
    }
  }
  if (Array.isArray(root)) return { root, sample: firstObj(root) };
  if (isObject(root)) {
    const hits = getPath(root, "hits.hits");
    if (Array.isArray(hits)) return { root, sample: firstObj(hits) };
    for (const k of CONTAINER_KEYS) {
      const arr = getCI(root, k);
      if (Array.isArray(arr)) return { root, sample: firstObj(arr) };
    }
    return { root, sample: root };
  }
  return { root, sample: null };
}

// ───────────────────────────── JSON record signatures (ordered) ─────────────────────────────

function isSandbox(s: Row): boolean {
  return (!!getCI(s, "info") && (!!getCI(s, "signatures") || !!getCI(s, "target"))) ||
    (getCI(s, "verdict") != null && (getCI(s, "threat_score") != null || !!getCI(s, "mitre_attcks") || !!getCI(s, "vx_family") || !!getCI(s, "submit_name"))) ||
    !!getCI(s, "CAPE") || getCI(s, "malscore") != null;
}
function isAws(s: Row): boolean {
  return !!getCI(s, "eventName") && !!getCI(s, "eventSource");
}
function isGcp(s: Row): boolean {
  return !!getCI(s, "protoPayload") || /cloudaudit/i.test(str(getCI(s, "logName")));
}
function isAzure(s: Row): boolean {
  return (!!getCI(s, "operationName") || !!getCI(s, "OperationNameValue") || !!getCI(s, "OperationName")) &&
    (!!getCI(s, "caller") || !!getCI(s, "Caller") || !!getCI(s, "resourceId") || !!getCI(s, "ResourceId") || !!getCI(s, "correlationId"));
}
function isM365(s: Row): boolean {
  return !!getCI(s, "Operation") || !!getCI(s, "Operations") || !!getCI(s, "AuditData") ||
    (!!getCI(s, "userPrincipalName") && (!!getCI(s, "riskState") || !!getCI(s, "riskLevelDuringSignIn") || !!getCI(s, "status"))) ||
    (!!getCI(s, "activityDisplayName") && (!!getCI(s, "initiatedBy") || !!getCI(s, "targetResources")));
}
function isChainsaw(s: Row): boolean {
  // Chainsaw hunt (embedded document/rule) or a raw evtx_dump record ({ Event: { System } }).
  return !!getCI(s, "document") || !!getCI(s, "documents") ||
    (isObject(getCI(s, "Event")) && isObject(getPath(s, "Event.System")));
}
function isVelociraptor(s: Row, root: unknown): boolean {
  if (!!getCI(s, "_Source") || !!getCI(s, "Artifact") || !!getCI(s, "_Artifact")) return true;
  const rule = getCI(s, "Rule");
  if (typeof rule === "string" && (!!getCI(s, "Strings") || !!getCI(s, "Meta") || !!getCI(s, "Namespace"))) return true;
  if (isObject(getCI(s, "System")) && !!getCI(s, "EventData")) return true; // VR parsed-evtx (no Event wrapper)
  return isArtifactMap(root);
}
function isArtifactMap(root: unknown): boolean {
  if (!isObject(root) || Array.isArray(root)) return false;
  const entries = Object.entries(root);
  return entries.length > 0 &&
    entries.every(([k, v]) => Array.isArray(v) && !CONTAINER_KEYS.includes(k.toLowerCase())) &&
    entries.some(([, v]) => (v as unknown[]).some(isObject));
}
function isHayabusaJson(s: Row): boolean {
  if (!!getCI(s, "RuleTitle")) return true;
  if (!!getCI(s, "Level") && (!!getCI(s, "MitreTactics") || !!getCI(s, "MitreTags"))) return true;
  // Velociraptor's `Windows.Hayabusa.Rules` artifact emits Hayabusa VERDICT rows: a rule `Title`
  // + `Level` over a Windows `Channel`/`EID`/`RecordID` (it uses `Title`, not `RuleTitle`, and
  // carries no Mitre columns). A raw SIEM event has no rule `Title`, so this is specific enough to
  // claim here — ahead of the `Channel`-based `isSiem` catch-all — and the Hayabusa importer maps
  // it verdict-first instead of mislabeling each row "SIEM event:".
  if (!!getCI(s, "Title") && !!getCI(s, "Level") &&
      (!!getCI(s, "Channel") || getCI(s, "EID") != null || getCI(s, "RecordID") != null)) return true;
  return false;
}
function isNetwork(s: Row): boolean {
  return !!getCI(s, "event_type") || !!getCI(s, "_path");
}
// Cyber Triage timeline JSONL: every row carries `epoch_timestamp` + (`timestamp_desc` |
// `timestamp_description`) + `message`, with a Cyber Triage `score`/`scoreDescription` verdict.
// Specific enough to claim ahead of the `message`-based SIEM catch-all.
function isCybertriage(s: Row): boolean {
  return getCI(s, "epoch_timestamp") != null &&
    (getCI(s, "timestamp_desc") != null || getCI(s, "timestamp_description") != null) &&
    (getCI(s, "message") != null || getCI(s, "score") != null || getCI(s, "scoreDescription") != null);
}
function isThor(s: Row): boolean {
  return !!getCI(s, "module") && !!getCI(s, "message") && !!getCI(s, "level");
}
function isSiem(s: Row): boolean {
  return !!getCI(s, "event_id") || !!getCI(s, "EventID") || !!getCI(s, "winlog") ||
    !!getCI(s, "log_name") || !!getCI(s, "Channel") || !!getCI(s, "channel") ||
    !!getCI(s, "@timestamp") || !!getCI(s, "message") || !!getCI(s, "_source");
}

function detectJson(root: unknown, sample: Row): ImportKind {
  if (isSandbox(sample)) return "sandbox";
  if (isAws(sample)) return "aws";
  if (isGcp(sample)) return "cloud";
  if (isAzure(sample)) return "cloud";
  if (isM365(sample)) return "m365";
  if (isChainsaw(sample)) return "chainsaw";
  if (isVelociraptor(sample, root)) return "velociraptor";
  if (isHayabusaJson(sample)) return "hayabusa";
  if (isCybertriage(sample)) return "cybertriage";
  if (isNetwork(sample)) return "network";
  if (isThor(sample)) return "thor";
  if (isSiem(sample)) return "siem";
  return "siem"; // any other event-shaped JSON → the SIEM importer's field auto-detection
}

// ───────────────────────────── CSV header signatures ─────────────────────────────

const has = (h: Set<string>, ...keys: string[]): boolean => keys.every((k) => h.has(k.toLowerCase()));

function m365CsvSig(h: Set<string>): boolean {
  return h.has("auditdata") || (h.has("operations") && h.has("recordtype"));
}
function plasoSig(h: Set<string>): boolean {
  return (h.has("datetime") && h.has("message")) ||
    (h.has("date") && h.has("time") && h.has("timezone") && (h.has("desc") || h.has("short")));
}
function hayabusaCsvSig(h: Set<string>): boolean {
  return (h.has("ruletitle") || h.has("rule title")) && h.has("level");
}
function cybertriageCsvSig(h: Set<string>): boolean {
  // Cyber Triage timeline CSV header: event_timestamp,epoch_timestamp,message,timestamp_description,item_type,threat_level
  return h.has("event_timestamp") && h.has("epoch_timestamp") && h.has("timestamp_description");
}
function kapeSig(h: Set<string>): boolean {
  return has(h, "executablename", "runcount") || has(h, "fullpath", "sha1") || has(h, "fullpath", "filekeylastwritetimestamp") ||
    (h.has("path") && h.has("lastmodifiedtimeutc")) || has(h, "updatereasons", "updatetimestamp") ||
    (has(h, "parentpath", "filename") && (h.has("created0x10") || h.has("lastmodified0x10"))) ||
    has(h, "bytessent", "bytesreceived") || has(h, "deletedon", "filename") ||
    (h.has("absolutepath") && (h.has("lastinteracted") || h.has("firstinteracted"))) ||
    has(h, "targetcreated", "arguments") || (h.has("appid") && h.has("path") && h.has("targetcreated"));
}

function detectCsv(text: string): ImportKind {
  const { headers, rows } = parseCsv(text);
  if (headers.length === 0) return "unknown";
  const h = new Set(headers.map((x) => x.trim().toLowerCase()));
  if (m365CsvSig(h)) return "m365";
  if (cybertriageCsvSig(h)) return "cybertriage";
  if (plasoSig(h)) return "plaso";
  if (hayabusaCsvSig(h)) return "hayabusa";
  if (kapeSig(h)) return "kape";
  // A comma-delimited table with data rows → the generic (AI) CSV importer.
  if (headers.length >= 2 && rows.length > 0) return "csv";
  return "log";
}

// Velociraptor names its JSON exports after the collected artifact, e.g.
// `Velociraptor-Windows.Triage.HighValueMemory.json` or `Generic.System.Pstree.json`. Many
// artifacts (process lists, file listings, memory acquisition) emit rows with no distinctive
// content signature, so they sniff as the generic SIEM fallback. When the FILENAME marks a
// Velociraptor export we route those to the Velociraptor importer instead — it reads each
// artifact's own columns and tags the source, rather than mislabeling rows "SIEM event:".
const VR_ARTIFACT = /\b(?:Windows|Linux|MacOS|Generic|Custom|Server|Exchange|Admin|Network)\.[A-Za-z]\w*(?:\.\w+)+/;
function looksLikeVelociraptorFile(filename: string): boolean {
  const n = filename ?? "";
  return /velociraptor/i.test(n) || VR_ARTIFACT.test(n);
}

// ───────────────────────────── top-level ─────────────────────────────

export function detectImportKind(filename: string, text: string): ImportKind {
  const t = (text ?? "").trim();
  if (!t) return "unknown";

  // A Velociraptor-named export that only matched the generic SIEM fallback is better served by
  // the Velociraptor importer (a more-specific content match — sandbox/hayabusa/… — always wins).
  const vrHint = (k: ImportKind): ImportKind =>
    k === "siem" && looksLikeVelociraptorFile(filename) ? "velociraptor" : k;

  // JSON / NDJSON.
  if (t[0] === "{" || t[0] === "[") {
    const { root, sample } = jsonSample(t);
    if (sample) return vrHint(detectJson(root, sample));
    return "unknown"; // looked like JSON but unparseable / not an object
  }
  // NDJSON that doesn't start with a brace is unusual; still try a first-line parse.
  const firstLine = t.split(/\r\n|\r|\n/, 1)[0]?.trim() ?? "";
  if (firstLine[0] === "{") {
    const { root, sample } = jsonSample(t);
    if (sample) return vrHint(detectJson(root, sample));
  }

  // Tabular (CSV / EZ / Plaso / Hayabusa-csv / M365-csv) vs a line-oriented log.
  const csvKind = detectCsv(t);
  if (csvKind !== "unknown" && csvKind !== "log") return csvKind;
  // No CSV signature and no comma-table → treat as a generic log (AI line triage).
  return "log";
}
