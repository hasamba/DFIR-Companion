// Deterministic importer for Velociraptor native JSON output — the fifth deterministic
// ingest path (THOR, SIEM, Chainsaw, Hayabusa, Velociraptor); no AI call.
//
// Velociraptor is a collection + detection platform: VQL artifacts emit JSON rows whose
// columns vary completely by artifact. Per the Companion's post-detection principle we
// ingest its OUTPUT — we do not run VQL/Sigma/YARA ourselves. The richest rows for the
// timeline are its DETECTION artifacts, so each row is classified and mapped accordingly:
//
//   • Sigma     (`*.Detection.Sigma`, or a `Rule:{Title,Level}` + parsed event) — verdict
//                first: the matched rule's Level drives severity, its Title leads the
//                description, its tags become MITRE; the parsed EVTX event underneath is
//                mapped with the SAME per-EID logic the SIEM/Chainsaw paths use (reused).
//   • YARA      (`*.Detection.Yara.*`, or a string `Rule` + Strings/Meta/Namespace) — a
//                real detection ⇒ High; rule name + scanned file/process + hash → event+IOCs.
//   • EventLog  (a parsed evtx row: `System`+`EventData`) — reuse `mapWindows` per-EID.
//   • Generic   (pslist / netstat / file listing / any other artifact) — auto-detect the
//                artifact's own time (NOT the `_ts` collection time unless nothing better),
//                host, and message; pull IOCs from every column.
//
// Inputs accepted: a JSON array, JSONL/NDJSON (the native collection-results form), a single
// object, an Elastic-style wrapper, or a Velociraptor multi-artifact map { "Artifact.Name":
// [rows], … }. All events are tagged "Velociraptor" for cross-source correlation.

import type { Severity } from "./stateTypes.js";
import { parseCsv } from "./csvImport.js";
import {
  extractRecords,
  mapWindows,
  aggregateEvents,
  flatten,
  genericIocs,
  parseHashes,
  cleanIp,
  addIoc,
  mergeRowIocs,
  firstStr,
  baseName,
  oneLine,
  worst,
  str,
  isObject,
  getCI,
  getPath,
  normalizeTime,
  type MappedEvent,
  type SiemEvent,
  type SiemIoc,
} from "./siemImport.js";
// A row from a Velociraptor artifact that shells out to Chainsaw and streams its rows back as
// VQL (e.g. a custom "run chainsaw" artifact) carries Chainsaw's flat Sigma-mapping shape
// (Detection/Severity/Rule Group siblings), not Velociraptor's own DetectRaptor {Detection:{Name,
// Criticality}} convention — reuse chainsawImport's shape check + mapper so it isn't misclassified
// as a generic detection() row, which would read no severity from a sibling field and silently
// downgrade a real Critical (e.g. "Security Audit Logs Cleared") to a keyword-guessed Medium.
import { isFlatChainsawRow, mapFlatChainsawRow } from "./chainsawImport.js";

type Row = Record<string, unknown>;

// ───────────────────────── Elastic-indexed Velociraptor normalization ─────────────────────────
//
// When Velociraptor uploads to Elasticsearch and the analyst pushes the Kibana search back, the rows
// arrive RESHAPED by ES, not in native VQL form: nested columns are flattened to dotted keys
// (`Detection.StringHit`), text fields gain `.keyword`/`.text` multi-fields, the artifact name lives
// in the `artifact_<name>` index, and ES doc metadata (`_id`/`_index`/`_version`) rides along. This
// reverses that so the classifier/mappers below see the native nested shape. It is GATED (only runs
// when a row has dotted keys or an `artifact_` index), so native Velociraptor JSON is untouched.

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
    let cur: Row = out;
    let ok = true;
    for (let i = 0; i < parts.length - 1; i++) {
      const next = cur[parts[i]];
      if (next === undefined) { const o: Row = {}; cur[parts[i]] = o; cur = o; }
      else if (isObject(next)) { cur = next as Row; }
      else { ok = false; break; } // collision — a leaf sits where a branch is needed
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
    if (bare !== k) { if (!(bare in collapsed) && !(bare in row)) collapsed[bare] = v; }
    else collapsed[k] = v;
  }
  // 2) Un-flatten the remaining dotted keys to nested objects.
  const nested = unflattenDotted(collapsed);
  // 3) Synthesize the artifact source from the ES index name when the row carries no artifact field.
  if (!getCI(nested, "_Source") && !getCI(nested, "Artifact") && /^artifact[_-]/i.test(idx)) {
    nested._Source = idx.replace(/^artifact[_-]/i, "");
  }
  return nested;
}

export interface VelociraptorImportOptions {
  aggregate?: boolean;
  minSeverity?: Severity;
  maxEvents?: number;
  maxIocs?: number;
  artifact?: string;   // fallback artifact/source label (e.g. the filename) when rows carry no _Source
  hostFallback?: string;   // asset to stamp on events whose row carries no host (single-client flow import)
}

export interface VelociraptorParseResult {
  events: SiemEvent[];
  iocs: SiemIoc[];
  total: number;       // rows found
  kept: number;        // events emitted (after aggregation + cap)
  dropped: number;     // rows not represented (below floor / capped)
  groups: number;      // distinct event groups before the cap
  detections: number;  // Sigma + YARA detection rows seen
  format: string;      // "array" | "jsonl" | "artifact-map" | "single" | …
  hostname: string;
}

const IPV4 = /^\d{1,3}(?:\.\d{1,3}){3}$/;
const HEX_HASH = /^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i;

const SIGMA_LEVEL: Record<string, Severity> = {
  critical: "Critical", crit: "Critical",
  high: "High",
  medium: "Medium", med: "Medium",
  low: "Low",
  informational: "Info", info: "Info",
};
const SEV_WORDS: Record<string, Severity> = {
  ...SIGMA_LEVEL, warning: "Medium", warn: "Medium", error: "High", notice: "Low", alert: "Critical",
};

const WRAPPER_KEYS = new Set(["data", "hits", "events", "records", "results", "logs", "rows", "items", "alerts", "value"]);

// Pull MITRE technique ids out of any tactic/tag/meta text.
function mitreFromText(...parts: string[]): string[] {
  const out = new Set<string>();
  for (const p of parts) for (const m of p.matchAll(/\bt\d{4}(?:\.\d{3})?\b/gi)) out.add(m[0].toUpperCase());
  return [...out];
}

function flatStr(v: unknown): string {
  if (v == null) return "";
  if (Array.isArray(v)) return v.map(flatStr).join(" ");
  if (isObject(v)) return Object.values(v).map(flatStr).join(" ");
  return String(v);
}

// The human-readable message for a row. Velociraptor Sigma/Hayabusa rows put it in `Details`; the
// parsed event (when present) carries its own `Message`. Used for the description AND for keeping
// distinct detections distinct (see msgFingerprint).
function rowMessage(row: Row): string {
  const m = firstStr(row, ["Message", "Details", "message"]);
  if (m) return m;
  const ev = getCI(row, "_Event");
  return isObject(ev) ? str(getCI(ev, "Message")) : "";
}

// The FULL untruncated event detail (raw EVTX rendered Message / ScriptBlock text, etc.) that the
// analyst may want to read in full, beyond the truncated one-line `description`. Generously capped
// so it stays bounded in state. Returns "" when there's no message OR the message adds nothing
// beyond what's already in `description` (so we don't stamp a redundant expandable block).
const MESSAGE_CAP = 4000;
function fullMessage(row: Row, description: string): string {
  const raw = rowMessage(row).trim();
  if (!raw) return "";
  const capped = raw.length > MESSAGE_CAP ? `${raw.slice(0, MESSAGE_CAP)}…` : raw;
  // If the description already contains (nearly) the whole message there's no extra detail to reveal.
  if (description.includes(raw) || raw.length <= 80) return "";
  return capped;
}

// High-signal labels in a RENDERED Windows event message (4688 process creation, Sysmon, service
// install, etc.). When an artifact ships the event as free text — no structured EventData to map —
// these carry the actual evidence (the LOLBIN binary + its command line), which the boilerplate
// header ("Creator Subject… Target Subject…") buries past the description cut-off. Surfacing them
// makes e.g. "Use of 32-bit LOLBINs" name the binary that ran, not just the rule. (#102)
const MSG_FIELD_LABELS = [
  "New Process Name", "Process Command Line", "CommandLine", "Command Line",
  "Image", "Application Name", "TargetFilename", "Service File Name", "ServiceFileName", "ScriptBlockText",
];
// Velociraptor renders some fields with a trailing "!S!" sentinel — strip it for readability.
function cleanFieldValue(v: string): string {
  return v.trim().replace(/!S!\s*$/, "").trim();
}
function fieldFromMessage(msg: string, label: string): string {
  const re = new RegExp(`${label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\s*:[ \\t]*([^\\r\\n]+)`, "i");
  const m = re.exec(msg);
  return m ? cleanFieldValue(m[1]) : "";
}
function salientFromMessage(msg: string): string {
  if (!msg || !msg.includes(":")) return "";
  const seen = new Set<string>();
  const out: string[] = [];
  for (const label of MSG_FIELD_LABELS) {
    const v = fieldFromMessage(msg, label);
    if (v && v !== "-" && !seen.has(v)) { seen.add(v); out.push(`${label}: ${v}`); }
  }
  return out.join(" - ").slice(0, 400);
}
// The created/executed process named in a rendered event message (the LOLBIN), for the structured
// processName field + IOC when the row carries no structured process column.
function parsedNewProcess(msg: string): string {
  return fieldFromMessage(msg, "New Process Name") || fieldFromMessage(msg, "Image");
}

// A stable djb2 hash → base36, for folding message content into an aggregation key compactly.
function hashStr(s: string): string {
  let h = 5381;
  for (let i = 0; i < s.length; i++) h = (((h << 5) + h) + s.charCodeAt(i)) | 0;
  return (h >>> 0).toString(36);
}

// Fingerprint a message for aggregation: normalize away VOLATILE bits (GUIDs, any digits — PIDs,
// thread/record ids, counters) but keep the words, then hash the WHOLE thing. So two detections
// that differ only in a PID collapse, while two that name different tools (HackTool:Passview vs
// HackTool:Mimikatz) stay separate — the message, not just the rule title, decides identity. The
// hash (not a prefix) means a distinguishing token anywhere in a long, boilerplate-heavy message
// still separates the events.
function msgFingerprint(msg: string): string {
  const norm = oneLine(msg).toLowerCase()
    .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/g, "")
    .replace(/\d+/g, "")
    .replace(/[^a-z]+/g, " ")
    .trim();
  return norm ? hashStr(norm) : "";
}

// ───────────────────────────── detection verdicts ─────────────────────────────

// Many Velociraptor "*.Detection.*" artifacts (DetectRaptor et al.) carry their VERDICT in a
// `Detection` field — a bare string ("Cobalt Strike: trick_ryuk.profile") or an object with a
// rule `Name` (+ optional `Criticality`/`Severity`) — or in `RuleName`/`RuleID`. Per the
// post-detection principle we consume that verdict (we don't re-evaluate the rule): its text
// leads the description, its own criticality drives severity, and any Txxxx ids become MITRE.
interface Verdict { title: string; critWord: string; mitre: string[] }

function rowVerdict(row: Row): Verdict | null {
  const d = getCI(row, "Detection");
  let title = "";
  let critWord = "";
  if (typeof d === "string") title = d.trim();
  else if (isObject(d)) {
    title = str(getCI(d, "Name") ?? getCI(d, "Title") ?? getCI(d, "Rule") ?? getCI(d, "ID")).trim();
    critWord = str(getCI(d, "Criticality") ?? getCI(d, "Severity") ?? getCI(d, "Level")).trim().toLowerCase();
    // DetectRaptor "keyword scan" detections (e.g. .Detection.MFT) carry the matched string in
    // StringHit/HitString rather than a rule Name — use it as the verdict subject so the row is
    // treated as a detection (severity escalates on a malware/tool keyword) instead of generic noise.
    if (!title) title = str(getCI(d, "StringHit") ?? getCI(d, "HitString") ?? getCI(d, "Hit")).trim();
  }
  if (!title) title = firstStr(row, ["RuleName", "RuleID"]).trim();
  if (!title) return null;
  const mitre = mitreFromText(title, firstStr(row, ["RuleName"]), flatStr(getCI(row, "Tags") ?? getCI(row, "Mitre")));
  return { title, critWord, mitre };
}

// Known malware-family / offensive-tooling keywords in a verdict title → escalate. These read
// the tool's OWN verdict wording, not the raw artifact, so it stays "consume, don't re-detect".
const CRIT_KEYWORDS = /ransom|lockbit|\bconti\b|wannacry|black\s*cat|\balphv\b|emotet|trickbot|qakbot|\bhive\b/i;
const HIGH_KEYWORDS = /cobalt\s*strike|mimikatz|web\s*shell|webshell|lazagne|rubeus|sharphound|bloodhound|meterpreter|\bbeacon\b|reverse\s*shell|secretsdump|psexec|\bsliver\b|brute\s*ratel|nanodump|seatbelt|\blsass\b|kerberoast|dcsync|impacket/i;

// Severity for a detection verdict: the rule's explicit Criticality/Severity wins; else
// DetectRaptor conventions (a "BAU …" baseline or an "IN DEVELOPMENT" rule → Low); else a
// malware/tool keyword escalates; else Medium (a named detection rule fired — worth surfacing).
function detectionSeverity({ title, critWord }: Verdict): Severity {
  const explicit = critWord ? (SIGMA_LEVEL[critWord] ?? SEV_WORDS[critWord]) : undefined;
  if (explicit) return explicit;
  if (/\bin\s*development\b/i.test(title)) return "Low";
  if (/^\s*bau\b/i.test(title)) return "Low";
  if (CRIT_KEYWORDS.test(title)) return "Critical";
  if (HIGH_KEYWORDS.test(title)) return "High";
  return "Medium";
}

// ───────────────────────────── timestamps ─────────────────────────────

// Velociraptor times arrive as RFC3339 strings, epoch numbers (`_ts` is collection-time
// epoch seconds), or `{ SystemTime }` objects. Normalize any of them to UTC ISO.
function vrTime(v: unknown): string {
  if (v == null) return "";
  if (typeof v === "number") {
    if (!Number.isFinite(v) || v <= 0) return "";
    const d = new Date(v > 1e12 ? v : v * 1000); // >1e12 ⇒ already ms
    return Number.isNaN(d.getTime()) ? "" : d.toISOString();
  }
  if (isObject(v)) {
    const st = getCI(v, "SystemTime") ?? getPath(v as Row, "#attributes.SystemTime");
    return st != null ? vrTime(st) : "";
  }
  return normalizeTime(str(v));
}

// The artifact's OWN time first; `_ts` (collection time) only as a last resort. Includes a few
// nested forensic containers (MFT $SI/$FN, file-info, hit-context) and registry/app keys so the
// detection artifacts that bury their time one level down still get a real timestamp.
const TIME_KEYS = [
  "System.TimeCreated.SystemTime", "System.TimeCreated", "EventTime", "EventTimestamp", "Mtime", "Btime",
  "Ctime", "Created", "CreationTime", "LastWriteTime", "KeyLastWriteTimestamp", "KeyMTime", "TimeGenerated",
  "Timestamp", "timestamp", "time", "StartTime",
  "SITimestamps.LastModified0x10", "SITimestamps.LastRecordChange0x10", "SITimestamps.Created0x10", "FNTimestamps.Created0x30",
  // Bare NTFS $FILE_NAME / $STANDARD_INFO timestamps: Windows.NTFS.MFT (and USN) emit these as TOP-LEVEL
  // columns on many server versions (not nested under SITimestamps/FNTimestamps), so an MFT row would
  // otherwise land with NO time. Prefer $FN Created (0x30 — harder to timestomp) per analyst preference,
  // then $SI Created, then last-modified / record-change / access.
  "Created0x30", "Created0x10", "LastModified0x10", "LastModified0x30", "LastRecordChange0x10", "LastAccess0x10",
  // Windows.Forensics.Lnk buries the target's birth time under OSPath (the stat object), so the shortcut
  // lands dated at its target's creation. Browser-history (visit) + registry (UserAssist/Shellbags) time
  // columns whose exact names vary by version.
  "OSPath.Btime", "visit_time", "last_visit_time", "LastVisited", "LastExecution", "LastExecutionTime", "last_run",
  // Nested file-stat blocks: FileInfo.* (DetectRaptor PSReadline), Stat.* (the Generic PSReadline /
  // QuickWins shape), so history-line + Amcache/LolDrivers (KeyMTime) rows land dated, not at epoch 0.
  "FileInfo.Mtime", "FileInfo.Ctime", "FileInfo.Btime", "Stat.Mtime", "Stat.Ctime", "Stat.Btime", "HitContext.Mtime",
  "@timestamp", // Elasticsearch-indexed rows (Kibana push) carry the event time here
];

// A column whose NAME denotes an event time — used by the fallback scan when no explicit TIME_KEY matched.
const TIME_NAME_RE = /(?:time|date|created|modif|written|changed|access|visit|execut|last.?run|last.?used|btime|mtime|ctime|atime|\bborn\b)/i;
// Plausibility window for the fallback: skip FILETIME (1601) / Unix (1970) / epoch-0 "unset" sentinels
// and absurd far-future values, so a blank timestamp field can't date an event to the year 1601.
const MIN_TIME_MS = Date.parse("2000-01-01T00:00:00Z");
const MAX_TIME_MS = Date.parse("2100-01-01T00:00:00Z");

function pickTime(row: Row): string {
  for (const k of TIME_KEYS) {
    const v = k.includes(".") ? getPath(row, k) : getCI(row, k);
    const t = vrTime(v);
    if (t) return t;
  }
  // Fallback: no known column matched (browser history, shellbags, userassist, and other raw artifacts
  // whose time column varies by Velociraptor version). Scan every time-NAMED column (incl. one nesting
  // level) for the EARLIEST plausible timestamp — a real artifact time beats the `_ts` collection time
  // below, and a blank/sentinel field can't win.
  let best = "", bestMs = Infinity;
  const scan = (obj: Row, prefix: string, depth: number): void => {
    for (const [k, v] of Object.entries(obj)) {
      if (v == null) continue;
      if (isObject(v)) { if (depth < 1) scan(v as Row, `${prefix}${k}.`, depth + 1); continue; }
      if (Array.isArray(v)) continue;
      if (!TIME_NAME_RE.test(prefix + k)) continue;
      const t = vrTime(v);
      if (!t) continue;
      const ms = Date.parse(t);
      if (ms >= MIN_TIME_MS && ms <= MAX_TIME_MS && ms < bestMs) { bestMs = ms; best = t; }
    }
  };
  scan(row, "", 0);
  if (best) return best;
  return vrTime(getCI(row, "_ts"));   // collection time — absolute last resort, only when nothing else dated the row
}

const HOST_KEYS = ["Fqdn", "Hostname", "Computer", "System.Computer", "Host", "ClientName"];
function pickHost(row: Row): string {
  for (const k of HOST_KEYS) {
    const v = k.includes(".") ? getPath(row, k) : getCI(row, k);
    const s = str(v).trim();
    if (s) return s;
  }
  return "";
}

// ───────────────────────────── IOCs / hashes ─────────────────────────────

function vrHashes(row: Row): { sha256?: string; md5?: string } {
  const h = parseHashes(row, row); // "Hashes" string + hashes_ex object
  let { sha256, md5 } = h;
  if (!sha256) {
    const d = firstStr(row, ["HashSHA256", "SHA256", "Sha256", "sha256", "UploadSHA256", "Hash.SHA256", "Hash.Sha256"]).toLowerCase();
    if (/^[a-f0-9]{64}$/.test(d)) sha256 = d;
  }
  if (!md5) {
    const d = firstStr(row, ["MD5", "Md5", "md5", "Hash.MD5", "Hash.Md5"]).toLowerCase();
    if (/^[a-f0-9]{32}$/.test(d)) md5 = d;
  }
  return { sha256, md5 };
}

// A compiled Sigma signature file (Velociraptor's ".yms" convention) — never an observed
// indicator, since a hit naming one is a match against the RULE's own content, not evidence.
const isYmsPath = (v: string): boolean => /\.yms$/i.test(v.trim());

// Extract IOCs from every column of a row (used by generic + YARA rows).
function collectRowIocs(row: Row, sink: Map<string, SiemIoc>): { sha256?: string; md5?: string } {
  const pairs: [string, string][] = [];
  flatten(row, pairs);
  genericIocs(pairs.filter(([, v]) => !isYmsPath(v)), sink);
  const { sha256, md5 } = vrHashes(row);
  if (sha256) addIoc(sink, "hash", sha256);
  else if (md5) addIoc(sink, "hash", md5);
  for (const [k, v] of pairs) {
    const val = v.trim();
    const ip = cleanIp(val);
    if (ip && (/ip|addr/i.test(k) || IPV4.test(val))) addIoc(sink, "ip", ip);
    if (HEX_HASH.test(val)) addIoc(sink, "hash", val.toLowerCase());
  }
  return { sha256, md5 };
}

// Scrape IOCs out of a free-text detection field (a matched command Line, file Content, or
// HitString) — `genericIocs` only fires on structured keys, so the download URL / C2 IP embedded
// in a PowerShell-web-request or webshell hit (exactly the indicator the rule fired on) is
// otherwise missed. URLs, octet-bounded IPv4 (so "10.0.22000" version strings aren't IPs), and
// SHA256/SHA1/MD5 hashes.
const TEXT_URL = /\bhttps?:\/\/[^\s"'<>)\]}]+/gi;
const TEXT_IPV4 = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
const TEXT_HASH = /\b[a-f0-9]{64}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{32}\b/gi;
function scrapeText(text: string, sink: Map<string, SiemIoc>): void {
  if (!text) return;
  for (const m of text.matchAll(TEXT_URL)) addIoc(sink, "url", m[0].replace(/[.,;:)\]]+$/, "").slice(0, 300));
  for (const m of text.matchAll(TEXT_IPV4)) { const ip = cleanIp(m[0]); if (ip) addIoc(sink, "ip", ip); }
  for (const m of text.matchAll(TEXT_HASH)) addIoc(sink, "hash", m[0].toLowerCase());
}

// The free-text fields that carry a detection's evidence (and its embedded IOCs).
const EVIDENCE_TEXT_KEYS = ["Line", "Content", "CommandLine", "HitString", "StringHit", "Message", "Details"];
function scrapeEvidence(row: Row, sink: Map<string, SiemIoc>): void {
  for (const k of EVIDENCE_TEXT_KEYS) scrapeText(str(getCI(row, k)), sink);
}

// ───────────────────────────── EVTX-row normalization ─────────────────────────────

// A Velociraptor parsed-evtx row carries `System` + `EventData` (sometimes under `Event`), or —
// for artifacts that flatten the event (e.g. DetectRaptor's Windows.Detection.Evtx) — top-level
// `Channel`/`EventID`/`EventData`. Reshape either to the flat record `mapWindows` consumes,
// normalizing the EventID (number or `{ Value }`/`{ #text }`) to a bare value, plus the host.
function winRowToFlat(row: Row): { rec: Row; host: string } | null {
  const sys = isObject(getCI(row, "System")) ? (getCI(row, "System") as Row)
    : isObject(getPath(row, "Event.System")) ? (getPath(row, "Event.System") as Row) : null;
  const edRaw = getCI(row, "EventData") ?? getPath(row, "Event.EventData");

  if (sys) {
    let eid: unknown = getCI(sys, "EventID");
    if (isObject(eid)) eid = getCI(eid, "Value") ?? getCI(eid, "#text");
    const channel = str(getCI(sys, "Channel")) || str(getPath(sys, "Provider.Name")) || str(getPath(sys, "Provider.#attributes.Name"));
    return {
      host: str(getCI(sys, "Computer")).trim(),
      rec: { event_id: eid, channel, event_data: isObject(edRaw) ? edRaw : {}, "@timestamp": vrTime(getCI(sys, "TimeCreated")), message: str(getCI(row, "Message")) },
    };
  }

  // Flat shape: top-level Channel/EventID/EventData with no System wrapper.
  let eidFlat: unknown = getCI(row, "EventID") ?? getCI(row, "EventId");
  if (eidFlat == null && !isObject(edRaw)) return null;
  if (isObject(eidFlat)) eidFlat = getCI(eidFlat, "Value") ?? getCI(eidFlat, "#text");
  return {
    host: str(getCI(row, "Computer")).trim(),
    rec: { event_id: eidFlat, channel: str(getCI(row, "Channel")), event_data: isObject(edRaw) ? edRaw : {}, "@timestamp": pickTime(row), message: str(getCI(row, "Message")) },
  };
}

// ───────────────────────────── per-row mapping ─────────────────────────────

type Kind = "sigma" | "yara" | "chainsaw" | "detection" | "eventlog" | "pslist" | "netstat" | "download" | "startup" | "taskscheduler" | "generic";

function artifactName(row: Row): string {
  return firstStr(row, ["_Source", "Artifact", "_Artifact", "artifact", "Source", "ArtifactName"]);
}

function classify(row: Row, artifact: string): Kind {
  const a = artifact.toLowerCase();
  if (/yara/.test(a)) return "yara";
  if (/sigma/.test(a)) return "sigma";
  // Artifact-name fast-paths for the most common telemetry artifacts (column detection is the fallback)
  if (/netstat/.test(a)) return "netstat";
  if (/pslist|pstree|psscan/.test(a)) return "pslist";
  if (/browserdownload|evidence.*download/i.test(a)) return "download";
  if (/startup|autorun/i.test(a)) return "startup";
  if (/taskscheduler/i.test(a)) return "taskscheduler";

  const rule = getCI(row, "Rule");
  if (typeof rule === "string" && rule.trim() && (getCI(row, "Strings") || getCI(row, "Meta") || getCI(row, "Namespace") || getCI(row, "Rules"))) return "yara";
  if (isObject(rule) && (getCI(rule, "Title") || getCI(rule, "Level"))) return "sigma";

  // Chainsaw's flat Sigma-mapping row (Detection/Severity/Rule Group siblings) — BEFORE the
  // generic rowVerdict() check below, which would otherwise treat the bare `Detection` string
  // as a DetectRaptor verdict and never read the sibling `Severity`/`Rule Group` fields.
  if (isFlatChainsawRow(row)) return "chainsaw";

  // A `Detection`/`RuleName` verdict → verdict-first, BEFORE the eventlog branch so a detection
  // that also carries a parsed Windows event (DetectRaptor's Evtx) is overlaid, not flattened.
  if (rowVerdict(row)) return "detection";

  if (getCI(row, "System") || getCI(row, "EventData") || getPath(row, "Event.System")) {
    if (firstStr(row, ["Level"]) && firstStr(row, ["Title", "SigmaTitle", "RuleTitle"])) return "sigma";
    return "eventlog";
  }
  // Column-based fallbacks for files without _Source markers
  if (getCI(row, "CallChain") != null && getCI(row, "Pid") != null && getCI(row, "Name") != null) return "pslist";
  if (getCI(row, "Laddr") != null && getCI(row, "Lport") != null && getCI(row, "Status") != null) return "netstat";
  // Evidence-of-download rows: Zone.Identifier ADS data (DownloadedFilePath + HostUrl)
  if (getCI(row, "DownloadedFilePath") != null && getCI(row, "HostUrl") != null) return "download";
  // Startup/autorun rows: Name + OSPath + Enabled (Windows.Sys.StartupItems and similar)
  if (getCI(row, "Enabled") != null && getCI(row, "OSPath") != null && getCI(row, "Name") != null) return "startup";
  // Scheduled task rows (Windows.System.TaskScheduler/Analysis): TaskName is unique to this artifact
  if (getCI(row, "TaskName") != null && (getCI(row, "Mtime") != null || getCI(row, "OSPath") != null)) return "taskscheduler";
  return "generic";
}

function mapYara(row: Row, artifact: string, host: string, sink: Map<string, SiemIoc>): MappedEvent {
  const rule = getCI(row, "Rule");
  const ruleName = typeof rule === "string" && rule.trim() ? rule.trim()
    : str(getPath(row, "Rule.id")) || str(getPath(row, "Rule.Name")) || firstStr(row, ["RuleName", "Namespace"]) || "match";
  // A YARA hit's only OBSERVED indicator is the matched file (+ its hash / owning process). The rule's
  // Meta (reference/source_url/author/sample hashes), Strings, and the binary HitContext are detection
  // LOGIC — flattening the whole row (collectRowIocs) scrapes the rule's GitHub links and match-context
  // bytes as bogus IOCs (a pagefile scan produced 700+ junk hashes / 360+ junk URLs). Extract
  // selectively: structured file hash only. (#102)
  const { sha256, md5 } = vrHashes(row);
  if (sha256) addIoc(sink, "hash", sha256);
  else if (md5) addIoc(sink, "hash", md5);

  const path = firstStr(row, ["OSPath", "FullPath", "_FullPath", "File", "FilePath", "Path"]);
  const procName = firstStr(row, ["Exe", "ProcessName", "ImageName"]);
  const pid = firstStr(row, ["Pid", "ProcessId"]);
  if (path && !isYmsPath(path)) addIoc(sink, "file", path);
  if (procName) addIoc(sink, "process", baseName(procName));

  const mitre = mitreFromText(flatStr(getCI(row, "Meta")), flatStr(getCI(row, "Tags")), ruleName);

  let description = `Velociraptor YARA: ${ruleName}`;
  if (procName) description += ` - ${baseName(procName)}${pid ? ` (pid ${pid})` : ""}`;
  else if (path) description += ` - ${path}`;
  if (host) description += ` @ ${host}`;
  description = description.slice(0, 600);

  return {
    timestamp: pickTime(row),
    description,
    severity: "High", // a YARA hit is a real detection verdict
    mitre,
    aggKey: `vr-yara|${ruleName.toLowerCase()}|${(path || procName).toLowerCase()}|${host.toLowerCase()}`.slice(0, 400),
    sources: ["Velociraptor"],
    ...(sha256 ? { sha256 } : {}),
    ...(md5 && !sha256 ? { md5 } : {}),
    ...(path ? { path } : {}),
    ...(host ? { asset: host } : {}),
    ...(procName ? { processName: baseName(procName) } : {}),
  };
}

function mapSigma(row: Row, host: string, sink: Map<string, SiemIoc>): MappedEvent {
  const ruleObj = isObject(getCI(row, "Rule")) ? (getCI(row, "Rule") as Row) : undefined;
  const title = (ruleObj ? str(getCI(ruleObj, "Title")) : "") || firstStr(row, ["Title", "SigmaTitle", "RuleTitle"]) || "detection";
  const level = (ruleObj ? str(getCI(ruleObj, "Level")) : "") || firstStr(row, ["Level"]);
  const sev = SIGMA_LEVEL[level.toLowerCase()];
  const tags = mitreFromText(flatStr(ruleObj ? getCI(ruleObj, "Tags") : getCI(row, "Tags")), flatStr(getCI(row, "MitreTags")), title);

  const flat = winRowToFlat(row);
  const win = flat ? mapWindows(flat.rec, flat.host || host, sink) : null;
  if (win) {
    if (sev) win.severity = worst(win.severity, sev);
    for (const m of tags) if (!win.mitre.includes(m)) win.mitre.push(m);
    win.description = `Velociraptor Sigma: ${title} - ${win.description}`.slice(0, 600);
    win.aggKey = `vr-sigma|${title.toLowerCase()}|${win.aggKey}`;
    win.sources = ["Velociraptor"];
    if (!win.timestamp) win.timestamp = pickTime(row);
    return win;
  }
  // No parsed event underneath (e.g. a Windows.Sigma.Base row whose event sits in `Details`/`_Event`)
  // — lead with the verdict, then the message so the analyst sees WHAT fired, not just the rule name.
  collectRowIocs(row, sink);
  scrapeEvidence(row, sink);
  const message = rowMessage(row);
  const detail = salientFromMessage(message) || (message ? oneLine(message).slice(0, 400) : "");
  let description = `Velociraptor Sigma: ${title}`;
  if (detail) description += ` - ${detail}`;
  if (host) description += ` @ ${host}`;
  return {
    timestamp: pickTime(row),
    description: description.slice(0, 600),
    severity: sev ?? "Medium",
    mitre: tags,
    aggKey: `vr-sigma|${title.toLowerCase()}|${host.toLowerCase()}`.slice(0, 400),
    sources: ["Velociraptor"],
    ...(host ? { asset: host } : {}),
  };
}


// DetectRaptor ships many distinct "*.Detection.*" rule packs (MFT, Amcache, LolDrivers,
// PSReadline, ...) that all flow through rowVerdict()/mapDetection() — folding them all under the
// generic "Velociraptor detection" bucket hides WHICH rule pack actually fired. When the artifact
// names a DetectRaptor pack, lead with its specific technique name instead (e.g. "DetectRaptor MFT
// detection"); any other Velociraptor-hosted rule pack (Custom.*, Chainsaw, etc.) keeps the
// generic "Velociraptor detection" label.
function detectionLabel(artifact: string): string {
  const a = artifact.trim();
  if (/^DetectRaptor\./i.test(a)) {
    const last = a.split(".").pop();
    if (last) return `DetectRaptor ${last} detection`;
  }
  return "Velociraptor detection";
}

// A DetectRaptor-style detection: the `Detection`/`RuleName` verdict leads. If a parsed Windows
// event sits underneath (Evtx), overlay the verdict onto the per-EID mapping (like Sigma);
// otherwise build the event from the row's file/process/pipe/path + hashes.
function mapDetection(row: Row, artifact: string, host: string, sink: Map<string, SiemIoc>): MappedEvent {
  const v = rowVerdict(row)!; // guaranteed by classify()
  let severity = detectionSeverity(v);
  scrapeEvidence(row, sink); // pull URLs/IPs/hashes out of the matched command line / file content
  const label = detectionLabel(artifact);

  const flat = winRowToFlat(row);
  const win = flat ? mapWindows(flat.rec, flat.host || host, sink) : null;
  if (win) {
    win.severity = worst(win.severity, severity);
    for (const m of v.mitre) if (!win.mitre.includes(m)) win.mitre.push(m);
    win.description = `${label}: ${v.title} - ${win.description}`.slice(0, 600);
    win.aggKey = `vr-det|${v.title.toLowerCase()}|${win.aggKey}`.slice(0, 400);
    win.sources = ["Velociraptor"];
    if (!win.timestamp) win.timestamp = pickTime(row);
    return win;
  }

  // Non-event detection (file / registry / named-pipe / history-line hit, or a flattened EVTX
  // detection whose event sits only in the rendered Message).
  const inUse = getCI(row, "InUse");
  const fileDeleted = inUse === false || str(inUse).toLowerCase() === "false";
  const { sha256, md5 } = collectRowIocs(row, sink);
  const message = rowMessage(row);
  const salient = salientFromMessage(message); // LOLBIN + command line out of a 4688-style message
  // The triggering FILE: include the Amcache/driver/registry path fields (EntryPath/EntryName/
  // Detection.PathName) and the nested FileInfo.OSPath (DetectRaptor ISEAutoSave/PSReadline shape)
  // so a verdict names the file that fired it even when OSPath is nested one level down.
  const path = firstStr(row, ["OSPath", "FullPath", "_FullPath", "File", "FilePath", "Path", "KeyPath", "EntryPath", "EntryName"])
    || str(getPath(row, "FileInfo.OSPath")).trim()
    || str(getPath(row, "Detection.PathName"));
  // The matched file is itself a Sigma rule (.yms — Velociraptor's compiled Sigma signature
  // format): the "hit" is a keyword match against the RULE's own text (tool names, MITRE ids,
  // etc. embedded in the signature), not against attacker-controlled content. Treat as Info
  // regardless of what keyword tripped detectionSeverity, so shipping/updating detection content
  // doesn't itself read as a Critical/High finding.
  if (isYmsPath(path)) severity = "Info";
  // The matched CONTENT/evidence: the full matched line/Content the analyst needs to read, falling
  // back to the rule's own HitString (the substring it matched). Track the source field name so
  // it can be shown as a label (Line: / Content: / CommandLine: / etc.). NOT Detection.Regex /
  // KeywordRegex (the rule pattern itself, which stays out of the description).
  const EVIDENCE_FIELD_KEYS = ["Line", "Content", "CommandLine", "StringHit", "HitString"] as const;
  let evidenceKey = "";
  let evidence = "";
  for (const k of EVIDENCE_FIELD_KEYS) {
    const v = str(getCI(row, k)).trim();
    if (v) { evidenceKey = k; evidence = v; break; }
  }
  if (!evidence) {
    const hit = str(getPath(row, "Detection.HitString")).trim();
    if (hit) { evidenceKey = "HitString"; evidence = hit; }
  }
  const procRaw = firstStr(row, ["Exe", "Image", "ProcessName", "ProcName", "NewProcessName"]) || parsedNewProcess(message);
  const parentRaw = firstStr(row, ["ParentName", "ParentImage", "ParentProcessName"]);
  const processName = procRaw ? baseName(procRaw) : undefined;
  const parentName = parentRaw ? baseName(parentRaw) : undefined;
  const pipe = firstStr(row, ["PipeName"]);
  if (processName) addIoc(sink, "process", processName);
  if (path && !isYmsPath(path)) addIoc(sink, "file", path);

  // Subject priority: the rendered event's high-signal fields (the actual LOLBIN/command line) win
  // over structured process/path, which win over the matched content/line. Every field is labeled
  // with its source key (ProcName: / PipeName: / Path: / Line: / Content: / …) and joined with
  // " - " so the analyst can read them at a glance without knowing the artifact's column layout.
  // Content-centric detections (ISEAutoSave, PSReadline) get both the filename AND the evidence.
  let subject: string;
  if (salient) {
    subject = salient;
  } else {
    const parts: string[] = [];
    if (processName) parts.push(`ProcName: ${processName}`);
    if (pipe) parts.push(`PipeName: ${pipe}`);
    if (path) parts.push(`Path: ${baseName(path)}`);
    if (parts.length === 0) {
      // No structured fields — fall back to the labeled evidence or plain message.
      if (evidence) {
        parts.push(`${evidenceKey}: ${oneLine(evidence)}`);
      } else {
        parts.push(oneLine(message));
      }
    } else if (!processName && !pipe && evidence) {
      // Content-centric detection (ISEAutoSave / PSReadline): path found but the evidence IS the
      // main signal — include it labeled so the analyst sees what the rule matched.
      parts.push(`${evidenceKey}: ${oneLine(evidence)}`);
    }
    subject = parts.join(" - ");
  }

  let description = `${label}: ${v.title}`;
  if (subject) description += ` - ${subject}`;
  if (fileDeleted) description += ` [deleted]`;
  if (host) description += ` @ ${host}`;
  description = description.slice(0, 4000);

  const aggKey = `vr-det|${v.title.toLowerCase()}|${(path || processName || pipe || subject).toLowerCase()}|${host.toLowerCase()}`
    .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/g, "<guid>")
    .replace(/\d+/g, "#")
    .slice(0, 400);

  return {
    timestamp: pickTime(row),
    description,
    severity,
    mitre: v.mitre,
    aggKey,
    sources: ["Velociraptor"],
    ...(sha256 ? { sha256 } : {}),
    ...(md5 && !sha256 ? { md5 } : {}),
    ...(path ? { path } : {}),
    ...(host ? { asset: host } : {}),
    ...(processName ? { processName } : {}),
    ...(parentName ? { parentName } : {}),
  };
}

function mapEventlog(row: Row, host: string, sink: Map<string, SiemIoc>): MappedEvent | null {
  const flat = winRowToFlat(row);
  if (!flat) return null;
  const win = mapWindows(flat.rec, flat.host || host, sink);
  if (!win) return null;
  win.sources = ["Velociraptor"];
  if (!win.timestamp) win.timestamp = pickTime(row);
  return win;
}

const GENERIC_MSG_KEYS = ["Message", "Details", "message", "Description", "Category", "DisplayName", "Line", "Stdout", "CommandLine", "PipeName", "KeyPath", "OSPath", "FullPath", "Name"];
// Keys whose values are big/structured (rule regexes, PE internals, raw file content) — useful
// for IOC scanning but noise in a one-line description, so they're skipped in the key=value fallback.
const NOISE_KEY = /regex|ignore|imports|exports|sections|resources|directories|versioninformation|dllinfo|hitcontext|\bmeta\b|content|reference|url|license/i;
// Collection-metadata keys (the artifact id surfaced in the "[artifact]" prefix, the _ts collection
// time) — skipped in the key=value fallback so they don't duplicate the prefix / add noise.
const META_KEY = /^(_ts|_Source|_Artifact|ArtifactName)$/i;

function mapGeneric(row: Row, artifact: string, host: string, sink: Map<string, SiemIoc>): MappedEvent {
  const { sha256, md5 } = collectRowIocs(row, sink);
  scrapeEvidence(row, sink); // URLs/IPs/hashes embedded in Message/Line/Content (key-driven extractors miss these)
  const msg = firstStr(row, GENERIC_MSG_KEYS);
  const pairs: [string, string][] = [];
  flatten(row, pairs);
  const base = msg ? oneLine(msg)
    : pairs.filter(([k, v]) => !META_KEY.test(k) && !NOISE_KEY.test(k) && v.length <= 200).slice(0, 8).map(([k, v]) => `${k}=${v}`).join(" - ");

  const sevWord = firstStr(row, ["Severity", "Level", "Risk", "Priority"]).toLowerCase();
  const severity: Severity = SEV_WORDS[sevWord] ?? "Info";

  const procName = firstStr(row, ["Exe", "Image", "ProcessName"]);
  const parentName = firstStr(row, ["ParentName", "ParentImage", "ParentExe", "ParentProcessName"]);
  const path = firstStr(row, ["OSPath", "FullPath", "_FullPath", "FilePath"]);

  let description = `Velociraptor${artifact ? ` [${artifact}]` : ""}: ${base}`.slice(0, 600);
  if (host && !description.toLowerCase().includes(host.toLowerCase())) description = `${description} @ ${host}`.slice(0, 600);

  const aggKey = `vr|${artifact.toLowerCase()}|${host.toLowerCase()}|${base.toLowerCase()}`
    .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/g, "<guid>")
    .replace(/\d+/g, "#")
    .slice(0, 400);

  return {
    timestamp: pickTime(row),
    description,
    severity,
    mitre: [],
    aggKey,
    sources: ["Velociraptor"],
    ...(sha256 ? { sha256 } : {}),
    ...(md5 && !sha256 ? { md5 } : {}),
    ...(path ? { path } : {}),
    ...(host ? { asset: host } : {}),
    ...(procName ? { processName: baseName(procName) } : {}),
    ...(parentName ? { parentName: baseName(parentName) } : {}),
  };
}

function mapPslist(row: Row, host: string, sink: Map<string, SiemIoc>): MappedEvent {
  const name = str(getCI(row, "Name")).trim();
  const exe = firstStr(row, ["Exe", "Image"]);
  const cmdline = str(getCI(row, "CommandLine")).trim();
  const pid = str(getCI(row, "Pid")).trim();
  const ppid = str(getCI(row, "Ppid")).trim();
  const callChain = str(getCI(row, "CallChain")).trim();

  if (exe) addIoc(sink, "process", baseName(exe));
  else if (name) addIoc(sink, "process", name);

  // "svchost.exe (1004) ← ppid 592 [chain: ...]: C:\Windows\... @ WIN11"
  let description = `${name || "process"}${pid ? ` (pid ${pid})` : ""}`;
  if (ppid && ppid !== "0") description += ` ← ppid ${ppid}`;
  if (callChain && callChain !== name) description += ` [${callChain}]`;
  const subject = cmdline || exe;
  if (subject) description += `: ${oneLine(subject).slice(0, 300)}`;
  if (host) description += ` @ ${host}`;
  description = description.slice(0, 600);

  const aggKey = `vr-pslist|${name.toLowerCase()}|${ppid}|${host.toLowerCase()}|${(cmdline || exe || name).toLowerCase()}`
    .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/g, "<guid>")
    .replace(/\d+/g, "#")
    .slice(0, 400);

  return {
    timestamp: pickTime(row),
    description,
    severity: "Info",
    mitre: [],
    aggKey,
    sources: ["Velociraptor"],
    ...(exe ? { path: exe } : {}),
    ...(host ? { asset: host } : {}),
    ...(name ? { processName: name } : {}),
  };
}

function mapNetstat(row: Row, host: string, sink: Map<string, SiemIoc>): MappedEvent {
  const { sha256, md5 } = collectRowIocs(row, sink);

  const laddr = str(getCI(row, "Laddr")).trim();
  const lport = str(getCI(row, "Lport")).trim();
  const raddr = str(getCI(row, "Raddr")).trim();
  const rport = str(getCI(row, "Rport")).trim();
  const status = str(getCI(row, "Status")).trim();
  const proto = firstStr(row, ["Type", "Proto", "Family"]);
  const name = str(getCI(row, "Name")).trim();
  const pid = str(getCI(row, "Pid")).trim();
  const path = firstStr(row, ["Path", "Exe"]);

  // Remote IP as IOC for non-zero, non-loopback addresses
  const rAddrIsReal = raddr && raddr !== "0.0.0.0" && raddr !== "::" && raddr !== "::1" && raddr !== "127.0.0.1";
  if (rAddrIsReal) addIoc(sink, "ip", raddr);
  if (name) addIoc(sink, "process", name);

  // ESTABLISHED connections to non-RFC-1918 remote IPs are Low (worth reviewing)
  const isExternal = rAddrIsReal && !/^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/.test(raddr);
  const severity: Severity = status === "ESTABLISHED" && isExternal ? "Low" : "Info";

  // "svchost.exe (pid 896) - TCP - LISTEN - 0.0.0.0:135 → 0.0.0.0"
  const src = lport ? `${laddr}:${lport}` : laddr;
  const dst = rport && rport !== "0" ? `${raddr}:${rport}` : raddr;
  let description = `${name || "process"}${pid ? ` (pid ${pid})` : ""}`;
  if (proto) description += ` - ${proto}`;
  if (status) description += ` - ${status}`;
  description += ` - ${src} → ${dst}`;
  if (host) description += ` @ ${host}`;
  description = description.slice(0, 600);

  const aggKey = `vr-netstat|${name.toLowerCase()}|${status.toLowerCase()}|${lport}|${raddr.toLowerCase()}|${rport}|${host.toLowerCase()}`
    .replace(/\d+/g, "#")
    .slice(0, 400);

  return {
    timestamp: pickTime(row),
    description,
    severity,
    mitre: [],
    aggKey,
    sources: ["Velociraptor"],
    ...(sha256 ? { sha256 } : {}),
    ...(md5 && !sha256 ? { md5 } : {}),
    ...(path ? { path } : {}),
    ...(host ? { asset: host } : {}),
    ...(name ? { processName: name } : {}),
  };
}

function mapDownload(row: Row, host: string, sink: Map<string, SiemIoc>): MappedEvent {
  // Velociraptor renders NTFS device paths with a leading \\.\  — strip it for readability.
  const raw = str(getCI(row, "DownloadedFilePath"));
  const rawPath = (raw.startsWith("\\\\.\\") ? raw.slice(4) : raw).trim();
  const hostUrl = str(getCI(row, "HostUrl")).trim();
  const referrerUrl = str(getCI(row, "ReferrerUrl")).trim();
  const name = rawPath ? baseName(rawPath) : "";

  if (hostUrl && /^https?:\/\//i.test(hostUrl)) addIoc(sink, "url", hostUrl.slice(0, 300));
  if (referrerUrl && /^https?:\/\//i.test(referrerUrl)) addIoc(sink, "url", referrerUrl.slice(0, 300));
  if (rawPath) addIoc(sink, "file", rawPath);

  // FileHash is a nested object {MD5, SHA1, SHA256} in the Velociraptor artifact
  const hashObj = getCI(row, "FileHash");
  const { sha256, md5 } = isObject(hashObj) ? vrHashes(hashObj as Row) : vrHashes(row);
  if (sha256) addIoc(sink, "hash", sha256);
  else if (md5) addIoc(sink, "hash", md5);

  const urlDisplay = hostUrl || "unknown source";
  // Prefix with "Velociraptor:" so the artifact-name injection in the main loop can insert
  // [_Source] right after "Velociraptor" (consistent with every other mapper).
  let description = `Velociraptor: Downloaded ${name || rawPath || "file"} from ${urlDisplay}`;
  if (host) description += ` @ ${host}`;
  description = description.slice(0, 600);

  const aggKey = `vr-download|${name.toLowerCase()}|${urlDisplay.toLowerCase()}|${host.toLowerCase()}`
    .replace(/\d+/g, "#")
    .slice(0, 400);

  return {
    timestamp: pickTime(row),
    description,
    severity: "Info",
    mitre: [],
    aggKey,
    sources: ["Velociraptor"],
    ...(sha256 ? { sha256 } : {}),
    ...(md5 && !sha256 ? { md5 } : {}),
    ...(rawPath ? { path: rawPath } : {}),
    ...(host ? { asset: host } : {}),
  };
}

function mapStartup(row: Row, host: string, sink: Map<string, SiemIoc>): MappedEvent {
  const name = str(getCI(row, "Name")).trim();
  const ospath = str(getCI(row, "OSPath")).trim();
  const details = str(getCI(row, "Details")).trim();
  const enabledRaw = str(getCI(row, "Enabled")).trim().toLowerCase();
  const enabled = enabledRaw === "enable" || enabledRaw === "enabled" || enabledRaw === "true" || enabledRaw === "1";

  // Add the executable path or registry path as file/process IOC when it looks like a real path.
  const cmdPath = details.replace(/^["']?([A-Za-z]:\\[^"'\s]+).*$/, "$1");
  if (details && /^[A-Za-z]:\\/.test(cmdPath)) addIoc(sink, "file", cmdPath.slice(0, 300));
  if (ospath && /^[A-Za-z]:\\/.test(ospath)) addIoc(sink, "file", ospath.slice(0, 300));

  const enabledLabel = enabled ? "enabled" : "disabled";
  const subject = details && details !== name ? oneLine(details).slice(0, 300) : ospath;
  let description = `Velociraptor: Startup [${name || "item"}] — ${subject} (${enabledLabel})`;
  if (host) description += ` @ ${host}`;
  description = description.slice(0, 600);

  // Active persistence is worth surfacing; disabled items are informational.
  const severity: Severity = enabled ? "Low" : "Info";

  const aggKey = `vr-startup|${name.toLowerCase()}|${ospath.toLowerCase()}`
    .replace(/\d+/g, "#")
    .slice(0, 400);

  return {
    timestamp: pickTime(row),
    description,
    severity,
    mitre: enabled ? ["T1547"] : [],
    aggKey,
    sources: ["Velociraptor"],
    ...(host ? { asset: host } : {}),
  };
}

function mapTaskScheduler(row: Row, host: string, sink: Map<string, SiemIoc>): MappedEvent {
  const taskName = str(getCI(row, "TaskName")).trim();
  const command = str(getCI(row, "Command")).trim();
  const args = str(getCI(row, "Arguments")).trim();
  const userId = str(getCI(row, "UserId")).trim();
  const runLevel = str(getCI(row, "RunLevel")).trim();
  const ospath = str(getCI(row, "OSPath")).trim();

  if (ospath) addIoc(sink, "file", ospath);
  if (command && /^[A-Za-z]:\\/.test(command)) addIoc(sink, "file", command.slice(0, 300));

  const cmd = [command, args].filter(Boolean).join(" ");
  const userLabel = userId === "S-1-5-18" ? "SYSTEM"
    : userId === "S-1-5-19" ? "LOCAL SERVICE"
    : userId === "S-1-5-20" ? "NETWORK SERVICE"
    : userId;

  let description = `Velociraptor: Scheduled Task [${taskName || "task"}]`;
  if (cmd) description += ` — ${oneLine(cmd).slice(0, 250)}`;
  if (userLabel) description += ` (${userLabel}${runLevel ? `, ${runLevel}` : ""})`;
  if (host) description += ` @ ${host}`;
  description = description.slice(0, 600);

  const aggKey = `vr-task|${taskName.toLowerCase()}|${host.toLowerCase()}`
    .replace(/\d+/g, "#")
    .slice(0, 400);

  return {
    timestamp: pickTime(row),
    description,
    severity: "Info",
    mitre: [],
    aggKey,
    sources: ["Velociraptor"],
    ...(ospath ? { path: ospath } : {}),
    ...(host ? { asset: host } : {}),
  };
}

// ───────────────────────────── row extraction ─────────────────────────────

// Returns the flat row list. Handles a Velociraptor multi-artifact map { "Artifact": [rows] }
// (tagging each row's _Source), else delegates to the shared extractor (array/jsonl/wrapped).
// Parse a CSV export (Elastic Discover "Download CSV") into flat row objects keyed by header,
// dropping Kibana's "-" empty-cell placeholder. Returns null when it doesn't look tabular.
function csvToRows(text: string): { rows: Row[]; format: string } | null {
  const { headers, rows } = parseCsv(text);
  if (headers.length < 2 || rows.length === 0) return null;
  const out: Row[] = rows.map((cells) => {
    const o: Row = {};
    headers.forEach((h, i) => {
      const v = cells[i];
      if (v != null && v !== "" && v !== "-") o[h] = v;
    });
    return o;
  });
  return { rows: out, format: "csv" };
}

function extractRows(text: string): { rows: Row[]; format: string } {
  const trimmed = text.trim();
  if (!trimmed) return { rows: [], format: "empty" };

  // CSV export from Elastic Discover (Velociraptor data indexed into Elastic) — not JSON/NDJSON.
  // Each row becomes a flat object keyed by header; "-" (Kibana's empty-cell placeholder) is dropped.
  // normalizeElasticRow (in the per-row loop) then un-flattens the dotted/.keyword columns.
  if (trimmed[0] !== "{" && trimmed[0] !== "[") {
    const csv = csvToRows(trimmed);
    if (csv) return csv;
  }

  let root: unknown = null;
  try { root = JSON.parse(trimmed); } catch { /* NDJSON path below */ }

  if (root && isObject(root) && !Array.isArray(root)) {
    const entries = Object.entries(root);
    const isArtifactMap = entries.length > 0
      && entries.every(([k, v]) => Array.isArray(v) && !WRAPPER_KEYS.has(k.toLowerCase()))
      && entries.some(([, v]) => (v as unknown[]).some((x) => isObject(x)));
    if (isArtifactMap) {
      const rows: Row[] = [];
      for (const [artifact, arr] of entries) {
        for (const r of arr as unknown[]) {
          if (isObject(r)) rows.push(getCI(r, "_Source") || getCI(r, "Artifact") ? r : { ...r, _Source: artifact });
        }
      }
      return { rows, format: "artifact-map" };
    }
  }

  const { records, format } = extractRecords(trimmed);
  return { rows: records, format: format === "ndjson" ? "jsonl" : format };
}

// ───────────────────────────── top-level parse ─────────────────────────────

export function parseVelociraptorJson(text: string, opts: VelociraptorImportOptions = {}): VelociraptorParseResult {
  const maxIocs = opts.maxIocs ?? 5000;
  const { rows, format } = extractRows(text);
  const total = rows.length;
  if (total === 0) {
    return { events: [], iocs: [], total: 0, kept: 0, dropped: 0, groups: 0, detections: 0, format: "empty", hostname: "" };
  }

  const iocSink = new Map<string, SiemIoc>();
  const hostTally = new Map<string, number>();
  const mapped: MappedEvent[] = [];
  let detections = 0;

  const fallbackArtifact = (opts.artifact ?? "").trim();
  // A single-client FLOW export has no per-row host column — the whole collection is implicitly for
  // one client — so the resolved hostname is threaded in here to attribute rows that carry no host.
  const fallbackHost = (opts.hostFallback ?? "").trim();

  for (const rawRow of rows) {
    const row = normalizeElasticRow(rawRow); // reshape an ES-indexed push back to native form (gated)
    const artifact = artifactName(row) || fallbackArtifact;
    const host = pickHost(row) || fallbackHost; // a row's own host always wins; fallback only fills the gap
    if (host) hostTally.set(host, (hostTally.get(host) ?? 0) + 1);

    const rowSink = new Map<string, SiemIoc>();
    const kind = classify(row, artifact);
    let m: MappedEvent | null;
    if (kind === "yara") { m = mapYara(row, artifact, host, rowSink); detections++; }
    else if (kind === "sigma") { m = mapSigma(row, host, rowSink); detections++; }
    else if (kind === "chainsaw") { m = mapFlatChainsawRow(row, host, rowSink); detections++; }
    else if (kind === "detection") { m = mapDetection(row, artifact, host, rowSink); detections++; }
    else if (kind === "eventlog") { m = mapEventlog(row, host, rowSink) ?? mapGeneric(row, artifact, host, rowSink); }
    else if (kind === "pslist") { m = mapPslist(row, host, rowSink); }
    else if (kind === "netstat") { m = mapNetstat(row, host, rowSink); }
    else if (kind === "download") { m = mapDownload(row, host, rowSink); }
    else if (kind === "startup") { m = mapStartup(row, host, rowSink); }
    else if (kind === "taskscheduler") { m = mapTaskScheduler(row, host, rowSink); }
    else { m = mapGeneric(row, artifact, host, rowSink); }
    if (m) {
      // Stamp the produced event with the VQL artifact that emitted it. Done once here (rather than in
      // each map* function) because `artifact` is already resolved in this dispatch loop and every
      // mapper's result flows through — so downstream (dwell-time window, evidence graph) can tell
      // "from the MFT" apart from "a Sigma detection". Uses the resolved `artifact` (the row's
      // _Source/_Artifact, or the filename fallback) so telemetry rows without _Source still carry it.
      if (artifact) m.artifactName = artifact;
      // Carry the FULL untruncated event message so the super-timeline row can reveal it expandably,
      // when it adds detail beyond the truncated `description`. Stamped here (like artifactName) so
      // every mapper's result benefits. Set only if the mapper didn't already provide one.
      if (!m.message) {
        const full = fullMessage(row, m.description);
        if (full) m.message = full;
      }
      // Tag every event with the SOURCE artifact (from the row's _Source/_Artifact — stamped by the
      // browser push, or carried by an artifact-map import) so the analyst can navigate back to it.
      // Place it consistently right after "Velociraptor" (the same spot mapGeneric already uses), so
      // detection/sigma/yara read "Velociraptor [artifact] detection: …" not "… [artifact]" at the
      // end. Only a REAL artifact name (from _Source) is shown — never the filename fallback.
      // Skip when mapDetection already led with a DetectRaptor-specific label (detectionLabel()) —
      // that already names the rule pack, so bracketing the full dotted artifact too is redundant.
      const realArtifact = artifactName(row);
      if (realArtifact && !m.description.includes(realArtifact) && !m.description.startsWith("DetectRaptor ")) {
        m.description = (m.description.startsWith("Velociraptor")
          ? m.description.replace(/^Velociraptor/, `Velociraptor [${realArtifact}]`)
          : `[${realArtifact}] ${m.description}`).slice(0, 1200);
      }
      // Forensic distinctness: detections sharing a rule title/EID but describing different
      // artifacts (HackTool:Passview vs HackTool:Mimikatz) are SEPARATE events. Fold the message
      // fingerprint into the agg key so they don't collapse on title alone — while truly identical
      // repeats (differing only in volatile ids) still merge. See msgFingerprint.
      const fp = msgFingerprint(rowMessage(row));
      if (fp) m.aggKey = `${m.aggKey}|m:${fp}`.slice(0, 440);
      mergeRowIocs(iocSink, rowSink, m.aggKey);
      mapped.push(m);
    }
  }

  const { events, groups } = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents: opts.maxEvents ?? 2000,
  });

  const represented = events.reduce((n, e) => n + (e.count ?? 1), 0);
  const hostname = [...hostTally.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] ?? "";

  return {
    events,
    iocs: [...iocSink.values()].slice(0, maxIocs),
    total,
    kept: events.length,
    dropped: Math.max(0, total - represented),
    groups,
    detections,
    format,
    hostname,
  };
}
