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
import {
  extractRecords,
  mapWindows,
  aggregateEvents,
  flatten,
  genericIocs,
  parseHashes,
  cleanIp,
  addIoc,
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

type Row = Record<string, unknown>;

export interface VelociraptorImportOptions {
  aggregate?: boolean;
  minSeverity?: Severity;
  maxEvents?: number;
  maxIocs?: number;
  artifact?: string;   // fallback artifact/source label (e.g. the filename) when rows carry no _Source
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
  return out.join(" ¦ ").slice(0, 400);
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
  "System.TimeCreated.SystemTime", "System.TimeCreated", "EventTime", "Mtime", "Btime",
  "Ctime", "Created", "CreationTime", "LastWriteTime", "KeyLastWriteTimestamp", "TimeGenerated",
  "Timestamp", "timestamp", "time", "StartTime",
  "SITimestamps.LastModified0x10", "SITimestamps.Created0x10", "FNTimestamps.Created0x30",
  "FileInfo.Mtime", "FileInfo.Ctime", "FileInfo.Btime", "HitContext.Mtime",
  "_ts",
];
function pickTime(row: Row): string {
  for (const k of TIME_KEYS) {
    const v = k.includes(".") ? getPath(row, k) : getCI(row, k);
    const t = vrTime(v);
    if (t) return t;
  }
  return "";
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

// Extract IOCs from every column of a row (used by generic + YARA rows).
function collectRowIocs(row: Row, sink: Map<string, SiemIoc>): { sha256?: string; md5?: string } {
  const pairs: [string, string][] = [];
  flatten(row, pairs);
  genericIocs(pairs, sink);
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

type Kind = "sigma" | "yara" | "detection" | "eventlog" | "generic";

function artifactName(row: Row): string {
  return firstStr(row, ["_Source", "Artifact", "_Artifact", "artifact", "Source", "ArtifactName"]);
}

function classify(row: Row, artifact: string): Kind {
  const a = artifact.toLowerCase();
  if (/yara/.test(a)) return "yara";
  if (/sigma/.test(a)) return "sigma";

  const rule = getCI(row, "Rule");
  if (typeof rule === "string" && rule.trim() && (getCI(row, "Strings") || getCI(row, "Meta") || getCI(row, "Namespace") || getCI(row, "Rules"))) return "yara";
  if (isObject(rule) && (getCI(rule, "Title") || getCI(rule, "Level"))) return "sigma";

  // A `Detection`/`RuleName` verdict → verdict-first, BEFORE the eventlog branch so a detection
  // that also carries a parsed Windows event (DetectRaptor's Evtx) is overlaid, not flattened.
  if (rowVerdict(row)) return "detection";

  if (getCI(row, "System") || getCI(row, "EventData") || getPath(row, "Event.System")) {
    if (firstStr(row, ["Level"]) && firstStr(row, ["Title", "SigmaTitle", "RuleTitle"])) return "sigma";
    return "eventlog";
  }
  return "generic";
}

function mapYara(row: Row, artifact: string, host: string, sink: Map<string, SiemIoc>): MappedEvent {
  const rule = getCI(row, "Rule");
  const ruleName = typeof rule === "string" && rule.trim() ? rule.trim()
    : str(getPath(row, "Rule.id")) || str(getPath(row, "Rule.Name")) || firstStr(row, ["RuleName", "Namespace"]) || "match";
  const { sha256, md5 } = collectRowIocs(row, sink);

  const path = firstStr(row, ["OSPath", "FullPath", "_FullPath", "File", "FilePath", "Path"]);
  const procName = firstStr(row, ["Exe", "ProcessName", "ImageName"]);
  const pid = firstStr(row, ["Pid", "ProcessId"]);
  if (path) addIoc(sink, "file", path);
  if (procName) addIoc(sink, "process", baseName(procName));

  const mitre = mitreFromText(flatStr(getCI(row, "Meta")), flatStr(getCI(row, "Tags")), ruleName);

  let description = `Velociraptor YARA: ${ruleName}`;
  if (procName) description += ` — ${baseName(procName)}${pid ? ` (pid ${pid})` : ""}`;
  else if (path) description += ` — ${path}`;
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
    win.description = `Velociraptor Sigma: ${title} | ${win.description}`.slice(0, 600);
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
  if (detail) description += ` — ${detail}`;
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

// A DetectRaptor-style detection: the `Detection`/`RuleName` verdict leads. If a parsed Windows
// event sits underneath (Evtx), overlay the verdict onto the per-EID mapping (like Sigma);
// otherwise build the event from the row's file/process/pipe/path + hashes.
function mapDetection(row: Row, artifact: string, host: string, sink: Map<string, SiemIoc>): MappedEvent {
  const v = rowVerdict(row)!; // guaranteed by classify()
  const severity = detectionSeverity(v);
  scrapeEvidence(row, sink); // pull URLs/IPs/hashes out of the matched command line / file content

  const flat = winRowToFlat(row);
  const win = flat ? mapWindows(flat.rec, flat.host || host, sink) : null;
  if (win) {
    win.severity = worst(win.severity, severity);
    for (const m of v.mitre) if (!win.mitre.includes(m)) win.mitre.push(m);
    win.description = `Velociraptor detection: ${v.title} | ${win.description}`.slice(0, 600);
    win.aggKey = `vr-det|${v.title.toLowerCase()}|${win.aggKey}`.slice(0, 400);
    win.sources = ["Velociraptor"];
    if (!win.timestamp) win.timestamp = pickTime(row);
    return win;
  }

  // Non-event detection (file / registry / named-pipe / history-line hit, or a flattened EVTX
  // detection whose event sits only in the rendered Message).
  const { sha256, md5 } = collectRowIocs(row, sink);
  const message = rowMessage(row);
  const salient = salientFromMessage(message); // LOLBIN + command line out of a 4688-style message
  const path = firstStr(row, ["OSPath", "FullPath", "_FullPath", "File", "FilePath", "Path", "KeyPath"]);
  const procRaw = firstStr(row, ["Exe", "Image", "ProcessName", "ProcName", "NewProcessName"]) || parsedNewProcess(message);
  const parentRaw = firstStr(row, ["ParentName", "ParentImage", "ParentProcessName"]);
  const processName = procRaw ? baseName(procRaw) : undefined;
  const parentName = parentRaw ? baseName(parentRaw) : undefined;
  const pipe = firstStr(row, ["PipeName"]);
  if (processName) addIoc(sink, "process", processName);

  // Subject priority: the rendered event's high-signal fields (the actual LOLBIN/command line) win
  // over structured process/path, which win over the raw matched line. A flattened DetectRaptor Evtx
  // row carries its detail only in Message, so without this the verdict would show only boilerplate.
  let subject: string;
  if (salient) {
    subject = salient;
  } else {
    const parts: string[] = [];
    if (processName) parts.push(processName);
    if (pipe) parts.push(`pipe ${pipe}`);
    if (path && !processName) parts.push(path);
    if (parts.length === 0) {
      const line = firstStr(row, ["Line", "StringHit", "HitString", "CommandLine"]);
      parts.push(line ? oneLine(line).slice(0, 160) : oneLine(message).slice(0, 200));
    }
    subject = parts.join(" ");
  }

  let description = `Velociraptor detection: ${v.title}`;
  if (subject) description += ` — ${subject}`;
  if (host) description += ` @ ${host}`;
  description = description.slice(0, 600);

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

function mapGeneric(row: Row, artifact: string, host: string, sink: Map<string, SiemIoc>): MappedEvent {
  const { sha256, md5 } = collectRowIocs(row, sink);
  scrapeEvidence(row, sink); // URLs/IPs/hashes embedded in Message/Line/Content (key-driven extractors miss these)
  const msg = firstStr(row, GENERIC_MSG_KEYS);
  const pairs: [string, string][] = [];
  flatten(row, pairs);
  const base = msg ? oneLine(msg)
    : pairs.filter(([k, v]) => k !== "_ts" && !NOISE_KEY.test(k) && v.length <= 200).slice(0, 8).map(([k, v]) => `${k}=${v}`).join(" ");

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

// ───────────────────────────── row extraction ─────────────────────────────

// Returns the flat row list. Handles a Velociraptor multi-artifact map { "Artifact": [rows] }
// (tagging each row's _Source), else delegates to the shared extractor (array/jsonl/wrapped).
function extractRows(text: string): { rows: Row[]; format: string } {
  const trimmed = text.trim();
  if (!trimmed) return { rows: [], format: "empty" };

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

  for (const row of rows) {
    const artifact = artifactName(row) || fallbackArtifact;
    const host = pickHost(row);
    if (host) hostTally.set(host, (hostTally.get(host) ?? 0) + 1);

    const kind = classify(row, artifact);
    let m: MappedEvent | null;
    if (kind === "yara") { m = mapYara(row, artifact, host, iocSink); detections++; }
    else if (kind === "sigma") { m = mapSigma(row, host, iocSink); detections++; }
    else if (kind === "detection") { m = mapDetection(row, artifact, host, iocSink); detections++; }
    else if (kind === "eventlog") { m = mapEventlog(row, host, iocSink) ?? mapGeneric(row, artifact, host, iocSink); }
    else { m = mapGeneric(row, artifact, host, iocSink); }
    if (m) {
      // Forensic distinctness: detections sharing a rule title/EID but describing different
      // artifacts (HackTool:Passview vs HackTool:Mimikatz) are SEPARATE events. Fold the message
      // fingerprint into the agg key so they don't collapse on title alone — while truly identical
      // repeats (differing only in volatile ids) still merge. See msgFingerprint.
      const fp = msgFingerprint(rowMessage(row));
      if (fp) m.aggKey = `${m.aggKey}|m:${fp}`.slice(0, 440);
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
