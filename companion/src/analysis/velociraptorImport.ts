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

// The artifact's OWN time first; `_ts` (collection time) only as a last resort.
const TIME_KEYS = [
  "System.TimeCreated.SystemTime", "System.TimeCreated", "EventTime", "Mtime", "Btime",
  "Ctime", "Created", "CreationTime", "LastWriteTime", "TimeGenerated", "Timestamp",
  "timestamp", "time", "StartTime", "_ts",
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

// ───────────────────────────── EVTX-row normalization ─────────────────────────────

// A Velociraptor parsed-evtx row carries `System` + `EventData` (sometimes under `Event`).
// Reshape to the flat record `mapWindows` consumes, normalizing the EventID (which can be a
// number or `{ Value }`/`{ #text }`) to a bare value, plus the host.
function winRowToFlat(row: Row): { rec: Row; host: string } | null {
  const sys = isObject(getCI(row, "System")) ? (getCI(row, "System") as Row)
    : isObject(getPath(row, "Event.System")) ? (getPath(row, "Event.System") as Row) : null;
  const edRaw = getCI(row, "EventData") ?? getPath(row, "Event.EventData");
  if (!sys) return null;

  let eid: unknown = getCI(sys, "EventID");
  if (isObject(eid)) eid = getCI(eid, "Value") ?? getCI(eid, "#text");
  const channel = str(getCI(sys, "Channel")) || str(getPath(sys, "Provider.Name")) || str(getPath(sys, "Provider.#attributes.Name"));
  const host = str(getCI(sys, "Computer")).trim();
  const time = vrTime(getCI(sys, "TimeCreated"));

  return {
    host,
    rec: {
      event_id: eid,
      channel,
      event_data: isObject(edRaw) ? edRaw : {},
      "@timestamp": time,
      message: str(getCI(row, "Message")),
    },
  };
}

// ───────────────────────────── per-row mapping ─────────────────────────────

type Kind = "sigma" | "yara" | "eventlog" | "generic";

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
  // No parsed event underneath — keep the verdict alone.
  collectRowIocs(row, sink);
  return {
    timestamp: pickTime(row),
    description: `Velociraptor Sigma: ${title}${host ? ` @ ${host}` : ""}`.slice(0, 600),
    severity: sev ?? "Medium",
    mitre: tags,
    aggKey: `vr-sigma|${title.toLowerCase()}|${host.toLowerCase()}`.slice(0, 400),
    sources: ["Velociraptor"],
    ...(host ? { asset: host } : {}),
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

const GENERIC_MSG_KEYS = ["Message", "message", "Description", "Line", "Stdout", "CommandLine", "OSPath", "FullPath", "Name"];

function mapGeneric(row: Row, artifact: string, host: string, sink: Map<string, SiemIoc>): MappedEvent {
  const { sha256, md5 } = collectRowIocs(row, sink);
  const msg = firstStr(row, GENERIC_MSG_KEYS);
  const pairs: [string, string][] = [];
  flatten(row, pairs);
  const base = msg ? oneLine(msg) : pairs.filter(([k]) => k !== "_ts").slice(0, 8).map(([k, v]) => `${k}=${v}`).join(" ");

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

  for (const row of rows) {
    const artifact = artifactName(row);
    const host = pickHost(row);
    if (host) hostTally.set(host, (hostTally.get(host) ?? 0) + 1);

    const kind = classify(row, artifact);
    let m: MappedEvent | null;
    if (kind === "yara") { m = mapYara(row, artifact, host, iocSink); detections++; }
    else if (kind === "sigma") { m = mapSigma(row, host, iocSink); detections++; }
    else if (kind === "eventlog") { m = mapEventlog(row, host, iocSink) ?? mapGeneric(row, artifact, host, iocSink); }
    else { m = mapGeneric(row, artifact, host, iocSink); }
    if (m) mapped.push(m);
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
