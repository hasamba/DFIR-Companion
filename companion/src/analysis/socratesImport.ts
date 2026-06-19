// Deterministic importer for SO-CRATES (dougburks/so-crates) — the post-detection layer over one
// uploaded artifact. SO-CRATES emits three verdict classes, all pushed by the browser extension's
// SO-CRATES adapter (or importable as raw exports):
//   - Suricata IDS `alert` events (eve.json)         → reuse parseNetworkLogs (alert→event, telemetry→IOC)
//   - YARA `filealerts` (synthetic eve.json)         → file-match detection + hash/file IOCs
//   - Sigma alerts (separate /api/sigma-alerts feed)  → log detection, verdict-first severity + MITRE
// No AI. Per the Companion's post-detection principle we ingest the tool's verdicts, never re-run
// detection. Events are tagged "SO-CRATES" (+ the underlying engine) for cross-source correlation.

import type { Severity } from "./stateTypes.js";
import {
  extractRecords,
  aggregateEvents,
  addIoc,
  str,
  getCI,
  isObject,
  oneLine,
  baseName,
  normalizeTime,
  mapWindows,
  worst,
  type MappedEvent,
  type SiemEvent,
  type SiemIoc,
} from "./siemImport.js";
import { parseNetworkLogs } from "./networkImport.js";

type Row = Record<string, unknown>;

export interface SocratesImportOptions {
  aggregate?: boolean;
  minSeverity?: Severity;
  maxEvents?: number;
  maxIocs?: number;
}

export interface SocratesParseResult {
  events: SiemEvent[];
  iocs: SiemIoc[];
  total: number;    // records found
  kept: number;     // events emitted (after aggregation + cap)
  dropped: number;  // records not represented (telemetry / below floor / capped / unknown)
  groups: number;   // distinct event groups before the cap
  alerts: number;   // Suricata alerts seen
  yara: number;     // YARA filealerts seen
  sigma: number;    // Sigma alerts seen
  format: string;   // "suricata" | "yara" | "sigma" | "mixed" | "empty"
}

const HEX_HASH = /^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i;
const SEV_RANK: Record<Severity, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };

// Scan free text / arrays / comma-strings for ATT&CK technique ids (Txxxx[.nnn]).
function mitreFrom(...vals: unknown[]): string[] {
  const out = new Set<string>();
  const scan = (s: string): void => {
    for (const m of s.matchAll(/\bt\d{4}(?:\.\d{3})?\b/gi)) out.add(m[0].toUpperCase());
  };
  for (const v of vals) {
    if (Array.isArray(v)) v.forEach((x) => scan(str(x)));
    else if (v != null && typeof v === "object") scan(JSON.stringify(v));
    else scan(str(v));
  }
  return [...out];
}

// Sigma/severity word → Severity (verdict-first, like the SIEM per-EID table).
function sigmaSeverity(level: string): Severity {
  switch (level.trim().toLowerCase()) {
    case "critical": return "Critical";
    case "high": return "High";
    case "medium": return "Medium";
    case "low": return "Low";
    case "informational":
    case "info": return "Info";
    default: return "Medium";
  }
}

function addHash(sink: Map<string, SiemIoc>, v: unknown): void {
  const h = str(v).trim().toLowerCase();
  if (HEX_HASH.test(h)) addIoc(sink, "hash", h);
}
function addFile(sink: Map<string, SiemIoc>, v: unknown): void {
  const f = str(v).trim();
  if (f && f !== "-" && f.length > 1) addIoc(sink, "file", f.slice(0, 300));
}

// A SO-CRATES eve.json record (Suricata/Zeek telemetry or detection).
function isEve(row: Row): boolean {
  return getCI(row, "event_type") != null || getCI(row, "_path") != null;
}

// YARA `filealerts` synthetic eve.json → a file-match detection event.
function mapYara(row: Row, sink: Map<string, SiemIoc>): MappedEvent {
  const fa = getCI(row, "filealerts");
  const f: Row = fa != null && typeof fa === "object" ? (fa as Row) : {};
  const meta = getCI(f, "meta");
  const filename = meta != null && typeof meta === "object" ? str(getCI(meta as Row, "filename")) : "";
  const rule = str(getCI(f, "rule_name")) || "YARA rule";
  const sha256 = str(getCI(f, "sha256")).toLowerCase();

  addHash(sink, sha256);
  addHash(sink, getCI(f, "md5"));
  if (filename) addFile(sink, filename);

  const target = filename || (HEX_HASH.test(sha256) ? sha256.slice(0, 16) : "file");
  return {
    timestamp: normalizeTime(str(getCI(row, "timestamp"))),
    description: `YARA: ${rule} on ${target}`.slice(0, 600),
    severity: "Medium",
    mitre: mitreFrom(getCI(f, "tags"), getCI(f, "meta")),
    aggKey: `socrates-yara|${rule.toLowerCase()}|${sha256}`.slice(0, 400),
    sources: ["SO-CRATES", "YARA"],
    ...(HEX_HASH.test(sha256) ? { sha256 } : {}),
  };
}

// The matched log event SO-CRATES carries alongside a Sigma alert — the actual record that
// tripped the rule (process create, network connection, …). It lives as a JSON STRING in
// `original_log`, or (same event) under `json_data.matches[0]`. Parse whichever is present so the
// alert event carries the real process context (CommandLine/ParentImage/…), not just the rule name.
function parseMatchedEvent(row: Row): Row | null {
  const ol = getCI(row, "original_log");
  if (isObject(ol)) return ol;                       // already-parsed
  if (typeof ol === "string" && ol.trim()) {
    try { const o = JSON.parse(ol); if (isObject(o)) return o; } catch { /* fall through */ }
  }
  const jd = getCI(row, "json_data");
  if (typeof jd === "string" && jd.trim()) {
    try {
      const o = JSON.parse(jd);
      const m = isObject(o) ? getCI(o, "matches") : null;
      if (Array.isArray(m) && isObject(m[0])) return m[0] as Row;
    } catch { /* fall through */ }
  }
  return null;
}

// Salient process/network fields to surface from a matched event on the non-Windows path (the
// Windows path renders these via mapWindows). Also harvests the event's own IOCs.
const SIGMA_CTX_KEYS = ["Image", "CommandLine", "ParentImage", "ParentCommandLine", "CurrentDirectory", "User", "TargetFilename", "DestinationIp"];
function evContext(ev: Row, sink: Map<string, SiemIoc>): string {
  addHash(sink, getCI(ev, "SHA256"));
  addHash(sink, getCI(ev, "MD5"));
  const img = str(getCI(ev, "Image"));
  if (img && /[\\/]/.test(img)) addFile(sink, img);
  const proc = baseName(img);
  if (proc) addIoc(sink, "process", proc);
  const parts: string[] = [];
  for (const k of SIGMA_CTX_KEYS) {
    const v = oneLine(str(getCI(ev, k))).trim();
    if (v && v !== "-") parts.push(`${k}=${v.slice(0, 140)}`);
  }
  return parts.join(" - ");
}

// Sigma alert (from /api/sigma-alerts) → a log detection event, verdict-first. When the matched
// event is a Windows/Sysmon record, reuse `mapWindows` for the rich process detail + hash/file/
// process IOCs and OVERLAY the Sigma verdict (mirrors chainsawImport): rule title leads, the rule
// `level` drives severity, attack tags add MITRE. `ParentCommandLine` is appended explicitly since
// the shared Windows mapper's subject fields omit it.
function mapSigma(row: Row, sink: Map<string, SiemIoc>): MappedEvent {
  const title = str(getCI(row, "rule_title")) || "Sigma rule";
  const level = str(getCI(row, "level")) || str(getCI(row, "severity"));
  const logsource = str(getCI(row, "logsource"));
  const sev = sigmaSeverity(level);
  const mitre = mitreFrom(getCI(row, "mitre_techniques"), getCI(row, "tags"));
  const ruleKey = (str(getCI(row, "rule_id")) || title).toLowerCase();
  const ev = parseMatchedEvent(row);

  // Windows/Sysmon matched event → full process mapping + IOCs, then overlay the Sigma verdict.
  if (ev) {
    const host = str(getCI(ev, "Computer"));
    const win = mapWindows({
      event_id: getCI(ev, "EventID") ?? getCI(ev, "event_id"),
      channel: getCI(ev, "Channel") ?? getCI(ev, "channel") ?? logsource,
      event_data: ev,
      "@timestamp": str(getCI(ev, "SystemTime")) || str(getCI(ev, "UtcTime")) || str(getCI(row, "timestamp")),
    }, host, sink);
    if (win) {
      // mapWindows reads hashes from the combined Sysmon `Hashes` string; some matched events
      // expose only standalone SHA256/MD5 fields — capture those defensively.
      const sha = str(getCI(ev, "SHA256")).toLowerCase();
      const md5 = str(getCI(ev, "MD5")).toLowerCase();
      if (!win.sha256 && HEX_HASH.test(sha)) win.sha256 = sha;
      addHash(sink, sha);
      addHash(sink, md5);
      // ParentCommandLine is now part of mapWindows' standard subject fields, so the rich detail
      // (CommandLine/ParentImage/ParentCommandLine, ` - `-separated) is already in win.description.
      win.description = `Sigma: ${title} - ${win.description}`.slice(0, 600);
      win.severity = worst(sev, win.severity);
      for (const m of mitre) if (!win.mitre.includes(m)) win.mitre.push(m);
      win.sources = ["SO-CRATES", "Sigma"];
      win.aggKey = `socrates-sigma|${ruleKey}|${win.aggKey}`.slice(0, 400);
      return win;
    }
  }

  // Non-Windows (or no matched event) — verdict-first from the rule, with any process context.
  const ctx = ev ? evContext(ev, sink) : "";
  const processName = ev ? baseName(str(getCI(ev, "Image"))) : "";
  const parentName = ev ? baseName(str(getCI(ev, "ParentImage"))) : "";
  return {
    timestamp: normalizeTime(str(getCI(row, "timestamp")) || (ev ? str(getCI(ev, "SystemTime")) : "")),
    description: (`Sigma: ${title}` + (logsource ? ` [${logsource}]` : "") + (ctx ? ` - ${ctx}` : "")).slice(0, 600),
    severity: sev,
    mitre,
    aggKey: `socrates-sigma|${ruleKey}`.slice(0, 400),
    sources: ["SO-CRATES", "Sigma"],
    ...(processName ? { processName } : {}),
    ...(parentName ? { parentName } : {}),
  };
}

export function parseSocrates(text: string, opts: SocratesImportOptions = {}): SocratesParseResult {
  const maxEvents = opts.maxEvents ?? 2000;
  const maxIocs = opts.maxIocs ?? 5000;
  const { records } = extractRecords(text);
  const total = records.length;
  if (total === 0) {
    return { events: [], iocs: [], total: 0, kept: 0, dropped: 0, groups: 0, alerts: 0, yara: 0, sigma: 0, format: "empty" };
  }

  // Partition records by shape.
  const eve: Row[] = [];        // Suricata/Zeek telemetry + alerts (minus YARA filealerts)
  const yaraRows: Row[] = [];   // YARA filealerts
  const sigmaRows: Row[] = [];  // Sigma alerts
  for (const row of records) {
    if (isEve(row)) {
      if (str(getCI(row, "event_type")).toLowerCase() === "filealerts" || getCI(row, "filealerts") != null) {
        yaraRows.push(row);
      } else {
        eve.push(row);
      }
    } else if (getCI(row, "rule_title") != null || getCI(row, "rule_id") != null) {
      sigmaRows.push(row);
    }
    // else: unknown shape → dropped
  }

  const iocSink = new Map<string, SiemIoc>();

  // (1) Suricata/Zeek detections + telemetry IOCs — reuse the network importer wholesale.
  let netEvents: SiemEvent[] = [];
  let netGroups = 0;
  let alerts = 0;
  if (eve.length) {
    const net = parseNetworkLogs(JSON.stringify(eve), {
      aggregate: opts.aggregate,
      minSeverity: opts.minSeverity,
      maxEvents,
      maxIocs,
    });
    alerts = net.alerts;
    netGroups = net.groups;
    netEvents = net.events.map((e) => ({ ...e, sources: ["SO-CRATES", ...(e.sources ?? [])] }));
    for (const c of net.iocs) addIoc(iocSink, c.type, c.value);
  }

  // (2) YARA filealerts + (3) Sigma alerts → map then aggregate together.
  const mapped: MappedEvent[] = [];
  for (const row of yaraRows) mapped.push(mapYara(row, iocSink));
  for (const row of sigmaRows) mapped.push(mapSigma(row, iocSink));
  const { events: fileEvents, groups: fileGroups } = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents,
  });

  // Combine (network events are already aggregated/sorted), sort worst-first, cap.
  const combined = [...netEvents, ...fileEvents]
    .sort((a, b) =>
      SEV_RANK[a.severity] - SEV_RANK[b.severity] ||
      (b.count ?? 1) - (a.count ?? 1) ||
      (a.timestamp || "~").localeCompare(b.timestamp || "~"))
    .slice(0, maxEvents);

  const present: string[] = [];
  if (eve.length) present.push("suricata");
  if (yaraRows.length) present.push("yara");
  if (sigmaRows.length) present.push("sigma");
  const format = present.length === 0 ? "empty" : present.length === 1 ? present[0] : "mixed";

  const represented = combined.reduce((n, e) => n + (e.count ?? 1), 0);
  return {
    events: combined,
    iocs: [...iocSink.values()].slice(0, maxIocs),
    total,
    kept: combined.length,
    dropped: Math.max(0, total - represented),
    groups: netGroups + fileGroups,
    alerts,
    yara: yaraRows.length,
    sigma: sigmaRows.length,
    format,
  };
}
