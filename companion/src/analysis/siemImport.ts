// Deterministic importer for SIEM / EDR JSON exports — the second JSON ingest path
// besides THOR. Where THOR has a fixed JSON-Lines schema, SIEM/EDR exports vary wildly
// (Elastic/Kibana, Splunk, an EDR console, a raw winlogbeat dump…), so this module:
//
//   1. UNWRAPS the common container envelopes to a flat array of event records:
//      Elastic/Kibana table export ({ data: [{ _source }] }), an Elasticsearch search
//      response ({ hits: { hits: [{ _source }] } }), a plain JSON array, NDJSON
//      (one JSON object per line, optionally _source-wrapped), or { events|records|
//      results|logs: [...] }.
//   2. MAPS each record to a forensic event DETERMINISTICALLY (no AI call). Windows
//      Event Log + Sysmon records (the dominant SIEM data, and the attached example
//      file) get a rich per-EID mapping (label, derived severity, MITRE, structured
//      IOC/asset extraction). Any OTHER SIEM/EDR record falls back to field
//      auto-detection (timestamp / host / message / severity), so a CrowdStrike /
//      Defender / SentinelOne export still produces dated events + IOCs.
//   3. AGGREGATES repetitive identical events into one counted row (like THOR /
//      logAggregate) and caps the total, so an 11k-event export does not flood the
//      timeline. Synthesis + the high-severity backfill still cover everything.
//
// Windows logs carry no maliciousness score (`level` is "Information" for almost
// everything), so severity is DERIVED from the event type (WIN_EVENTS / SYSMON_EVENTS),
// with a conservative bump for LOLBin / suspicious command lines and LSASS access.

import type { Severity } from "./stateTypes.js";
import { toUtcIso } from "./timeUtc.js";
import { reconTechniques } from "./reconTechniques.js";
import { tradecraftSignal } from "./tradecraftRules.js";

export interface SiemImportOptions {
  // Collapse repetitive identical events into one counted row. Default true.
  aggregate?: boolean;
  // Drop events below this severity floor (e.g. "Low" drops Info noise like logoffs /
  // process-terminated). Default undefined = keep everything.
  minSeverity?: Severity;
  // Safety cap on emitted events (most-severe first). Default 2000.
  maxEvents?: number;
  // Safety cap on emitted IOCs. Default 5000.
  maxIocs?: number;
}

// A delta-shaped forensic event (matches deltaSchema.forensicEvents), produced deterministically.
export interface SiemEvent {
  id: string;
  timestamp: string;
  description: string;
  severity: Severity;
  mitreTechniques: string[];
  count?: number;
  endTimestamp?: string;
  sha256?: string;
  md5?: string;
  path?: string;
  asset?: string;
  sources?: string[];
  processName?: string;
  parentName?: string;
  pid?: number;
  srcIp?: string;
  dstIp?: string;
  port?: number;
  // The source artifact/rule that produced this event (e.g. a Velociraptor VQL artifact name).
  artifactName?: string;
  // Full, untruncated event message/detail (beyond the truncated `description`) when the mapper had it.
  message?: string;
}

export interface SiemIoc {
  type: "ip" | "domain" | "hash" | "file" | "process" | "url" | "sid" | "other";
  value: string;
}

export interface SiemParseResult {
  events: SiemEvent[];
  iocs: SiemIoc[];
  total: number;     // records found in the container
  kept: number;      // events emitted (after aggregation + cap)
  dropped: number;   // records not represented (below floor / capped / unparseable)
  groups: number;    // distinct event groups before the cap
  format: string;    // detected container shape (elastic-data / elastic-hits / ndjson / array / events:<key> / single)
  hostname: string;  // best-effort dominant host
}

type Row = Record<string, unknown>;

const SEVERITY_RANK: Record<Severity, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };

// ───────────────────────────── small value helpers ─────────────────────────────

export function isObject(v: unknown): v is Row {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
export function str(v: unknown): string {
  return typeof v === "string" ? v : v == null ? "" : typeof v === "object" ? "" : String(v);
}
export function oneLine(s: string): string {
  return s.replace(/\s*[\r\n]+\s*/g, " ").trim();
}
export function baseName(p: string): string {
  return (p.trim().split(/[\\/]/).pop() || p.trim());
}
// Case-insensitive single-key lookup.
export function getCI(row: Row, key: string): unknown {
  if (key in row) return row[key];
  const lower = key.toLowerCase();
  for (const k of Object.keys(row)) if (k.toLowerCase() === lower) return row[k];
  return undefined;
}
// First non-empty string across candidate keys (case-insensitive), supporting dotted paths.
export function firstStr(row: Row, keys: string[]): string {
  for (const k of keys) {
    const v = k.includes(".") ? getPath(row, k) : getCI(row, k);
    const s = str(v).trim();
    if (s) return s;
  }
  return "";
}
// Dotted-path getter ("host.name", "event.action"), case-insensitive per segment.
export function getPath(row: Row, path: string): unknown {
  let cur: unknown = row;
  for (const seg of path.split(".")) {
    if (!isObject(cur)) return undefined;
    cur = getCI(cur, seg);
  }
  return cur;
}

// ───────────────────────────── container unwrapping ─────────────────────────────

// If an element wraps its real fields under `_source` (Elastic), return that; else the element.
function unwrapSource(el: unknown): Row | null {
  if (!isObject(el)) return null;
  const src = getCI(el, "_source");
  return isObject(src) ? src : el;
}

const RECORD_ARRAY_KEYS = ["events", "Events", "records", "Records", "results", "Results", "logs", "Logs", "rows", "items", "alerts", "Alerts", "value"];

// Parse the file and extract the flat array of event records + a label for the shape.
// Parse a stream of CONCATENATED top-level JSON values (objects/arrays), tolerating pretty-
// printing and any separators (commas / whitespace / newlines) between them. This is the shape
// Hayabusa's `json-timeline` emits by default: many multi-line `{ … }` objects with NO array
// wrapper and NO commas — which is neither a single JSON document nor NDJSON, so both the
// whole-file parse and the line-by-line NDJSON parse miss it. Walks the string tracking brace/
// bracket depth (ignoring braces inside string literals) and JSON.parses each depth-0 value.
// Pure; malformed chunks are skipped rather than throwing.
export function parseConcatenatedJson(text: string): unknown[] {
  const out: unknown[] = [];
  let depth = 0, start = -1, inStr = false, esc = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (inStr) {
      if (esc) esc = false;
      else if (ch === "\\") esc = true;
      else if (ch === '"') inStr = false;
      continue;
    }
    if (ch === '"') { inStr = true; continue; }
    if (ch === "{" || ch === "[") { if (depth === 0) start = i; depth++; }
    else if (ch === "}" || ch === "]") {
      if (depth > 0 && --depth === 0 && start !== -1) {
        try { out.push(JSON.parse(text.slice(start, i + 1))); } catch { /* skip malformed chunk */ }
        start = -1;
      }
    }
  }
  return out;
}

export function extractRecords(text: string): { records: Row[]; format: string } {
  const trimmed = text.trim();
  if (!trimmed) return { records: [], format: "empty" };

  // First try the whole thing as one JSON value.
  let root: unknown;
  let parsed = false;
  try { root = JSON.parse(trimmed); parsed = true; } catch { /* fall through to NDJSON */ }

  if (parsed) {
    if (Array.isArray(root)) {
      return { records: root.map(unwrapSource).filter((r): r is Row => r !== null), format: "array" };
    }
    if (isObject(root)) {
      // Elastic/Kibana table export: { data: [ { _source } ] }
      const data = getCI(root, "data");
      if (Array.isArray(data)) {
        return { records: data.map(unwrapSource).filter((r): r is Row => r !== null), format: "elastic-data" };
      }
      // Elasticsearch search response: { hits: { hits: [ { _source } ] } }
      const hits = getPath(root, "hits.hits");
      if (Array.isArray(hits)) {
        return { records: hits.map(unwrapSource).filter((r): r is Row => r !== null), format: "elastic-hits" };
      }
      // { events: [...] } / { records: [...] } / { results: [...] } …
      for (const key of RECORD_ARRAY_KEYS) {
        const arr = getCI(root, key);
        if (Array.isArray(arr)) {
          return { records: arr.map(unwrapSource).filter((r): r is Row => r !== null), format: `events:${key}` };
        }
      }
      // A single event object.
      const single = unwrapSource(root);
      return { records: single ? [single] : [], format: "single" };
    }
    return { records: [], format: "unknown" };
  }

  // NDJSON: one JSON object per line (winlogbeat / filebeat / `_source`-wrapped lines).
  // Skip Elastic _bulk action lines ({ "index": {...} }) — those have no event fields.
  const records: Row[] = [];
  for (const line of trimmed.split(/\r\n|\r|\n/)) {
    const l = line.trim();
    if (!l) continue;
    let obj: unknown;
    try { obj = JSON.parse(l); } catch { continue; }
    const rec = unwrapSource(obj);
    if (rec && Object.keys(rec).length > 0) records.push(rec);
  }
  if (records.length > 0) return { records, format: "ndjson" };

  // Last resort: concatenated pretty-printed JSON values (Hayabusa `json-timeline` default —
  // multi-line objects, no array, no commas). NDJSON's per-line parse can't see these.
  const concat: Row[] = [];
  for (const v of parseConcatenatedJson(trimmed)) {
    if (Array.isArray(v)) { for (const e of v) { const r = unwrapSource(e); if (r && Object.keys(r).length > 0) concat.push(r); } }
    else { const r = unwrapSource(v); if (r && Object.keys(r).length > 0) concat.push(r); }
  }
  if (concat.length > 0) return { records: concat, format: "concatenated-json" };
  return { records: [], format: "ndjson" };
}

// ───────────────────────────── Windows / Sysmon tables ─────────────────────────────

interface WinEventDef {
  label: string;
  severity: Severity;
  mitre?: string[];
  kind?: "process" | "network" | "dns" | "procaccess" | "file" | "service";
}

// Security + System channel events keyed by Event ID.
const WIN_EVENTS: Record<number, WinEventDef> = {
  // Authentication / logon
  4624: { label: "Successful logon", severity: "Low" },
  4625: { label: "Failed logon", severity: "Medium", mitre: ["T1110"] },
  4634: { label: "Logoff", severity: "Info" },
  4647: { label: "User-initiated logoff", severity: "Info" },
  4648: { label: "Logon with explicit credentials", severity: "Medium", mitre: ["T1078"] },
  4672: { label: "Special privileges assigned to new logon", severity: "Low" },
  4768: { label: "Kerberos TGT requested (AS-REQ)", severity: "Low" },
  4769: { label: "Kerberos service ticket requested (TGS-REQ)", severity: "Low" },
  4771: { label: "Kerberos pre-authentication failed", severity: "Medium", mitre: ["T1110"] },
  4776: { label: "NTLM credential validation", severity: "Low" },
  // Account / group management
  4720: { label: "User account created", severity: "High", mitre: ["T1136.001"] },
  4722: { label: "User account enabled", severity: "Medium" },
  4723: { label: "Password change attempt", severity: "Low" },
  4724: { label: "Password reset attempt", severity: "Medium", mitre: ["T1098"] },
  4725: { label: "User account disabled", severity: "Medium" },
  4726: { label: "User account deleted", severity: "Medium" },
  4728: { label: "Member added to global security group", severity: "High", mitre: ["T1098"] },
  4732: { label: "Member added to local security group", severity: "High", mitre: ["T1098"] },
  4756: { label: "Member added to universal security group", severity: "High", mitre: ["T1098"] },
  4738: { label: "User account changed", severity: "Low" },
  4740: { label: "User account locked out", severity: "Medium" },
  4767: { label: "User account unlocked", severity: "Low" },
  // Persistence / execution
  4697: { label: "Service installed (Security)", severity: "High", kind: "service", mitre: ["T1543.003"] },
  4698: { label: "Scheduled task created", severity: "High", mitre: ["T1053.005"] },
  4699: { label: "Scheduled task deleted", severity: "Medium", mitre: ["T1053.005"] },
  4700: { label: "Scheduled task enabled", severity: "Low", mitre: ["T1053.005"] },
  4702: { label: "Scheduled task updated", severity: "Medium", mitre: ["T1053.005"] },
  4688: { label: "Process created", severity: "Low", kind: "process", mitre: ["T1059"] },
  4689: { label: "Process exited", severity: "Info" },
  // Object / share / policy
  4663: { label: "Object access attempt", severity: "Low" },
  4670: { label: "Permissions on object changed", severity: "Medium" },
  5140: { label: "Network share accessed", severity: "Low", mitre: ["T1021.002"] },
  5142: { label: "Network share added", severity: "Medium" },
  5143: { label: "Network share modified", severity: "Medium" },
  5145: { label: "Network share object checked", severity: "Low", mitre: ["T1021.002"] },
  4946: { label: "Windows Firewall rule added", severity: "Medium", mitre: ["T1562.004"] },
  4947: { label: "Windows Firewall rule modified", severity: "Medium", mitre: ["T1562.004"] },
  5058: { label: "Key file operation", severity: "Low" },
  5059: { label: "Key migration operation", severity: "Low" },
  // Defense evasion
  1102: { label: "Security audit log cleared", severity: "High", mitre: ["T1070.001"] },
  4719: { label: "System audit policy changed", severity: "High", mitre: ["T1562.002"] },
  // System channel
  7045: { label: "Service installed", severity: "High", kind: "service", mitre: ["T1543.003"] },
  7034: { label: "Service crashed unexpectedly", severity: "Low" },
  7036: { label: "Service state changed", severity: "Info" },
  7040: { label: "Service start type changed", severity: "Low" },
  104: { label: "Event log cleared", severity: "High", mitre: ["T1070.001"] },
  6005: { label: "Event log service started", severity: "Info" },
  6006: { label: "Event log service stopped", severity: "Low" },
};

// Sysmon (Microsoft-Windows-Sysmon/Operational) events — keyed separately because the
// EID numbering overlaps the Security channel (Sysmon 1 ≠ Security 1).
const SYSMON_EVENTS: Record<number, WinEventDef> = {
  1: { label: "Process create", severity: "Low", kind: "process", mitre: ["T1059"] },
  2: { label: "File creation time changed (timestomp)", severity: "Medium", mitre: ["T1070.006"] },
  3: { label: "Network connection", severity: "Low", kind: "network" },
  4: { label: "Sysmon service state changed", severity: "Info" },
  5: { label: "Process terminated", severity: "Info" },
  6: { label: "Driver loaded", severity: "Medium", mitre: ["T1543.003"] },
  7: { label: "Image (DLL) loaded", severity: "Low", mitre: ["T1574.002"] },
  8: { label: "CreateRemoteThread (possible injection)", severity: "High", mitre: ["T1055"] },
  9: { label: "RawAccessRead", severity: "Medium", mitre: ["T1006"] },
  10: { label: "Process accessed", severity: "Medium", kind: "procaccess", mitre: ["T1003"] },
  11: { label: "File created", severity: "Low" },
  12: { label: "Registry object created/deleted", severity: "Low", mitre: ["T1112"] },
  13: { label: "Registry value set", severity: "Low", mitre: ["T1112"] },
  14: { label: "Registry object renamed", severity: "Low", mitre: ["T1112"] },
  15: { label: "Alternate data stream created", severity: "Medium", mitre: ["T1564.004"] },
  17: { label: "Named pipe created", severity: "Low" },
  18: { label: "Named pipe connected", severity: "Low" },
  19: { label: "WMI event filter registered", severity: "Medium", mitre: ["T1546.003"] },
  20: { label: "WMI event consumer registered", severity: "Medium", mitre: ["T1546.003"] },
  21: { label: "WMI consumer-to-filter binding", severity: "Medium", mitre: ["T1546.003"] },
  22: { label: "DNS query", severity: "Low", kind: "dns" },
  23: { label: "File deleted (archived)", severity: "Low", mitre: ["T1070.004"] },
  24: { label: "Clipboard changed", severity: "Low" },
  25: { label: "Process image tampering", severity: "High", mitre: ["T1055.012"] },
  26: { label: "File delete logged", severity: "Low", mitre: ["T1070.004"] },
};

// LOLBins whose appearance as the image (Sysmon 1 / 4688) bumps a benign process-create.
const LOLBINS = new Set([
  "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
  "rundll32.exe", "regsvr32.exe", "wmic.exe", "certutil.exe", "bitsadmin.exe", "msiexec.exe",
  "installutil.exe", "regasm.exe", "regsvcs.exe", "msbuild.exe", "cmstp.exe", "schtasks.exe",
  "at.exe", "sc.exe", "net.exe", "net1.exe", "psexec.exe", "psexesvc.exe", "vssadmin.exe",
  "bcdedit.exe", "wevtutil.exe", "reg.exe", "curl.exe", "ftp.exe", "hh.exe", "odbcconf.exe",
]);
// Core OS processes that legitimately call CreateRemoteThread (Sysmon EID 8) during normal
// session/process setup — csrss/wininit/services injecting is routine, so we downgrade those
// from the default High (they stay in the timeline; synthesis/legit-marking can still act).
// Core OS processes that legitimately CreateRemoteThread as routine session/service setup, PLUS
// Windows Defender / Defender-for-Endpoint, which inject monitoring threads into user processes as
// part of behavioral scanning — a benign EID 8 source, not injection tradecraft. Also the desktop/
// shell brokers that routinely inject as part of ordinary UI plumbing: Windows Search indexing its
// own protocol host, dllhost.exe (COM Surrogate) loading shell-extension/COM objects, and the UWP
// app-model brokers taskhostw/RuntimeBroker — all fire constantly on a stock, uncompromised desktop
// and otherwise drown real injection signal in noise (see the fairhaven-rdp-takeover benchmark,
// where this exact pairing on unrelated hosts got escalated into a fabricated finding).
const BENIGN_THREAD_SOURCES = new Set([
  "csrss.exe", "wininit.exe", "services.exe", "smss.exe", "svchost.exe", "wmiprvse.exe", "lsm.exe", "winlogon.exe",
  "msmpeng.exe", "mpdefendercoreservice.exe", "mssense.exe", "sensendr.exe", "mpcmdrun.exe", // Defender / MDE
  "searchindexer.exe", "searchprotocolhost.exe", "dllhost.exe", "taskhostw.exe", "runtimebroker.exe", // shell/UI brokers
]);
// Windows-native processes that access LSASS constantly as part of normal operation (#198). A
// Sysmon EID 10 ProcessAccess to lsass.exe from one of these is NOT credential dumping — Defender /
// Defender-for-Endpoint scan it on every boot, and core OS processes open it routinely. Keyed on the
// SourceImage basename; still graded High when the source runs from a SUSPICIOUS path (a masqueraded
// "svchost.exe" in \Temp\ is not benign), and a non-listed accessor (e.g. a renamed dumper) stays High.
const BENIGN_LSASS_ACCESSORS = new Set([
  "msmpeng.exe", "mpdefendercoreservice.exe", "mssense.exe", "sensendr.exe", "mpcmdrun.exe", // Defender / MDE
  "svchost.exe", "services.exe", "csrss.exe", "wininit.exe", "lsass.exe", "wmiprvse.exe", "smss.exe", "lsm.exe",
]);
// Command-line markers strongly associated with attacker tradecraft → stronger bump.
const STRONG_CMD = /mimikatz|sekurlsa|lsadump|invoke-mimikatz|-dumpcr|comsvcs\.dll.*minidump|vssadmin\s+delete|wbadmin\s+delete|wevtutil\s+cl\b|fsutil\s+usn\s+deletejournal|lsass[^\n]{0,40}\.dmp|\.dmp[^\n]{0,40}lsass|(?:-p|--pid|--process)\s+lsass|nanodump|dumpert|handlekatz|procdump[^\n]*lsass|reg\s+save\s+[^\n]*\\sam\b|ntds\.dit|ntdsutil[^\n]*ifm/i;
const SUSP_CMD = /-enc\b|-e\s+[A-Za-z0-9+/]{20,}|encodedcommand|frombase64string|-nop\b|-noni\b|-noprofile|-w\s*hidden|-windowstyle\s+hidden|iex\b|invoke-expression|downloadstring|downloadfile|net\.webclient|-bypass|certutil.*-urlcache|bitsadmin.*\/transfer|\/add\b|reg\s+add.*\\run|mysqldump|pg_dump|mongodump|(?:curl|wget)\b[^\n]*(?:--data-binary|--upload-file|\s-T\b|\s-F\b|--form|-d\s+@)/i;
// Execution from a user-writable / staging directory is itself a weak masquerade/tradecraft signal
// (#199) — a non-system binary launched from Temp / AppData / Downloads / Public / ProgramData, or
// /tmp,/dev/shm,/var/tmp on *nix. Tested against the IMAGE path (not the whole command) to avoid
// matching a path that merely appears as an argument. ProgramData recurs across the DFIR Report and
// Huntress corpora as ransomware/dropper staging ground (msidxsvc.exe, locker.exe, sc-created
// payloads, renamed PowerShell) — same Medium-bump tier as the other user-writable paths, not High.
// EXCEPTION: `\ProgramData\Microsoft\Windows Defender\` is Defender's own legitimate install path
// (MsMpEng.exe et al. really live there), so it's carved out — otherwise every benign Defender
// EID 8/10 event would trip the masquerade override in BENIGN_THREAD_SOURCES/BENIGN_LSASS_ACCESSORS.
const SUSP_PATH = /\\(?:appdata|temp|downloads)\\|\\users\\public\\|\\programdata\\(?!microsoft\\windows defender\\)|(?:^|[\s"])\/(?:tmp|var\/tmp|dev\/shm)\//i;

// Channel → short tool label for the description and source tag.
function channelLabel(channel: string): string {
  if (/sysmon/i.test(channel)) return "Sysmon";
  if (/security/i.test(channel)) return "Windows Security";
  if (/system/i.test(channel)) return "Windows System";
  if (/powershell/i.test(channel)) return "Windows PowerShell";
  if (/application/i.test(channel)) return "Windows Application";
  return "Windows Event Log";
}

// ───────────────────────────── timestamps ─────────────────────────────

// Normalize a "YYYY-MM-DD HH:MM:SS(.fff)" (Sysmon UtcTime) to ISO "…Z"; pass ISO through
// toUtcIso (which converts a numeric offset to UTC and leaves "…Z"/naive untouched).
export function normalizeTime(s: string): string {
  const t = s.trim();
  if (!t) return "";
  const m = /^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(\.\d+)?Z?$/.exec(t);
  if (m && !/[+-]\d{2}:?\d{2}$|Z$/.test(t)) return `${m[1]}T${m[2]}${m[3] ?? ""}Z`;
  const kib = parseKibanaDate(t);
  if (kib) return kib;
  return toUtcIso(t);
}

// Kibana's Discover / CSV-export display format, e.g. "May 7, 2026 @ 16:31:04.000". Carries no
// timezone, so — consistent with this codebase's naive-time convention — we read it as UTC. (Kibana
// renders in the browser TZ unless `dateFormat:tz` is UTC; without offset info that's unrecoverable.)
const KIBANA_DATE = /^([A-Z][a-z]{2}) (\d{1,2}), (\d{4}) @ (\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?$/;
const KIBANA_MONTHS: Record<string, string> = {
  Jan: "01", Feb: "02", Mar: "03", Apr: "04", May: "05", Jun: "06",
  Jul: "07", Aug: "08", Sep: "09", Oct: "10", Nov: "11", Dec: "12",
};
function parseKibanaDate(t: string): string {
  const m = KIBANA_DATE.exec(t);
  if (!m) return "";
  const mon = KIBANA_MONTHS[m[1]];
  if (!mon) return "";
  const ms = (m[7] ?? "").padEnd(3, "0");
  return `${m[3]}-${mon}-${m[2].padStart(2, "0")}T${m[4]}:${m[5]}:${m[6]}.${ms || "000"}Z`;
}

const TIME_KEYS = [
  "@timestamp", "timestamp", "_time", "eventTime", "EventTime", "event_time",
  "DeviceEventTime", "createdAt", "created", "event.created", "ingested",
  "generated_time", "received_time", "observed_timestamp", "time", "date", "@time",
];

// The event's own time. For Sysmon prefer the structured UtcTime (the in-event clock —
// the artifact's own time); otherwise the record's @timestamp / common time fields.
// Never the import time.
function pickTimestamp(rec: Row, ed: Row | undefined): string {
  const sysmonUtc = ed ? str(getCI(ed, "UtcTime")).trim() : "";
  return normalizeTime(sysmonUtc || firstStr(rec, TIME_KEYS));
}

const HOST_KEYS = [
  "computer_name", "Computer", "hostname", "host.name", "host", "host_name",
  "agent.hostname", "beat.hostname", "device.hostname", "endpoint.name", "MachineName",
  "src_host", "source.host", "winlog.computer_name",
];

function pickHost(rec: Row): string {
  for (const k of HOST_KEYS) {
    const v = k.includes(".") ? getPath(rec, k) : getCI(rec, k);
    if (typeof v === "string" && v.trim()) return v.trim();
    if (isObject(v)) { const n = str(getCI(v, "name")).trim(); if (n) return n; } // ECS host:{name}
  }
  return "";
}

// ───────────────────────────── IOC / hash helpers ─────────────────────────────

const IPV4 = /^\d{1,3}(?:\.\d{1,3}){3}$/;
const HEX_HASH = /^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i;
const NOISE_IP = new Set(["::1", "127.0.0.1", "0.0.0.0", "::", "-", "::ffff:127.0.0.1"]);
// A real IPv6 shape check (full + every valid "::"-compressed form), NOT just "contains a colon" —
// that naive check let ANY colon-bearing string through as a "valid" IPv6 IOC, including free-text
// blobs (a PowerShell cmdletization proxy dump, `cim:ModifyInstance`, `::new(...)`, etc. all contain
// colons) whenever the field happened to reach cleanIp — e.g. a key loosely matching /ip|addr/i.
const IPV6_RE =
  /^(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}$|^(?:[0-9a-f]{1,4}:){1,7}:$|^(?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}$|^(?:[0-9a-f]{1,4}:){1,5}(?::[0-9a-f]{1,4}){1,2}$|^(?:[0-9a-f]{1,4}:){1,4}(?::[0-9a-f]{1,4}){1,3}$|^(?:[0-9a-f]{1,4}:){1,3}(?::[0-9a-f]{1,4}){1,4}$|^(?:[0-9a-f]{1,4}:){1,2}(?::[0-9a-f]{1,4}){1,5}$|^[0-9a-f]{1,4}:(?:(?::[0-9a-f]{1,4}){1,6})$|^:(?:(?::[0-9a-f]{1,4}){1,7}|:)$/i;

// Strip an IPv4-mapped IPv6 prefix ("::ffff:10.0.0.1" → "10.0.0.1"); drop loopback/empty.
export function cleanIp(raw: string): string {
  let v = raw.trim();
  if (!v || NOISE_IP.has(v)) return "";
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(v);
  if (mapped) v = mapped[1];
  if (NOISE_IP.has(v)) return "";
  if (IPV4.test(v)) return v;
  // Keep a routable, well-shaped IPv6, but not link-local/loopback.
  if (IPV6_RE.test(v) && !/^fe80:|^::$/i.test(v)) return v;
  return "";
}

// Parse a Sysmon "Hashes" string ("SHA1=..,MD5=..,SHA256=..,IMPHASH=..") + a hashes_ex
// object into { sha256, md5 } (lowercased).
export function parseHashes(rec: Row, ed: Row | undefined): { sha256?: string; md5?: string } {
  const out: { sha256?: string; md5?: string } = {};
  const take = (algo: string, val: string): void => {
    const v = val.trim().toLowerCase();
    if (!HEX_HASH.test(v)) return;
    if (algo === "SHA256" && v.length === 64) out.sha256 ??= v;
    if (algo === "MD5" && v.length === 32) out.md5 ??= v;
  };
  const hashStr = ed ? str(getCI(ed, "Hashes")).trim() : "";
  for (const pair of hashStr.split(",")) {
    const [k, val] = pair.split("=");
    if (k && val) take(k.trim().toUpperCase(), val);
  }
  const hx = getCI(rec, "hashes_ex");
  if (isObject(hx)) { take("SHA256", str(getCI(hx, "SHA256"))); take("MD5", str(getCI(hx, "MD5"))); }
  return out;
}

// ───────────────────────────── Windows record → event ─────────────────────────────

// event_data fields rendered into the description (curated + stable — no volatile ports,
// GUIDs, or logon IDs, so identical events aggregate). User/domain handled by winAccounts.
const SUBJECT_KEYS = [
  "LogonType", "IpAddress", "WorkstationName", "ServiceName", "ServiceFileName",
  "Image", "CommandLine", "NewProcessName", "ParentImage", "ParentCommandLine", "SourceImage", "TargetImage",
  "TargetFilename", "ImageLoaded", "DestinationIp", "DestinationPort", "DestinationHostname",
  "Protocol", "QueryName", "ShareName", "RelativeTargetName", "TaskName", "PipeName",
  "TargetObject", "MemberName", "Status", "SubStatus", "FailureReason",
];

function renderFields(ed: Row, keys: string[]): string {
  const parts: string[] = [];
  for (const k of keys) {
    const v = str(getCI(ed, k)).trim();
    if (v && v !== "-" && v !== "%%1833") parts.push(`${k}=${oneLine(v).slice(0, 140)}`);
  }
  return parts.join(" - ");
}

// Compose DOMAIN\user (or UPN) account references so the asset graph picks them up.
function winAccounts(ed: Row): string[] {
  const out = new Set<string>();
  const pairs: [string, string][] = [["TargetDomainName", "TargetUserName"], ["SubjectDomainName", "SubjectUserName"]];
  for (const [dk, uk] of pairs) {
    const user = str(getCI(ed, uk)).trim();
    if (!user || user === "-" || user === "*") continue;
    const dom = str(getCI(ed, dk)).trim();
    if (user.includes("@")) out.add(user);                       // already a UPN
    else if (dom && dom !== "-") out.add(`${dom}\\${user}`);
    else out.add(user);
  }
  return [...out];
}

// Grade a process image + command line for attacker tradecraft: "strong" (mimikatz / lsadump /
// log-clearing), "weak" (a LOLBin or an encoded / hidden / download command), or null. Exported so
// the memory-forensics importer can bump a Volatility `cmdline` row the same way.
export function isSuspiciousCmd(image: string, cmd: string): "strong" | "weak" | null {
  const blob = `${image} ${cmd}`;
  if (STRONG_CMD.test(blob)) return "strong";
  if (LOLBINS.has(baseName(image).toLowerCase()) || SUSP_CMD.test(blob) || SUSP_PATH.test(image)) return "weak";
  return null;
}

export interface MappedEvent {
  timestamp: string;
  description: string;
  severity: Severity;
  mitre: string[];
  aggKey: string;
  sha256?: string;
  md5?: string;
  path?: string;
  asset?: string;
  processName?: string;
  parentName?: string;
  pid?: number;
  // Per-event tool source(s). siem mapping leaves this unset (the pipeline tags the whole
  // import); reused by chainsawImport, which tags each event Chainsaw/EVTX individually.
  sources?: string[];
  srcIp?: string;
  dstIp?: string;
  port?: number;
  // The source artifact/rule that produced this event (carried through aggregation to SiemEvent).
  artifactName?: string;
  // Full, untruncated event message/detail (beyond the truncated `description`) when available.
  message?: string;
}

// Parse a Windows pid that may be decimal ("5292") or hex ("0x14ac", as 4688 renders it). Returns a
// positive integer or undefined.
export function parsePid(raw: string): number | undefined {
  const s = raw.trim();
  if (!s || s === "-") return undefined;
  const n = /^0x[0-9a-f]+$/i.test(s) ? parseInt(s, 16) : Number(s);
  return Number.isInteger(n) && n > 0 ? n : undefined;
}

// Map a Windows Event Log / Sysmon record. Returns null if it is not a Windows record.
// RC4 Kerberos ticket-encryption types (0x17 RC4-HMAC, 0x18 RC4-HMAC-EXP) — the weak cipher an
// attacker forces so a service ticket can be cracked offline. Sourced from the Kerberoasting
// detection tell in Anthropic-Cybersecurity-Skills `detecting-kerberoasting-attacks` (Apache-2.0):
// a TGS-REQ (4769) encrypted with RC4 against a *user* service account (SPN owner) is the classic
// roasting request. Sibling AS-REP roasting (4768 with pre-auth disabled) is standard AD tradecraft.
const RC4_ENC_TYPES = new Set(["0x17", "0x18"]);

// Verdict-OVERLAY (we grade + tag the otherwise-Low 4769/4768, we do not re-detect): conservative to
// respect signal-to-noise — RC4 to a machine account (`name$`) or the krbtgt service is normal in a
// mixed AD and stays Low; a single RC4 request isn't proof, so we grade Medium and rely on the
// technique tag + high-volume-spray correlation (many 4769s → the burst/asset views) to surface it.
export function kerberosRoastSignal(eid: number, ed: Row): { severity: Severity; mitre: string[] } | null {
  if (eid !== 4769 && eid !== 4768) return null;
  const enc = str(getCI(ed, "TicketEncryptionType")).trim().toLowerCase();
  if (!RC4_ENC_TYPES.has(enc)) return null;
  if (eid === 4769) {
    // TGS-REQ: the account the ticket is FOR is the ServiceName (the SPN owner).
    const service = str(getCI(ed, "ServiceName")).trim();
    if (!service || service.endsWith("$") || service.toLowerCase().includes("krbtgt")) return null;
    return { severity: "Medium", mitre: ["T1558.003"] }; // Kerberoasting
  }
  // AS-REQ (4768): AS-REP roasting only when pre-authentication is disabled (PreAuthType 0) — RC4 on
  // a normal logon is far too common to flag, so require the roastable-account tell to stay low-FP.
  const preAuth = str(getCI(ed, "PreAuthType")).trim();
  const target = str(getCI(ed, "TargetUserName")).trim();
  if (preAuth !== "0" || !target || target.endsWith("$")) return null;
  return { severity: "Medium", mitre: ["T1558.004"] }; // AS-REP roasting
}

export function mapWindows(rec: Row, host: string, iocSink: Map<string, SiemIoc>): MappedEvent | null {
  const eidRaw = getCI(rec, "event_id") ?? getCI(rec, "EventID") ?? getPath(rec, "winlog.event_id") ?? getPath(rec, "event.code");
  const eid = Number(typeof eidRaw === "object" && isObject(eidRaw) ? getCI(eidRaw, "#text") : eidRaw);
  const channel = firstStr(rec, ["log_name", "channel", "Channel", "winlog.channel", "source_name"]);
  if (!Number.isFinite(eid) || !channel) return null;

  const edRaw = getCI(rec, "event_data") ?? getPath(rec, "winlog.event_data") ?? getCI(rec, "EventData");
  const ed: Row = isObject(edRaw) ? edRaw : {};
  const isSysmon = /sysmon/i.test(channel);
  const def: WinEventDef = (isSysmon ? SYSMON_EVENTS[eid] : WIN_EVENTS[eid]) ?? {
    label: oneLine(firstStr(rec, ["message", "Message"]).split(/[\r\n]/)[0] || `Event ${eid}`).slice(0, 120),
    severity: "Info",
  };

  const tool = channelLabel(channel);
  const accts = winAccounts(ed);
  const subject = renderFields(ed, SUBJECT_KEYS);
  let description = `${tool} ${def.label} (EID ${eid})`;
  if (accts.length) description += ` - ${accts.join(", ")}`;
  if (subject) description += ` - ${subject}`;
  if (host) description += ` @ ${host}`;
  description = description.slice(0, 600);

  // Severity — start from the table, then bump on suspicious process/command.
  let severity = def.severity;
  const mitre = [...(def.mitre ?? [])];
  if (def.kind === "process") {
    const image = str(getCI(ed, "Image")) || str(getCI(ed, "NewProcessName"));
    const cmd = str(getCI(ed, "CommandLine"));
    const susp = isSuspiciousCmd(image, cmd);
    if (susp === "strong") { severity = worst(severity, "High"); if (!mitre.includes("T1003")) mitre.push("T1003"); }
    else if (susp === "weak") severity = worst(severity, "Medium");
    // Deterministic attacker-tradecraft grading harvested from real intrusions (Defender-disable,
    // recovery inhibition, reverse-tunnel C2, Impacket lateral movement, cloud exfil, RMM/C2 tooling)
    // with the CORRECT ATT&CK technique per match (not isSuspiciousCmd's T1003 default).
    const tc = tradecraftSignal(image, cmd);
    if (tc) {
      severity = worst(severity, tc.weight === "strong" ? "High" : "Medium");
      for (const t of tc.mitre) if (!mitre.includes(t)) mitre.push(t);
    }
    // Tag discovery / credential-access recon (whoami, net group /domain, dir /s, findstr password,
    // .ssh/id_rsa, …) so the case identifies the enumeration phase even when each command is Info/Low.
    for (const t of reconTechniques(image, cmd)) if (!mitre.includes(t)) mitre.push(t);
  }
  if (def.kind === "procaccess" && /lsass\.exe$/i.test(str(getCI(ed, "TargetImage")))) {
    const srcImg = str(getCI(ed, "SourceImage"));
    const benign = BENIGN_LSASS_ACCESSORS.has(baseName(srcImg).toLowerCase()) && !SUSP_PATH.test(srcImg);
    if (benign) {
      // Routine OS / Defender LSASS access — keep as Low evidence, NOT a credential-dump finding (#198).
      severity = "Low";
    } else {
      severity = "High";
      if (!mitre.includes("T1003.001")) mitre.push("T1003.001");
    }
  }
  // CreateRemoteThread (Sysmon 8) from a core OS process or Defender is routine session setup /
  // behavioral monitoring, not injection — downgrade from the table's default High and drop the
  // T1055 tag so it doesn't drown real signal. A benign name run from a SUSPICIOUS path (a
  // masqueraded svchost.exe in \Temp\) is NOT benign and keeps High + T1055.
  if (isSysmon && eid === 8) {
    const srcImg = str(getCI(ed, "SourceImage"));
    if (BENIGN_THREAD_SOURCES.has(baseName(srcImg).toLowerCase()) && !SUSP_PATH.test(srcImg)) {
      severity = "Low";
      const i = mitre.indexOf("T1055");
      if (i >= 0) mitre.splice(i, 1);
    }
  }
  // Kerberoasting / AS-REP roasting: an RC4-encrypted Kerberos ticket request for a user service
  // account grades the otherwise-Low 4769/4768 with the correct technique (see kerberosRoastSignal).
  if (!isSysmon) {
    const roast = kerberosRoastSignal(eid, ed);
    if (roast) {
      severity = worst(severity, roast.severity);
      for (const t of roast.mitre) if (!mitre.includes(t)) mitre.push(t);
    }
  }

  // Structured correlation/IOC fields.
  const { sha256, md5 } = parseHashes(rec, ed);
  const imagePath = firstStr(ed, ["Image", "NewProcessName", "ImageLoaded", "TargetFilename", "ServiceFileName", "TargetImage"]);
  const processName = def.kind === "process" || def.kind === "procaccess"
    ? baseName(str(getCI(ed, "Image")) || str(getCI(ed, "SourceImage")) || str(getCI(ed, "NewProcessName"))) || undefined
    : undefined;
  const parentName = baseName(str(getCI(ed, "ParentImage"))) || undefined;
  // Subject (created-process) pid on process-CREATION events only — Security 4688 renders it as
  // NewProcessId (hex), Sysmon EID 1 as ProcessId (decimal). Used for cross-tool correlation.
  const pid = (!isSysmon && eid === 4688) ? parsePid(str(getCI(ed, "NewProcessId")))
    : (isSysmon && eid === 1) ? parsePid(str(getCI(ed, "ProcessId")))
    : undefined;

  // IOCs from the structured fields.
  for (const ipKey of ["IpAddress", "DestinationIp", "SourceIp", "ClientAddress"]) {
    const ip = cleanIp(str(getCI(ed, ipKey)));
    if (ip) addIoc(iocSink, "ip", ip);
  }
  if (sha256) addIoc(iocSink, "hash", sha256);
  else if (md5) addIoc(iocSink, "hash", md5);
  for (const fk of ["Image", "NewProcessName", "ImageLoaded", "TargetFilename", "ServiceFileName"]) {
    const f = str(getCI(ed, fk)).trim();
    if (f && f !== "-" && /[\\/]/.test(f)) addIoc(iocSink, "file", f);
  }
  if (processName) addIoc(iocSink, "process", processName);
  // Scrape indicators embedded in a process command line's free-text (download / exfil URLs, C2
  // domains, public IPs) — the structured-field extraction above misses these, so an exfil URL like
  // `Invoke-RestMethod -Uri https://mft.attacker.tld -InFile loot.zip` never became an IOC. textIocs
  // already skips internal AD/mDNS zones (.local/.lan/.corp) and filenames, so this stays signal-rich.
  if (def.kind === "process") textIocs(str(getCI(ed, "CommandLine")), iocSink);
  const dns = str(getCI(ed, "QueryName")).trim();
  if (def.kind === "dns" && dns && dns !== "-" && /\./.test(dns)) addIoc(iocSink, "domain", dns.replace(/\.$/, ""));

  return {
    timestamp: pickTimestamp(rec, ed),
    description,
    severity,
    mitre,
    // pid (on process-creation events) is in the key so distinct creations stay distinct rows rather
    // than aggregating into one — preserving per-process granularity and enabling pid correlation.
    aggKey: `win|${channel}|${eid}|${accts.join(",")}|${subject}${pid !== undefined ? `|pid=${pid}` : ""}`.toLowerCase(),
    ...(sha256 ? { sha256 } : {}),
    ...(md5 ? { md5 } : {}),
    ...(imagePath ? { path: imagePath } : {}),
    ...(host ? { asset: host } : {}),
    ...(processName ? { processName } : {}),
    ...(def.kind === "process" && parentName ? { parentName } : {}),
    ...(pid !== undefined ? { pid } : {}),
  };
}

export function worst(a: Severity, b: Severity): Severity {
  return SEVERITY_RANK[b] < SEVERITY_RANK[a] ? b : a;
}

// ───────────────────────────── generic record → event ─────────────────────────────

const SEV_WORDS: Record<string, Severity> = {
  critical: "Critical", crit: "Critical", emergency: "Critical", alert: "Critical", fatal: "Critical",
  high: "High", error: "High", err: "High",
  medium: "Medium", med: "Medium", moderate: "Medium", warning: "Medium", warn: "Medium",
  low: "Low", notice: "Low",
  info: "Info", informational: "Info", debug: "Info",
};
const SEVERITY_FIELD_KEYS = ["severity", "Severity", "alert.severity", "event.severity", "priority", "Priority", "risk", "risk_level", "risk_score", "score", "threat_level", "confidence", "level"];

// Best-effort severity for a non-Windows record from an explicit severity/level field.
function pickGenericSeverity(rec: Row): Severity {
  for (const k of SEVERITY_FIELD_KEYS) {
    const v = k.includes(".") ? getPath(rec, k) : getCI(rec, k);
    if (v == null) continue;
    if (typeof v === "number") {
      // Common 0-10 / 0-100 risk scales: map high→Critical, etc.
      if (v >= 90 || (v >= 9 && v <= 10)) return "Critical";
      if (v >= 70 || (v >= 7 && v < 9)) return "High";
      if (v >= 40 || (v >= 4 && v < 7)) return "Medium";
      if (v > 0) return "Low";
      continue;
    }
    const w = SEV_WORDS[str(v).trim().toLowerCase()];
    if (w) return w;
  }
  return "Low";
}

const GENERIC_MSG_KEYS = [
  "message", "Message", "description", "Description", "desc", "Desc", "event.action", "action",
  "rule.name", "ruleName", "signature", "signature_name", "name", "alert_name",
  "title", "event.original", "_raw", "raw", "summary",
];

// Flatten a record to dotted key/value string pairs (objects one+ levels deep).
export function flatten(obj: Row, out: [string, string][], prefix = "", depth = 0): void {
  if (depth > 3) return;
  for (const [k, v] of Object.entries(obj)) {
    const key = prefix ? `${prefix}.${k}` : k;
    if (typeof v === "string" || typeof v === "number" || typeof v === "boolean") {
      out.push([key, String(v)]);
    } else if (isObject(v)) {
      flatten(v, out, key, depth + 1);
    } else if (Array.isArray(v)) {
      for (const item of v) {
        if (typeof item === "string" || typeof item === "number") out.push([key, String(item)]);
        else if (isObject(item)) flatten(item, out, key, depth + 1);
      }
    }
  }
}

// IOC extraction for non-Windows records, driven by key-name heuristics.
export function genericIocs(pairs: [string, string][], iocSink: Map<string, SiemIoc>): void {
  for (const [key, value] of pairs) {
    const k = key.toLowerCase();
    const v = value.trim();
    if (!v || v === "-") continue;
    if (/(?:^|[._])(?:ip|ipaddr|ipaddress|src_ip|dst_ip|source_ip|dest_ip|destination_ip|remote_ip|client_ip|address)$/.test(k)) {
      const ip = cleanIp(v); if (ip) addIoc(iocSink, "ip", ip); continue;
    }
    if (/sha256|sha1|\bmd5\b|imphash|(?:^|[._])hash$/.test(k) && HEX_HASH.test(v)) { addIoc(iocSink, "hash", v.toLowerCase()); continue; }
    if (/(?:url|uri)$/.test(k) && /^https?:\/\//i.test(v)) { addIoc(iocSink, "url", v.slice(0, 300)); continue; }
    if (/(?:domain|fqdn|dns|query|host_name|hostname)$/.test(k) && /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(v) && !IPV4.test(v) && !TEXT_DOMAIN_SKIP_RE.test(v) && !TEXT_FILE_EXT_RE.test(v)) { addIoc(iocSink, "domain", v.toLowerCase()); continue; }
    if (/(?:image|process|exe|process_name|processname|command_line|commandline|cmdline)$/.test(k)) {
      const bn = baseName(v); if (/\.\w{2,4}$/.test(bn)) addIoc(iocSink, "process", bn); continue;
    }
    if (/(?:file|filename|filepath|file_path|path|target_filename)$/.test(k) && /[\\/]/.test(v)) { addIoc(iocSink, "file", v.slice(0, 300)); continue; }
  }
}

// Scan a record's free-text human message for embedded indicators that live INSIDE the message
// rather than in a dedicated structured field — e.g. an SSH auth line
// "Failed password for svc_mgmt from 10.44.20.20 port 52310 on PROXY-BO-01". genericIocs only reads
// IP-/hash-/url-NAMED keys, so without this an indicator that only appears in the message text lands
// in the timeline (which renders the description) but never becomes an IOC. Internal RFC1918 IPs are
// kept (an internal SSH source is investigative); the `.local` mDNS suffix is skipped so every event's
// AD hostname doesn't flood the IOC list.
const TEXT_URL_RE = /\bhttps?:\/\/[^\s'"|;>]+/gi;
const TEXT_IPV4_RE = /\b\d{1,3}(?:\.\d{1,3}){3}\b/g;
const TEXT_HASH_RE = /\b[a-f0-9]{64}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{32}\b/gi;
// Windows domain/local ACCOUNT SIDs only (S-1-5-21-<3 domain ids>-<RID>). These name a specific
// principal and are genuinely investigative. Deliberately NOT the well-known service/builtin SIDs
// (S-1-5-18/19/20 LocalSystem etc., S-1-5-32-* builtin groups) — those ride nearly every Windows
// event and would flood the IOC list, exactly the signal-to-noise trap the analyst wants avoided.
const TEXT_SID_RE = /\bS-1-5-21(?:-\d{1,10}){4}\b/gi;
const TEXT_DOMAIN_RE = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi;
// Internal-only zones — an AD/mDNS hostname is an asset, not an indicator; don't flood the IOC list.
const TEXT_DOMAIN_SKIP_RE = /\.(?:local|localdomain|internal|lan|home|corp|arpa)$/i;
// A "domain" ending in a common file extension is really a filename (evil.exe, payload.bin, report.json)
// — keep it out of the domain IOCs (the URL/path importers already capture files where relevant).
const TEXT_FILE_EXT_RE = /\.(?:exe|dll|sys|ps1|bat|cmd|vbs|js|jar|sh|bin|conf|log|txt|json|xml|yml|yaml|cfg|ini|py|pl|so|gz|tar|zip|7z|rar|tmp|bak|dat|pid|sock|key|pem|crt|doc|docx|xls|xlsx|pdf|png|jpg|gif)$/i;

export function textIocs(text: string, sink: Map<string, SiemIoc>): void {
  if (!text) return;
  for (const m of text.match(TEXT_URL_RE) ?? []) addIoc(sink, "url", m.replace(/[).,;]+$/, "").slice(0, 300));
  for (const m of text.match(TEXT_SID_RE) ?? []) addIoc(sink, "sid", m.toUpperCase());
  for (const m of text.match(TEXT_HASH_RE) ?? []) addIoc(sink, "hash", m.toLowerCase());
  for (const m of text.match(TEXT_IPV4_RE) ?? []) { const ip = cleanIp(m); if (ip) addIoc(sink, "ip", ip); }
  for (const m of text.matchAll(TEXT_DOMAIN_RE)) {
    const d = m[0].toLowerCase();
    const after = text[(m.index ?? 0) + m[0].length] ?? "";
    if (after === "@") continue;                          // local-part of user@host, not a domain
    if (IPV4.test(d) || TEXT_DOMAIN_SKIP_RE.test(d) || TEXT_FILE_EXT_RE.test(d)) continue;
    addIoc(sink, "domain", d);
  }
}

// Document/transport metadata that carries no investigative signal — excluded from the fallback
// field dump so the description leads with real content (e.g. Elasticsearch hit metadata).
const META_KEYS = new Set([
  "_id", "_index", "_type", "_score", "_version", "_ignored", "_routing", "_seq_no",
  "_primary_term", "sort", "clientid", "flowid", "highlight",
]);
// Field names worth surfacing first when there's no standard message field (detections, rule hits,
// command lines, paths, …). Matched against flattened (possibly dotted) key names.
const SALIENT_RE = /(name|message|detection|rule|signature|title|desc|stringhit|scriptblock|command|cmdline|action|alert|artifact|reference|keyword|path|process|original|user|account)/i;

// Build a one-line summary from a record's fields when it has no recognized message field: drop
// metadata noise, prefer salient fields, and fall back to the first handful of the rest.
function summarizePairs(pairs: [string, string][]): string {
  const meaningful = pairs.filter(([k]) => !k.startsWith("_") && !META_KEYS.has(k.toLowerCase()));
  const salient = meaningful.filter(([k]) => SALIENT_RE.test(k));
  return (salient.length ? salient : meaningful).slice(0, 8).map(([k, v]) => `${k}=${v}`).join(" - ");
}

export function mapGeneric(rec: Row, host: string, iocSink: Map<string, SiemIoc>): MappedEvent {
  const vendor = detectVendor(rec);
  const msg = firstStr(rec, GENERIC_MSG_KEYS);
  const pairs: [string, string][] = [];
  flatten(rec, pairs);
  genericIocs(pairs, iocSink);

  const base = msg ? oneLine(msg) : summarizePairs(pairs);
  textIocs(base, iocSink);   // scrape indicators embedded in the free-text message (not in a named field)
  let description = `${vendor ?? "SIEM event"}: ${base}`.slice(0, 600);
  if (host && !description.toLowerCase().includes(host.toLowerCase())) description = `${description} @ ${host}`.slice(0, 600);

  const severity = pickGenericSeverity(rec);
  // Aggregate identical generic events, normalizing volatile numbers/GUIDs out of the key.
  const aggKey = `gen|${vendor ?? ""}|${host}|${base}`
    .toLowerCase()
    .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/g, "<guid>")
    .replace(/\d+/g, "#")
    .slice(0, 400);

  return { timestamp: pickTimestamp(rec, undefined), description, severity, mitre: [], aggKey, ...(host ? { asset: host } : {}) };
}

// Detect the vendor/tool behind a generic record from its source/provider/index fields.
function detectVendor(rec: Row): string | undefined {
  const blob = firstStr(rec, ["vendor", "product", "source_name", "provider", "provider_guid", "_index", "agent.type", "observer.vendor", "tags"]);
  if (/sentinel.?one/i.test(blob)) return "SentinelOne";
  if (/crowdstrike|falcon/i.test(blob)) return "CrowdStrike Falcon";
  if (/defender|mde/i.test(blob)) return "Microsoft Defender";
  if (/carbon.?black/i.test(blob)) return "Carbon Black";
  if (/cortex|palo.?alto/i.test(blob)) return "Cortex XDR";
  if (/splunk/i.test(blob)) return "Splunk";
  if (/elastic|kibana|winlogbeat|filebeat|beats/i.test(blob)) return "Elastic";
  if (/qradar/i.test(blob)) return "QRadar";
  if (/wazuh/i.test(blob)) return "Wazuh";
  return undefined;
}

// ───────────────────────────── IOC sink ─────────────────────────────

export function addIoc(sink: Map<string, SiemIoc>, type: SiemIoc["type"], value: string): void {
  const v = value.trim();
  if (!v) return;
  const key = `${type}:${v.toLowerCase()}`;
  if (!sink.has(key)) sink.set(key, { type, value: v });
}

// ───────────────────────────── aggregation (shared) ─────────────────────────────

// Incremental accumulator behind aggregateEvents — collapse mapped events by aggKey into counted
// rows, apply the severity floor, then sort + cap on finish(). Exposed as an accumulator (not just
// the one-shot function) so a STREAMING caller (e.g. the Plaso file importer reading a 555 MB
// super-timeline line-by-line) can feed events one at a time without ever materializing the full
// mapped[] array — memory stays bounded by the distinct-key set, not the row count. Stateful.
export interface EventAggregator {
  add(m: MappedEvent): void;
  finish(): { events: SiemEvent[]; groups: number };
}

export function createEventAggregator(
  opts: { aggregate?: boolean; minSeverity?: Severity; maxEvents?: number } = {},
): EventAggregator {
  const aggregate = opts.aggregate ?? true;
  const maxEvents = opts.maxEvents ?? 2000;
  const floorRank = opts.minSeverity ? SEVERITY_RANK[opts.minSeverity] : Infinity;

  const byKey = new Map<string, SiemEvent>();
  const order: string[] = [];

  return {
    add(m: MappedEvent): void {
      if (SEVERITY_RANK[m.severity] > floorRank) return;          // below the severity floor
      const key = aggregate ? m.aggKey : `${order.length}`;       // no-agg ⇒ unique key per row
      const existing = byKey.get(key);
      if (existing) {
        existing.count = (existing.count ?? 1) + 1;
        const t = m.timestamp;
        if (t) {
          if (!existing.timestamp || t < existing.timestamp) existing.timestamp = t;
          if (!existing.endTimestamp || t > existing.endTimestamp) existing.endTimestamp = t;
        }
        existing.severity = worst(existing.severity, m.severity);
        for (const mt of m.mitre) if (!existing.mitreTechniques.includes(mt)) existing.mitreTechniques.push(mt);
        if (m.sources) for (const s of m.sources) { (existing.sources ??= []); if (!existing.sources.includes(s)) existing.sources.push(s); }
        if (!existing.artifactName && m.artifactName) existing.artifactName = m.artifactName; // first-wins provenance
        if (!existing.message && m.message) existing.message = m.message; // first-wins full detail
      } else {
        byKey.set(key, {
          id: "",
          timestamp: m.timestamp,
          description: m.description,
          severity: m.severity,
          mitreTechniques: [...m.mitre],
          count: 1,
          ...(m.sha256 ? { sha256: m.sha256 } : {}),
          ...(m.md5 ? { md5: m.md5 } : {}),
          ...(m.path ? { path: m.path } : {}),
          ...(m.asset ? { asset: m.asset } : {}),
          ...(m.processName ? { processName: m.processName } : {}),
          ...(m.parentName ? { parentName: m.parentName } : {}),
          ...(m.pid !== undefined ? { pid: m.pid } : {}),
          ...(m.sources?.length ? { sources: [...m.sources] } : {}),
          ...(m.srcIp ? { srcIp: m.srcIp } : {}),
          ...(m.dstIp ? { dstIp: m.dstIp } : {}),
          ...(m.port ? { port: m.port } : {}),
          ...(m.artifactName ? { artifactName: m.artifactName } : {}),
          ...(m.message ? { message: m.message } : {}),
        });
        order.push(key);
      }
    },
    finish(): { events: SiemEvent[]; groups: number } {
      // Drop the synthetic count:1 marker on un-aggregated singletons for a cleaner timeline.
      const events = order.map((k) => byKey.get(k)!);
      for (const e of events) if (e.count === 1) delete e.count;
      const groups = events.length;

      // Most-severe first, then noisiest, then earliest — then cap.
      events.sort((a, b) =>
        SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] ||
        (b.count ?? 1) - (a.count ?? 1) ||
        (a.timestamp || "~").localeCompare(b.timestamp || "~"));

      return { events: events.slice(0, maxEvents), groups };
    },
  };
}

// Collapse mapped events by their aggKey into counted rows, apply the severity floor,
// sort (most-severe → noisiest → earliest) and cap. Shared by the SIEM and Chainsaw/EVTX
// importers so both aggregate, sort, and cap identically. Returns the capped rows plus the
// group count BEFORE the cap (so callers can report "N over the cap"). Pure.
export function aggregateEvents(
  mapped: Iterable<MappedEvent>,
  opts: { aggregate?: boolean; minSeverity?: Severity; maxEvents?: number } = {},
): { events: SiemEvent[]; groups: number } {
  const agg = createEventAggregator(opts);
  for (const m of mapped) agg.add(m);
  return agg.finish();
}

// ───────────────────────────── top-level parse ─────────────────────────────

// Map a flat array of already-extracted records to the SIEM result (Windows per-EID mapping,
// generic field auto-detection fallback, aggregation + caps). Shared by parseSiemExport (which
// unwraps JSON/NDJSON containers first) and the Windows-Event-XML importer (which parses the XML
// envelope to the same record shape) so both produce an identical SiemParseResult. Pure.
export function buildSiemResult(records: Row[], format: string, opts: SiemImportOptions = {}): SiemParseResult {
  const maxIocs = opts.maxIocs ?? 5000;
  const total = records.length;

  const iocSink = new Map<string, SiemIoc>();
  const hostTally = new Map<string, number>();
  const mapped: MappedEvent[] = [];

  for (const rec of records) {
    const host = pickHost(rec);
    if (host) hostTally.set(host, (hostTally.get(host) ?? 0) + 1);
    mapped.push(mapWindows(rec, host, iocSink) ?? mapGeneric(rec, host, iocSink));
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
    format,
    hostname,
  };
}

export function parseSiemExport(text: string, opts: SiemImportOptions = {}): SiemParseResult {
  const { records, format } = extractRecords(text);
  return buildSiemResult(records, format, opts);
}
