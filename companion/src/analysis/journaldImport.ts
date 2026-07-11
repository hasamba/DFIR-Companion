// Deterministic importer for **systemd-journald** structured logs — `journalctl -o json` /
// `-o json-pretty` exports. The second Linux-host ingest path (closes #62, with auditd + sysdig);
// no AI call.
//
// journald JSON is one entry per object (NDJSON for `-o json`, or pretty-printed concatenated
// objects for `-o json-pretty`), every field UPPERCASE: `MESSAGE`, `PRIORITY` (syslog 0–7),
// `SYSLOG_IDENTIFIER` / `_SYSTEMD_UNIT` (the service), `_HOSTNAME`, `_COMM` / `_EXE` / `_CMDLINE`
// / `_PID` / `_UID`, and microsecond-epoch timestamps. This module:
//   1. READS each entry at its OWN time — `_SOURCE_REALTIME_TIMESTAMP` (when the app emitted it)
//      in preference to `__REALTIME_TIMESTAMP` (when the journal received it); both µs epoch.
//   2. DERIVES severity from PRIORITY, then BUMPS it from the message + identifier with a Linux
//      tradecraft table (sshd auth, sudo, useradd/usermod, kernel segfaults) — because most
//      security-relevant lines log at PRIORITY info/notice, not err.
//   3. EXTRACTS IOCs — `_EXE`/`_COMM`/`_CMDLINE` → process + file, and IPs/domains/URLs scraped
//      from the `MESSAGE` (sshd's "Failed password for root from 1.2.3.4 port 22").
//   4. AGGREGATES repetitive identical entries (shared with the SIEM importer) and caps the total.

import type { Severity } from "./stateTypes.js";
import {
  extractRecords,
  aggregateEvents,
  cleanIp,
  addIoc,
  firstStr,
  str,
  getCI,
  isObject,
  baseName,
  oneLine,
  worst,
  type MappedEvent,
  type SiemEvent,
  type SiemIoc,
} from "./siemImport.js";

type Row = Record<string, unknown>;

export interface JournaldImportOptions {
  aggregate?: boolean;
  minSeverity?: Severity;
  maxEvents?: number;
  maxIocs?: number;
}

export interface JournaldParseResult {
  events: SiemEvent[];
  iocs: SiemIoc[];
  total: number;
  kept: number;
  dropped: number;
  groups: number;
  format: string;   // "journald" | "empty"
  hostname: string;
}

const IPV4_G = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
const URL_G = /\bhttps?:\/\/[^\s"'<>)\]]+/gi;
const DOMAIN_G = /\b(?=[a-z0-9.-]{4,253}\b)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|info|biz|top|xyz|co|de|uk|club|online|site|live|shop|tk|ml|ga|cf|gq)\b/gi;

// syslog PRIORITY → severity. Conservative on the noisy middle (err→Medium, warning→Low); the
// keyword bumps below escalate the genuinely security-relevant lines regardless of their priority.
const PRIORITY_SEVERITY: Record<number, Severity> = {
  0: "Critical", // emerg
  1: "Critical", // alert
  2: "High",     // crit
  3: "Medium",   // err
  4: "Low",      // warning
  5: "Info",     // notice
  6: "Info",     // info
  7: "Info",     // debug
};

// MESSAGE / identifier tradecraft → severity floor + MITRE. First match wins for the label note.
const BUMPS: { re: RegExp; severity: Severity; mitre: string[] }[] = [
  { re: /failed password|authentication failure|invalid user|failed publickey|maximum authentication attempts|too many authentication failures/i, severity: "Medium", mitre: ["T1110"] },
  { re: /accepted password|accepted publickey|session opened for user root|new session \d+ of user root/i, severity: "Low", mitre: ["T1078"] },
  { re: /\buseradd\b|\bnew user\b|\badduser\b/i, severity: "High", mitre: ["T1136.001"] },
  { re: /\bnew group\b|\bgroupadd\b/i, severity: "Medium", mitre: ["T1136.002"] },
  { re: /\busermod\b|password changed for|\bpasswd\b.*changed/i, severity: "Medium", mitre: ["T1098"] },
  { re: /\bsudo\b.*command=|sudo:session.*opened for user root|\bCOMMAND=/i, severity: "Medium", mitre: ["T1548.003"] },
  { re: /promiscuous mode|entered promiscuous/i, severity: "High", mitre: ["T1040"] },
  { re: /segfault|general protection|kernel panic|oom-killer|killed process/i, severity: "Low", mitre: [] },
  { re: /possible break-in attempt|reverse mapping checking getaddrinfo/i, severity: "Medium", mitre: ["T1078"] },
  { re: /audit.*\bavc\b.*denied|apparmor=.?denied/i, severity: "Medium", mitre: ["T1562.001"] },
];

// The service / program behind the entry, for the description prefix + aggregation.
function identifier(rec: Row): string {
  return firstStr(rec, ["SYSLOG_IDENTIFIER", "_SYSTEMD_UNIT", "_COMM", "UNIT", "_SYSTEMD_CGROUP"]) || "journal";
}

// journald MESSAGE may be a byte array (numbers) when the line isn't valid UTF-8. Render either.
function messageOf(rec: Row): string {
  const m = getCI(rec, "MESSAGE");
  if (typeof m === "string") return m;
  if (Array.isArray(m)) return m.map((b) => (typeof b === "number" ? String.fromCharCode(b) : str(b))).join("");
  return str(m);
}

// µs-epoch string (journald) → ISO ms. Prefer the app's own time over the journal receipt time.
function journalTime(rec: Row): string {
  const us = firstStr(rec, ["_SOURCE_REALTIME_TIMESTAMP", "__REALTIME_TIMESTAMP"]);
  const n = Number(us);
  if (!Number.isFinite(n) || n <= 0) return "";
  const d = new Date(Math.floor(n / 1000));
  return Number.isNaN(d.getTime()) ? "" : d.toISOString();
}

function priorityOf(rec: Row): number {
  const p = getCI(rec, "PRIORITY");
  const n = typeof p === "number" ? p : parseInt(str(p), 10);
  return Number.isFinite(n) && n >= 0 && n <= 7 ? n : 6; // default info
}

function scrapeIocs(message: string, sink: Map<string, SiemIoc>): void {
  for (const m of message.matchAll(URL_G)) addIoc(sink, "url", m[0].slice(0, 300));
  for (const m of message.matchAll(IPV4_G)) { const ip = cleanIp(m[0]); if (ip) addIoc(sink, "ip", ip); }
  for (const m of message.matchAll(DOMAIN_G)) addIoc(sink, "domain", m[0].toLowerCase());
}

function mapEntry(rec: Row, iocSink: Map<string, SiemIoc>): MappedEvent | null {
  const message = oneLine(messageOf(rec));
  const ident = identifier(rec);
  const host = firstStr(rec, ["_HOSTNAME", "HOSTNAME"]);
  const exe = firstStr(rec, ["_EXE"]);
  const comm = firstStr(rec, ["_COMM"]);
  const cmdline = firstStr(rec, ["_CMDLINE"]);
  if (!message && !exe && !comm) return null; // nothing to anchor an event on

  let severity = PRIORITY_SEVERITY[priorityOf(rec)] ?? "Info";
  const mitre: string[] = [];
  const blob = `${ident} ${message} ${cmdline}`;
  for (const b of BUMPS) {
    if (b.re.test(blob)) {
      severity = worst(severity, b.severity);
      for (const t of b.mitre) if (!mitre.includes(t)) mitre.push(t);
    }
  }

  // IOCs.
  if (exe && exe.includes("/")) { addIoc(iocSink, "file", exe.slice(0, 300)); addIoc(iocSink, "process", baseName(exe)); }
  else if (comm) addIoc(iocSink, "process", comm);
  scrapeIocs(message, iocSink);

  let description = `journald [${ident}]: ${message || comm || exe}`;
  if (host) description += ` @ ${host}`;
  description = description.slice(0, 600);

  const procName = comm || baseName(exe) || undefined;
  return {
    timestamp: journalTime(rec),
    description,
    severity,
    mitre,
    aggKey: `journald|${ident}|${message}`.toLowerCase().replace(/\b\d+\b/g, "#").replace(/[0-9a-f]{2}(?::[0-9a-f]{2})+/gi, "<mac>").slice(0, 400),
    sources: ["journald"],
    ...(host ? { asset: host } : {}),
    ...(exe && exe.includes("/") ? { path: exe } : {}),
    ...(procName ? { processName: procName } : {}),
  };
}

// True when a record looks like a journald entry — leading-underscore trusted fields or a µs clock.
export function looksLikeJournald(rec: Row): boolean {
  return getCI(rec, "__REALTIME_TIMESTAMP") != null || getCI(rec, "__CURSOR") != null ||
    getCI(rec, "_BOOT_ID") != null || getCI(rec, "_MACHINE_ID") != null ||
    (getCI(rec, "MESSAGE") != null && getCI(rec, "PRIORITY") != null && getCI(rec, "_TRANSPORT") != null);
}

export function parseJournald(text: string, opts: JournaldImportOptions = {}): JournaldParseResult {
  const maxIocs = opts.maxIocs ?? 5000;
  const { records } = extractRecords(text);
  const journal = records.filter((r) => isObject(r) && looksLikeJournald(r));
  if (journal.length === 0) {
    return { events: [], iocs: [], total: records.length, kept: 0, dropped: records.length, groups: 0, format: "empty", hostname: "" };
  }

  const iocSink = new Map<string, SiemIoc>();
  const hostTally = new Map<string, number>();
  const mapped: MappedEvent[] = [];
  for (const rec of journal) {
    const host = firstStr(rec, ["_HOSTNAME", "HOSTNAME"]);
    if (host) hostTally.set(host, (hostTally.get(host) ?? 0) + 1);
    const m = mapEntry(rec, iocSink);
    if (m) mapped.push(m);
  }

  const { events, groups } = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents: opts.maxEvents ?? (Number(process.env.DFIR_MAX_EVENTS) || 2000),
  });

  const represented = events.reduce((n, e) => n + (e.count ?? 1), 0);
  const hostname = [...hostTally.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] ?? "";

  return {
    events,
    iocs: [...iocSink.values()].slice(0, maxIocs),
    total: journal.length,
    kept: events.length,
    dropped: Math.max(0, journal.length - represented),
    groups,
    format: "journald",
    hostname,
  };
}
