import type { Severity } from "./stateTypes.js";
import {
  extractRecords,
  aggregateEvents,
  addIoc,
  oneLine,
  isObject,
  getCI,
  str,
  normalizeTime,
  cleanIp,
  maxEventsDefault,
  type MappedEvent,
  type SiemEvent,
  type SiemIoc,
  type SiemParseResult,
} from "./siemImport.js";
import { createCanonicalEvent } from "./canonicalEvent.js";
import { parseEvtxXml } from "./evtxXmlImport.js";
import { parseAuditdLog } from "./auditdImport.js";
import { mapSyslogLine } from "./syslogImport.js";
import type { ImportDebugRecorder } from "./importDebug.js";

// Deterministic adapter for Linux telemetry exported from Microsoft Sentinel / Log Analytics (#2098).
// Two table shapes, one per row, and a file may mix them:
//
//  - `Syslog`: the real record is a string in `SyslogMessage`. Sysmon for Linux writes a whole
//    `<Event>` XML document there; AUOMS (the Azure Monitor auditd plugin) writes an auditd-style
//    `type=AUOMS_EXECVE audit(…): …` record; anything else is a plain syslog message. Each goes to
//    the parser that already reads that format — this module only unwraps and routes.
//  - `VMConnection` (VM insights): one aggregated connection per row, with the owning process.
//    Mapped to a network-flow event at the same Low grade the other flow importers use; no new
//    grading here (#2099 grades the java → shell shape).
//
// Before this the file fell to the SIEM catch-all and every row was a generic Low "SIEM event"
// whose command line could not be read.

type Row = Record<string, unknown>;

export interface SentinelLinuxImportOptions {
  aggregate?: boolean;
  minSeverity?: Severity;
  maxEvents?: number;
  maxIocs?: number;
  /** This attempt's import debug recorder (#1736): decisions and counts only, never row content. */
  debug?: ImportDebugRecorder;
}

export const SENTINEL_SYSLOG_SOURCE = "Microsoft Sentinel Syslog";
export const VMCONNECTION_SOURCE = "Azure VM insights (VMConnection)";
const FLOW_SEVERITY: Severity = "Low";
const DESCRIPTION_CAP = 600;
const HOST_KEYS = ["HostName", "Computer"] as const;
const TIME_KEYS = ["TimeGenerated", "EventTime"] as const;
const AUDIT_RECORD_RE =
  /^type=(?:AUOMS_\w+|SYSCALL|EXECVE|PROCTITLE|PATH|CWD|USER_\w+|CRED_\w+|LOGIN)\s+(?:msg=)?audit\(/;
const SYSMON_XML_RE = /^\s*<Event[\s>]/;
// Sentinel strips the `;` from the entities inside SyslogMessage (`&lt unknown process&gt `). Put
// it back so the XML parser decodes the entity instead of printing it.
const BROKEN_ENTITY_RE = /&(lt|gt|quot|amp|apos)\b(?!;) ?/g;
// RFC 5424 facility / severity numbers for rebuilding a `<PRI>` header from Sentinel's names.
const FACILITY: Record<string, number> = {
  kern: 0,
  user: 1,
  mail: 2,
  daemon: 3,
  auth: 4,
  syslog: 5,
  lpr: 6,
  news: 7,
  uucp: 8,
  cron: 9,
  authpriv: 10,
  ftp: 11,
  local0: 16,
  local1: 17,
  local2: 18,
  local3: 19,
  local4: 20,
  local5: 21,
  local6: 22,
  local7: 23,
};
const SEVERITY: Record<string, number> = {
  emerg: 0,
  alert: 1,
  crit: 2,
  err: 3,
  error: 3,
  warning: 4,
  warn: 4,
  notice: 5,
  info: 6,
  debug: 7,
};

function firstOf(row: Row, keys: readonly string[]): string {
  for (const k of keys) {
    const v = str(getCI(row, k)).trim();
    if (v) return v;
  }
  return "";
}

function typeIs(row: Row, expected: string): boolean {
  const t = str(getCI(row, "Type")).trim();
  return !t || t.toLowerCase() === expected.toLowerCase();
}

/** A Sentinel `Syslog` table row: SyslogMessage + Facility + a host + a time column. */
export function isSentinelSyslogRow(row: Row): boolean {
  return (
    typeof getCI(row, "SyslogMessage") === "string" &&
    str(getCI(row, "Facility")).trim() !== "" &&
    firstOf(row, HOST_KEYS) !== "" &&
    firstOf(row, TIME_KEYS) !== "" &&
    typeIs(row, "Syslog")
  );
}

/** A VM insights `VMConnection` row: Direction + ProcessName + a remote IP + DestinationPort + time. */
export function isVmConnectionRow(row: Row): boolean {
  return (
    str(getCI(row, "Direction")).trim() !== "" &&
    str(getCI(row, "ProcessName")).trim() !== "" &&
    firstOf(row, ["DestinationIp", "RemoteIp"]) !== "" &&
    getCI(row, "DestinationPort") != null &&
    str(getCI(row, "TimeGenerated")).trim() !== "" &&
    typeIs(row, "VMConnection")
  );
}

/** Detection signature for importDetect: the sampled row is one of the two table shapes. */
export function looksLikeSentinelLinux(sample: Row): boolean {
  return isSentinelSyslogRow(sample) || isVmConnectionRow(sample);
}

// ───────────────────────────── VMConnection ─────────────────────────────

function num(row: Row, key: string): number {
  const n = Number(getCI(row, key));
  return Number.isFinite(n) ? n : 0;
}

function mapVmConnection(row: Row, sink: Map<string, SiemIoc>): MappedEvent {
  const host = firstOf(row, ["Computer", "HostName"]);
  const proc = str(getCI(row, "ProcessName")).trim();
  const direction = str(getCI(row, "Direction")).trim().toLowerCase();
  const src = str(getCI(row, "SourceIp")).trim();
  const remote = firstOf(row, ["RemoteIp", "DestinationIp"]);
  const dst = firstOf(row, ["DestinationIp", "RemoteIp"]);
  const port = num(row, "DestinationPort");
  const protocol = str(getCI(row, "Protocol")).trim().toLowerCase() || "tcp";
  const sent = num(row, "BytesSent");
  const received = num(row, "BytesReceived");
  const timestamp = normalizeTime(str(getCI(row, "TimeGenerated")));
  const remoteIoc = cleanIp(remote);
  if (remoteIoc) addIoc(sink, "ip", remoteIoc);

  // Source → destination is the connection's own direction for both inbound and outbound rows.
  const description = oneLine(
    `VMConnection: ${proc} ${direction || "connection"} ${src || host} -> ${dst}:${port} (${protocol}), remote ${remote}, sent ${sent} B, received ${received} B` +
      (num(row, "LinksEstablished") ? `, ${num(row, "LinksEstablished")} link(s) established` : ""),
  ).slice(0, DESCRIPTION_CAP);
  const portField = port > 0 ? { port } : {};
  return {
    timestamp,
    description,
    severity: FLOW_SEVERITY,
    mitre: [],
    aggKey: `vmconnection|${timestamp}|${host}|${proc}|${direction}|${src}|${dst}|${port}|${protocol}`
      .toLowerCase()
      .slice(0, 400),
    sources: [VMCONNECTION_SOURCE],
    ...(host ? { asset: host } : {}),
    ...(proc ? { processName: proc } : {}),
    ...(src ? { srcIp: src } : {}),
    ...(dst ? { dstIp: dst } : {}),
    ...portField,
    canonical: createCanonicalEvent({
      event: { category: "network", type: "flow", action: direction || "connection" },
      network: {
        ...(src ? { source: { address: src, provenance: "edge-observed" } } : {}),
        ...(dst ? { destination: { address: dst, ...portField } } : {}),
        protocol,
      },
      ...(proc ? { process: { name: proc } } : {}),
      ...(host ? { target: { kind: "host", name: host } } : {}),
      time: { observed: timestamp, normalized: timestamp, timezone: "UTC" },
      evidence: {
        rawRecords: [{ source: "vmconnection", locator: str(getCI(row, "ConnectionId")) || timestamp }],
      },
      producer: {
        importer: "vmconnection",
        parserVersion: "1",
        mappingVersion: "vmconnection-v1",
        ruleVersions: ["vmconnection-v1"],
      },
    }),
  };
}

// ───────────────────────────── Syslog routing ─────────────────────────────

function rebuildSyslogLine(row: Row): string {
  const fac = FACILITY[str(getCI(row, "Facility")).trim().toLowerCase()] ?? 1;
  const sev = SEVERITY[str(getCI(row, "SeverityLevel")).trim().toLowerCase()] ?? 6;
  const time = normalizeTime(firstOf(row, TIME_KEYS)) || firstOf(row, TIME_KEYS);
  const host = firstOf(row, HOST_KEYS).replace(/\s+/g, "_") || "-";
  const app = str(getCI(row, "ProcessName")).trim().replace(/\s+/g, "_") || "-";
  const msg = oneLine(str(getCI(row, "SyslogMessage")));
  return `<${fac * 8 + sev}>1 ${time} ${host} ${app} - - - ${msg}`;
}

interface Buckets {
  sysmonXml: string[];
  /** Audit lines keyed by the row's host, so one host's serials never merge with another's. */
  auditByHost: Map<string, string[]>;
  syslogRows: Row[];
  vmRows: Row[];
  hosts: Map<string, number>;
  unrecognized: number;
}

function auditBucket(byHost: Map<string, string[]>, host: string): string[] {
  const existing = byHost.get(host);
  if (existing) return existing;
  const created: string[] = [];
  byHost.set(host, created);
  return created;
}

function bucketRows(records: Row[]): Buckets {
  const b: Buckets = {
    sysmonXml: [],
    auditByHost: new Map(),
    syslogRows: [],
    vmRows: [],
    hosts: new Map(),
    unrecognized: 0,
  };
  for (const raw of records) {
    if (!isObject(raw)) {
      b.unrecognized++;
      continue;
    }
    const host = firstOf(raw, HOST_KEYS);
    if (host) b.hosts.set(host, (b.hosts.get(host) ?? 0) + 1);
    if (isVmConnectionRow(raw)) b.vmRows.push(raw);
    else if (!isSentinelSyslogRow(raw)) b.unrecognized++;
    else {
      const msg = str(getCI(raw, "SyslogMessage"));
      if (SYSMON_XML_RE.test(msg)) b.sysmonXml.push(msg.replace(BROKEN_ENTITY_RE, "&$1;"));
      else if (AUDIT_RECORD_RE.test(msg.trim())) auditBucket(b.auditByHost, host).push(oneLine(msg).trim());
      else b.syslogRows.push(raw);
    }
  }
  return b;
}

// auditd groups records by audit serial, and serials are per host: parse each host's records on
// their own and stamp that host, so a multi-host export neither merges colliding serials nor
// hands every command to the dominant host (#2098).
function parseAuditByHost(
  byHost: Map<string, string[]>,
  inner: Parameters<typeof parseAuditdLog>[1],
): SiemParseResult[] {
  return [...byHost.entries()].map(([host, lines]) => {
    const r = parseAuditdLog(lines.join("\n"), inner);
    return host ? { ...r, events: r.events.map((e) => (e.asset ? e : { ...e, asset: host })) } : r;
  });
}

function dominantHost(hosts: Map<string, number>): string {
  return [...hosts.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] ?? "";
}

// The inner parsers number their own events; give the merged list one id sequence and fill a
// missing host from the export's dominant HostName.
function finalize(events: SiemEvent[], host: string): SiemEvent[] {
  return events.map((e, i) => ({ ...e, id: `sl${i + 1}`, ...(!e.asset && host ? { asset: host } : {}) }));
}

function emptyResult(total: number): SiemParseResult {
  return { events: [], iocs: [], total, kept: 0, dropped: total, groups: 0, format: "empty", hostname: "" };
}

export function parseSentinelLinux(input: string, opts: SentinelLinuxImportOptions = {}): SiemParseResult {
  const trimmed = input.trim();
  if (!trimmed) return emptyResult(0);
  const records = extractRecords(trimmed).records;
  if (records.length === 0) return emptyResult(0);
  const b = bucketRows(records);
  opts.debug?.skipped("unrecognized_record", b.unrecognized);
  const inner = {
    aggregate: opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents: opts.maxEvents,
    debug: opts.debug,
  };

  const parts: SiemParseResult[] = [];
  if (b.sysmonXml.length) parts.push(parseEvtxXml(`<Events>${b.sysmonXml.join("\n")}</Events>`, inner));
  parts.push(...parseAuditByHost(b.auditByHost, inner));

  const sink = new Map<string, SiemIoc>();
  const mapped: MappedEvent[] = [];
  for (const row of b.syslogRows) {
    const m = mapSyslogLine(rebuildSyslogLine(row), new Date().getUTCFullYear(), sink);
    if (m) mapped.push({ ...m, sources: [SENTINEL_SYSLOG_SOURCE] });
    else opts.debug?.skipped("unparseable_syslog_row");
  }
  for (const row of b.vmRows) mapped.push(mapVmConnection(row, sink));
  const agg = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents: opts.maxEvents ?? maxEventsDefault(),
  });

  const host = dominantHost(b.hosts);
  const events = finalize([...parts.flatMap((p) => p.events), ...agg.events], host);
  const iocMap = new Map<string, SiemIoc>();
  for (const ioc of [...parts.flatMap((p) => p.iocs), ...sink.values()])
    iocMap.set(`${ioc.type}|${ioc.value}`, ioc);
  const total = records.length;
  const represented = events.reduce((n, e) => n + (e.count ?? 1), 0);
  return {
    events,
    iocs: [...iocMap.values()].slice(0, opts.maxIocs ?? 5000),
    total,
    kept: events.length,
    dropped: Math.max(0, total - represented),
    groups: parts.reduce((n, p) => n + p.groups, agg.groups),
    format: events.length ? "sentinel-linux" : "empty",
    hostname: host,
  };
}
