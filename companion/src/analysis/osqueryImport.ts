// Deterministic importer for **osquery** scheduled-query result logs — endpoint telemetry; no AI
// call. Sourced from the Anthropic-Cybersecurity-Skills `deploying-osquery-for-endpoint-monitoring`
// (Apache-2.0) result-log format; consumed as evidence, NOT re-implemented as a detection engine.
//
// osqueryd writes its scheduled-query results as JSON-lines, in two shapes:
//   • differential — one row per line: `{ name, hostIdentifier, unixTime, columns:{…}, action }`
//     (`action` = "added" | "removed").
//   • snapshot     — a full result set per line: `{ name, hostIdentifier, unixTime,
//     snapshot:[{…},…], action:"snapshot" }`.
// A result row carries no maliciousness verdict, so severity is **Info by default** (like the ECAR /
// auditd raw-telemetry importers) with a CONSERVATIVE bump only when a row's command line matches
// the shared tradecraft grader (process_events / process rows carry `cmdline`). Each row's structured
// columns become IOCs (path/hash → file/hash, remote address → ip, cmdline → scraped indicators) and
// the query's own `unixTime` is the event time. Tagged osquery.

import type { Severity } from "./stateTypes.js";
import {
  extractRecords,
  aggregateEvents,
  cleanIp,
  addIoc,
  baseName,
  worst,
  str,
  isObject,
  getCI,
  oneLine,
  normalizeTime,
  textIocs,
  isSuspiciousCmd,
  parsePid,
  type MappedEvent,
  type SiemEvent,
  type SiemIoc,
  maxEventsDefault,
} from "./siemImport.js";
import { tradecraftSignal } from "./tradecraftRules.js";
import { reconTechniques } from "./reconTechniques.js";

type Row = Record<string, unknown>;

export interface OsqueryImportOptions {
  aggregate?: boolean;
  minSeverity?: Severity;
  maxEvents?: number;
  maxIocs?: number;
}

export interface OsqueryParseResult {
  events: SiemEvent[];
  iocs: SiemIoc[];
  total: number;
  kept: number;
  dropped: number;
  groups: number;
  format: string; // "osquery" | "empty"
}

// Cap how many rows a single snapshot line expands to, so a full-table snapshot (thousands of rows)
// can't blow up the timeline before aggregation/caps run.
const MAX_SNAPSHOT_ROWS = 500;

// Salient column keys rendered into the description (first present wins order), plus the keys that
// carry a command line to grade / an indicator to extract.
const CMD_KEYS = ["cmdline", "command_line", "cmd", "arguments"];
const PATH_KEYS = ["path", "target_path", "binary_path", "exe", "executable", "source"];
const HASH_KEYS = ["sha256", "sha1", "md5"];
const IP_KEYS = ["remote_address", "address", "destination", "remote_ip", "src_ip", "dst_ip"];
const SUMMARY_KEYS = ["name", "path", "cmdline", "command_line", "remote_address", "address", "username", "user", "uid", "pid", "port", "key", "value"];

function timeOf(rec: Row): string {
  const unix = Number(getCI(rec, "unixTime"));
  if (Number.isFinite(unix) && unix > 0) return new Date(unix * 1000).toISOString();
  const cal = str(getCI(rec, "calendarTime")).trim();
  if (cal) {
    const d = new Date(cal); // "Tue Aug 1 12:00:00 2024 UTC"
    if (!Number.isNaN(d.getTime())) return d.toISOString();
  }
  return normalizeTime(str(getCI(rec, "time")));
}

function firstCol(cols: Row, keys: string[]): string {
  for (const k of keys) { const v = str(getCI(cols, k)).trim(); if (v && v !== "-") return v; }
  return "";
}

// Map ONE result row (a `columns` object or one element of a `snapshot`) to a forensic event.
function mapRow(name: string, host: string, action: string, ts: string, cols: Row, sink: Map<string, SiemIoc>): MappedEvent {
  const path = firstCol(cols, PATH_KEYS);
  const cmd = firstCol(cols, CMD_KEYS);
  const image = path || baseName(cmd.split(/\s+/)[0] || "");

  let severity: Severity = "Info";
  const mitre: string[] = [];
  // Conservative tradecraft grading on a command-line column (process_events / process rows).
  if (cmd) {
    const susp = isSuspiciousCmd(image, cmd);
    if (susp === "strong") { severity = worst(severity, "High"); if (!mitre.includes("T1003")) mitre.push("T1003"); }
    else if (susp === "weak") severity = worst(severity, "Medium");
    const tc = tradecraftSignal(image, cmd);
    if (tc) {
      severity = worst(severity, tc.weight === "strong" ? "High" : "Medium");
      for (const t of tc.mitre) if (!mitre.includes(t)) mitre.push(t);
    }
    for (const t of reconTechniques(image, cmd)) if (!mitre.includes(t)) mitre.push(t);
    textIocs(cmd, sink);
  }

  // IOCs from structured columns.
  for (const hk of HASH_KEYS) { const h = str(getCI(cols, hk)).trim(); if (/^[a-f0-9]{32,64}$/i.test(h)) { addIoc(sink, "hash", h.toLowerCase()); break; } }
  if (path && /[\\/]/.test(path)) addIoc(sink, "file", path.slice(0, 300));
  const procName = baseName(image) || undefined;
  if (procName) addIoc(sink, "process", procName);
  const ip = cleanIp(firstCol(cols, IP_KEYS));
  if (ip) addIoc(sink, "ip", ip);
  const pid = parsePid(str(getCI(cols, "pid")));

  // Compact description: the query name + action + a few salient columns.
  const parts: string[] = [];
  for (const k of SUMMARY_KEYS) {
    const v = str(getCI(cols, k)).trim();
    if (v && v !== "-") parts.push(`${k}=${oneLine(v).slice(0, 120)}`);
    if (parts.length >= 5) break;
  }
  let description = `osquery ${name}${action ? ` [${action}]` : ""}`;
  if (parts.length) description += ` — ${parts.join(", ")}`;
  if (host) description += ` @ ${host}`;
  description = description.slice(0, 600);

  const colSig = parts.join("|") || firstCol(cols, SUMMARY_KEYS);
  return {
    timestamp: ts,
    description, severity, mitre,
    aggKey: `osquery|${name}|${action}|${colSig}`.toLowerCase().replace(/\b\d{3,}\b/g, "#").slice(0, 400),
    sources: ["osquery"],
    ...(host ? { asset: host } : {}),
    ...(path && /[\\/]/.test(path) ? { path } : {}),
    ...(procName ? { processName: procName } : {}),
    ...(pid !== undefined ? { pid } : {}),
  };
}

export function parseOsqueryLog(text: string, opts: OsqueryImportOptions = {}): OsqueryParseResult {
  const maxIocs = opts.maxIocs ?? 5000;
  const { records } = extractRecords(text);
  const total = records.length;
  if (total === 0) {
    return { events: [], iocs: [], total: 0, kept: 0, dropped: 0, groups: 0, format: "empty" };
  }

  const iocSink = new Map<string, SiemIoc>();
  const mapped: MappedEvent[] = [];
  for (const rec of records) {
    const name = str(getCI(rec, "name"));
    const columns = getCI(rec, "columns");
    const snapshot = getCI(rec, "snapshot");
    if (!name || (!isObject(columns) && !Array.isArray(snapshot))) continue;

    const host = str(getCI(rec, "hostIdentifier")) || str(getCI(rec, "host_identifier"));
    const action = str(getCI(rec, "action"));
    const ts = timeOf(rec);

    if (isObject(columns)) {
      mapped.push(mapRow(name, host, action, ts, columns, iocSink));
    } else if (Array.isArray(snapshot)) {
      let n = 0;
      for (const row of snapshot) {
        if (!isObject(row)) continue;
        mapped.push(mapRow(name, host, action || "snapshot", ts, row, iocSink));
        if (++n >= MAX_SNAPSHOT_ROWS) break;
      }
    }
  }
  if (mapped.length === 0) {
    return { events: [], iocs: [], total, kept: 0, dropped: total, groups: 0, format: "empty" };
  }

  const { events, groups } = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents: opts.maxEvents ?? maxEventsDefault(),
  });

  const represented = events.reduce((n, e) => n + (e.count ?? 1), 0);
  return {
    events,
    iocs: [...iocSink.values()].slice(0, maxIocs),
    total,
    kept: events.length,
    dropped: Math.max(0, total - represented),
    groups,
    format: "osquery",
  };
}
