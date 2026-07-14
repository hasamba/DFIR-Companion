// Deterministic importer for Snort / Suricata "fast" alert logs — the classic single-line IDS alert
// format (`alert_fast`, the default `snort -A fast` / `alert` file). Snort is a DETECTOR, so this
// consumes its verdict (rule + priority) rather than re-deriving anything — the same "ingest the tool's
// output" stance as the Chainsaw/Hayabusa/Velociraptor importers. A line looks like:
//
//   05/14-12:26:09.500 [**] [1:2009714:9] ET WEB_SERVER Possible SQL Injection Attempt UNION SELECT [**] \
//     [Classification: web-application-attack] [Priority: 1] {TCP} 145.78.103.167:60278 -> 45.83.220.5:80
//
// Severity is the rule's own Priority verdict (1=High, 2=Medium, 3=Low). Like a Cisco ASA / BSD syslog
// line the timestamp carries NO YEAR (`MM/DD-HH:MM:SS`), so we stamp an assumed year — the deterministic
// year-clamp in mergeDelta then re-anchors it to the case's dominant year, so importing alongside dated
// evidence lands the alerts correctly. PUBLIC src/dst IPs become IOCs (internal RFC1918 skipped, like
// the ECAR/network importers, to keep the IOC list tight). Pure, no AI. Reuses siemImport's helpers.

import type { Severity } from "./stateTypes.js";
import { aggregateEvents, addIoc, cleanIp, oneLine, type MappedEvent, type SiemEvent, type SiemIoc, type SiemParseResult,
  maxEventsDefault,
} from "./siemImport.js";

export interface SnortImportOptions {
  aggregate?: boolean;
  minSeverity?: Severity;
  maxEvents?: number;
  maxIocs?: number;
  assumeYear?: number; // year stamped onto the year-less timestamps (default: current UTC year)
}

export type SnortParseResult = SiemParseResult;

export const SNORT_SOURCE = "Snort";

// A Snort fast-alert line: timestamp, [**], [gid:sid:rev], …, [Priority: N]. Anchored enough to not
// match arbitrary logs. Used both to detect a line and to gate parsing.
const ALERT_LINE = /^\s*\d{1,2}\/\d{1,2}-\d{2}:\d{2}:\d{2}(?:\.\d+)?\s+\[\*\*\]\s+\[\d+:\d+:\d+\]/;

// Is this text a Snort/Suricata fast-alert log? True when a meaningful share of the first non-blank
// lines match the alert shape (so a stray mention in another log doesn't trip it). Pure.
export function looksLikeSnort(text: string): boolean {
  const lines = text.split(/\r?\n/).map((l) => l.trim()).filter(Boolean).slice(0, 50);
  if (!lines.length) return false;
  const hits = lines.filter((l) => ALERT_LINE.test(l)).length;
  return hits >= 1 && hits >= lines.length * 0.5;
}

function isPrivateIp(ip: string): boolean {
  const m = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  if (a === 10 || a === 127 || a === 0) return true;
  if (a === 192 && b === 168) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 169 && b === 254) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  return false;
}

function severityForPriority(p: number): Severity {
  return p <= 1 ? "High" : p === 2 ? "Medium" : "Low";
}

// Parse the year-less Snort timestamp ("MM/DD-HH:MM:SS.ffffff") into an ISO string at `year`. Returns ""
// when unparseable. Fractional seconds are truncated to milliseconds.
function parseSnortTime(ts: string, year: number): string {
  const m = ts.match(/^(\d{1,2})\/(\d{1,2})-(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?$/);
  if (!m) return "";
  const [, mm, dd, hh, mi, ss, frac] = m;
  const ms = frac ? frac.slice(0, 3).padEnd(3, "0") : "000";
  const iso = `${year}-${mm.padStart(2, "0")}-${dd.padStart(2, "0")}T${hh}:${mi}:${ss}.${ms}Z`;
  const t = Date.parse(iso);
  return Number.isNaN(t) ? "" : new Date(t).toISOString();
}

// Map one alert line to a forensic event (collecting IOCs), or null if it isn't an alert line.
export function mapSnortLine(line: string, year: number, sink: Map<string, SiemIoc>): MappedEvent | null {
  if (!ALERT_LINE.test(line)) return null;
  // The line has two "[**]" separators: "<ts> [**] [sid] <msg> [**] <tail>".
  const parts = line.split("[**]");
  if (parts.length < 3) return null;
  const timestamp = parseSnortTime(parts[0].trim(), year);

  const mid = parts[1].trim(); // "[1:2009714:9] ET WEB_SERVER … UNION SELECT"
  const sidM = mid.match(/^\[(\d+:\d+:\d+)\]\s*/);
  const sid = sidM ? sidM[1] : "";
  const message = oneLine(sidM ? mid.slice(sidM[0].length) : mid) || "IDS alert";

  const tail = parts.slice(2).join("[**]"); // "[Classification: …] [Priority: 1] {TCP} src -> dst"
  const cls = tail.match(/\[Classification:\s*([^\]]+)\]/i)?.[1]?.trim() ?? "";
  const prio = Number(tail.match(/\[Priority:\s*(\d+)\]/i)?.[1] ?? "3");
  const proto = tail.match(/\{(\w+)\}/)?.[1] ?? "";
  const flow = tail.match(/\{(?:\w+)\}\s+([0-9.]+)(?::(\d+))?\s*->\s*([0-9.]+)(?::(\d+))?/);
  const srcIp = flow ? cleanIp(flow[1]) : "";
  const srcPort = flow?.[2];
  const dstIp = flow ? cleanIp(flow[3]) : "";
  const dstPort = flow?.[4];

  for (const ip of [srcIp, dstIp]) if (ip && !isPrivateIp(ip)) addIoc(sink, "ip", ip);

  const flowStr = flow ? ` ${srcIp}${srcPort ? `:${srcPort}` : ""} → ${dstIp}${dstPort ? `:${dstPort}` : ""}` : "";
  const description = `Snort IDS: ${message}` +
    (sid ? ` (SID ${sid}${cls ? `, ${cls}` : ""})` : cls ? ` (${cls})` : "") +
    (proto ? ` [${proto}]` : "") + flowStr;

  const port = dstPort && /^\d+$/.test(dstPort) ? Number(dstPort) : undefined;
  return {
    timestamp,
    description,
    severity: severityForPriority(prio),
    mitre: [],
    aggKey: `snort|${sid}|${srcIp}|${dstIp}:${dstPort ?? ""}`,
    sources: [SNORT_SOURCE],
    ...(srcIp ? { srcIp } : {}),
    ...(dstIp ? { dstIp } : {}),
    ...(port && port > 0 && port <= 65535 ? { port } : {}),
  };
}

// Parse a Snort/Suricata fast-alert log into the shared SIEM result shape (aggregated + capped). Pure.
export function parseSnortLog(text: string, opts: SnortImportOptions = {}): SnortParseResult {
  const year = opts.assumeYear ?? new Date().getUTCFullYear();
  const maxIocs = opts.maxIocs ?? 5000;
  const sink = new Map<string, SiemIoc>();
  const mapped: MappedEvent[] = [];
  let total = 0;

  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) continue;
    const m = mapSnortLine(line, year, sink);
    if (m) { total++; mapped.push(m); }
  }

  const { events, groups } = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents: opts.maxEvents ?? maxEventsDefault(),
  });
  const represented = events.reduce((n, e) => n + (e.count ?? 1), 0);

  return {
    events,
    iocs: [...sink.values()].slice(0, maxIocs),
    total,
    kept: events.length,
    dropped: Math.max(0, total - represented),
    groups,
    format: "snort-fast",
    hostname: "",
  };
}
