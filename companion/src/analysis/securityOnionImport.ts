// Deterministic importer for Security Onion Console (SOC) events — the Alerts / Hunt views the
// browser extension pushes (issue: Security Onion support). No AI call.
//
// Per the Companion's post-detection principle we CONSUME Security Onion's verdict — we do NOT
// re-evaluate the rule. SOC returns each event as an `EventRecord.payload`: a flattened ECS
// document with FLAT dotted keys ("event.severity_label", "rule.name", "source.ip", …). The
// browser adapter forwards each payload with `_id`/`_index` metadata and a `_Source` stamp.
//
// Mapping (verdict-first):
//   • severity   ← `event.severity_label` (Suricata/SO label) → forensic severity; else the
//                  numeric `event.severity` priority; else Medium (a named alert fired).
//   • description← `rule.name` (the signature that fired) + module + src→dst + host.
//   • MITRE      ← ECS `threat.technique.id` / `rule.metadata.mitre_*` (any Txxxx ids).
//   • IOCs       ← source/destination IPs, dns.query / url / *.domain, file hashes + name.
//   • time       ← the event's own `@timestamp` (never the capture time).
// Events are tagged "Security Onion" for cross-source correlation.

import type { Severity } from "./stateTypes.js";
import {
  extractRecords,
  aggregateEvents,
  cleanIp,
  addIoc,
  mergeRowIocs,
  str,
  isObject,
  getCI,
  getPath,
  normalizeTime,
  type MappedEvent,
  type SiemEvent,
  type SiemIoc,
  maxEventsDefault,
} from "./siemImport.js";
import type { ImportDebugRecorder } from "./importDebug.js";

type Row = Record<string, unknown>;

export interface SecurityOnionImportOptions {
  aggregate?: boolean;
  minSeverity?: Severity;
  maxEvents?: number;
  maxIocs?: number;
  /** This attempt's import debug recorder (#1736): decisions and counts only, never row content. */
  debug?: ImportDebugRecorder;
}

export interface SecurityOnionParseResult {
  events: SiemEvent[];
  iocs: SiemIoc[];
  total: number; // records found
  kept: number; // events emitted (after aggregation + cap)
  dropped: number; // records not turned into events (below floor / capped)
  groups: number; // distinct event groups before the cap
  hostname: string;
}

const IPV4 = /^\d{1,3}(?:\.\d{1,3}){3}$/;
const HEX_HASH = /^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i;
const DOMAIN = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i;

// SOC flattens ECS docs to FLAT dotted keys ("source.ip"); a raw API export may nest them
// ("source":{"ip"}). Try the literal dotted key first, then the nested path.
function field(row: Row, key: string): unknown {
  const flat = getCI(row, key);
  if (flat != null) return flat;
  return key.includes(".") ? getPath(row, key) : undefined;
}
function fstr(row: Row, key: string): string {
  return str(field(row, key)).trim();
}

const SEV_LABEL: Record<string, Severity> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  moderate: "Medium",
  low: "Low",
  informational: "Info",
  info: "Info",
};

// Suricata signature priority (`event.severity`): 1 = most severe (ET/Talos use 1–4).
function numSeverity(n: number): Severity {
  if (n <= 1) return "High";
  if (n === 2) return "Medium";
  if (n === 3) return "Low";
  return "Info";
}

// SOC's own verdict for a row: the explicit label wins, then the numeric priority, then a
// sensible default (Medium when a rule fired, else Info).
export function securityOnionSeverity(row: Row): Severity {
  const label = fstr(row, "event.severity_label").toLowerCase();
  if (label && SEV_LABEL[label]) return SEV_LABEL[label];
  const alt = str(
    field(row, "signal.rule.severity") ?? field(row, "kibana.alert.severity") ?? field(row, "rule.severity"),
  )
    .trim()
    .toLowerCase();
  if (alt && SEV_LABEL[alt]) return SEV_LABEL[alt];
  const num = Number(field(row, "event.severity"));
  if (Number.isFinite(num) && num >= 1 && num <= 4) return numSeverity(num);
  const hasRule = !!fstr(row, "rule.name") || !!fstr(row, "signal.rule.name");
  return hasRule ? "Medium" : "Info";
}

// SO `@timestamp` is ISO ("…Z"); a raw export may carry epoch seconds/millis.
function soTime(v: unknown): string {
  if (typeof v === "number") {
    if (!Number.isFinite(v) || v <= 0) return "";
    const d = new Date(v > 1e12 ? v : v * 1000);
    return Number.isNaN(d.getTime()) ? "" : d.toISOString();
  }
  return normalizeTime(str(v));
}

function pushTxxxx(set: Set<string>, v: unknown): void {
  if (Array.isArray(v)) {
    for (const el of v) pushTxxxx(set, el);
    return;
  }
  for (const m of str(v).matchAll(/\bt\d{4}(?:\.\d{3})?\b/gi)) set.add(m[0].toUpperCase());
}
function soMitre(row: Row): string[] {
  const out = new Set<string>();
  pushTxxxx(out, field(row, "threat.technique.id"));
  pushTxxxx(out, field(row, "rule.metadata.mitre_technique_id"));
  // Any flat dotted key that names a MITRE/technique field (e.g. rule.metadata.mitre_technique_id).
  for (const [k, v] of Object.entries(row)) {
    if (/mitre|technique/i.test(k)) pushTxxxx(out, v);
  }
  return [...out];
}

function addIp(sink: Map<string, SiemIoc>, v: string): void {
  const ip = cleanIp(v);
  if (ip) addIoc(sink, "ip", ip);
}
function addDomain(sink: Map<string, SiemIoc>, v: string): void {
  const d = v.trim().replace(/\.$/, "").toLowerCase();
  if (d && !IPV4.test(d) && DOMAIN.test(d)) addIoc(sink, "domain", d);
}
function addUrl(sink: Map<string, SiemIoc>, v: string): void {
  const u = v.trim();
  if (/^https?:\/\//i.test(u)) addIoc(sink, "url", u.slice(0, 300));
}
function addHash(sink: Map<string, SiemIoc>, v: string): void {
  const h = v.trim().toLowerCase();
  if (HEX_HASH.test(h)) addIoc(sink, "hash", h);
}
function addFile(sink: Map<string, SiemIoc>, v: string): void {
  const f = v.trim();
  if (f && f !== "-" && f.length > 1) addIoc(sink, "file", f.slice(0, 300));
}

// The first populated key's value; `onKey` hears which key it was (#1736) — the name, never the value.
function firstOf(row: Row, keys: readonly string[], onKey?: (key: string) => void): string {
  for (const k of keys) {
    const v = fstr(row, k);
    if (v) {
      onKey?.(k);
      return v;
    }
  }
  return "";
}

const HOST_KEYS = ["observer.name", "host.name", "host.hostname", "agent.name", "agent.hostname"];

function pickHost(row: Row, onKey?: (key: string) => void): string {
  return firstOf(row, HOST_KEYS, onKey);
}

function mapSecurityOnionRow(row: Row, sink: Map<string, SiemIoc>, debug?: ImportDebugRecorder): MappedEvent {
  const ruleName = firstOf(row, ["rule.name", "signal.rule.name", "message", "event.action"], (k) =>
    debug?.field("rule", k),
  );
  const moduleName = fstr(row, "event.module") || fstr(row, "event.dataset");
  const category = fstr(row, "rule.category");
  const severity = securityOnionSeverity(row);

  const srcRaw = firstOf(row, ["source.ip", "src_ip"], (k) => debug?.field("source_ip", k));
  const dstRaw = firstOf(row, ["destination.ip", "dest_ip"], (k) => debug?.field("dest_ip", k));
  const src = cleanIp(srcRaw);
  const dst = cleanIp(dstRaw);
  const sp = fstr(row, "source.port");
  const dp = fstr(row, "destination.port");
  const host = pickHost(row, (k) => debug?.field("host", k));
  if (!host) debug?.observed("missing_host");

  // IOCs.
  addIp(sink, src);
  addIp(sink, dst);
  addDomain(sink, fstr(row, "dns.query"));
  addDomain(sink, fstr(row, "dns.query_name"));
  addDomain(sink, fstr(row, "destination.domain"));
  addDomain(sink, fstr(row, "url.domain"));
  addDomain(sink, fstr(row, "server.domain"));
  addUrl(sink, fstr(row, "url.full") || fstr(row, "url.original"));
  const sha256 = fstr(row, "file.hash.sha256").toLowerCase();
  const md5 = fstr(row, "file.hash.md5").toLowerCase();
  addHash(sink, sha256);
  addHash(sink, md5);
  addFile(sink, fstr(row, "file.name") || fstr(row, "file.path"));

  let description = `Security Onion alert: ${ruleName || "event"}`;
  if (moduleName) description += ` [${moduleName}]`;
  else if (category) description += ` [${category}]`;
  if (src && dst) description += ` - ${src}${sp ? `:${sp}` : ""} → ${dst}${dp ? `:${dp}` : ""}`;
  if (host) description += ` @ ${host}`;
  description = description.slice(0, 600);

  const atTimestamp = field(row, "@timestamp");
  const timeValue = atTimestamp ?? getCI(row, "timestamp");
  if (timeValue != null) debug?.field("timestamp", atTimestamp != null ? "@timestamp" : "timestamp");
  return {
    timestamp: soTime(timeValue),
    description,
    severity,
    mitre: soMitre(row),
    aggKey: `securityonion|${(ruleName || moduleName || "event").toLowerCase()}|${src}|${dst}|${dp}`.slice(
      0,
      400,
    ),
    sources: ["Security Onion"],
    ...(host ? { asset: host } : {}),
    ...(src ? { srcIp: src } : {}),
    ...(dst ? { dstIp: dst } : {}),
    ...(dp && Number.isFinite(Number(dp)) ? { port: Number(dp) } : {}),
    ...(HEX_HASH.test(sha256) ? { sha256 } : {}),
    ...(HEX_HASH.test(md5) ? { md5 } : {}),
  };
}

export function parseSecurityOnion(
  text: string,
  opts: SecurityOnionImportOptions = {},
): SecurityOnionParseResult {
  const maxIocs = opts.maxIocs ?? 5000;
  const { records } = extractRecords(text);
  const total = records.length;
  if (total === 0) {
    return { events: [], iocs: [], total: 0, kept: 0, dropped: 0, groups: 0, hostname: "" };
  }

  const iocSink = new Map<string, SiemIoc>();
  const hostTally = new Map<string, number>();
  const mapped: MappedEvent[] = [];

  for (const row of records) {
    if (!isObject(row)) {
      opts.debug?.skipped("not_an_object");
      continue;
    }
    const host = pickHost(row);
    if (host) hostTally.set(host, (hostTally.get(host) ?? 0) + 1);
    const rowSink = new Map<string, SiemIoc>();
    const m = mapSecurityOnionRow(row, rowSink, opts.debug);
    mergeRowIocs(iocSink, rowSink, m.aggKey);
    mapped.push(m);
  }

  const { events, groups } = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents: opts.maxEvents ?? maxEventsDefault(),
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
    hostname,
  };
}
