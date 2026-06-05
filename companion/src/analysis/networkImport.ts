// Deterministic importer for network-monitor logs — Suricata `eve.json` and Zeek (Bro)
// JSON logs, the network side of Security Onion / Corelight. The sixth deterministic ingest
// path; no AI call.
//
// Per the Companion's post-detection principle, the TIMELINE is built only from the tools'
// DETECTIONS — Suricata `event_type:"alert"` (an IDS signature hit: signature/category/
// severity + ATT&CK metadata) and Zeek `_path:"notice"` (Zeek's notice framework). The
// surrounding TELEMETRY (dns / http / tls / files / conn …) is high-volume and is NOT added
// to the timeline; instead it contributes OBSERVED IOCs (domains, URLs, file hashes, and the
// alert/notice IPs) so the case still captures network indicators without drowning the
// timeline in raw flow records.
//
// Inputs: NDJSON (the native `eve.json` / Zeek JSON form), a JSON array, or an Elastic-style
// wrapper. Rows are routed per-record: Suricata (has `event_type`) vs Zeek (has `_path`).
// Events are tagged "Suricata" / "Zeek" for cross-source correlation.

import type { Severity } from "./stateTypes.js";
import {
  extractRecords,
  aggregateEvents,
  cleanIp,
  addIoc,
  firstStr,
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

export interface NetworkImportOptions {
  aggregate?: boolean;
  minSeverity?: Severity;
  maxEvents?: number;
  maxIocs?: number;
}

export interface NetworkParseResult {
  events: SiemEvent[];
  iocs: SiemIoc[];
  total: number;     // records found
  kept: number;      // events emitted (after aggregation + cap)
  dropped: number;   // records not turned into events (telemetry / below floor / capped)
  groups: number;    // distinct event groups before the cap
  alerts: number;    // detection records (Suricata alert + Zeek notice) seen
  format: string;    // "suricata" | "zeek" | "mixed" | "empty"
  hostname: string;
}

const IPV4 = /^\d{1,3}(?:\.\d{1,3}){3}$/;
const HEX_HASH = /^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i;
const DOMAIN = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i;

// ───────────────────────────── small helpers ─────────────────────────────

// Suricata signature priority: 1 = most severe. (ET/Talos rulesets use 1–3 mostly.)
function suricataSeverity(sev: number | undefined): Severity {
  if (sev === 1) return "High";
  if (sev === 2) return "Medium";
  if (sev === 3) return "Low";
  if (sev != null && sev >= 4) return "Info";
  return "Medium";
}

// Suricata times carry an offset ("2017-12-01T00:00:00.123456+0000"); Zeek `ts` is epoch
// seconds (float). Normalize either to UTC ISO.
function netTime(v: unknown): string {
  if (typeof v === "number") {
    if (!Number.isFinite(v) || v <= 0) return "";
    const d = new Date(v > 1e12 ? v : v * 1000);
    return Number.isNaN(d.getTime()) ? "" : d.toISOString();
  }
  return normalizeTime(str(v));
}

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

function addIp(sink: Map<string, SiemIoc>, v: unknown): void {
  const ip = cleanIp(str(v));
  if (ip) addIoc(sink, "ip", ip);
}
function addDomain(sink: Map<string, SiemIoc>, v: unknown): void {
  const d = str(v).trim().replace(/\.$/, "").toLowerCase();
  if (d && !IPV4.test(d) && DOMAIN.test(d)) addIoc(sink, "domain", d);
}
function addUrl(sink: Map<string, SiemIoc>, v: unknown): void {
  const u = str(v).trim();
  if (/^https?:\/\//i.test(u)) addIoc(sink, "url", u.slice(0, 300));
}
function addHash(sink: Map<string, SiemIoc>, v: unknown): void {
  const h = str(v).trim().toLowerCase();
  if (HEX_HASH.test(h)) addIoc(sink, "hash", h);
}
function addFile(sink: Map<string, SiemIoc>, v: unknown): void {
  const f = str(v).trim();
  if (f && f !== "-" && f.length > 1) addIoc(sink, "file", f.slice(0, 300));
}

// ───────────────────────────── Suricata ─────────────────────────────

// Extract IOCs from a Suricata record (any event_type): the flow IPs (alerts only — telemetry
// IPs are too voluminous), plus any app-layer domain/URL/hash carried in the record.
function suricataIocs(row: Row, etype: string, sink: Map<string, SiemIoc>): void {
  if (etype === "alert") { addIp(sink, getCI(row, "src_ip")); addIp(sink, getCI(row, "dest_ip")); }

  const dns = getCI(row, "dns");
  if (isObject(dns)) addDomain(sink, getCI(dns, "rrname"));
  const http = getCI(row, "http");
  if (isObject(http)) { addDomain(sink, getCI(http, "hostname")); addUrl(sink, getCI(http, "url")); }
  const tls = getCI(row, "tls");
  if (isObject(tls)) addDomain(sink, getCI(tls, "sni"));
  const fi = getCI(row, "fileinfo");
  if (isObject(fi)) { addHash(sink, getCI(fi, "sha256")); addHash(sink, getCI(fi, "md5")); addFile(sink, getCI(fi, "filename")); }
}

function mapSuricataAlert(row: Row, host: string, sink: Map<string, SiemIoc>): MappedEvent {
  const sig = str(getPath(row, "alert.signature")) || "alert";
  const category = str(getPath(row, "alert.category"));
  const sigId = str(getPath(row, "alert.signature_id"));
  const severity = suricataSeverity(Number(getPath(row, "alert.severity")) || undefined);
  const mitre = mitreFromText(flatStr(getPath(row, "alert.metadata")));

  const src = str(getCI(row, "src_ip")), sp = str(getCI(row, "src_port"));
  const dst = str(getCI(row, "dest_ip")), dp = str(getCI(row, "dest_port"));
  const proto = str(getCI(row, "proto"));

  let description = `Suricata alert: ${sig}`;
  if (category) description += ` [${category}]`;
  if (src && dst) description += ` — ${src}${sp ? `:${sp}` : ""} → ${dst}${dp ? `:${dp}` : ""}${proto ? ` ${proto}` : ""}`;
  if (host) description += ` @ ${host}`;
  description = description.slice(0, 600);

  return {
    timestamp: netTime(getCI(row, "timestamp")),
    description,
    severity,
    mitre,
    aggKey: `suricata|${sigId || sig.toLowerCase()}|${src}|${dst}|${dp}`.slice(0, 400),
    sources: ["Suricata"],
    ...(host ? { asset: host } : {}),
  };
}

// ───────────────────────────── Zeek ─────────────────────────────

function zeekIocs(row: Row, path: string, sink: Map<string, SiemIoc>): void {
  switch (path) {
    case "dns": addDomain(sink, getCI(row, "query")); break;
    case "http": addDomain(sink, getCI(row, "host")); addUrl(sink, getCI(row, "uri")); break;
    case "ssl":
    case "x509": addDomain(sink, getCI(row, "server_name")); break;
    case "files":
      addHash(sink, getCI(row, "sha256")); addHash(sink, getCI(row, "sha1")); addHash(sink, getCI(row, "md5"));
      addFile(sink, getCI(row, "filename"));
      break;
    case "notice":
      addIp(sink, getCI(row, "src")); addIp(sink, getCI(row, "dst"));
      addDomain(sink, getCI(row, "host")); addHash(sink, getCI(row, "sha256"));
      break;
    default: break; // conn / weird / dhcp / … → no IOCs (pure telemetry)
  }
}

function mapZeekNotice(row: Row, host: string, sink: Map<string, SiemIoc>): MappedEvent {
  const note = str(getCI(row, "note")) || "notice";
  const msg = str(getCI(row, "msg"));
  const sub = str(getCI(row, "sub"));
  const src = str(getCI(row, "src")), dst = str(getCI(row, "dst"));

  let description = `Zeek notice: ${note}`;
  if (msg) description += ` — ${msg}`;
  if (sub) description += ` (${sub})`;
  if (src && dst) description += ` [${src} → ${dst}]`;
  if (host) description += ` @ ${host}`;
  description = description.slice(0, 600);

  return {
    timestamp: netTime(getCI(row, "ts")),
    description,
    severity: "Medium", // a Zeek notice is, by definition, worth surfacing
    mitre: mitreFromText(note, msg),
    aggKey: `zeek|${note.toLowerCase()}|${src}|${dst}`.slice(0, 400),
    sources: ["Zeek"],
    ...(host ? { asset: host } : {}),
  };
}

// ───────────────────────────── host ─────────────────────────────

function pickHost(row: Row): string {
  const h = getCI(row, "host");
  if (isObject(h)) return str(getCI(h, "name")).trim();
  return firstStr(row, ["hostname", "agent.hostname", "agent.name", "observer.name"]) || str(h).trim();
}

// ───────────────────────────── top-level parse ─────────────────────────────

export function parseNetworkLogs(text: string, opts: NetworkImportOptions = {}): NetworkParseResult {
  const maxIocs = opts.maxIocs ?? 5000;
  const { records } = extractRecords(text);
  const total = records.length;
  if (total === 0) {
    return { events: [], iocs: [], total: 0, kept: 0, dropped: 0, groups: 0, alerts: 0, format: "empty", hostname: "" };
  }

  const iocSink = new Map<string, SiemIoc>();
  const hostTally = new Map<string, number>();
  const mapped: MappedEvent[] = [];
  let alerts = 0;
  let sawSuricata = false, sawZeek = false;

  for (const row of records) {
    const host = pickHost(row);
    if (host) hostTally.set(host, (hostTally.get(host) ?? 0) + 1);

    const etype = str(getCI(row, "event_type")).toLowerCase();
    const zpath = str(getCI(row, "_path")).toLowerCase();

    if (etype) {
      sawSuricata = true;
      suricataIocs(row, etype, iocSink);
      if (etype === "alert") { mapped.push(mapSuricataAlert(row, host, iocSink)); alerts++; }
    } else if (zpath) {
      sawZeek = true;
      zeekIocs(row, zpath, iocSink);
      if (zpath === "notice") { mapped.push(mapZeekNotice(row, host, iocSink)); alerts++; }
    }
    // rows that are neither Suricata nor Zeek are ignored (not network logs).
  }

  const { events, groups } = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents: opts.maxEvents ?? 2000,
  });

  const represented = events.reduce((n, e) => n + (e.count ?? 1), 0);
  const hostname = [...hostTally.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] ?? "";
  const format = sawSuricata && sawZeek ? "mixed" : sawSuricata ? "suricata" : sawZeek ? "zeek" : "empty";

  return {
    events,
    iocs: [...iocSink.values()].slice(0, maxIocs),
    total,
    kept: events.length,
    dropped: Math.max(0, total - represented),
    groups,
    alerts,
    format,
    hostname,
  };
}
