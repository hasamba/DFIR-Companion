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
  mergeRowIocs,
  firstStr,
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

type Row = Record<string, unknown>;

export interface NetworkImportOptions {
  aggregate?: boolean;
  minSeverity?: Severity;
  maxEvents?: number;
  maxIocs?: number;
  // Zeek exported as per-stream JSON has no `_path`; the filename names the stream (conn.json,
  // dns.json, …). When provided, it's the authoritative stream for records that carry no `_path`.
  filename?: string;
}

const ZEEK_STREAMS = [
  "conn", "dns", "http", "ssl", "x509", "files", "notice", "weird", "dhcp", "smtp",
  "ftp", "ssh", "dce_rpc", "kerberos", "ntlm", "rdp", "snmp", "sip", "dnp3", "modbus",
  "radius", "syslog", "tunnel", "irc", "mysql", "pe", "socks", "ntp", "ocsp",
];

// Derive the Zeek stream from a (possibly seq-prefixed) filename: "0004_conn.json" → "conn".
export function zeekStreamFromName(name: string): string {
  const base = name.toLowerCase().replace(/^.*[\\/]/, "").replace(/\.(json|log|ndjson|jsonl|gz)$/g, "");
  const m = base.match(new RegExp(`(?:^|[._-])(${ZEEK_STREAMS.join("|")})(?:[._-]|$)`));
  return m ? m[1] : "";
}

// Infer the Zeek stream from a record's own fields when there's no filename hint and no `_path`.
export function inferZeekStream(row: Row): string {
  if (getCI(row, "query") != null || getCI(row, "qtype_name") != null) return "dns";
  if (getCI(row, "uri") != null || getCI(row, "method") != null) return "http";
  if (getCI(row, "server_name") != null || getCI(row, "cipher") != null || getCI(row, "ssl_history") != null) return "ssl";
  if (getCI(row, "san.dns") != null || getCI(row, "fingerprint") != null ||
      Object.keys(row).some((k) => k.startsWith("certificate."))) return "x509";
  if (getCI(row, "fuid") != null || getCI(row, "mime_type") != null) return "files";
  if (getCI(row, "note") != null) return "notice";
  return "conn"; // id.orig_h + conn_state → pure flow telemetry (no IOC, no timeline event)
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
  if (src && dst) description += ` - ${src}${sp ? `:${sp}` : ""} → ${dst}${dp ? `:${dp}` : ""}${proto ? ` ${proto}` : ""}`;
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
    ...(src ? { srcIp: src } : {}),
    ...(dst ? { dstIp: dst } : {}),
    ...(dp && Number.isFinite(Number(dp)) ? { port: Number(dp) } : {}),
  };
}

// ───────────────────────────── Zeek ─────────────────────────────

function zeekIocs(row: Row, path: string, sink: Map<string, SiemIoc>): void {
  switch (path) {
    case "dns": addDomain(sink, getCI(row, "query")); break;
    case "http": addDomain(sink, getCI(row, "host")); addUrl(sink, getCI(row, "uri")); break;
    case "ssl": addDomain(sink, getCI(row, "server_name")); break;
    case "x509": {
      // x509 records name the cert host in `san.dns` (string or array), not `server_name`.
      addDomain(sink, getCI(row, "server_name"));
      const san = getCI(row, "san.dns");
      if (Array.isArray(san)) for (const d of san) addDomain(sink, d);
      else addDomain(sink, san);
      break;
    }
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
  if (msg) description += ` - ${msg}`;
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
    ...(src ? { srcIp: src } : {}),
    ...(dst ? { dstIp: dst } : {}),
  };
}

// ───────────────────────── Zeek conn: flow aggregation ─────────────────────────
// A conn record is one TCP/UDP flow, and a busy sensor emits them by the hundred thousand — far too
// many to carry one event each, which is why they used to be dropped outright. Dropping them also
// threw away the one thing only flow telemetry knows: HOW MUCH data moved. On the
// northpeak-insider-codetheft benchmark the bulk repo clone and the NFS design-doc grab left no
// trace anywhere else — they are visible only as 1.5 GB pulled from the git server and a single
// 412 MB NFS read. Folding conn by (src → dst:port/proto) collapses 75,951 rows to ~7,000 and keeps
// exactly that: peers, connection count, byte totals.

interface FlowAgg {
  src: string; dst: string; port: string; proto: string; service: string;
  count: number; origBytes: number; respBytes: number; firstTs: string;
}

const KB = 1024, MB = KB * 1024, GB = MB * 1024;
function humanBytes(n: number): string {
  if (n >= GB) return `${(n / GB).toFixed(1)} GB`;
  if (n >= MB) return `${(n / MB).toFixed(1)} MB`;
  if (n >= KB) return `${(n / KB).toFixed(1)} KB`;
  return `${n} B`;
}

function flowKey(row: Row): string {
  return [
    str(getCI(row, "id.orig_h")), str(getCI(row, "id.resp_h")),
    str(getCI(row, "id.resp_p")), str(getCI(row, "proto")),
  ].join("|");
}

// Fold one conn record into the running per-flow tally.
function tallyFlow(row: Row, sink: Map<string, FlowAgg>): void {
  const key = flowKey(row);
  const ts = netTime(getCI(row, "ts"));
  const orig = Number(getCI(row, "orig_bytes")) || 0;
  const resp = Number(getCI(row, "resp_bytes")) || 0;
  const existing = sink.get(key);
  if (existing) {
    existing.count += 1;
    existing.origBytes += orig;
    existing.respBytes += resp;
    if (ts && ts < existing.firstTs) existing.firstTs = ts;
    if (!existing.service) existing.service = str(getCI(row, "service"));
    return;
  }
  sink.set(key, {
    src: str(getCI(row, "id.orig_h")), dst: str(getCI(row, "id.resp_h")),
    port: str(getCI(row, "id.resp_p")), proto: str(getCI(row, "proto")),
    service: str(getCI(row, "service")),
    count: 1, origBytes: orig, respBytes: resp, firstTs: ts,
  });
}

function mapFlow(f: FlowAgg, host: string): MappedEvent {
  const peer = `${f.src} → ${f.dst}${f.port ? `:${f.port}` : ""}`;
  const proto = [f.proto, f.service].filter(Boolean).join("/");
  let description = `Flow: ${peer}${proto ? ` (${proto})` : ""}` +
    ` — ${f.count} connection${f.count === 1 ? "" : "s"},` +
    ` ${humanBytes(f.origBytes)} sent, ${humanBytes(f.respBytes)} received`;
  if (host) description += ` @ ${host}`;
  return {
    timestamp: f.firstTs,
    description: description.slice(0, 600),
    // Pure telemetry: Info keeps it out of the AI prompt (the forensic gate demotes it to the
    // analyst-only super-timeline) while making it searchable and promotable. No MITRE claim —
    // a flow on its own asserts nothing about technique.
    severity: "Info",
    mitre: [],
    // Already unique per flow, so the shared aggregator passes these straight through rather than
    // re-folding them (and the description, not `count`, carries the connection tally).
    aggKey: `zeek|conn|${f.src}|${f.dst}|${f.port}|${f.proto}`.slice(0, 400),
    sources: ["Zeek"],
    ...(host ? { asset: host } : {}),
    ...(f.src ? { srcIp: f.src } : {}),
    ...(f.dst ? { dstIp: f.dst } : {}),
    ...(Number.isFinite(Number(f.port)) && f.port ? { port: Number(f.port) } : {}),
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
  const flowSink = new Map<string, FlowAgg>();
  let flowHost = "";
  let alerts = 0;
  let sawSuricata = false, sawZeek = false;
  // Per-stream Zeek JSON (no `_path`): the filename is the authoritative stream for the whole file.
  const fileStream = opts.filename ? zeekStreamFromName(opts.filename) : "";

  for (const row of records) {
    const host = pickHost(row);
    if (host) hostTally.set(host, (hostTally.get(host) ?? 0) + 1);

    const etype = str(getCI(row, "event_type")).toLowerCase();
    const zpath = str(getCI(row, "_path")).toLowerCase();
    const rowSink = new Map<string, SiemIoc>();

    if (etype) {
      sawSuricata = true;
      suricataIocs(row, etype, rowSink);
      if (etype === "alert") {
        const m = mapSuricataAlert(row, host, rowSink);
        mergeRowIocs(iocSink, rowSink, m.aggKey);
        mapped.push(m);
        alerts++;
      } else {
        mergeRowIocs(iocSink, rowSink);
      }
    } else {
      // Zeek: either `_path`-tagged (combined JSON) or per-stream (filename / field-inferred).
      const zstream = zpath || fileStream || inferZeekStream(row);
      sawZeek = true;
      zeekIocs(row, zstream, rowSink);
      if (zstream === "notice") {
        const m = mapZeekNotice(row, host, rowSink);
        mergeRowIocs(iocSink, rowSink, m.aggKey);
        mapped.push(m);
        alerts++;
      } else {
        // conn is folded per-flow (see tallyFlow) and emitted once after the loop, so the byte
        // totals can be summed across every record in the group.
        if (zstream === "conn") { tallyFlow(row, flowSink); if (!flowHost && host) flowHost = host; }
        mergeRowIocs(iocSink, rowSink);
      }
    }
  }

  // Select the flows biggest-first and truncate HERE, before handing them to the shared aggregator.
  // That aggregator caps by "most-severe, then noisiest, then earliest" — and every flow is Info, so
  // flows sort last and its cut would fall on them in an order that has nothing to do with volume.
  // On the benchmark that silently discarded the 1.5 GB bulk-clone flow while keeping a 292 KB one
  // to the same server. Pre-selecting means whatever survives is the high-volume traffic, which is
  // the entire reason to carry flow rows at all.
  const flowBudget = opts.maxEvents ?? maxEventsDefault();
  const flows = [...flowSink.values()]
    .sort((a, b) => (b.origBytes + b.respBytes) - (a.origBytes + a.respBytes))
    .slice(0, flowBudget);
  for (const f of flows) mapped.push(mapFlow(f, flowHost));

  const { events, groups } = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents: opts.maxEvents ?? maxEventsDefault(),
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
