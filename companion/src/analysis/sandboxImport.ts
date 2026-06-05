// Deterministic importer for malware-sandbox detonation reports — CAPEv2 and CrowdStrike
// Falcon Sandbox (Hybrid Analysis). The twelfth deterministic ingest path; no AI call.
//
// A sandbox report is the cleanest "ingest a verdict" case: the sandbox already detonated the
// sample and emitted its verdict (score / family), a list of behavioural SIGNATURES (each a
// detection with its own severity + ATT&CK), and the observed artefacts (dropped/extracted
// files, network hosts/domains/URLs). We map the verdict + each signature to forensic events
// and harvest every hash/domain/IP/URL as an IOC. NOT a detection engine — we consume the
// sandbox's output.
//
// One report = one JSON object (an array of reports is also accepted). The format is
// auto-detected: CAPEv2 (`info` + `signatures`/`target`) vs Falcon Sandbox (`verdict` +
// `sha256`/`threat_score`).

import type { Severity } from "./stateTypes.js";
import {
  aggregateEvents,
  cleanIp,
  addIoc,
  str,
  isObject,
  getCI,
  getPath,
  oneLine,
  normalizeTime,
  type MappedEvent,
  type SiemEvent,
  type SiemIoc,
} from "./siemImport.js";

type Row = Record<string, unknown>;

export interface SandboxImportOptions {
  aggregate?: boolean;
  minSeverity?: Severity;
  maxEvents?: number;
  maxIocs?: number;
}

export interface SandboxParseResult {
  events: SiemEvent[];
  iocs: SiemIoc[];
  total: number;       // reports parsed
  kept: number;        // events emitted (after aggregation + cap)
  dropped: number;
  groups: number;
  signatures: number;  // signature detections seen
  format: string;      // "capev2" | "falcon" | "mixed" | "empty"
}

const HEX_HASH = /^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i;
const DOMAIN = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i;
const IPV4 = /^\d{1,3}(?:\.\d{1,3}){3}$/;

function mitreFromText(...parts: string[]): string[] {
  const out = new Set<string>();
  for (const p of parts) for (const m of p.matchAll(/\bt\d{4}(?:\.\d{3})?\b/gi)) out.add(m[0].toUpperCase());
  return [...out];
}
function flatStr(v: unknown): string {
  if (v == null) return "";
  if (Array.isArray(v)) return v.map(flatStr).join(" ");
  if (isObject(v)) return [...Object.keys(v), ...Object.values(v).map(flatStr)].join(" ");
  return String(v);
}

function addHash(sink: Map<string, SiemIoc>, v: unknown): void {
  const h = str(v).trim().toLowerCase();
  if (HEX_HASH.test(h)) addIoc(sink, "hash", h);
}
function addDomain(sink: Map<string, SiemIoc>, v: unknown): void {
  const d = str(v).trim().replace(/\.$/, "").toLowerCase();
  if (d && !IPV4.test(d) && DOMAIN.test(d)) addIoc(sink, "domain", d);
}
function addUrl(sink: Map<string, SiemIoc>, v: unknown): void {
  const u = str(v).trim();
  if (/^https?:\/\//i.test(u)) addIoc(sink, "url", u.slice(0, 300));
}
function addAnyIp(sink: Map<string, SiemIoc>, v: unknown): void {
  const raw = isObject(v) ? str(getCI(v, "ip")) : str(v);
  const ip = cleanIp(raw);
  if (ip) addIoc(sink, "ip", ip);
}
function addFile(sink: Map<string, SiemIoc>, v: unknown): void {
  const f = str(v).trim();
  if (f && f !== "-" && f.length > 1 && !/^https?:/i.test(f)) addIoc(sink, "file", f.slice(0, 300));
}
function asArray(v: unknown): unknown[] {
  return Array.isArray(v) ? v : [];
}

// ───────────────────────────── severity ─────────────────────────────

function score10Severity(n: number): Severity {
  if (n >= 7) return "High";
  if (n >= 4) return "Medium";
  if (n > 0) return "Low";
  return "Info";
}
// CAPE/Cuckoo signature severity is 1 (low) .. 3 (high).
function capeSigSeverity(n: number): Severity {
  if (n >= 3) return "High";
  if (n === 2) return "Medium";
  return "Low";
}
function falconVerdictSeverity(verdict: string, _score: number): Severity {
  const v = verdict.toLowerCase();
  if (/malicious/.test(v)) return "High";
  if (/suspicious/.test(v)) return "Medium";
  if (/no specific threat/.test(v)) return "Low";
  return "Info"; // whitelisted / clean / unknown
}
function falconSigSeverity(human: string, threatLevel: number): Severity {
  const h = human.toLowerCase();
  if (/malicious/.test(h) || threatLevel >= 2) return "High";
  if (/suspicious/.test(h) || threatLevel === 1) return "Medium";
  if (/informative|clean|benign/.test(h)) return "Info";
  return "Low";
}

// ───────────────────────────── CAPEv2 ─────────────────────────────

function mapCape(report: Row, sink: Map<string, SiemIoc>): MappedEvent[] {
  const out: MappedEvent[] = [];
  const tfile = isObject(getPath(report, "target.file")) ? (getPath(report, "target.file") as Row) : {};
  const sha256 = str(getCI(tfile, "sha256"));
  const md5 = str(getCI(tfile, "md5"));
  const name = str(getCI(tfile, "name")) || str(getPath(report, "target.url"));
  const malscore = Number(getCI(report, "malscore") ?? getPath(report, "info.score")) || 0;
  const family = str(getCI(report, "malfamily")) || flatStr(getCI(report, "detections")).split(" ")[0] || "";
  const time = normalizeTime(str(getPath(report, "info.started")));

  if (sha256) addHash(sink, sha256);
  if (md5) addHash(sink, md5);
  if (name && /[\\/.]/.test(name)) addFile(sink, name);

  // The sample verdict event.
  out.push({
    timestamp: time,
    description: `CAPE sandbox: ${family || "analysis"} — ${name || sha256.slice(0, 16) || "sample"}${sha256 ? ` (sha256 ${sha256.slice(0, 12)}…)` : ""} score ${malscore}/10`.slice(0, 600),
    severity: score10Severity(malscore),
    mitre: [],
    aggKey: `sandbox|cape|sample|${sha256 || name}`.toLowerCase().slice(0, 400),
    sources: ["CAPEv2"],
    ...(sha256 ? { sha256 } : {}),
    ...(md5 && !sha256 ? { md5 } : {}),
  });

  // One event per behavioural signature (the detections).
  for (const s of asArray(getCI(report, "signatures"))) {
    if (!isObject(s)) continue;
    const sname = str(getCI(s, "name"));
    const sdesc = str(getCI(s, "description"));
    if (!sname && !sdesc) continue;
    const mitre = mitreFromText(flatStr(getCI(s, "ttp")), flatStr(getCI(s, "attack")), flatStr(getCI(s, "references")), sname, sdesc);
    out.push({
      timestamp: time,
      description: `CAPE signature: ${sname || sdesc}${sname && sdesc ? ` — ${oneLine(sdesc).slice(0, 200)}` : ""}`.slice(0, 600),
      severity: capeSigSeverity(Number(getCI(s, "severity")) || 1),
      mitre,
      aggKey: `sandbox|cape|sig|${sname.toLowerCase()}|${sha256}`.slice(0, 400),
      sources: ["CAPEv2"],
      ...(sha256 ? { sha256 } : {}),
    });
  }

  // Dropped files + extracted CAPE payloads → file/hash IOCs.
  for (const d of [...asArray(getCI(report, "dropped")), ...asArray(getPath(report, "CAPE.payloads"))]) {
    if (!isObject(d)) continue;
    addHash(sink, getCI(d, "sha256")); addHash(sink, getCI(d, "md5"));
    addFile(sink, getCI(d, "name"));
  }
  // Network indicators.
  const net = getCI(report, "network");
  if (isObject(net)) {
    for (const h of asArray(getCI(net, "hosts"))) addAnyIp(sink, h);
    for (const d of asArray(getCI(net, "domains"))) { if (isObject(d)) { addDomain(sink, getCI(d, "domain")); addAnyIp(sink, getCI(d, "ip")); } else addDomain(sink, d); }
    for (const h of asArray(getCI(net, "http"))) { if (isObject(h)) { addDomain(sink, getCI(h, "host")); addUrl(sink, getCI(h, "uri")); } }
    for (const dns of asArray(getCI(net, "dns"))) { if (isObject(dns)) addDomain(sink, getCI(dns, "request")); }
  }
  return out;
}

// ───────────────────────────── Falcon Sandbox ─────────────────────────────

function mapFalcon(report: Row, sink: Map<string, SiemIoc>): MappedEvent[] {
  const out: MappedEvent[] = [];
  const sha256 = str(getCI(report, "sha256"));
  const md5 = str(getCI(report, "md5"));
  const name = str(getCI(report, "submit_name")) || str(getCI(report, "file_name"));
  const verdict = str(getCI(report, "verdict"));
  const score = Number(getCI(report, "threat_score")) || 0;
  const family = str(getCI(report, "vx_family"));
  const time = normalizeTime(str(getCI(report, "analysis_start_time")));

  if (sha256) addHash(sink, sha256);
  if (md5) addHash(sink, md5);
  if (name && /[\\/.]/.test(name)) addFile(sink, name);

  out.push({
    timestamp: time,
    description: `Falcon Sandbox: ${verdict || "analysis"}${family ? ` (${family})` : ""} — ${name || sha256.slice(0, 16) || "sample"} score ${score}/100`.slice(0, 600),
    severity: falconVerdictSeverity(verdict, score),
    mitre: mitreFromText(flatStr(getCI(report, "mitre_attcks"))),
    aggKey: `sandbox|falcon|sample|${sha256 || name}`.toLowerCase().slice(0, 400),
    sources: ["Falcon Sandbox"],
    ...(sha256 ? { sha256 } : {}),
    ...(md5 && !sha256 ? { md5 } : {}),
  });

  for (const s of asArray(getCI(report, "signatures"))) {
    if (!isObject(s)) continue;
    const sname = str(getCI(s, "name"));
    const sdesc = str(getCI(s, "description"));
    if (!sname && !sdesc) continue;
    out.push({
      timestamp: time,
      description: `Falcon signature: ${sname || sdesc}${sname && sdesc ? ` — ${oneLine(sdesc).slice(0, 200)}` : ""}`.slice(0, 600),
      severity: falconSigSeverity(str(getCI(s, "threat_level_human")), Number(getCI(s, "threat_level")) || 0),
      mitre: mitreFromText(str(getCI(s, "attck_id")), sname, sdesc),
      aggKey: `sandbox|falcon|sig|${sname.toLowerCase()}|${sha256}`.slice(0, 400),
      sources: ["Falcon Sandbox"],
      ...(sha256 ? { sha256 } : {}),
    });
  }

  for (const f of asArray(getCI(report, "extracted_files"))) {
    if (!isObject(f)) continue;
    addHash(sink, getCI(f, "sha256")); addHash(sink, getCI(f, "md5")); addFile(sink, getCI(f, "name"));
  }
  for (const p of asArray(getCI(report, "processes"))) {
    if (isObject(p)) { addHash(sink, getCI(p, "sha256")); addFile(sink, getCI(p, "normalized_path") || getCI(p, "name")); }
  }
  for (const h of [...asArray(getCI(report, "hosts")), ...asArray(getCI(report, "compromised_hosts"))]) addAnyIp(sink, h);
  for (const d of asArray(getCI(report, "domains"))) addDomain(sink, d);
  return out;
}

// ───────────────────────────── classification ─────────────────────────────

function isFalcon(r: Row): boolean {
  return !!getCI(r, "verdict") && (getCI(r, "threat_score") != null || !!getCI(r, "environment_id") ||
    !!getCI(r, "vx_family") || !!getCI(r, "mitre_attcks") || !!getCI(r, "submit_name"));
}
function isCape(r: Row): boolean {
  return (!!getCI(r, "info") && (!!getCI(r, "signatures") || !!getCI(r, "target"))) ||
    !!getCI(r, "CAPE") || getCI(r, "malscore") != null;
}

// ───────────────────────────── top-level parse ─────────────────────────────

export function parseSandboxReport(text: string, opts: SandboxImportOptions = {}): SandboxParseResult {
  const maxIocs = opts.maxIocs ?? 5000;
  let root: unknown;
  try { root = JSON.parse(text.trim()); } catch { root = null; }
  const reports: Row[] = Array.isArray(root) ? root.filter(isObject) as Row[] : isObject(root) ? [root] : [];
  const total = reports.length;
  if (total === 0) {
    return { events: [], iocs: [], total: 0, kept: 0, dropped: 0, groups: 0, signatures: 0, format: "empty" };
  }

  const iocSink = new Map<string, SiemIoc>();
  const mapped: MappedEvent[] = [];
  let sawCape = false, sawFalcon = false, matched = 0;

  for (const r of reports) {
    if (isFalcon(r)) { mapped.push(...mapFalcon(r, iocSink)); sawFalcon = true; matched++; }
    else if (isCape(r)) { mapped.push(...mapCape(r, iocSink)); sawCape = true; matched++; }
  }
  if (mapped.length === 0) {
    return { events: [], iocs: [], total, kept: 0, dropped: total, groups: 0, signatures: 0, format: "empty" };
  }

  const signatures = mapped.filter((e) => /signature:/.test(e.description)).length;
  const { events, groups } = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents: opts.maxEvents ?? 2000,
  });

  const format = sawCape && sawFalcon ? "mixed" : sawCape ? "capev2" : sawFalcon ? "falcon" : "empty";
  return {
    events,
    iocs: [...iocSink.values()].slice(0, maxIocs),
    total,
    kept: events.length,
    dropped: Math.max(0, total - matched), // reports that matched neither format
    groups,
    signatures,
    format,
  };
}
