// Deterministic importer for TheHive 5 incident response platform exports. No AI call.
//
// Companion's post-detection principle: we consume TheHive's own verdicts and severity
// ratings — we do not re-score or re-classify the data.
//
// Input forms accepted:
//   • Single case/alert object  { _type: "case" | "alert", … }
//   • Array of case/alert objects (bulk export)
//   • Search result container   { data: [ …case/alert objects… ] }
//   • Array of observable objects  [{ dataType, data, … }, …]
//
// Cases and alerts → forensic events (one per record).
// Observables → IOCs only (mapped by dataType).
//
// Elasticsearch guard: any record carrying `_source` is an ES hit wrapper, not a TheHive
// object — skipped so we don't false-positive on Elasticsearch exports.

import type { Severity } from "./stateTypes.js";
import {
  addIoc,
  aggregateEvents,
  getCI,
  isObject,
  normalizeTime,
  str,
  type MappedEvent,
  type SiemEvent,
  type SiemIoc,
} from "./siemImport.js";

type Row = Record<string, unknown>;

export interface TheHiveImportOptions {
  aggregate?: boolean;
  minSeverity?: Severity;
  maxEvents?: number;
  maxIocs?: number;
  allObservables?: boolean; // include observables not flagged ioc:true (default: false)
}

export interface TheHiveParseResult {
  events: SiemEvent[];
  iocs: SiemIoc[];
  total: number;       // records found (cases/alerts)
  kept: number;        // events emitted
  dropped: number;     // cases/alerts below the severity floor or over the cap
  groups: number;      // distinct groups before the cap
  observables: number; // observable records found
  iocCount: number;    // IOCs extracted
  format: string;      // "single" | "array" | "container" | "observables" | "empty"
}

// ───────────────────────────── severity mapping ─────────────────────────────

// TheHive severity: 1 = Low (Info), 2 = Medium, 3 = High, 4 = Critical
function mapSeverity(raw: unknown): Severity {
  const n = typeof raw === "number" ? raw : Number(str(raw));
  if (n >= 4) return "Critical";
  if (n === 3) return "High";
  if (n === 2) return "Medium";
  return "Info";
}

// ───────────────────────────── MITRE tag extraction ─────────────────────────────

// Extract ATT&CK technique IDs from TheHive tags (e.g. "T1059.001", "attack.T1566").
const MITRE_RE = /\bT\d{4}(?:\.\d{3})?\b/gi;

function mitreFromTags(tags: unknown): string[] {
  if (!Array.isArray(tags)) return [];
  const out = new Set<string>();
  for (const t of tags) {
    const s = str(t);
    for (const m of s.matchAll(MITRE_RE)) {
      out.add(m[0].toUpperCase());
    }
  }
  return [...out];
}

// ───────────────────────────── TLP / PAP labels ─────────────────────────────

const TLP_MAP: Record<number, string> = { 0: "TLP:WHITE", 1: "TLP:GREEN", 2: "TLP:AMBER", 3: "TLP:RED" };
const PAP_MAP: Record<number, string> = { 0: "PAP:WHITE", 1: "PAP:GREEN", 2: "PAP:AMBER", 3: "PAP:RED" };

function tlpPapPrefix(rec: Row): string {
  const parts: string[] = [];
  const tlp = getCI(rec, "tlp");
  if (tlp != null) {
    const label = TLP_MAP[Number(tlp)] ?? `TLP:${tlp}`;
    parts.push(label);
  }
  const pap = getCI(rec, "pap");
  if (pap != null) {
    const label = PAP_MAP[Number(pap)] ?? `PAP:${pap}`;
    parts.push(label);
  }
  return parts.length ? `[${parts.join(" ")}] ` : "";
}

// ───────────────────────────── customFields rendering ─────────────────────────────

function renderCustomFields(cf: unknown): string {
  if (!isObject(cf)) return "";
  const parts: string[] = [];
  for (const [k, v] of Object.entries(cf)) {
    if (!isObject(v)) continue;
    const val = getCI(v as Row, "value") ?? getCI(v as Row, "string") ?? getCI(v as Row, "number");
    if (val != null && str(val).trim()) parts.push(`${k}: ${str(val).trim()}`);
  }
  return parts.length ? ` [${parts.join("; ")}]` : "";
}

// ───────────────────────────── time ─────────────────────────────

function recordTime(rec: Row): string {
  // Prefer startDate (incident time) over _createdAt (platform creation time)
  const startDate = getCI(rec, "startDate");
  const createdAt = getCI(rec, "_createdAt");
  // TheHive 5 stores timestamps as epoch milliseconds
  for (const raw of [startDate, createdAt]) {
    if (raw == null) continue;
    const n = typeof raw === "number" ? raw : Number(str(raw));
    if (Number.isFinite(n) && n > 0) {
      const d = new Date(n > 1e12 ? n : n * 1000);
      if (!Number.isNaN(d.getTime())) return d.toISOString();
    }
    const s = str(raw).trim();
    if (s) return normalizeTime(s);
  }
  return "";
}

// ───────────────────────────── case / alert → event ─────────────────────────────

function mapRecord(rec: Row): MappedEvent {
  const type = str(getCI(rec, "_type")).toLowerCase() || "alert";
  const title = str(getCI(rec, "title")).trim();
  const description = str(getCI(rec, "description")).trim();
  const assignee = str(getCI(rec, "assignee")).trim();
  const tags = getCI(rec, "tags");
  const customFields = getCI(rec, "customFields");

  const severity = mapSeverity(getCI(rec, "severity"));
  const mitre = mitreFromTags(tags);
  const prefix = tlpPapPrefix(rec);
  const cfSuffix = renderCustomFields(customFields);

  const label = type === "case" ? "TheHive Case" : "TheHive Alert";
  const subject = title || description.slice(0, 120) || `${label} (untitled)`;
  const body = [prefix + subject, description && description !== title ? description.slice(0, 300) : "", cfSuffix]
    .filter(Boolean).join(" — ");

  const fullDesc = (`${label}: ${body}` + (assignee ? ` (assignee: ${assignee})` : "")).slice(0, 600);

  return {
    timestamp: recordTime(rec),
    description: fullDesc,
    severity,
    mitre,
    aggKey: `thehive|${type}|${severity}|${title.toLowerCase().slice(0, 120)}`,
    sources: ["TheHive"],
    ...(assignee ? { asset: assignee } : {}),
  };
}

// ───────────────────────────── observable → IOC ─────────────────────────────

const OBS_TYPE_MAP: Record<string, SiemIoc["type"]> = {
  ip: "ip",
  domain: "domain",
  fqdn: "domain",
  url: "url",
  hash: "hash",
  filename: "file",
  mail: "other",   // email addresses — stored as "other" (SiemIoc has no "email" type)
};

function mapObservable(rec: Row, sink: Map<string, SiemIoc>, allObservables: boolean): void {
  const iocFlag = getCI(rec, "ioc");
  if (!allObservables && iocFlag !== true) return;

  const dataType = str(getCI(rec, "dataType")).toLowerCase().trim();
  const data = str(getCI(rec, "data")).trim();
  if (!data) return;

  const iocType = OBS_TYPE_MAP[dataType];
  if (iocType) {
    addIoc(sink, iocType, data.slice(0, 300));
  }
}

// ───────────────────────────── record extraction ─────────────────────────────

type RecordKind = "case_or_alert" | "observable" | "skip";

function classifyRecord(rec: Row): RecordKind {
  // Elasticsearch guard: hit wrappers always have `_source`
  if (getCI(rec, "_source") != null) return "skip";

  const t = str(getCI(rec, "_type")).toLowerCase();
  if (t === "case" || t === "alert") return "case_or_alert";

  // Observable: carries `dataType` + `data`
  if (getCI(rec, "dataType") != null && getCI(rec, "data") != null) return "observable";

  return "skip";
}

function extractRecords(root: unknown): { records: Row[]; format: string } {
  if (Array.isArray(root)) {
    const records = root.filter(isObject);
    if (records.length === 0) return { records: [], format: "empty" };
    return { records, format: "array" };
  }
  if (isObject(root)) {
    // Container: { data: [...] } (search result)
    const data = getCI(root, "data");
    if (Array.isArray(data)) {
      const records = data.filter(isObject);
      return { records, format: "container" };
    }
    // Single record
    return { records: [root], format: "single" };
  }
  return { records: [], format: "empty" };
}

// ───────────────────────────── top-level parse ─────────────────────────────

export function parseTheHive(text: string, opts: TheHiveImportOptions = {}): TheHiveParseResult {
  const maxIocs = opts.maxIocs ?? 5000;
  const t = text.trim();
  if (!t) {
    return { events: [], iocs: [], total: 0, kept: 0, dropped: 0, groups: 0, observables: 0, iocCount: 0, format: "empty" };
  }

  let root: unknown;
  try { root = JSON.parse(t); } catch { /* fall through to empty */ }

  if (root === undefined) {
    return { events: [], iocs: [], total: 0, kept: 0, dropped: 0, groups: 0, observables: 0, iocCount: 0, format: "empty" };
  }

  const { records, format } = extractRecords(root);
  if (records.length === 0) {
    return { events: [], iocs: [], total: 0, kept: 0, dropped: 0, groups: 0, observables: 0, iocCount: 0, format };
  }

  const sink = new Map<string, SiemIoc>();
  const mapped: MappedEvent[] = [];
  let observableCount = 0;

  for (const rec of records) {
    const kind = classifyRecord(rec);
    if (kind === "case_or_alert") {
      mapped.push(mapRecord(rec));
    } else if (kind === "observable") {
      observableCount++;
      mapObservable(rec, sink, opts.allObservables ?? false);
    }
  }

  const caseAlertTotal = mapped.length;

  const { events, groups } = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents: opts.maxEvents ?? (Number(process.env.DFIR_MAX_EVENTS) || 2000),
  });

  const represented = events.reduce((n, e) => n + (e.count ?? 1), 0);
  const iocs = [...sink.values()].slice(0, maxIocs);

  // Determine the true format label
  let finalFormat = format;
  if (observableCount > 0 && caseAlertTotal === 0) finalFormat = "observables";

  return {
    events,
    iocs,
    total: caseAlertTotal,
    kept: events.length,
    dropped: Math.max(0, caseAlertTotal - represented),
    groups,
    observables: observableCount,
    iocCount: iocs.length,
    format: finalFormat,
  };
}
