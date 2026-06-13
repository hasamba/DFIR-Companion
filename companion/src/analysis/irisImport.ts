// Deterministic importer for an existing DFIR-IRIS case (issue #88) — the reverse of the
// Companion → IRIS push. No AI call.
//
// Companion's post-detection principle: we CONSUME the IRIS case's own data (the analyst's
// curated assets, IOCs and timeline) — we do not re-score or re-classify it. A case the
// Companion previously pushed round-trips faithfully (severity from the event colour, MITRE
// from the tags, asset/hash/path from the structured content lines the push wrote); a native
// IRIS case degrades gracefully (severity falls back to a tag word, IOC type to value-shape).
//
// This module is PURE: it maps already-fetched IRIS rows. The network fetch lives in the
// orchestrator (integrations/iris/irisImportFetch.ts), which is unit-tested with a mock client.
//
// Mapping:
//   • timeline events → forensic events (one per row; date, title/content, severity, MITRE, asset)
//   • IOCs            → IOCs (type from the IRIS ioc-type name, else inferred from the value)
//   • assets          → evidence events (so nothing is lost and the asset graph picks them up)

import type { Severity } from "./stateTypes.js";
import {
  addIoc,
  aggregateEvents,
  baseName,
  cleanIp,
  getCI,
  isObject,
  normalizeTime,
  oneLine,
  str,
  type MappedEvent,
  type SiemEvent,
  type SiemIoc,
} from "./siemImport.js";

type Row = Record<string, unknown>;

// Raw IRIS rows fetched from a case (the input to the pure parser). The orchestrator
// (irisImportFetch.ts) populates this from the IRIS REST list endpoints.
export interface IrisCaseData {
  irisCaseId?: number;
  caseName?: string;
  assets: Row[];     // /case/assets/list rows
  iocs: Row[];       // /case/ioc/list rows
  timeline: Row[];   // /case/timeline/events rows
}

export interface IrisImportOptions {
  aggregate?: boolean;
  minSeverity?: Severity;
  maxEvents?: number;
  maxIocs?: number;
  includeAssets?: boolean;   // map IRIS assets to evidence events (default true)
}

export interface IrisImportResult {
  events: SiemEvent[];
  iocs: SiemIoc[];
  timelineCount: number;   // timeline rows found
  assetCount: number;      // asset rows found
  iocRecords: number;      // ioc rows found
  kept: number;            // events emitted (after aggregation + cap)
  dropped: number;         // events not represented (below floor / capped)
  groups: number;          // distinct event groups before the cap
  iocCount: number;        // IOCs extracted
  caseName?: string;
  irisCaseId?: number;
}

// ───────────────────────────── severity ─────────────────────────────

// Reverse of irisMap's SEV_COLOR — a Companion-pushed event carries its severity in the colour.
const COLOR_SEVERITY: Record<string, Severity> = {
  "#ef4444": "Critical",
  "#f97316": "High",
  "#eab308": "Medium",
  "#3b82f6": "Low",
  "#6b7280": "Info",
};

const SEVERITY_WORDS: Record<string, Severity> = {
  critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info", informational: "Info",
};

function severityFromTags(tags: string): Severity | undefined {
  for (const tok of tags.toLowerCase().split(/[,\s]+/)) {
    const sev = SEVERITY_WORDS[tok.trim()];
    if (sev) return sev;
  }
  return undefined;
}

function eventSeverity(row: Row): Severity {
  const color = str(getCI(row, "event_color")).trim().toLowerCase();
  if (color && COLOR_SEVERITY[color]) return COLOR_SEVERITY[color];
  const tagSev = severityFromTags(str(getCI(row, "event_tags")));
  return tagSev ?? "Info";
}

// ───────────────────────────── MITRE ─────────────────────────────

const MITRE_RE = /\bT\d{4}(?:\.\d{3})?\b/gi;

function mitreFrom(...texts: string[]): string[] {
  const out = new Set<string>();
  for (const t of texts) for (const m of t.matchAll(MITRE_RE)) out.add(m[0].toUpperCase());
  return [...out];
}

// ───────────────────────────── time ─────────────────────────────

// IRIS stores event_date as `%Y-%m-%dT%H:%M:%S.%f` (microseconds, NO trailing Z) with the
// timezone carried separately in event_tz. Combine them and normalize to a UTC ISO string.
function irisEventTime(dateRaw: unknown, tzRaw: unknown): string {
  let d = str(dateRaw).trim();
  if (!d) return "";
  d = d.replace(/(\.\d{3})\d+/, "$1"); // microseconds → milliseconds (JS Date is millisecond-precision)
  if (/[+-]\d{2}:?\d{2}$|Z$/.test(d)) return normalizeTime(d);
  const tz = str(tzRaw).trim();
  if (tz && tz !== "+00:00" && tz !== "Z") return normalizeTime(d + tz);
  return normalizeTime(d);
}

// ───────────────────────────── timeline event → forensic event ─────────────────────────────

// Pull a "Key: value" line out of the Companion-written event_content (best-effort, native
// IRIS content simply won't match and the field stays unset).
function contentField(content: string, key: string): string {
  const re = new RegExp(`^\\s*${key}\\s*:\\s*(.+)$`, "im");
  return re.exec(content)?.[1]?.trim() ?? "";
}

export function mapIrisEvent(row: Row, sink: Map<string, SiemIoc>): MappedEvent {
  const title = oneLine(str(getCI(row, "event_title"))).trim();
  const content = str(getCI(row, "event_content"));
  const tags = str(getCI(row, "event_tags"));
  const severity = eventSeverity(row);
  const description = (title || oneLine(content).slice(0, 200) || "(IRIS event)").slice(0, 600);
  const mitre = mitreFrom(tags, content);

  const sha256 = contentField(content, "SHA256");
  const md5 = contentField(content, "MD5");
  const path = contentField(content, "Path");
  const asset = contentField(content, "Asset");
  const processName = contentField(content, "Process");

  if (sha256) addIoc(sink, "hash", sha256);
  else if (md5) addIoc(sink, "hash", md5);
  if (path) addIoc(sink, "file", path);

  return {
    timestamp: irisEventTime(getCI(row, "event_date"), getCI(row, "event_tz")),
    description,
    severity,
    mitre,
    aggKey: `iris|${severity}|${description.toLowerCase().slice(0, 160)}`,
    sources: ["DFIR-IRIS"],
    ...(sha256 ? { sha256 } : {}),
    ...(md5 && !sha256 ? { md5 } : {}),
    ...(path ? { path } : {}),
    ...(asset ? { asset } : {}),
    ...(processName ? { processName: baseName(processName) } : {}),
  };
}

// ───────────────────────────── asset → evidence event ─────────────────────────────

export function mapIrisAsset(row: Row): MappedEvent | null {
  const name = str(getCI(row, "asset_name")).trim();
  if (!name) return null;
  // The push writes asset_compromise_status_id 1 = compromised; treat only that as a signal.
  const compromised = Number(getCI(row, "asset_compromise_status_id")) === 1;
  const ip = str(getCI(row, "asset_ip")).trim();
  const domain = str(getCI(row, "asset_domain")).trim();
  const desc = str(getCI(row, "asset_description")).trim();
  const tags = str(getCI(row, "asset_tags"));

  const detail = [ip && `IP ${ip}`, domain && `domain ${domain}`, compromised && "COMPROMISED"]
    .filter(Boolean).join(", ");
  const description = (`IRIS asset: ${name}${detail ? ` (${detail})` : ""}${desc ? ` — ${desc}` : ""}`).slice(0, 600);

  return {
    timestamp: "",   // assets carry no event time
    description,
    severity: compromised ? "High" : "Info",
    mitre: mitreFrom(tags, desc),
    aggKey: `iris-asset|${name.toLowerCase()}`,
    sources: ["DFIR-IRIS"],
    asset: name,
  };
}

// ───────────────────────────── IOC → SiemIoc ─────────────────────────────

const HEX = /^[a-f0-9]+$/i;

// IRIS ioc-type names (MISP taxonomy) → our coarse IOC type.
function typeFromIrisName(name: string): SiemIoc["type"] | undefined {
  const n = name.toLowerCase().trim();
  if (!n) return undefined;
  if (n.startsWith("ip-") || n === "ip") return "ip";
  if (n === "domain" || n === "hostname") return "domain";
  if (n === "url" || n === "uri" || n === "link") return "url";
  if (n === "md5" || n === "sha1" || n === "sha256" || n === "sha512" || n.includes("hash")) return "hash";
  if (n === "filename" || n === "file") return "file";
  if (n.startsWith("process")) return "process";
  return undefined;
}

// Infer the IOC type from the value's shape when IRIS gives no usable type name. File paths are
// checked before IP because a Windows path ("C:\…") contains a colon that cleanIp reads as IPv6.
function typeFromValue(value: string): SiemIoc["type"] {
  const v = value.trim();
  if (/^https?:\/\//i.test(v)) return "url";
  if (/[\\]/.test(v) || /^[a-z]:[\\/]/i.test(v)) return "file";   // backslash / Windows drive path
  if (cleanIp(v)) return "ip";
  if (HEX.test(v) && [32, 40, 64, 128].includes(v.length)) return "hash";
  if (v.includes("/")) return "file";                              // unix path
  if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(v) && !v.includes(" ")) return "domain";
  return "other";
}

// Read the IRIS ioc-type NAME from a row (the list endpoint may nest it under ioc_type, or
// flatten it as ioc_type_name / type_name — be tolerant).
function irisIocTypeName(row: Row): string {
  const t = getCI(row, "ioc_type");
  if (typeof t === "string") return t;
  if (isObject(t)) return str(getCI(t, "type_name") ?? getCI(t, "name"));
  return str(getCI(row, "ioc_type_name") ?? getCI(row, "type_name"));
}

export function mapIrisIoc(row: Row, sink: Map<string, SiemIoc>): boolean {
  const value = str(getCI(row, "ioc_value")).trim();
  if (!value) return false;
  const type = typeFromIrisName(irisIocTypeName(row)) ?? typeFromValue(value);
  addIoc(sink, type, value.slice(0, 300));
  return true;
}

// ───────────────────────────── top-level parse ─────────────────────────────

export function parseIrisCase(data: IrisCaseData, opts: IrisImportOptions = {}): IrisImportResult {
  const maxIocs = opts.maxIocs ?? 5000;
  const includeAssets = opts.includeAssets ?? true;

  const sink = new Map<string, SiemIoc>();
  const mapped: MappedEvent[] = [];

  for (const row of data.timeline) if (isObject(row)) mapped.push(mapIrisEvent(row, sink));
  if (includeAssets) {
    for (const row of data.assets) {
      if (!isObject(row)) continue;
      const ev = mapIrisAsset(row);
      if (ev) mapped.push(ev);
    }
  }
  let iocRecords = 0;
  for (const row of data.iocs) if (isObject(row) && mapIrisIoc(row, sink)) iocRecords += 1;

  const mappedTotal = mapped.length;
  const { events, groups } = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents: opts.maxEvents ?? 5000,
  });
  const represented = events.reduce((n, e) => n + (e.count ?? 1), 0);
  const iocs = [...sink.values()].slice(0, maxIocs);

  return {
    events,
    iocs,
    timelineCount: data.timeline.length,
    assetCount: data.assets.length,
    iocRecords,
    kept: events.length,
    dropped: Math.max(0, mappedTotal - represented),
    groups,
    iocCount: iocs.length,
    caseName: data.caseName,
    irisCaseId: data.irisCaseId,
  };
}
