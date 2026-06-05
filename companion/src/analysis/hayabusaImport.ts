// Deterministic importer for Hayabusa (Yamato Security) timelines — the sister of the
// Chainsaw importer. Hayabusa runs Sigma over Windows EVTX and emits an enriched
// *detection timeline*; like Chainsaw it is a detection tool, so the Companion ingests its
// VERDICTS (it does not re-run Sigma). The fourth deterministic ingest path (THOR, SIEM,
// Chainsaw, Hayabusa) — no AI call.
//
// Two output forms are handled, auto-detected:
//   1. JSON / JSONL  (`hayabusa json-timeline [-J]`) — a JSON array, or NDJSON, of records.
//   2. CSV           (`hayabusa csv-timeline`, the default) — a header row + rows; the
//      Details / ExtraFieldInfo cells are " ¦ "-separated `Key: value` pairs.
//
// Unlike Chainsaw, Hayabusa does NOT embed the raw EVTX `Event` node — it presents the
// matched rule plus already-rendered, ALIASED detail fields (Proc/CmdLine/TgtIP/…). So this
// maps verdict-first: the Sigma rule's `Level` drives severity, its `RuleTitle` leads the
// description, and `MitreTactics`/`MitreTags` (any `Txxxx` ids) become MITRE techniques.
// IOCs/asset/process-chain are pulled from the Details + ExtraFieldInfo fields with the
// SAME generic extractors the SIEM importer uses (reused), so the timeline still carries
// hashes/IPs/files/processes for correlation and the asset↔IoC graph.

import type { Severity } from "./stateTypes.js";
import { parseCsv } from "./csvImport.js";
import {
  extractRecords,
  aggregateEvents,
  flatten,
  genericIocs,
  parseHashes,
  cleanIp,
  addIoc,
  firstStr,
  baseName,
  oneLine,
  str,
  isObject,
  getCI,
  normalizeTime,
  type MappedEvent,
  type SiemEvent,
  type SiemIoc,
} from "./siemImport.js";

type Row = Record<string, unknown>;

export interface HayabusaImportOptions {
  aggregate?: boolean;
  minSeverity?: Severity;
  maxEvents?: number;
  maxIocs?: number;
}

export interface HayabusaParseResult {
  events: SiemEvent[];
  iocs: SiemIoc[];
  total: number;   // records found
  kept: number;    // events emitted (after aggregation + cap)
  dropped: number; // records not represented (below floor / capped)
  groups: number;  // distinct event groups before the cap
  format: string;  // "json" | "csv" | "empty"
  hostname: string;
}

// Hayabusa level vocabulary → our Severity. Hayabusa abbreviates in some versions
// (crit/med) and spells out in others (critical/medium); accept both.
const LEVEL: Record<string, Severity> = {
  critical: "Critical", crit: "Critical",
  high: "High",
  medium: "Medium", med: "Medium",
  low: "Low",
  informational: "Info", info: "Info",
};

const IPV4 = /^\d{1,3}(?:\.\d{1,3}){3}$/;
const HEX_HASH = /^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i;

// Pull MITRE technique ids (T1059, T1003.001) out of any tactic/tag/title text.
function mitreFromText(...parts: string[]): string[] {
  const out = new Set<string>();
  for (const p of parts) for (const m of p.matchAll(/\bt\d{4}(?:\.\d{3})?\b/gi)) out.add(m[0].toUpperCase());
  return [...out];
}

// Render any field value (string | array | object) to a flat string for scanning.
function flatStr(v: unknown): string {
  if (v == null) return "";
  if (Array.isArray(v)) return v.map(flatStr).join(" ");
  if (isObject(v)) return Object.values(v).map(flatStr).join(" ");
  return String(v);
}

// Hayabusa CSV/JSON timestamp → UTC ISO. CSV is "YYYY-MM-DD HH:MM:SS.fff +HH:MM"; convert
// to ISO (T separator, no space before the offset) then normalize (honors the offset; a
// missing offset is treated as UTC, matching `hayabusa -U`).
function hayaTime(s: string): string {
  const t = s.trim();
  if (!t) return "";
  const iso = t.replace(
    /^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s*([+-]\d{2}:?\d{2}|Z)?$/,
    (_m, d, hms, tz) => `${d}T${hms}${tz ?? ""}`,
  );
  return normalizeTime(iso);
}

// Parse a Hayabusa CSV `Details`/`ExtraFieldInfo` cell ("Proc: x ¦ CmdLine: y ¦ …") into a
// field map. JSON timelines already give an object, handled separately.
function parseDetailCell(cell: string): Row {
  const out: Row = {};
  for (const part of cell.split(/\s*[¦|]\s*/)) {
    const idx = part.indexOf(":");
    if (idx <= 0) continue;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    if (k) out[k] = v;
  }
  return out;
}

// Common Hayabusa detail-field aliases for the structured correlation fields.
const PROC_KEYS = ["Proc", "Image", "Process", "NewProc", "NewProcessName", "ProcessName"];
const PARENT_KEYS = ["ParentProc", "ParentImage", "ParentProcessName", "PProc", "ParentProcess"];
const PATH_KEYS = ["TgtFile", "TargetFilename", "Path", "File", "FilePath", "Image", "ImageLoaded"];

// Map one Hayabusa record (already field-merged: top-level fields + the parsed details map)
// to a forensic event, pulling IOCs into the sink. Verdict-first; null only if there is no
// usable rule/title at all.
function mapRecord(rec: Row, details: Row, iocSink: Map<string, SiemIoc>): { mapped: MappedEvent; host: string } | null {
  const ruleTitle = firstStr(rec, ["RuleTitle", "Rule Title", "RuleName", "Title"]);
  const channel = firstStr(rec, ["Channel"]);
  const eid = firstStr(rec, ["EventID", "Event ID", "EventId"]);
  if (!ruleTitle && !eid) return null;

  const host = firstStr(rec, ["Computer", "Hostname", "ComputerName"]);
  const level = firstStr(rec, ["Level"]).toLowerCase();
  const severity: Severity = LEVEL[level] ?? "Medium";

  const mitre = mitreFromText(
    flatStr(getCI(rec, "MitreTactics") ?? getCI(rec, "MITRE Tactics")),
    flatStr(getCI(rec, "MitreTags") ?? getCI(rec, "MITRE Tags")),
    flatStr(getCI(rec, "OtherTags") ?? getCI(rec, "Other Tags")),
    ruleTitle,
  );

  // IOCs from the rendered detail fields (+ any ExtraFieldInfo already merged into `details`).
  const pairs: [string, string][] = [];
  flatten(details, pairs);
  genericIocs(pairs, iocSink);
  const { sha256, md5 } = parseHashes(details, details);
  if (sha256) addIoc(iocSink, "hash", sha256);
  else if (md5) addIoc(iocSink, "hash", md5);
  for (const [k, v] of pairs) {
    const val = v.trim();
    const ip = cleanIp(val);
    if (ip && (/ip|addr/i.test(k) || IPV4.test(val))) addIoc(iocSink, "ip", ip);
    if (HEX_HASH.test(val)) addIoc(iocSink, "hash", val.toLowerCase());
  }

  const procRaw = firstStr(details, PROC_KEYS);
  const parentRaw = firstStr(details, PARENT_KEYS);
  const pathRaw = firstStr(details, PATH_KEYS);
  const processName = procRaw ? baseName(procRaw) : undefined;
  const parentName = parentRaw ? baseName(parentRaw) : undefined;
  if (processName) addIoc(iocSink, "process", processName);

  // A compact subject from the first few rendered detail fields.
  const subject = pairs.slice(0, 6).map(([k, v]) => `${k}=${oneLine(v).slice(0, 120)}`).join(" ");
  let description = `Hayabusa: ${ruleTitle || `Event ${eid}`}`;
  if (eid || channel) description += ` (EID ${eid || "?"}${channel ? ` ${channel}` : ""})`;
  if (subject) description += ` — ${subject}`;
  if (host) description += ` @ ${host}`;
  description = description.slice(0, 600);

  const timestamp = hayaTime(firstStr(rec, ["Timestamp", "@timestamp", "datetime"]));
  const aggKey = `hayabusa|${(ruleTitle || eid).toLowerCase()}|${channel.toLowerCase()}|${eid}|${host.toLowerCase()}|${subject}`
    .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/g, "<guid>")
    .replace(/\d+/g, "#")
    .slice(0, 400);

  return {
    host,
    mapped: {
      timestamp,
      description,
      severity,
      mitre,
      aggKey,
      sources: ["Hayabusa"],
      ...(sha256 ? { sha256 } : {}),
      ...(md5 && !sha256 ? { md5 } : {}),
      ...(pathRaw ? { path: pathRaw } : {}),
      ...(host ? { asset: host } : {}),
      ...(processName ? { processName } : {}),
      ...(parentName ? { parentName } : {}),
    },
  };
}

// ───────────────────────────── record extraction ─────────────────────────────

// JSON/JSONL → records (Details already an object). CSV → records (Details a parsed map).
function extractHayabusaRecords(text: string): { records: { rec: Row; details: Row }[]; format: string } {
  const trimmed = text.trim();
  if (!trimmed) return { records: [], format: "empty" };

  // A JSON timeline (array or NDJSON) starts with [ or { (or NDJSON of objects).
  if (trimmed[0] === "[" || trimmed[0] === "{") {
    const { records } = extractRecords(trimmed);
    const out = records.map((rec) => {
      const det = getCI(rec, "Details");
      const extra = getCI(rec, "ExtraFieldInfo") ?? getCI(rec, "Extra Field Info");
      const details: Row = {
        ...(isObject(det) ? det : det != null ? { Details: str(det) } : {}),
        ...(isObject(extra) ? extra : {}),
      };
      return { rec, details };
    });
    return { records: out, format: "json" };
  }

  // CSV timeline.
  const { headers, rows } = parseCsv(trimmed);
  if (headers.length === 0) return { records: [], format: "empty" };
  const out = rows.map((cols) => {
    const rec: Row = {};
    headers.forEach((h, i) => { rec[h.trim()] = cols[i] ?? ""; });
    const detailsCell = firstStr(rec, ["Details"]);
    const extraCell = firstStr(rec, ["ExtraFieldInfo", "Extra Field Info"]);
    const details: Row = { ...parseDetailCell(detailsCell), ...parseDetailCell(extraCell) };
    return { rec, details };
  });
  return { records: out, format: "csv" };
}

// ───────────────────────────── top-level parse ─────────────────────────────

export function parseHayabusaTimeline(text: string, opts: HayabusaImportOptions = {}): HayabusaParseResult {
  const maxIocs = opts.maxIocs ?? 5000;
  const { records, format } = extractHayabusaRecords(text);
  const total = records.length;
  if (total === 0) {
    return { events: [], iocs: [], total: 0, kept: 0, dropped: 0, groups: 0, format: "empty", hostname: "" };
  }

  const iocSink = new Map<string, SiemIoc>();
  const hostTally = new Map<string, number>();
  const mapped: MappedEvent[] = [];

  for (const { rec, details } of records) {
    const r = mapRecord(rec, details, iocSink);
    if (!r) continue;
    if (r.host) hostTally.set(r.host, (hostTally.get(r.host) ?? 0) + 1);
    mapped.push(r.mapped);
  }

  const { events, groups } = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents: opts.maxEvents ?? 2000,
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
    format,
    hostname,
  };
}
