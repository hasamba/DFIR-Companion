import type { Severity } from "./stateTypes.js";
import { parseCsv } from "./csvImport.js";
import {
  boundQuarantineVariants,
  quarantineOverlay,
  type QuarantineRow,
  type QuarantineTimeOption,
} from "./quarantineRecord.js";
import {
  extractRecords,
  aggregateEvents,
  mergeRowIocs,
  oneLine,
  isObject,
  getCI,
  normalizeTime,
  type MappedEvent,
  type SiemEvent,
  type SiemIoc,
  maxEventsDefault,
} from "./siemImport.js";

// Deterministic importer for macOS host artifacts — the platform gap beside the Windows (KAPE/EVTX)
// and Linux (auditd/journald) paths. No AI call. Two shapes, auto-detected:
//
//   1. UNIFIED LOG — `log show --style json` / `log collect` exported to JSON. The closest macOS has
//      to an event log, though it is telemetry rather than a security log: process, subsystem,
//      category and a free-text message, with no verdict anywhere.
//   2. LSQUARANTINE — the download-provenance database (`~/Library/Preferences/
//      com.apple.LaunchServices.QuarantineEventsV2`), dumped to CSV. This is macOS's Mark-of-the-Web:
//      which app downloaded a file, from which URL, and from which referring page. On an initial-
//      access question it is often the single most useful macOS artifact there is.
//
// EVERY ROW IS Info, like kapeImport and hindsightImport. Neither artifact adjudicates anything: a
// quarantine record proves a file arrived from a URL, not that the file was malicious. Escalation is
// the job of correlation against a real detection, a hash lookup, or a sandbox verdict.

type Row = Record<string, unknown>;

export interface MacosImportOptions {
  aggregate?: boolean;
  minSeverity?: Severity;
  maxEvents?: number;
  maxIocs?: number;
  /** A converted quarantine dump's epoch, declared by the analyst (quarantineRecord.ts). */
  quarantineTime?: QuarantineTimeOption;
}

export interface MacosParseResult {
  events: SiemEvent[];
  iocs: SiemIoc[];
  total: number;
  kept: number;
  dropped: number;
  groups: number;
  format: string; // "macos-unified-log" | "macos-quarantine" | "empty"
}

function text(value: unknown): string {
  return typeof value === "string" ? value : value == null ? "" : String(value);
}

function pick(rec: Row, keys: readonly string[]): string {
  for (const k of keys) {
    const v = getCI(rec, k);
    if (v != null && text(v).trim() !== "") return text(v).trim();
  }
  return "";
}

// `log show` writes "2026-05-02 10:00:00.123456+0000" — a space instead of the ISO 'T' and six
// fractional digits. normalizeTime handles ISO; this makes the unified-log form ISO first.
function normalizeUnifiedTime(raw: string): string {
  const iso = raw.trim().replace(" ", "T");
  return normalizeTime(iso);
}

function baseName(path: string): string {
  const parts = path.split(/[\\/]/);
  return parts[parts.length - 1] || path;
}

function mapUnifiedLog(rec: Row): MappedEvent | null {
  const timestamp = pick(rec, ["timestamp", "time"]);
  if (!timestamp) return null;

  const message = pick(rec, ["eventMessage", "message", "composedMessage"]);
  const proc = pick(rec, ["processImagePath", "process"]);
  const subsystem = pick(rec, ["subsystem"]);
  const category = pick(rec, ["category"]);
  const asset = pick(rec, ["machineName", "hostname", "host"]);
  const pid = pick(rec, ["processID", "pid"]);

  const procName = proc ? baseName(proc) : "";
  let description = `macOS log${procName ? ` ${procName}` : ""}`;
  if (pid) description += `[${pid}]`;
  if (subsystem || category) description += ` (${[subsystem, category].filter(Boolean).join(" / ")})`;
  if (message) description += `: ${oneLine(message).slice(0, 400)}`;
  description = description.slice(0, 600);

  return {
    timestamp: normalizeUnifiedTime(timestamp),
    description,
    severity: "Info", // telemetry, not a verdict — see the header
    mitre: [],
    aggKey: `macos-ulog|${subsystem}|${procName}`.toLowerCase().slice(0, 400),
    sources: ["macOS Unified Log"],
    ...(asset ? { asset } : {}),
    ...(proc ? { path: proc } : {}),
  };
}

// One LSQuarantineEventsV2 record → what it establishes (quarantineRecord.ts, #933 item 7): the
// kind, the agent, the RESOURCE and the ORIGIN as distinct URLs, the time by its declared encoding,
// the event identifier — and never the local file, which this record does not name.
function mapQuarantine(rec: Row, sink: Map<string, SiemIoc>, opts: MacosImportOptions): QuarantineRow | null {
  // Once the file is a quarantine dump every record with ANY quarantine fact is a row — an email
  // attachment carries no URL and is still a download event.
  const hasAny = Object.entries(rec).some(([k, v]) => k.trim() !== "" && text(v).trim() !== "");
  return hasAny
    ? quarantineOverlay(rec, sink, {
        ...(opts.quarantineTime ? { quarantineTime: opts.quarantineTime } : {}),
        deferIocs: true,
      })
    : null;
}

// A quarantine dump names itself by its native columns, or — a converted export — by a coherent
// set of the aliases the reader accepts (a data url with an event id, an agent or an origin).
// Aliases by DIMENSION: the resource (`data_url`/`url`) plus one independent quarantine signal —
// `origin_url` and `referrer` are one dimension, so two synonyms never count as two signals.
const RESOURCE_ALIASES = ["data_url", "url"];
const SIGNAL_DIMENSIONS = [["event_id"], ["agent"], ["origin_url", "referrer"]];
function looksLikeQuarantine(headers: readonly string[]): boolean {
  const h = headers.map((x) => x.trim().toLowerCase());
  if (h.some((x) => /lsquarantine/i.test(x))) return true;
  const resource = RESOURCE_ALIASES.some((k) => h.includes(k));
  const signals = SIGNAL_DIMENSIONS.filter((dim) => dim.some((k) => h.includes(k))).length;
  return resource && signals >= 1;
}

export function parseMacos(input: string, opts: MacosImportOptions = {}): MacosParseResult {
  const maxIocs = opts.maxIocs ?? 5000;
  const empty: MacosParseResult = {
    events: [],
    iocs: [],
    total: 0,
    kept: 0,
    dropped: 0,
    groups: 0,
    format: "empty",
  };

  const trimmed = input.trim();
  if (!trimmed) return empty;

  const iocSink = new Map<string, SiemIoc>();
  const mapped: MappedEvent[] = [];
  let total = 0;
  let format = "empty";

  const quarantineRows: QuarantineRow[] = [];
  if (trimmed[0] === "[" || trimmed[0] === "{") {
    const records = extractRecords(trimmed).records.filter(isObject) as Row[];
    total = records.length;
    // A JSON dump of the quarantine database is a quarantine file too — record by record: a
    // unified-log record in the same array is never a download event.
    let quarantine = false;
    for (const rec of records) {
      const isQuarantine = looksLikeQuarantine(Object.keys(rec));
      quarantine ||= isQuarantine;
      const event = isQuarantine ? mapQuarantine(rec, iocSink, opts) : mapUnifiedLog(rec);
      if (event) mapped.push(event);
      if (event && isQuarantine) quarantineRows.push(event as QuarantineRow);
    }
    format = quarantine ? "macos-quarantine" : "macos-unified-log";
  } else {
    const { headers, rows } = parseCsv(trimmed);
    if (!headers.length) return empty;
    const quarantine = looksLikeQuarantine(headers);
    const objects = rows.map((cols) => {
      const r: Row = {};
      headers.forEach((h, i) => {
        r[h.trim()] = cols[i] ?? "";
      });
      return r;
    });
    total = objects.length;
    for (const rec of objects) {
      const event = quarantine ? mapQuarantine(rec, iocSink, opts) : mapUnifiedLog(rec);
      if (event) mapped.push(event);
      if (event && quarantine) quarantineRows.push(event as QuarantineRow);
    }
    format = quarantine ? "macos-quarantine" : "macos-unified-log";
  }

  if (total === 0) return empty;
  // A UUID that names two different fact sets is said on both rows; past a budget of fact sets
  // per UUID the rest fold into one overflow row (quarantineRecord.ts).
  const bounded = boundQuarantineVariants(quarantineRows);
  // The excess variants leave `mapped` too, so the bound holds with aggregation off; indicators come
  // only from the rows that survived, linked to their rows.
  const dropped = new Set(quarantineRows.filter((r) => !bounded.includes(r)));
  const kept = mapped.filter((m) => !dropped.has(m as QuarantineRow));
  for (const r of bounded) {
    const rowSink = new Map<string, SiemIoc>(r.iocs.map((i) => [`${i.type}:${i.value.toLowerCase()}`, i]));
    mergeRowIocs(iocSink, rowSink, r.aggKey);
  }

  const { events, groups } = aggregateEvents(kept, {
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
    dropped: Math.max(0, mapped.length - represented),
    groups,
    format: mapped.length ? format : "empty",
  };
}
