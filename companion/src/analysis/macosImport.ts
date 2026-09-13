import type { Severity } from "./stateTypes.js";
import { parseCsv } from "./csvImport.js";
import {
  NATIVE_COLUMN_RE,
  RepeatedColumn,
  boundQuarantineVariants,
  quarantineOverlay,
  type QuarantineRow,
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
// kind, the agent, the RESOURCE and the ORIGIN as distinct URLs, the time by the encoding its column declares,
// the event identifier — and never the local file, which this record does not name.
function mapQuarantine(rec: Row, sink: Map<string, SiemIoc>): QuarantineRow | null {
  return quarantineOverlay(rec, sink, { deferIocs: true });
}

// A quarantine RECORD names itself by its values, never by its header alone: a native
// `LSQuarantine*` field that is filled (an email attachment carries no URL and is still a download
// event), or — a converted export with no native column — a coherent set of filled aliases: the
// resource (`data_url`/`url`) plus one independent quarantine signal. Aliases by DIMENSION:
// `origin_url` and `referrer` are one dimension, so two synonyms never count as two signals. A row
// whose native columns are all empty is not a download record, whatever its generic columns hold.
const RESOURCE_ALIASES = ["data_url", "url"];
const SIGNAL_DIMENSIONS = [["event_id"], ["agent"], ["origin_url", "referrer"]];
// Only the native columns the reader knows — `LSQuarantineError` is not one, whatever its prefix.
const NATIVE_RE = NATIVE_COLUMN_RE;
function isQuarantineRecord(rec: Row, headers: readonly string[]): boolean {
  // A repeated header is filled when any of its values is.
  const hasValue = (v: unknown) =>
    v instanceof RepeatedColumn ? v.values.some((x) => x.trim() !== "") : text(v).trim() !== "";
  const filled = (k: string) =>
    Object.entries(rec).some(([h, v]) => h.trim().toLowerCase() === k && hasValue(v));
  if (headers.some((h) => NATIVE_RE.test(h.trim())))
    return Object.entries(rec).some(([h, v]) => NATIVE_RE.test(h.trim()) && hasValue(v));
  const resource = RESOURCE_ALIASES.some(filled);
  const signals = SIGNAL_DIMENSIONS.filter((dim) => dim.some(filled)).length;
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
      const isQuarantine = isQuarantineRecord(rec, Object.keys(rec));
      quarantine ||= isQuarantine;
      const event = isQuarantine ? mapQuarantine(rec, iocSink) : mapUnifiedLog(rec);
      if (event) mapped.push(event);
      if (event && isQuarantine) quarantineRows.push(event as QuarantineRow);
    }
    format = quarantine ? "macos-quarantine" : "macos-unified-log";
  } else {
    const { headers, rows } = parseCsv(trimmed);
    if (!headers.length) return empty;
    const objects = rows.map((cols) => {
      const r: Row = {};
      // A header the file repeats keeps every value (a RepeatedColumn) — the quarantine reader
      // treats a repeated time column as two time columns, never as the last one.
      headers.forEach((h, i) => {
        const k = h.trim();
        const v = cols[i] ?? "";
        const prev = r[k];
        r[k] = !(k in r)
          ? v
          : new RepeatedColumn([...(prev instanceof RepeatedColumn ? prev.values : [String(prev)]), v]);
      });
      return r;
    });
    total = objects.length;
    // Row by row, like JSON: a row of a quarantine dump whose native columns are empty is not a
    // download record — it is read as telemetry or dropped, and mints nothing.
    let quarantine = false;
    for (const rec of objects) {
      const isQuarantine = isQuarantineRecord(rec, headers);
      quarantine ||= isQuarantine;
      const event = isQuarantine ? mapQuarantine(rec, iocSink) : mapUnifiedLog(rec);
      if (event) mapped.push(event);
      if (event && isQuarantine) quarantineRows.push(event as QuarantineRow);
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
