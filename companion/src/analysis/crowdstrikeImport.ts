// Deterministic importer for CrowdStrike Falcon sensor exports (#2592): Event Search, Falcon
// LogScale and Next-Gen SIEM exports (`#event_simpleName`) and Falcon Data Replicator records
// (`event_simpleName`), as a JSON array, NDJSON or CSV.
//
// The generic SIEM importer could read these files but lost what makes them useful: it dated rows by
// the sensor's send time instead of `ContextTimeStamp`, found no host, dropped the remote address of a
// connection, extracted no IOC, graded every row Low and folded digits in its aggregation key, so all
// connections on a host collapsed into one row. This importer reads each event family itself
// (crowdstrikeMap.ts), labels every row `CrowdStrike Falcon` (so the case's main-source family is
// `crowdstrike` and hunts use CQL), and aggregates without folding identities away.
//
// Pure, deterministic, no AI call.

import { stampSourceArtifactHash } from "./canonicalEvent.js";
import {
  extractRecords,
  aggregateEvents,
  maxEventsDefault,
  type MappedEvent,
  type SiemIoc,
  type SiemParseResult,
} from "./siemImport.js";
import { parseCsv } from "./csvImport.js";
import { CROWDSTRIKE_SOURCE, eventName, field } from "./crowdstrikeFields.js";
import { mapCrowdstrikeRecord } from "./crowdstrikeMap.js";
import type { Severity } from "./stateTypes.js";
import type { ImportDebugRecorder } from "./importDebug.js";
import { createCodeTally, createFieldTally, recordAggregation } from "./parseDebugTally.js";

type Row = Record<string, unknown>;

export { CROWDSTRIKE_SOURCE };

export interface CrowdstrikeImportOptions {
  aggregate?: boolean; // collapse identical events into one counted row. Default true.
  minSeverity?: Severity; // drop events below this floor. Default: keep everything.
  maxEvents?: number; // safety cap on emitted events (most severe first). Default DFIR_MAX_EVENTS.
  maxIocs?: number; // safety cap on emitted IOCs. Default 5000.
  debug?: ImportDebugRecorder;
}

/** A Falcon sensor row: an event name AND the sensor's host identity (`aid` or `ComputerName`). */
export function isCrowdstrikeRecord(rec: unknown): boolean {
  if (!rec || typeof rec !== "object" || Array.isArray(rec)) return false;
  const r = rec as Row;
  return eventName(r) !== "" && (field(r, "aid") !== "" || field(r, "ComputerName") !== "");
}

/** The same signature on a lowercased CSV header set. */
export function crowdstrikeCsvSig(h: Set<string>): boolean {
  return (h.has("#event_simplename") || h.has("event_simplename")) && (h.has("aid") || h.has("computername"));
}

// ───────────────────────────── reading ─────────────────────────────

function readRecords(text: string): { records: Row[]; format: string } {
  const t = text.replace(/^\uFEFF/, "").trim();
  if (t[0] === "{" || t[0] === "[") return extractRecords(t);
  const { headers, rows } = parseCsv(t);
  if (!headers.length) return { records: [], format: "csv" };
  const names = headers.map((h) => h.trim());
  return {
    records: rows.map((cols) => Object.fromEntries(names.map((h, i) => [h, cols[i] ?? ""]))),
    format: "csv",
  };
}

// ───────────────────────────── time ─────────────────────────────

const MIN_MS = Date.UTC(1990, 0, 1);
const MAX_MS = Date.UTC(2100, 0, 1);

// One time field to epoch ms, or undefined when blank, zero, malformed or out of range. `unit` is the
// field's documented unit; a "seconds" value already in milliseconds (>= 1e11) is read as ms.
function toMs(raw: string, unit: "s" | "ms"): number | undefined {
  if (!raw) return undefined;
  const n = Number(raw);
  let ms: number;
  if (Number.isFinite(n)) {
    if (n <= 0) return undefined;
    ms = unit === "s" && n < 1e11 ? Math.round(n * 1000) : Math.round(n);
  } else {
    ms = Date.parse(raw);
    if (Number.isNaN(ms)) return undefined;
  }
  return ms >= MIN_MS && ms < MAX_MS ? ms : undefined;
}

// Event time, by validity: ContextTimeStamp (the event itself) → ProcessStartTime → timestamp (the
// sensor's send time) → @timestamp (LogScale ingest).
const TIME_FIELDS: [string, "s" | "ms"][] = [
  ["ContextTimeStamp", "s"],
  ["ProcessStartTime", "s"],
  ["timestamp", "ms"],
  ["@timestamp", "ms"],
];
export function crowdstrikeTime(rec: Row): { iso: string; from: string } | null {
  for (const [key, unit] of TIME_FIELDS) {
    const ms = toMs(field(rec, key), unit);
    if (ms !== undefined) return { iso: new Date(ms).toISOString(), from: key };
  }
  return null;
}

// ───────────────────────────── parse ─────────────────────────────

export function parseCrowdstrikeExport(text: string, opts: CrowdstrikeImportOptions = {}): SiemParseResult {
  const { records, format } = readRecords(text);
  const sink = new Map<string, SiemIoc>();
  const hostTally = new Map<string, number>();
  const mapped: MappedEvent[] = [];
  const fields = createFieldTally();
  const skipped = createCodeTally();
  const noted = createCodeTally();

  for (const [recordIndex, rec] of records.entries()) {
    if (!rec || typeof rec !== "object") {
      skipped.add("not_an_object");
      continue;
    }
    const time = crowdstrikeTime(rec);
    const m = mapCrowdstrikeRecord(rec, time?.iso ?? "", recordIndex, sink);
    if (!m) {
      skipped.add("no_event_simplename");
      continue;
    }
    mapped.push(m);
    if (time) fields.add("timestamp", time.from);
    else noted.add("empty_timestamp");
    if (m.asset) {
      fields.add("host", field(rec, "ComputerName") ? "ComputerName" : "aid");
      hostTally.set(m.asset, (hostTally.get(m.asset) ?? 0) + 1);
    } else noted.add("missing_host");
  }
  fields.flush(opts.debug);
  skipped.flush((code, n) => opts.debug?.skipped(code, n));
  noted.flush((code, n) => opts.debug?.observed(code, n));

  const { events, groups } = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents: opts.maxEvents ?? maxEventsDefault(),
  });
  recordAggregation(opts.debug, mapped.length, groups, events.length);
  const represented = events.reduce((n, e) => n + (e.count ?? 1), 0);
  return {
    events: stampSourceArtifactHash(events, text),
    iocs: [...sink.values()].slice(0, opts.maxIocs ?? 5000),
    total: records.length,
    kept: events.length,
    dropped: Math.max(0, records.length - represented),
    groups,
    format,
    hostname: [...hostTally.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] ?? "",
  };
}
