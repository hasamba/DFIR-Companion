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
import { alertRecords, isCrowdstrikeAlert, mapCrowdstrikeAlert } from "./crowdstrikeAlert.js";
import { crowdstrikeTime } from "./crowdstrikeTime.js";
export { crowdstrikeTime };
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
  // The uploaded file's text when `text` is a subset rebuilt from it (a split LogScale export, Part 3),
  // so every row keeps the hash of the artifact the analyst actually imported.
  sourceText?: string;
  // With sourceText: each row's record index in that original file, so evidence locators point there.
  recordIndexes?: readonly number[];
}

/** A Falcon sensor row: an event name AND the sensor's host identity (`aid` or `ComputerName`). */
export function isCrowdstrikeRecord(rec: unknown): boolean {
  if (!rec || typeof rec !== "object" || Array.isArray(rec)) return false;
  const r = rec as Row;
  return eventName(r) !== "" && (field(r, "aid") !== "" || field(r, "ComputerName") !== "");
}

const isMetaKey = (k: string): boolean => k[0] === "@" || k[0] === "#";

/**
 * A LogScale / Next-Gen SIEM row wrapping third-party data (Part 3): no Falcon event name, and either
 * the raw log in `@rawstring` with `#repo`/`#type`, or the parsed vendor record under `Vendor` (an
 * object, or dotted `Vendor.…` keys) next to at least one LogScale `@`/`#` metadata key.
 */
export function isCrowdstrikeWrapper(rec: unknown): boolean {
  if (!rec || typeof rec !== "object" || Array.isArray(rec)) return false;
  const r = rec as Row;
  if (eventName(r) !== "") return false;
  if (field(r, "@rawstring") !== "" && (field(r, "#repo") !== "" || field(r, "#type") !== "")) return true;
  const keys = Object.keys(r);
  const vendor =
    (r["Vendor"] !== null && typeof r["Vendor"] === "object" && !Array.isArray(r["Vendor"])) ||
    keys.some((k) => k.startsWith("Vendor."));
  return vendor && keys.some(isMetaKey);
}

/** The sensor or wrapper signature on a lowercased CSV header set. */
export function crowdstrikeCsvSig(h: Set<string>): boolean {
  if ((h.has("#event_simplename") || h.has("event_simplename")) && (h.has("aid") || h.has("computername")))
    return true;
  if (h.has("@rawstring") && (h.has("#repo") || h.has("#type"))) return true;
  const keys = [...h];
  return keys.some((k) => k.startsWith("vendor.")) && keys.some(isMetaKey);
}

// ───────────────────────────── reading ─────────────────────────────

export function readCrowdstrikeRecords(text: string): { records: Row[]; format: string } {
  const t = text.replace(/^\uFEFF/, "").trim();
  if (t[0] === "{" && t.includes('"resources"')) {
    // The Falcon API envelope `{ meta, resources: [...], errors }` (alerts / detects, Part 2).
    try {
      const alerts = alertRecords(JSON.parse(t));
      if (alerts) return { records: alerts, format: "falcon-api" };
    } catch {
      /* not one JSON document — fall through to NDJSON */
    }
  }
  if (t[0] === "{" || t[0] === "[") return extractRecords(t);
  const { headers, rows } = parseCsv(t);
  if (!headers.length) return { records: [], format: "csv" };
  const names = headers.map((h) => h.trim());
  return {
    records: rows.map((cols) => Object.fromEntries(names.map((h, i) => [h, cols[i] ?? ""]))),
    format: "csv",
  };
}

// ───────────────────────────── parse ─────────────────────────────

export function parseCrowdstrikeExport(text: string, opts: CrowdstrikeImportOptions = {}): SiemParseResult {
  const { records, format } = readCrowdstrikeRecords(text);
  const sink = new Map<string, SiemIoc>();
  const hostTally = new Map<string, number>();
  const mapped: MappedEvent[] = [];
  const fields = createFieldTally();
  const skipped = createCodeTally();
  const noted = createCodeTally();

  for (const [i, rec] of records.entries()) {
    const recordIndex = opts.recordIndexes?.[i] ?? i;
    if (!rec || typeof rec !== "object") {
      skipped.add("not_an_object");
      continue;
    }
    if (isCrowdstrikeAlert(rec)) {
      for (const a of mapCrowdstrikeAlert(rec, recordIndex, sink)) {
        mapped.push(a);
        if (a.asset) hostTally.set(a.asset, (hostTally.get(a.asset) ?? 0) + 1);
      }
      fields.add("timestamp", "alert");
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
    events: stampSourceArtifactHash(events, opts.sourceText ?? text),
    iocs: [...sink.values()].slice(0, opts.maxIocs ?? 5000),
    total: records.length,
    kept: events.length,
    dropped: Math.max(0, records.length - represented),
    groups,
    format,
    hostname: [...hostTally.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] ?? "",
  };
}
