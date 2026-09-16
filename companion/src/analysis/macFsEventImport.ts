// FSEventsParser's (dlcowen/G-C Partners) real `All_FSEVENTS.tsv` report — the reduced 9-column
// R_COLUMNS set its own print_columns() writes, tab-joined (#933 item 9, "933.9"). Schema verified
// live against FSEParser_V4.1.py's Output.R_COLUMNS/print_columns()/append_row() split: the full
// attribute list (Output.COLUMNS, including id_hex/filename/mask/dls_version/record_end_offset)
// only reaches the tool's own SQLite DB, never this TSV. See RECOMMENDATION-11.md for the full
// research trail, including the design-review rejection that caught this exact mismatch.

import { createHash } from "node:crypto";
import { boundedAggKey } from "./aggKey.js";
import { parseCsvRecords } from "./csvImport.js";
import { createCanonicalEvent } from "./canonicalEvent.js";
import { MAC_FSEVENT_BASIS, MAX_FIELD_LEN, MAX_FLAGS, MAX_RECORD_TYPES } from "./canonicalMacFsEvent.js";
import type { MappedEvent, SiemEvent } from "./siemImport.js";
import { aggregateEvents } from "./eventAggregate.js";

export const MAX_FSEVENT_ROWS_SCANNED = 20_000; // report-wide

const HEADER = [
  "id",
  "node_id",
  "fs_uid",
  "fullpath",
  "type",
  "flags",
  "approx_dates_plus_minus_one_day",
  "source",
  "source_modified_time",
];

export interface MacFsEventOptions {
  aggregate?: boolean;
  maxEvents?: number;
}

export interface MacFsEventResult {
  events: SiemEvent[];
  iocs: [];
  total: number;
  kept: number;
  dropped: number;
  groups: number;
  format: string;
  malformedRows: number;
  rowsTruncated: boolean;
}

function clip(text: string, max: number): string {
  return text.length <= max ? text : text.slice(0, max);
}

function isValidHeader(header: string[]): boolean {
  if (header.length !== HEADER.length) return false;
  return header.every((h, i) => h.trim().toLowerCase() === HEADER[i]);
}

// FSEventsParser's own dotted date form ("2024.03.15" or "2024.03.15 - 2024.03.17") normalized to
// dashes so downstream sort/filter treats it as an ordinary date string; the untouched original is
// kept separately as approxDateRaw. "Unknown" (the parser's own literal for "nothing bracketed at
// all") normalizes to two empty strings, never a fabricated date.
function parseApproxDate(raw: string): { start: string; end: string } {
  const trimmed = raw.trim();
  if (!trimmed || trimmed.toLowerCase() === "unknown") return { start: "", end: "" };
  const parts = trimmed.split(" - ").map((p) => p.trim().replace(/\./g, "-"));
  const start = parts[0] ?? "";
  const end = parts[1] ?? start;
  return { start, end };
}

function mapRow(header: string[], row: string[], reportFingerprint: string): MappedEvent | null {
  const recordIdRaw = (row[0] ?? "").trim();
  if (!/^\d+$/.test(recordIdRaw)) return null; // real uint64 wd — digits-only, never Number()
  const nodeIdRaw = (row[1] ?? "").trim();
  const fsUidRaw = (row[2] ?? "").trim();
  const fullPath = clip((row[3] ?? "").trim(), MAX_FIELD_LEN);
  const typeRaw = (row[4] ?? "").trim();
  const flagsRaw = (row[5] ?? "").trim();
  const approxDateRaw = (row[6] ?? "").trim();
  const sourceLocation = clip((row[7] ?? "").trim(), MAX_FIELD_LEN);
  const sourceModifiedTime = (row[8] ?? "").trim();

  // Coalescing preserved verbatim — never reduced to one value or rejected for an "impossible"
  // combination (the design's own corrected lesson: FSEventsParser's check_record() gate applies
  // only to carved gzip input, which this exported TSV can't distinguish after the fact).
  const recordTypes = typeRaw
    .split(";")
    .map((s) => s.trim())
    .filter(Boolean)
    .slice(0, MAX_RECORD_TYPES);
  const flags = flagsRaw
    .split(";")
    .map((s) => s.trim())
    .filter(Boolean)
    .slice(0, MAX_FLAGS);
  const { start: approxDateStart, end: approxDateEnd } = parseApproxDate(approxDateRaw);

  const findingId = createHash("sha256")
    .update(JSON.stringify([sourceLocation, recordIdRaw, fullPath, typeRaw, flagsRaw, approxDateRaw]))
    .digest("hex");
  const aggKey = boundedAggKey(`mac-fsevent|${reportFingerprint}|${findingId}`);

  const reportTag = `; report ${reportFingerprint.slice(0, 16)}`;
  const pathLabel = fullPath || "(path not recorded)";
  const dateLabel = approxDateStart
    ? approxDateStart === approxDateEnd
      ? approxDateStart
      : `${approxDateStart} to ${approxDateEnd}`
    : "unknown date";
  const body = clip(
    `fsevents record: ${pathLabel} — ${recordTypes.join("/") || "unknown type"} ` +
      `(${flags.join(";") || "no flags"}) around ${dateLabel}; source ${sourceLocation || "(unknown)"}; ` +
      `a structural fact, never a complete audit trail or an exact event time`,
    600 - reportTag.length,
  );
  const description = `${body}${reportTag}`;

  return {
    timestamp: approxDateStart,
    description,
    severity: "Info",
    mitre: [],
    aggKey,
    sources: ["fseventsparser"],
    canonical: createCanonicalEvent({
      event: { category: "file", type: "mac-fsevent", action: "reported" },
      time: {
        observed: approxDateStart,
        normalized: approxDateStart,
        precision: "date",
        clockConfidence: approxDateStart ? "inferred" : "unknown",
      },
      evidence: { rawRecords: [{ source: "fseventsparser", locator: `record:${findingId.slice(0, 16)}` }] },
      producer: { importer: "mac-fsevent", parserVersion: "1", mappingVersion: "mac-fsevent-v1" },
      macFsEvent: {
        tool: "fseventsparser",
        recordId: recordIdRaw,
        fullPath,
        recordTypes,
        flags,
        approxDateRaw,
        approxDateStart,
        approxDateEnd,
        ...(nodeIdRaw ? { nodeId: clip(nodeIdRaw, MAX_FIELD_LEN) } : {}),
        ...(fsUidRaw ? { fsUid: clip(fsUidRaw, MAX_FIELD_LEN) } : {}),
        sourceLocation,
        sourceModifiedTime,
        reportFingerprint,
        mappingVersion: "mac-fsevent-v1",
        basis: MAC_FSEVENT_BASIS,
      },
    }),
  };
}

export function parseMacFsEventTsv(text: string, opts: MacFsEventOptions = {}): MacFsEventResult | null {
  const it = parseCsvRecords(text, "\t");
  const first = it.next();
  if (first.done) return null;
  const header = first.value;
  if (!isValidHeader(header)) return null;

  const reportFingerprint = createHash("sha256").update(text).digest("hex");

  const mapped: MappedEvent[] = [];
  let total = 0;
  let malformedRows = 0;
  let rowsTruncated = false;
  let scanned = 0;

  for (const row of it) {
    // Report-wide bound checked INSIDE this loop, per the standing item-7 lesson applied from the
    // start.
    if (scanned >= MAX_FSEVENT_ROWS_SCANNED) {
      rowsTruncated = true;
      break;
    }
    scanned += 1;
    total += 1;
    if (row.length !== header.length) {
      malformedRows += 1;
      continue;
    }
    const event = mapRow(header, row, reportFingerprint);
    if (!event) {
      malformedRows += 1;
      continue;
    }
    mapped.push(event);
  }

  const { events, groups } = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: "Info",
    maxEvents: opts.maxEvents ?? MAX_FSEVENT_ROWS_SCANNED,
  });

  return {
    events,
    iocs: [],
    total,
    kept: events.length,
    dropped: malformedRows,
    groups,
    format: "FSEventsParserTsv",
    malformedRows,
    rowsTruncated,
  };
}
