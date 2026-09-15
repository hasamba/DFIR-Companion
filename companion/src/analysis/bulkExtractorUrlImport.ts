// bulk_extractor's own url.txt feature file (#932 item 4): a URL string it found in the image's
// raw or decoded byte stream, with the byte offset (or decode path) it was found at and the
// tool's own ~16-byte context window. This is the FRAGMENT half of 932.4 only — a recovered
// string, never a claim that a file was reconstructed, that a site was visited, or that anything
// executed. The intact-file half (a complete carved object, needing a real completeness signal
// this format doesn't provide) is deliberately out of scope; see RECOMMENDATION-4.md for why.
//
// Format verified live against a real `bulk_extractor 2.0.0` url.txt (fetched via
// `frankwxu/digital-forensics-lab` on GitHub), not invented: a `#`-prefixed header block (NOT a
// fixed line count — `-b` prepends an arbitrary banner file), then tab-separated
// offset / feature / context rows.

import { createHash } from "node:crypto";
import { boundedAggKey, boundedTextTo } from "./aggKey.js";
import { createCanonicalEvent } from "./canonicalEvent.js";
import type { RecoveryCitation, RecoveryPathHop } from "./canonicalRecoveredFragment.js";
import { addIoc, type MappedEvent, type SiemEvent, type SiemIoc } from "./siemImport.js";
import { aggregateEvents } from "./eventAggregate.js";

export const MAX_VALUE_LEN = 2000;
export const MAX_CONTEXT_LEN = 600;
export const RECOVERY_CITATIONS_MAX = 64;
export const MAX_DISTINCT_VALUES = 2000;
export const MAX_ROWS_SCANNED = 500_000;
const MAX_HOPS = 8;
const URL_SHAPE_RE = /^[a-z][a-z0-9+.-]*:\/\//i;

export interface BulkExtractorUrlOptions {
  aggregate?: boolean;
  maxEvents?: number;
}

export interface BulkExtractorUrlResult {
  events: SiemEvent[];
  iocs: SiemIoc[];
  total: number;
  kept: number;
  dropped: number;
  groups: number;
  format: string;
  malformedRows: number;
  notCitedValues: number;
  truncatedScan: boolean;
}

/** Both anchors required inside the header block — a loose single-line signature risks
 * misclaiming an unrelated 3-column TSV (same lesson as KAPE's own Codex finding #9). */
export function isBulkExtractorUrlFeatureFile(text: string): boolean {
  const header = headerBlock(text);
  if (header === null) return false;
  const hasVersion = header.some((l) => /^#\s*BULK_EXTRACTOR-Version:/.test(l));
  const hasRecorder = header.some((l) => /^#\s*Feature-Recorder:\s*url\s*$/.test(l));
  return hasVersion && hasRecorder;
}

/** Every leading line starting with `#` (CRLF/BOM normalized first), bounded so a hostile huge
 * banner can't force an unbounded scan (Codex design review finding #6). Returns null when the
 * file has no header at all (the first line isn't a comment) — not a match. */
function headerBlock(text: string): string[] | null {
  const stripped = text.startsWith("﻿") ? text.slice(1) : text;
  const lines = stripped.split(/\r\n|\r|\n/);
  if (!lines[0]?.startsWith("#")) return null;
  const header: string[] = [];
  let bytes = 0;
  for (const line of lines) {
    if (!line.startsWith("#")) break;
    header.push(line);
    bytes += line.length + 1;
    if (header.length >= 200 || bytes >= 4096) break;
  }
  return header;
}

/** Parses one offset field. The raw string is always kept verbatim regardless of outcome — a
 * structured breakdown is a display convenience layered on top, never a replacement (Codex
 * design review finding #5: rejecting/rounding would corrupt real evidence offsets). */
function parseOffset(raw: string): { parsed: boolean; rootOffset?: number; path?: RecoveryPathHop[] } {
  const tokens = raw.split("-");
  const root = tokens[0];
  if (!root || !/^\d+$/.test(root) || !Number.isSafeInteger(Number(root))) return { parsed: false };
  const rest = tokens.slice(1);
  if (rest.length % 2 !== 0) return { parsed: false };
  const hopCount = rest.length / 2;
  if (hopCount > MAX_HOPS) return { parsed: false };
  const path: RecoveryPathHop[] = [];
  for (let i = 0; i < rest.length; i += 2) {
    const method = rest[i];
    const offsetTok = rest[i + 1];
    if (!method || !/^[A-Za-z0-9]+$/.test(method)) return { parsed: false };
    if (!offsetTok || !/^\d+$/.test(offsetTok) || !Number.isSafeInteger(Number(offsetTok)))
      return { parsed: false };
    path.push({ method, offset: Number(offsetTok) });
  }
  return { parsed: true, rootOffset: Number(root), path };
}

interface Row {
  rawOffset: string;
  value: string;
  context: string;
}

function scanRows(lines: readonly string[]): { rows: Row[]; malformedRows: number; truncatedScan: boolean } {
  const rows: Row[] = [];
  let malformedRows = 0;
  let scanned = 0;
  let truncatedScan = false;
  for (const line of lines) {
    if (!line || line.startsWith("#")) continue;
    if (scanned >= MAX_ROWS_SCANNED) {
      truncatedScan = true;
      break;
    }
    scanned += 1;
    const fields = line.split("\t");
    const [rawOffset, value, context] = fields;
    if (fields.length !== 3 || !rawOffset || !value) {
      malformedRows += 1;
      continue;
    }
    rows.push({ rawOffset, value, context: context ?? "" });
  }
  return { rows, malformedRows, truncatedScan };
}

function mapGroup(
  value: string,
  citationRows: readonly Row[],
  occurrences: number,
  reportFingerprint: string,
  sourceMedia: string | undefined,
  sink: Map<string, SiemIoc>,
): MappedEvent {
  const citations: RecoveryCitation[] = citationRows.slice(0, RECOVERY_CITATIONS_MAX).map((r) => {
    const p = parseOffset(r.rawOffset);
    return {
      rawOffset: r.rawOffset,
      parsed: p.parsed,
      ...(p.parsed ? { rootOffset: p.rootOffset, path: p.path } : {}),
      context: boundedTextTo(r.context, MAX_CONTEXT_LEN),
    };
  });
  const notCited = Math.max(0, citationRows.length - citations.length);
  const first = citations[0];
  const hopSummary =
    first?.parsed && first.path && first.path.length > 0
      ? `via ${first.path.map((h) => h.method).join("→")} decode at offset ${first.rootOffset}`
      : first?.parsed
        ? `directly in the image at offset ${first.rootOffset}`
        : `at recorded offset ${first?.rawOffset ?? "unknown"}`;
  const clippedValue = boundedTextTo(value, 300);
  const description = boundedTextTo(
    `Recovered URL fragment (bulk_extractor): ${clippedValue} — found ${hopSummary}; ` +
      `${occurrences} occurrence(s) in this upload; a recovered fragment, not a visited-site record`,
    600,
  );
  const aggKey = boundedAggKey(
    `bulk-extractor-url|${reportFingerprint}|${createHash("sha256").update(value).digest("hex")}`,
  );
  // A value with a recognizable URL shape becomes a case indicator, authoritatively linked to
  // THIS event via sourceAggKeys so resolveExtractedFrom (the ingest wrapper) can stamp
  // extractedFrom — a damaged/garbage recovered string still gets its fragment event, just never
  // promoted into a typed indicator (Codex design review finding #9).
  if (URL_SHAPE_RE.test(value)) {
    addIoc(sink, "url", boundedTextTo(value, MAX_VALUE_LEN));
    const key = `url:${value.trim().toLowerCase()}`;
    const ioc = sink.get(key);
    if (ioc) sink.set(key, { ...ioc, sourceAggKeys: [aggKey] });
  }

  return {
    timestamp: "",
    description,
    severity: "Info",
    mitre: [],
    aggKey,
    sources: ["bulk_extractor"],
    canonical: createCanonicalEvent({
      event: { category: "file", type: "recovered-fragment", action: "recovered" },
      time: { observed: "", normalized: "" },
      evidence: { rawRecords: [{ source: "bulk-extractor-url", locator: `value:${reportFingerprint}` }] },
      producer: {
        importer: "bulk-extractor-url",
        parserVersion: "1",
        mappingVersion: "bulk-extractor-url-v1",
      },
      recoveredFragment: {
        tool: "bulk_extractor",
        kind: "url",
        value: boundedTextTo(value, MAX_VALUE_LEN),
        artifactClass: "string-fragment",
        completeness:
          "not applicable — a recovered string fragment, not a reconstructed file; no completeness state exists for it",
        structuralValidation:
          "not reported — bulk_extractor's url scanner does not validate the recovered string's container structure",
        ...(sourceMedia ? { sourceMedia } : {}),
        reportFingerprint,
        citations,
        notCited,
        occurrences,
        basis:
          "a string bulk_extractor's scanner found in the image's raw or decoded byte stream; not a " +
          "browser-history entry, not proof of a completed transfer, and not evidence anyone acted on " +
          "it — corroborate independently before treating it as an event",
      },
    }),
  };
}

export function parseBulkExtractorUrl(
  text: string,
  opts: BulkExtractorUrlOptions = {},
): BulkExtractorUrlResult | null {
  if (!isBulkExtractorUrlFeatureFile(text)) return null;

  const lines = text.split(/\r\n|\r|\n/);
  const filenameLine = lines.find((l) => /^#\s*Filename:/.test(l));
  const sourceMedia = filenameLine
    ? filenameLine.replace(/^#\s*Filename:\s*/, "").trim() || undefined
    : undefined;
  const reportFingerprint = createHash("sha256").update(text).digest("hex");

  const { rows, malformedRows, truncatedScan } = scanRows(lines);

  const byValue = new Map<string, Row[]>();
  let notCitedValues = 0;
  for (const row of rows) {
    let group = byValue.get(row.value);
    if (!group) {
      if (byValue.size >= MAX_DISTINCT_VALUES) {
        notCitedValues += 1;
        continue;
      }
      group = [];
      byValue.set(row.value, group);
    }
    group.push(row);
  }

  const sink = new Map<string, SiemIoc>();
  const mapped: MappedEvent[] = [];
  for (const [value, groupRows] of byValue) {
    mapped.push(mapGroup(value, groupRows, groupRows.length, reportFingerprint, sourceMedia, sink));
  }

  const { events, groups } = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: "Info",
    maxEvents: opts.maxEvents ?? MAX_DISTINCT_VALUES,
  });

  return {
    events,
    iocs: [...sink.values()],
    total: rows.length + malformedRows,
    kept: events.length,
    dropped: 0,
    groups,
    format: "BulkExtractorUrlFeatureFile",
    malformedRows,
    notCitedValues,
    truncatedScan,
  };
}
