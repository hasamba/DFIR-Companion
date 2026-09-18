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
import { boundedAggKey } from "./aggKey.js";
import { createCanonicalEvent } from "./canonicalEvent.js";
import {
  MAX_CONTEXT_LEN,
  MAX_HOPS,
  MAX_RAW_OFFSET_PARSE_LEN,
  MAX_VALUE_LEN,
  RECOVERY_CITATIONS_MAX,
  type RecoveryCitation,
  type RecoveryPathHop,
} from "./canonicalRecoveredFragment.js";
import { addIoc, mergeRowIocs, type MappedEvent, type SiemEvent, type SiemIoc } from "./siemImport.js";
import { aggregateEvents } from "./eventAggregate.js";

export { MAX_VALUE_LEN, MAX_CONTEXT_LEN, RECOVERY_CITATIONS_MAX };
export const MAX_DISTINCT_VALUES = 2000;
export const MAX_ROWS_SCANNED = 500_000;
const HEADER_MAX_LINES = 200;
const HEADER_MAX_BYTES = 4096;
// Shared with bulkExtractorCarvedImport.ts (#1116) — same feature-file grammar, one source of truth.
// A sanity ceiling on the RAW offset field's own length, applied at scan time — rawOffset is
// otherwise kept unbounded/verbatim (canonicalRecoveredFragment.ts), so a pathological field
// (megabytes before the first tab) is rejected outright as malformed rather than silently
// truncated, which would corrupt rather than preserve the evidence.
export const MAX_RAW_OFFSET_STORAGE_LEN = 10_000;
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

/** Both anchors required inside the header block, and the version anchor must carry a real
 * value — a loose single-line signature risks misclaiming an unrelated 3-column TSV (same lesson
 * as KAPE's own Codex finding #9). */
export function isBulkExtractorUrlFeatureFile(text: string): boolean {
  const header = headerBlock(text);
  if (header === null) return false;
  const hasVersion = header.some((l) => /^#\s*BULK_EXTRACTOR-Version:\s*\S+/.test(l));
  const hasRecorder = header.some((l) => /^#\s*Feature-Recorder:\s*url\s*$/.test(l));
  return hasVersion && hasRecorder;
}

/** Every leading line starting with `#` (CRLF/BOM normalized first), bounded so a hostile huge
 * banner can't force an unbounded scan (Codex design review finding #6). The `split` limit bounds
 * the work `split` itself does, not just the loop over its result (Codex code review finding:
 * splitting the WHOLE text first still scanned it all). Returns null when the file has no header
 * at all (the first line isn't a comment) — not a match. */
export function headerBlock(text: string): string[] | null {
  const stripped = text.startsWith("﻿") ? text.slice(1) : text;
  if (!stripped.startsWith("#")) return null;
  const lines = stripped.split(/\r\n|\r|\n/, HEADER_MAX_LINES + 10);
  const header: string[] = [];
  let bytes = 0;
  for (const line of lines) {
    if (!line.startsWith("#")) break;
    header.push(line);
    bytes += line.length + 1;
    if (header.length >= HEADER_MAX_LINES || bytes >= HEADER_MAX_BYTES) break;
  }
  return header;
}

/** Parses one offset field. The raw string is always kept verbatim regardless of outcome — a
 * structured breakdown is a display convenience layered on top, never a replacement (Codex
 * design review finding #5: rejecting/rounding would corrupt real evidence offsets). Bounded
 * BEFORE splitting so a pathological offset field (thousands of hyphens) can't force an
 * oversized intermediate array (Codex code review finding). */
export function parseOffset(raw: string): { parsed: boolean; rootOffset?: number; path?: RecoveryPathHop[] } {
  if (raw.length > MAX_RAW_OFFSET_PARSE_LEN) return { parsed: false };
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

/** Plain truncation, never a digest splice — `boundedTextTo` is for discriminator keys/aggKeys,
 * and splicing a hex digest into evidence text (e.g. a URL) can read as a fabricated fragment
 * (Codex code review finding). */
export function clip(text: string, max: number): { text: string; truncated: boolean } {
  if (text.length <= max) return { text, truncated: false };
  return { text: text.slice(0, max), truncated: true };
}

interface Row {
  rawOffset: string;
  /** sha256 of the FULL (unclipped) recovered value — the grouping/dedup identity, so two
   * distinct long values that merely share a clipped prefix never collapse into one group even
   * though only the clipped text is retained for display (Codex code review finding). */
  valueKey: string;
  value: string;
  valueTruncated: boolean;
  context: string;
}

function scanRows(lines: readonly string[]): { rows: Row[]; malformedRows: number; truncatedScan: boolean } {
  const rows: Row[] = [];
  let malformedRows = 0;
  let scanned = 0;
  let truncatedScan = false;
  for (const line of lines) {
    // Every examined line counts toward the budget, including blank/comment ones — otherwise a
    // hostile file could pad past the cap with lines that are cheap to skip but still force the
    // loop to run unbounded (Codex code review finding).
    if (scanned >= MAX_ROWS_SCANNED) {
      truncatedScan = true;
      break;
    }
    scanned += 1;
    if (!line || line.startsWith("#")) continue;
    const fields = line.split("\t");
    const [rawOffset, rawValue, rawContext] = fields;
    if (fields.length !== 3 || !rawOffset || !rawValue) {
      malformedRows += 1;
      continue;
    }
    // rawOffset is otherwise kept unbounded/verbatim — a pathological field is rejected outright
    // rather than silently truncated, which would corrupt rather than preserve the evidence.
    if (rawOffset.length > MAX_RAW_OFFSET_STORAGE_LEN) {
      malformedRows += 1;
      continue;
    }
    const valueKey = createHash("sha256").update(rawValue).digest("hex");
    const { text: value, truncated: valueTruncated } = clip(rawValue, MAX_VALUE_LEN);
    const { text: context } = clip(rawContext ?? "", MAX_CONTEXT_LEN);
    rows.push({ rawOffset, valueKey, value, valueTruncated, context });
  }
  return { rows, malformedRows, truncatedScan };
}

function mapGroup(
  valueKey: string,
  value: string,
  valueTruncated: boolean,
  citationRows: readonly Row[],
  occurrences: number,
  reportFingerprint: string,
  sourceMedia: string | undefined,
  sink: Map<string, SiemIoc>,
): MappedEvent {
  // Distinct (rawOffset, context) pairs, first-seen order, capped — duplicates must not consume
  // citation capacity that belongs to genuinely different provenance (Codex code review finding).
  const seen = new Map<string, RecoveryCitation>();
  for (const r of citationRows) {
    const dedupKey = createHash("sha256").update(r.rawOffset).update("\n").update(r.context).digest("hex");
    if (seen.has(dedupKey)) continue;
    if (seen.size >= RECOVERY_CITATIONS_MAX) continue;
    const p = parseOffset(r.rawOffset);
    seen.set(
      dedupKey,
      p.parsed
        ? {
            rawOffset: r.rawOffset,
            parsed: true,
            rootOffset: p.rootOffset!,
            path: p.path!,
            context: r.context,
          }
        : { rawOffset: r.rawOffset, parsed: false, context: r.context },
    );
  }
  const citations = [...seen.values()];
  // notCited counts DISTINCT citations beyond the cap, not raw duplicate rows.
  const distinctTotal = new Set(
    citationRows.map((r) =>
      createHash("sha256").update(r.rawOffset).update("\n").update(r.context).digest("hex"),
    ),
  ).size;
  const notCited = Math.max(0, distinctTotal - citations.length);

  const first = citations[0];
  const hopSummary =
    first?.parsed && first.path.length > 0
      ? `via ${first.path.map((h) => h.method).join("→")} decode at offset ${first.rootOffset}`
      : first?.parsed
        ? `directly in the image at offset ${first.rootOffset}`
        : `at recorded offset ${first?.rawOffset ?? "unknown"}`;
  const truncNote = valueTruncated ? " [value truncated — recovered string exceeded the storage bound]" : "";
  // The report tag is a FIXED-LENGTH suffix, reserved and appended after clipping the rest, so it
  // always survives truncation — this is the identity that keeps two SEPARATE uploads recovering
  // the identical URL from reading as one exact-duplicate row once aggKey is stripped at
  // persistence (correlate.ts's exact-duplicate pass keys on timestamp + description + host;
  // Codex code review finding #1).
  const reportTag = `; report ${reportFingerprint.slice(0, 16)}`;
  const body = clip(
    `Recovered URL fragment (bulk_extractor): ${value}${truncNote} — found ${hopSummary}; ` +
      `${occurrences} occurrence(s) in this upload; a recovered fragment, not a visited-site record; ` +
      `[undated: bulk_extractor's feature file carries no event time]`,
    600 - reportTag.length,
  ).text;
  const description = `${body}${reportTag}`;

  const aggKey = boundedAggKey(`bulk-extractor-url|${reportFingerprint}|${valueKey}`);
  // A non-truncated value with a recognizable URL shape becomes a case indicator, authoritatively
  // linked to THIS event via mergeRowIocs (which UNIONS sourceAggKeys rather than overwriting —
  // two case-variant groups sharing one lowercased IOC key must not erase each other's linkage,
  // Codex code review finding). A truncated value is never promoted — a clipped string is not a
  // trustworthy correlation key.
  if (!valueTruncated && URL_SHAPE_RE.test(value)) {
    const rowSink = new Map<string, SiemIoc>();
    addIoc(rowSink, "url", value);
    mergeRowIocs(sink, rowSink, aggKey);
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
        value,
        valueTruncated,
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

  const header = headerBlock(text) ?? [];
  // Read strictly from the validated leading header block — never from a later line, which could
  // otherwise let a data row smuggle a fabricated `# Filename:` value (Codex code review finding).
  const filenameLine = header.find((l) => /^#\s*Filename:/.test(l));
  const sourceMedia = filenameLine
    ? filenameLine.replace(/^#\s*Filename:\s*/, "").trim() || undefined
    : undefined;
  const reportFingerprint = createHash("sha256").update(text).digest("hex");

  const lines = text.split(/\r\n|\r|\n/);
  const { rows, malformedRows, truncatedScan } = scanRows(lines);

  const byValueKey = new Map<string, { value: string; valueTruncated: boolean; rows: Row[] }>();
  const overflowedValueKeys = new Set<string>();
  let notCitedValues = 0;
  for (const row of rows) {
    let group = byValueKey.get(row.valueKey);
    if (!group) {
      if (byValueKey.size >= MAX_DISTINCT_VALUES) {
        if (!overflowedValueKeys.has(row.valueKey)) {
          overflowedValueKeys.add(row.valueKey);
          notCitedValues += 1;
        }
        continue;
      }
      group = { value: row.value, valueTruncated: row.valueTruncated, rows: [] };
      byValueKey.set(row.valueKey, group);
    }
    group.rows.push(row);
  }

  const sink = new Map<string, SiemIoc>();
  const mapped: MappedEvent[] = [];
  for (const [valueKey, group] of byValueKey) {
    mapped.push(
      mapGroup(
        valueKey,
        group.value,
        group.valueTruncated,
        group.rows,
        group.rows.length,
        reportFingerprint,
        sourceMedia,
        sink,
      ),
    );
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
    dropped: malformedRows,
    groups,
    format: "BulkExtractorUrlFeatureFile",
    malformedRows,
    notCitedValues,
    truncatedScan,
  };
}
