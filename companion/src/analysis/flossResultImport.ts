// FLOSS (FLARE Obfuscated String Solver) `-j`/`--json` results document (#932 item 5, "932.6"):
// strings the tool recovered from a malware sample via decoding-routine analysis (`decoded`) or
// runtime stack-construction analysis (`stack`/`tight`). Never a claim of network contact,
// capability use, or a verified configuration — see RECOMMENDATION-5.md for the guardrails this
// enforces and why `static_strings`/"interpreted configuration" are deliberately out of scope.
//
// Schema verified live against FLOSS's own `results.py` dataclasses (mandiant/flare-floss on
// GitHub) and a real populated sample, not invented.

import { createHash } from "node:crypto";
import { boundedAggKey, boundedTextTo } from "./aggKey.js";
import { createCanonicalEvent } from "./canonicalEvent.js";
import {
  DECODED_STRING_BASIS,
  MAX_PRODUCER_VERSION_LEN,
  MAX_VALUE_LEN,
  RECOVERY_CITATIONS_MAX,
  type DecodedCitation,
  type SampleHash,
  type StackCitation,
} from "./canonicalDecodedString.js";
import { extractIocsFromText } from "./deobfuscate.js";
import {
  addIoc,
  isObject,
  mergeRowIocs,
  type MappedEvent,
  type SiemEvent,
  type SiemIoc,
} from "./siemImport.js";
import { aggregateEvents } from "./eventAggregate.js";

export { MAX_VALUE_LEN, RECOVERY_CITATIONS_MAX };
export const MAX_DISTINCT_VALUES = 2000; // per category
export const MAX_ENTRIES_SCANNED = 100_000; // total across all in-scope categories

const HASH_RE = { md5: /^[a-f0-9]{32}$/i, sha1: /^[a-f0-9]{40}$/i, sha256: /^[a-f0-9]{64}$/i };
const KINDS = ["decoded", "stack", "tight"] as const;
type Kind = (typeof KINDS)[number];

export interface FlossResultOptions {
  aggregate?: boolean;
  maxEvents?: number;
}

export interface FlossResultResult {
  events: SiemEvent[];
  iocs: SiemIoc[];
  total: number;
  kept: number;
  dropped: number;
  groups: number;
  format: string;
  malformedEntries: number;
  notCitedValues: number;
  entriesTruncated: boolean;
  staticStringsSeen: number;
}

/** Both anchors required: a `metadata` object with a real version/file_path, AND a `strings`
 * object with at least one recognized collection array (present-but-empty is a valid, real FLOSS
 * shape). A `metadata` with no `strings` sibling at all is not accepted — real FLOSS documents
 * always carry both. */
export function isFlossResult(root: unknown): boolean {
  if (!isObject(root)) return false;
  const metadata = root.metadata;
  const strings = root.strings;
  if (!isObject(metadata) || !isObject(strings)) return false;
  if (typeof metadata.version !== "string" || metadata.version.trim().length === 0) return false;
  if (typeof metadata.file_path !== "string") return false;
  return KINDS.map((k) => `${k}_strings`)
    .concat("static_strings")
    .some((key) => Array.isArray((strings as Record<string, unknown>)[key]));
}

// Matches the canonical schema's own constraint for address/pointer fields exactly — a value
// that fails this (fractional, negative, or outside Number.isSafeInteger) would otherwise reach
// createCanonicalEvent's own .parse() and throw, aborting the whole import (Codex code review
// finding). Rejected here means the ENTRY is treated as malformed, never a crash.
function nonNegSafeInt(v: unknown): number | undefined {
  return typeof v === "number" && Number.isInteger(v) && Number.isSafeInteger(v) && v >= 0 ? v : undefined;
}

// offset/frame_offset are FLOSS's own signed fields (a negative stack offset is normal).
function signedSafeInt(v: unknown): number | undefined {
  return typeof v === "number" && Number.isInteger(v) && Number.isSafeInteger(v) ? v : undefined;
}

function str(v: unknown): string | undefined {
  return typeof v === "string" ? v : undefined;
}

interface Row {
  kind: Kind;
  value: string;
  valueKey: string; // sha256 of the FULL (unclipped) value — grouping identity
  citationKey: string; // sha256 of this occurrence's own context fields — dedup identity
  citation: DecodedCitation | StackCitation;
}

function parseSampleHash(metadata: Record<string, unknown>): SampleHash {
  const md5 = str(metadata.md5);
  const sha1 = str(metadata.sha1);
  const sha256 = str(metadata.sha256);
  const out: SampleHash = { hashUnavailable: false };
  if (md5 && HASH_RE.md5.test(md5)) out.md5 = md5.toLowerCase();
  if (sha1 && HASH_RE.sha1.test(sha1)) out.sha1 = sha1.toLowerCase();
  if (sha256 && HASH_RE.sha256.test(sha256)) out.sha256 = sha256.toLowerCase();
  out.hashUnavailable = !out.md5 && !out.sha1 && !out.sha256;
  return out;
}

function scanCategory(
  kind: Kind,
  entries: unknown[],
  scannedSoFar: number,
): { rows: Row[]; malformed: number; scanned: number; truncated: boolean } {
  const rows: Row[] = [];
  let malformed = 0;
  let scanned = scannedSoFar;
  for (const raw of entries) {
    // Only true when an entry existed but was never examined — reaching the cap exactly, with
    // nothing left over, must not read as truncated (Codex code review finding).
    if (scanned >= MAX_ENTRIES_SCANNED) return { rows, malformed, scanned, truncated: true };
    scanned += 1;
    if (!isObject(raw)) {
      malformed += 1;
      continue;
    }
    const value = str(raw.string);
    if (!value) {
      malformed += 1;
      continue;
    }
    const valueKey = createHash("sha256").update(value).digest("hex");
    let citation: DecodedCitation | StackCitation | undefined;
    if (kind === "decoded") {
      const address = nonNegSafeInt(raw.address);
      const decodedAt = nonNegSafeInt(raw.decoded_at);
      const decodingRoutine = nonNegSafeInt(raw.decoding_routine);
      if (address !== undefined && decodedAt !== undefined && decodingRoutine !== undefined) {
        citation = {
          address,
          addressType: str(raw.address_type) ?? "unknown",
          encoding: str(raw.encoding) ?? "unknown",
          decodedAt,
          decodingRoutine,
        };
      }
    } else {
      const functionAddress = nonNegSafeInt(raw.function);
      const programCounter = nonNegSafeInt(raw.program_counter);
      const stackPointer = nonNegSafeInt(raw.stack_pointer);
      const originalStackPointer = nonNegSafeInt(raw.original_stack_pointer);
      const offset = signedSafeInt(raw.offset);
      const frameOffset = signedSafeInt(raw.frame_offset);
      if (
        functionAddress !== undefined &&
        programCounter !== undefined &&
        stackPointer !== undefined &&
        originalStackPointer !== undefined &&
        offset !== undefined &&
        frameOffset !== undefined
      ) {
        citation = {
          functionAddress,
          encoding: str(raw.encoding) ?? "unknown",
          programCounter,
          stackPointer,
          originalStackPointer,
          offset,
          frameOffset,
        };
      }
    }
    if (!citation) {
      malformed += 1;
      continue;
    }
    const citationKey = createHash("sha256").update(JSON.stringify(citation)).digest("hex");
    rows.push({ kind, value, valueKey, citationKey, citation });
  }
  return { rows, malformed, scanned, truncated: false };
}

function mapGroup(
  kind: Kind,
  valueKey: string,
  rows: readonly Row[],
  reportFingerprint: string,
  sampleHash: SampleHash,
  producerVersion: string,
  sink: Map<string, SiemIoc>,
): MappedEvent {
  const seen = new Map<string, DecodedCitation | StackCitation>();
  for (const r of rows) {
    if (seen.has(r.citationKey)) continue;
    if (seen.size >= RECOVERY_CITATIONS_MAX) continue;
    seen.set(r.citationKey, r.citation);
  }
  const citations = [...seen.values()];
  const distinctTotal = new Set(rows.map((r) => r.citationKey)).size;
  const notCited = Math.max(0, distinctTotal - citations.length);

  const rawValue = rows[0].value;
  const { text: value, truncated: valueTruncated } = clip(rawValue, MAX_VALUE_LEN);
  const occurrences = rows.length;
  const producerVersionClipped = clip(producerVersion, MAX_PRODUCER_VERSION_LEN).text;
  // The schema unifies stack/tight under ONE mapping version (identical citation shape) — the
  // producer metadata must record the SAME string, never a per-kind template that disagrees with
  // the canonical block's own literal (Codex code review finding).
  const mappingVersion: "floss-decoded-v1" | "floss-stack-v1" =
    kind === "decoded" ? "floss-decoded-v1" : "floss-stack-v1";

  const reportTag = `; report ${reportFingerprint.slice(0, 16)}`;
  const kindLabel = kind === "decoded" ? "decoded string" : `${kind} string`;
  const body = boundedTextTo(
    `Recovered ${kindLabel} (FLOSS): ${value}${valueTruncated ? " [value truncated]" : ""} — ` +
      `${occurrences} occurrence(s) in this upload; a recovered string, not proof of network ` +
      `contact or capability use; [undated: FLOSS's results document carries no event time]`,
    600 - reportTag.length,
  );
  const description = `${body}${reportTag}`;

  const aggKey = boundedAggKey(`floss|${reportFingerprint}|${kind}|${valueKey}`);

  if (!valueTruncated) {
    const rowSink = new Map<string, SiemIoc>();
    for (const raw of extractIocsFromText(value)) addIoc(rowSink, raw.type, raw.value);
    mergeRowIocs(sink, rowSink, aggKey);
  }
  const hashSink = new Map<string, SiemIoc>();
  for (const h of [sampleHash.sha256, sampleHash.sha1, sampleHash.md5]) if (h) addIoc(hashSink, "hash", h);
  mergeRowIocs(sink, hashSink, aggKey);

  const basis = DECODED_STRING_BASIS;

  const recoveredFragmentLike =
    kind === "decoded"
      ? {
          tool: "floss" as const,
          kind: "decoded" as const,
          value,
          valueTruncated,
          sampleHash,
          reportFingerprint,
          producerVersion: producerVersionClipped,
          mappingVersion: "floss-decoded-v1" as const,
          citations: citations as DecodedCitation[],
          notCited,
          occurrences,
          basis,
        }
      : {
          tool: "floss" as const,
          kind,
          value,
          valueTruncated,
          sampleHash,
          reportFingerprint,
          producerVersion: producerVersionClipped,
          mappingVersion: "floss-stack-v1" as const,
          citations: citations as StackCitation[],
          notCited,
          occurrences,
          basis,
        };

  return {
    timestamp: "",
    description,
    severity: "Info",
    mitre: [],
    aggKey,
    sources: ["FLOSS"],
    canonical: createCanonicalEvent({
      event: { category: "file", type: "decoded-string", action: "recovered" },
      time: { observed: "", normalized: "" },
      evidence: { rawRecords: [{ source: "floss-result", locator: `value:${valueKey}` }] },
      producer: { importer: "floss-result", parserVersion: "1", mappingVersion },
      decodedString: recoveredFragmentLike,
    }),
  };
}

function clip(text: string, max: number): { text: string; truncated: boolean } {
  if (text.length <= max) return { text, truncated: false };
  return { text: text.slice(0, max), truncated: true };
}

export function parseFlossResult(text: string, opts: FlossResultOptions = {}): FlossResultResult | null {
  let root: unknown;
  try {
    root = JSON.parse(text);
  } catch {
    return null;
  }
  if (!isFlossResult(root)) return null;
  const r = root as Record<string, unknown>;
  const metadata = r.metadata as Record<string, unknown>;
  const strings = r.strings as Record<string, unknown>;
  const producerVersion = String(metadata.version);
  const sampleHash = parseSampleHash(metadata);
  const reportFingerprint = createHash("sha256").update(text).digest("hex");

  let scanned = 0;
  let malformedEntries = 0;
  let entriesTruncated = false;
  const rowsByKind: Record<Kind, Row[]> = { decoded: [], stack: [], tight: [] };
  for (const kind of KINDS) {
    const entries = strings[`${kind}_strings`];
    if (!Array.isArray(entries)) continue;
    const result = scanCategory(kind, entries, scanned);
    rowsByKind[kind] = result.rows;
    malformedEntries += result.malformed;
    scanned = result.scanned;
    if (result.truncated) entriesTruncated = true;
  }
  const staticArr = strings.static_strings;
  const staticStringsSeen = Array.isArray(staticArr) ? staticArr.length : 0;

  const sink = new Map<string, SiemIoc>();
  const mapped: MappedEvent[] = [];
  let notCitedValues = 0;
  let total = malformedEntries;
  for (const kind of KINDS) {
    const byValueKey = new Map<string, Row[]>();
    // Per-category, so a value that overflows the cap is counted exactly once no matter how many
    // further rows share it (Codex code review finding — the prior version incremented once per
    // OVERFLOW ROW, not once per distinct omitted value).
    const overflowedValueKeys = new Set<string>();
    for (const row of rowsByKind[kind]) {
      total += 1;
      let group = byValueKey.get(row.valueKey);
      if (!group) {
        if (byValueKey.size >= MAX_DISTINCT_VALUES) {
          if (!overflowedValueKeys.has(row.valueKey)) {
            overflowedValueKeys.add(row.valueKey);
            notCitedValues += 1;
          }
          continue;
        }
        group = [];
        byValueKey.set(row.valueKey, group);
      }
      group.push(row);
    }
    for (const [valueKey, rows] of byValueKey) {
      mapped.push(mapGroup(kind, valueKey, rows, reportFingerprint, sampleHash, producerVersion, sink));
    }
  }

  const { events, groups } = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: "Info",
    maxEvents: opts.maxEvents ?? MAX_DISTINCT_VALUES * 3,
  });

  return {
    events,
    iocs: [...sink.values()],
    total,
    kept: events.length,
    dropped: malformedEntries,
    groups,
    format: "FlossResultDocument",
    malformedEntries,
    notCitedValues,
    entriesTruncated,
    staticStringsSeen,
  };
}
