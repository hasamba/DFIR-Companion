// FLOSS (FLARE Obfuscated String Solver) `-j`/`--json` results document (#932 item 5, "932.6",
// language-string half #1120): strings the tool recovered from a malware sample via
// decoding-routine analysis (`decoded`), runtime stack-construction analysis (`stack`/`tight`), or
// an identified language runtime's own string table (`language`, from `language_strings`/
// `language_strings_missed`). `static_strings` gets IOC-corroboration only, never its own event —
// see RECOMMENDATION-1120.md for why. Never a claim of network contact, capability use, or a
// verified configuration — see RECOMMENDATION-5.md/RECOMMENDATION-1120.md for the guardrails this
// enforces and why "interpreted configuration" stays deliberately out of scope.
//
// Schema verified live against FLOSS's own `results.py` dataclasses (mandiant/flare-floss on
// GitHub) and a real populated sample, not invented.

import { createHash } from "node:crypto";
import { boundedAggKey, boundedTextTo } from "./aggKey.js";
import { createCanonicalEvent } from "./canonicalEvent.js";
import {
  DECODED_STRING_BASIS,
  LANGUAGE_STRING_BASIS,
  MAX_PRODUCER_VERSION_LEN,
  MAX_VALUE_LEN,
  RECOVERY_CITATIONS_MAX,
  type DecodedCitation,
  type LanguageCitation,
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
export const MAX_ENTRIES_SCANNED = 100_000; // total across all in-scope categories, static last

const HASH_RE = { md5: /^[a-f0-9]{32}$/i, sha1: /^[a-f0-9]{40}$/i, sha256: /^[a-f0-9]{64}$/i };
const KINDS = ["decoded", "stack", "tight", "language"] as const;
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
  /** Entries from static_strings actually visited by the bounded IOC-only scan — may be less than
   * staticStringsSeen when the shared MAX_ENTRIES_SCANNED budget was exhausted before reaching the
   * end of the array, whether by higher-priority kinds first (static is always scanned last) or by
   * static_strings itself being large enough to exhaust the remainder. "Visited," not "yielded an
   * IOC." */
  staticStringsIocScanned: number;
  /** Raw IOC mentions found within static_strings values (pre-dedup, across all visited entries),
   * never promoted to an event — see RECOMMENDATION-1120.md. */
  staticStringsIocFound: number;
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
  citation: DecodedCitation | StackCitation | LanguageCitation;
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

// language_strings/language_strings_missed carry no per-entry provenance beyond string/offset —
// language/languageVersion/missed come from the report's own metadata + which array this entry
// was read from, passed in once per scanCategory call rather than per entry.
interface LanguageContext {
  language: string;
  languageVersion: string;
  missed: boolean;
}

function scanCategory(
  kind: Kind,
  entries: unknown[],
  scannedSoFar: number,
  langCtx?: LanguageContext,
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
    let citation: DecodedCitation | StackCitation | LanguageCitation | undefined;
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
    } else if (kind === "language") {
      const offset = signedSafeInt(raw.offset);
      if (offset !== undefined && langCtx) {
        // `||`, not `??` — an empty-string encoding falls back to "unknown" the same as a
        // missing one (Ollama code review finding), then clipped like every other report-supplied
        // string in this schema.
        citation = {
          offset,
          encoding: clip(str(raw.encoding) || "unknown", MAX_PRODUCER_VERSION_LEN).text,
          language: langCtx.language,
          languageVersion: langCtx.languageVersion,
          missed: langCtx.missed,
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
  const seen = new Map<string, DecodedCitation | StackCitation | LanguageCitation>();
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
  const mappingVersion: "floss-decoded-v1" | "floss-stack-v1" | "floss-language-v1" =
    kind === "decoded" ? "floss-decoded-v1" : kind === "language" ? "floss-language-v1" : "floss-stack-v1";

  // A mixed confirmed+candidate group (language_strings + language_strings_missed for the SAME
  // value) reads as confirmed if ANY citation is confirmed — the confident fact isn't hidden
  // behind an unconfirmed candidate's own presence, but `missed` stays visible per citation
  // regardless (never silently promoted or dropped).
  const anyConfirmed = kind === "language" ? (citations as LanguageCitation[]).some((c) => !c.missed) : true;
  const confirmationNote =
    kind === "language" ? (anyConfirmed ? "" : "; candidate, not independently confirmed") : "";

  const reportTag = `; report ${reportFingerprint.slice(0, 16)}`;
  const kindLabel =
    kind === "decoded"
      ? "decoded string"
      : kind === "language"
        ? "language-runtime string"
        : `${kind} string`;
  const body = boundedTextTo(
    `Recovered ${kindLabel} (FLOSS): ${value}${valueTruncated ? " [value truncated]" : ""} — ` +
      `${occurrences} occurrence(s) in this upload; a recovered string, not proof of network ` +
      `contact or capability use${confirmationNote}; [undated: FLOSS's results document carries no event time]`,
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
          basis: DECODED_STRING_BASIS,
        }
      : kind === "language"
        ? {
            tool: "floss" as const,
            kind: "language" as const,
            value,
            valueTruncated,
            sampleHash,
            reportFingerprint,
            producerVersion: producerVersionClipped,
            mappingVersion: "floss-language-v1" as const,
            citations: citations as LanguageCitation[],
            notCited,
            occurrences,
            basis: LANGUAGE_STRING_BASIS,
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
            basis: DECODED_STRING_BASIS,
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

// static_strings gets IOC-corroboration only, never its own event — same clip+skip-if-truncated
// rule the event path applies (mapGroup only extracts IOCs `if (!valueTruncated)`), so a
// multi-megabyte static string is bounded exactly like an oversized decoded/stack/tight value,
// never regex-scanned unbounded. `found` counts raw IOC mentions (pre-dedup, across all entries);
// `scanned` counts entries visited regardless of validity (a non-object/non-string entry is
// skipped, never counted as malformed — this asymmetry with the event path is deliberate: a raw
// string dump's own malformed-entry count was never load-bearing the way a citation parse failure
// is for decoded/stack/tight/language).
function scanStaticIocsOnly(
  entries: unknown[],
  scannedSoFar: number,
  sink: Map<string, SiemIoc>,
  aggKey: string,
): { found: number; scanned: number; truncated: boolean } {
  let scanned = scannedSoFar;
  let found = 0;
  const rowSink = new Map<string, SiemIoc>();
  for (const raw of entries) {
    // Merge whatever this scan already found BEFORE returning — an early exit that skipped the
    // merge would silently orphan every IOC visited before the cutoff (Ollama code review finding
    // — `found`/`staticStringsIocFound` would report them while `iocs` never carried them).
    if (scanned >= MAX_ENTRIES_SCANNED) {
      mergeRowIocs(sink, rowSink, aggKey);
      return { found, scanned, truncated: true };
    }
    scanned += 1;
    if (!isObject(raw)) continue;
    const value = str(raw.string);
    if (!value) continue;
    const { text: clipped, truncated } = clip(value, MAX_VALUE_LEN);
    if (truncated) continue; // exact same "skip extraction on truncated value" rule as mapGroup
    const foundIocs = extractIocsFromText(clipped);
    found += foundIocs.length;
    for (const ioc of foundIocs) addIoc(rowSink, ioc.type, ioc.value);
  }
  mergeRowIocs(sink, rowSink, aggKey);
  return { found, scanned, truncated: false };
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
  const rowsByKind: Record<Kind, Row[]> = { decoded: [], stack: [], tight: [], language: [] };
  const language = clip(str(metadata.language) || "unknown", MAX_PRODUCER_VERSION_LEN).text;
  const languageVersion = clip(str(metadata.language_version) || "unknown", MAX_PRODUCER_VERSION_LEN).text;
  for (const kind of KINDS) {
    if (kind === "language") {
      // language_strings scanned BEFORE language_strings_missed — for BOTH the shared entry
      // budget and the per-category MAX_DISTINCT_VALUES cap, so a confirmed value never loses its
      // dedup slot to a missed row of the same value arriving first (Ollama design review).
      for (const [entries, missed] of [
        [strings.language_strings, false],
        [strings.language_strings_missed, true],
      ] as const) {
        if (!Array.isArray(entries)) continue;
        const result = scanCategory("language", entries, scanned, { language, languageVersion, missed });
        rowsByKind.language.push(...result.rows);
        malformedEntries += result.malformed;
        scanned = result.scanned;
        if (result.truncated) entriesTruncated = true;
      }
      continue;
    }
    const entries = strings[`${kind}_strings`];
    if (!Array.isArray(entries)) continue;
    const result = scanCategory(kind, entries, scanned);
    rowsByKind[kind] = result.rows;
    malformedEntries += result.malformed;
    scanned = result.scanned;
    if (result.truncated) entriesTruncated = true;
  }

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

  // static_strings: scanned LAST (after decoded/stack/tight/language have already had first claim
  // on MAX_ENTRIES_SCANNED) so a huge static_strings array can never starve the citation-bearing
  // kinds; the reverse can happen (huge event-kind volume starves static to zero), disclosed via
  // staticStringsIocScanned < staticStringsSeen plus entriesTruncated.
  const staticArr = strings.static_strings;
  const staticStringsSeen = Array.isArray(staticArr) ? staticArr.length : 0;
  const staticAggKey = boundedAggKey(`floss|${reportFingerprint}|static-strings-corroboration`);
  let staticStringsIocScanned = 0;
  let staticStringsIocFound = 0;
  if (Array.isArray(staticArr)) {
    const before = scanned;
    const result = scanStaticIocsOnly(staticArr, scanned, sink, staticAggKey);
    staticStringsIocScanned = result.scanned - before;
    staticStringsIocFound = result.found;
    scanned = result.scanned;
    if (result.truncated) entriesTruncated = true;
  }

  // A static-only (or otherwise event-less) report would otherwise silently drop the sample's own
  // hash from `iocs` entirely, since hash IOCs are normally attached per mapped event.
  if (mapped.length === 0) {
    const hashSink = new Map<string, SiemIoc>();
    for (const h of [sampleHash.sha256, sampleHash.sha1, sampleHash.md5]) if (h) addIoc(hashSink, "hash", h);
    mergeRowIocs(sink, hashSink, staticAggKey);
  }

  const { events, groups } = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: "Info",
    maxEvents: opts.maxEvents ?? MAX_DISTINCT_VALUES * 4,
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
    staticStringsIocScanned,
    staticStringsIocFound,
  };
}
