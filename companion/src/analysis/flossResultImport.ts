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

function num(v: unknown): number | undefined {
  return typeof v === "number" && Number.isFinite(v) ? v : undefined;
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
): { rows: Row[]; scanned: number } {
  const rows: Row[] = [];
  let scanned = scannedSoFar;
  for (const raw of entries) {
    if (scanned >= MAX_ENTRIES_SCANNED) break;
    scanned += 1;
    if (!isObject(raw)) continue;
    const value = str(raw.string);
    if (!value) continue;
    const valueKey = createHash("sha256").update(value).digest("hex");
    let citation: DecodedCitation | StackCitation;
    if (kind === "decoded") {
      const address = num(raw.address);
      const decodedAt = num(raw.decoded_at);
      const decodingRoutine = num(raw.decoding_routine);
      if (address === undefined || decodedAt === undefined || decodingRoutine === undefined) continue;
      citation = {
        address,
        addressType: str(raw.address_type) ?? "unknown",
        encoding: str(raw.encoding) ?? "unknown",
        decodedAt,
        decodingRoutine,
      };
    } else {
      const functionAddress = num(raw.function);
      const programCounter = num(raw.program_counter);
      const stackPointer = num(raw.stack_pointer);
      const originalStackPointer = num(raw.original_stack_pointer);
      const offset = num(raw.offset);
      const frameOffset = num(raw.frame_offset);
      if (
        functionAddress === undefined ||
        programCounter === undefined ||
        stackPointer === undefined ||
        originalStackPointer === undefined ||
        offset === undefined ||
        frameOffset === undefined
      )
        continue;
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
    const citationKey = createHash("sha256").update(JSON.stringify(citation)).digest("hex");
    rows.push({ kind, value, valueKey, citationKey, citation });
  }
  return { rows, scanned };
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
          producerVersion,
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
          producerVersion,
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
      producer: { importer: "floss-result", parserVersion: "1", mappingVersion: `floss-${kind}-v1` },
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
  const rowsByKind: Record<Kind, Row[]> = { decoded: [], stack: [], tight: [] };
  for (const kind of KINDS) {
    const entries = strings[`${kind}_strings`];
    if (!Array.isArray(entries)) continue;
    const { rows, scanned: newScanned } = scanCategory(kind, entries, scanned);
    rowsByKind[kind] = rows;
    scanned = newScanned;
  }
  const entriesTruncated = scanned >= MAX_ENTRIES_SCANNED;
  const staticArr = strings.static_strings;
  const staticStringsSeen = Array.isArray(staticArr) ? staticArr.length : 0;

  const sink = new Map<string, SiemIoc>();
  const mapped: MappedEvent[] = [];
  let notCitedValues = 0;
  let total = 0;
  for (const kind of KINDS) {
    const byValueKey = new Map<string, Row[]>();
    for (const row of rowsByKind[kind]) {
      total += 1;
      let group = byValueKey.get(row.valueKey);
      if (!group) {
        if (byValueKey.size >= MAX_DISTINCT_VALUES) {
          notCitedValues += 1;
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
    dropped: 0,
    groups,
    format: "FlossResultDocument",
    notCitedValues,
    entriesTruncated,
    staticStringsSeen,
  };
}
