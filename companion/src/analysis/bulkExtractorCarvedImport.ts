// bulk_extractor's carved-object feature files (#932 item 4, intact-file half — #1116): one line
// per object a carving scanner reconstructed and wrote to disk (`jpeg.txt`, `zip_carved.txt`,
// `winpe_carved.txt`, `evtx_carved.txt`, `ntfs*_carved.txt`, …). This is the COMPLETE-FILE half
// that #1115's url.txt importer deliberately could not deliver: a real per-object digest, the
// tool's own size, the forensic offset/decode chain, and the tool's own dedup marker.
//
// Everything asserted here was read from bulk_extractor 2.x's own source (be20_api
// `feature_recorder.cpp` `carve()`/`write()`, every `scan_*.cpp` that calls `.carve(`), not from
// memory — see RECOMMENDATION-1116.md for the file:line of each claim. In particular:
//   - the digest is over the carver's DATA buffer; the 3-arg `carve()` overload forwards an EMPTY
//     header, so for every recorder except evtx's reconstructed-header path and rtti's ppm path
//     the digest covers the whole written file (`hashScope` says which);
//   - a re-carve of an already-seen digest writes feature `<CACHED>` and omits `<filename>` — the
//     tool never re-compares bytes, and neither does this importer (`dedupBasis`);
//   - the carver's complete/truncated verdict, where computed (jpeg_validator), is NOT written to
//     the line — only the NTFS/evtx recorders leak a verdict, via the carved filename suffix.
// Known undetectable/absent cases: a headers-only carved file (a genuine "carved nothing") has no
// data row to match and surfaces as an unrecognized upload; stoplist-diverted carve rows are
// written to the stoplist feature file by `write()` itself, so they never appear here.
//
// Never a claim that the file existed under a filesystem name, was executed, opened, or belongs
// to anyone. Undated, Info, no MITRE — the same posture as #1115.

import { createHash } from "node:crypto";
import { boundedAggKey } from "./aggKey.js";
import {
  clip,
  headerBlock,
  MAX_DISTINCT_VALUES,
  MAX_RAW_OFFSET_STORAGE_LEN,
  MAX_ROWS_SCANNED,
  parseOffset,
} from "./bulkExtractorUrlImport.js";
import { createCanonicalEvent } from "./canonicalEvent.js";
import {
  CARVED_COMPLETENESS,
  CARVED_DEDUP_BASIS,
  CARVED_FILE_BASIS,
  CARVED_HASH_PROMOTION_CAVEAT,
  CARVED_HASH_SCOPES,
  CARVED_STRUCTURAL_VALIDATION,
  MAX_CONTEXT_LEN,
  MAX_HASH_ALGO_LEN,
  MAX_HASH_HEX_LEN,
  MAX_RECORDER_LEN,
  MAX_VALUE_LEN,
  RECOVERY_CITATIONS_MAX,
  type CarvedToolFlag,
  type RecoveryCitation,
} from "./canonicalRecoveredFragment.js";
import { addIoc, mergeRowIocs, type MappedEvent, type SiemEvent, type SiemIoc } from "./siemImport.js";
import { aggregateEvents } from "./eventAggregate.js";

export { MAX_DISTINCT_VALUES, MAX_ROWS_SCANNED };
/** Detection quorum: every non-empty data row among the first K must carry the carved shape —
 * real carved files are produced solely by `carve()`'s single `write()`, so one stray row means
 * the file is not one. This defends against a TOOL-PRODUCED url.txt whose raw context windows
 * happen to contain fileobject bytes; it is not an authenticity control — an adversary who writes
 * the whole upload can satisfy it, which is why no record here claims existence or provenance. */
export const DETECT_QUORUM_ROWS = 8;

/** The three known children, in the order `carve()` writes them, nothing else admitted between
 * them; an enclosing quote PAIR tolerated (both or neither — `\1` backreference), since
 * `quote_if_necessary` only escapes bad UTF-8 and backslashes and `sanitize_filename` strips both
 * from the path, so real lines are clean. */
const FILEOBJECT_RE =
  /^(")?<fileobject>(?:<filename>([^<]{1,4000})<\/filename>)?<filesize>(\d{1,20})<\/filesize><hashdigest type='([A-Za-z0-9-]{1,32})'>([0-9A-Fa-f]{1,128})<\/hashdigest><\/fileobject>\1$/;
const CACHED_FEATURE = "<CACHED>"; // feature_recorder.h:229, `static inline const std::string CACHED`

/** Promotable digests and their exact hex lengths — an unrecognized `type=` keeps the digest in
 * the record and promotes nothing. Also each algorithm's empty-input digest (a zero-byte object). */
const PROMOTABLE: Record<string, { len: number; empty: string }> = {
  md5: { len: 32, empty: "d41d8cd98f00b204e9800998ecf8427e" },
  sha1: { len: 40, empty: "da39a3ee5e6b4b0d3255bfef95601890afd80709" },
  sha256: { len: 64, empty: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
};

/** Per-recorder header behaviour, verified against every located `.carve(` caller
 * (RECOMMENDATION-1116.md). Only recorders whose 3-arg (empty-header) call was actually read are
 * listed — `unrar_carved`/`utmp_carved` exist as recorder names but their carve call was not
 * located, so they fall to the "not stated" scope rather than carry the strong claim. */
const NO_HEADER_RECORDERS = new Set([
  "jpeg",
  "zip_carved",
  "winpe_carved",
  "sqlite_carved",
  "kml_carved",
  "vcard_carved",
  "ntfsmft_carved",
  "ntfsindx_carved",
  "ntfslogfile_carved",
  "ntfsusn_carved",
]);
const HEADER_PREPENDING_RECORDERS = new Set(["evtx_carved", "rtti"]);
/** The only recorders that write a verdict anywhere — as a carved-filename suffix. A matching
 * suffix on any OTHER recorder's path is not the tool's verdict and must not be read as one. */
const CORRUPTED_SUFFIX_RECORDERS = new Set([
  "ntfsmft_carved",
  "ntfsindx_carved",
  "ntfslogfile_carved",
  "ntfsusn_carved",
]);
const ORPHAN_SUFFIX_RECORDERS = new Set(["evtx_carved"]);

export interface BulkExtractorCarvedOptions {
  aggregate?: boolean;
  maxEvents?: number;
}

export interface BulkExtractorCarvedResult {
  events: SiemEvent[];
  iocs: SiemIoc[];
  total: number;
  kept: number;
  dropped: number;
  groups: number;
  format: string;
  recorder: string;
  malformedRows: number;
  notCitedValues: number;
  truncatedScan: boolean;
  /** Digests kept in the record but not promoted (unrecognized algorithm, hex-length mismatch,
   * or a degenerate zero-byte object). */
  unpromotedValues: number;
}

function recorderName(header: readonly string[]): string | undefined {
  const line = header.find((l) => /^#\s*Feature-Recorder:/.test(l));
  const name = line?.replace(/^#\s*Feature-Recorder:\s*/, "").trim();
  return name && /^[A-Za-z0-9_.-]{1,64}$/.test(name) ? name : undefined;
}

function producerVersion(header: readonly string[]): string | undefined {
  const line = header.find((l) => /^#\s*BULK_EXTRACTOR-Version:\s*\S+/.test(l));
  const v = line?.replace(/^#\s*BULK_EXTRACTOR-Version:\s*/, "").trim();
  return v ? clip(v, MAX_RECORDER_LEN).text : undefined;
}

interface ParsedContext {
  filename?: string;
  filesize?: number;
  algorithm: string;
  hex: string;
}

function parseContext(raw: string): ParsedContext | null {
  const m = FILEOBJECT_RE.exec(raw);
  if (!m) return null;
  const size = Number(m[3]);
  return {
    filename: m[2] || undefined,
    filesize: Number.isSafeInteger(size) && size >= 0 ? size : undefined,
    algorithm: m[4].toLowerCase().replace(/-/g, ""),
    hex: m[5].toLowerCase(),
  };
}

/** Structural, not name-based: both header anchors, and EVERY non-empty data row among the first
 * DETECT_QUORUM_ROWS carries the carved fileobject shape. Checked BEFORE the url detector in
 * importDetect.ts, since the url anchor is a Feature-Recorder name this check does not exclude. */
export function isBulkExtractorCarvedFeatureFile(text: string): boolean {
  const header = headerBlock(text);
  if (header === null) return false;
  if (!header.some((l) => /^#\s*BULK_EXTRACTOR-Version:\s*\S+/.test(l))) return false;
  if (!recorderName(header)) return false;
  const stripped = text.startsWith("﻿") ? text.slice(1) : text;
  const lines = stripped.split(/\r\n|\r|\n/, header.length + DETECT_QUORUM_ROWS * 4 + 10);
  let seen = 0;
  for (const line of lines) {
    if (!line || line.startsWith("#")) continue;
    const fields = line.split("\t");
    if (fields.length !== 3 || !parseContext(fields[2])) return false;
    seen += 1;
    if (seen >= DETECT_QUORUM_ROWS) break;
  }
  return seen > 0;
}

interface Row {
  rawOffset: string;
  feature: string; // carved relative path, or "<CACHED>"
  cached: boolean;
  /** Folded as cached by filename-absence while the feature was NOT the `<CACHED>` literal — a
   * shape carve() never writes; surfaced as an ordering/shape anomaly, never normalized. */
  cachedByAbsenceOnly: boolean;
  ctx: ParsedContext;
  context: string; // the raw context text, clipped — citation dedup partner of rawOffset
}

function scanRows(lines: readonly string[]): { rows: Row[]; malformedRows: number; truncatedScan: boolean } {
  const rows: Row[] = [];
  let malformedRows = 0;
  let scanned = 0;
  let truncatedScan = false;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (scanned >= MAX_ROWS_SCANNED) {
      // Only a real unprocessed line is a truncation — a file of exactly MAX_ROWS_SCANNED
      // newline-terminated lines leaves one empty trailing part (Ollama code review finding).
      truncatedScan = lines.slice(i).some((l) => l.length > 0);
      break;
    }
    scanned += 1;
    if (!line || line.startsWith("#")) continue;
    const fields = line.split("\t");
    const [rawOffset, feature, rawContext] = fields;
    // Exactly three fields: real carved contexts contain no tabs (`sanitize_filename` + hex).
    if (fields.length !== 3 || !rawOffset || !feature || !rawContext) {
      malformedRows += 1;
      continue;
    }
    if (rawOffset.length > MAX_RAW_OFFSET_STORAGE_LEN) {
      malformedRows += 1;
      continue;
    }
    const ctx = parseContext(rawContext);
    if (!ctx) {
      malformedRows += 1;
      continue;
    }
    // Cached rows are recognized by EITHER signal (feature literal OR filename absence) — the
    // source writes both together, so either alone suffices and neither can be spoofed apart.
    const cached = feature === CACHED_FEATURE || !ctx.filename;
    const cachedByAbsenceOnly = cached && feature !== CACHED_FEATURE;
    // A non-cached row's feature and <filename> child are the same variable in carve(); a mismatch
    // means the line was not produced by carve() (Ollama design review, B3 cross-check).
    if (!cached && ctx.filename !== feature) {
      malformedRows += 1;
      continue;
    }
    rows.push({
      rawOffset,
      feature,
      cached,
      cachedByAbsenceOnly,
      ctx,
      context: clip(rawContext, MAX_CONTEXT_LEN).text,
    });
  }
  return { rows, malformedRows, truncatedScan };
}

function toolFlagFor(recorder: string, carvedPath: string): CarvedToolFlag {
  // scan_ntfs{mft,indx,logfile,usn}.cpp / scan_evtx.cpp suffix the carved filename with their own
  // verdict; no other recorder writes one anywhere, so the suffix is only read for those.
  if (CORRUPTED_SUFFIX_RECORDERS.has(recorder) && /_corrupted$/i.test(carvedPath)) return "corrupted";
  if (ORPHAN_SUFFIX_RECORDERS.has(recorder) && /\.evtx_orphan_record$/i.test(carvedPath))
    return "orphan-record";
  return "none";
}

function hashScopeFor(recorder: string): (typeof CARVED_HASH_SCOPES)[number] {
  if (NO_HEADER_RECORDERS.has(recorder)) return CARVED_HASH_SCOPES[0];
  if (HEADER_PREPENDING_RECORDERS.has(recorder)) return CARVED_HASH_SCOPES[1];
  return CARVED_HASH_SCOPES[2];
}

function mapGroup(
  groupRows: readonly Row[],
  recorder: string,
  version: string,
  reportFingerprint: string,
  sourceMedia: string | undefined,
  sink: Map<string, SiemIoc>,
): { event: MappedEvent; promoted: boolean } {
  const firstRealIdx = groupRows.findIndex((r) => !r.cached);
  const firstReal = firstRealIdx >= 0 ? groupRows[firstRealIdx] : undefined;
  const allCachedAnomaly = !firstReal;
  // Pristine per digest means exactly ONE non-cached row and it comes FIRST (the carve cache
  // starts empty and blocks a second write) — a cache marker before it, a second real row, or a
  // row folded as cached by filename-absence alone are all shapes carve() never writes. Flagged,
  // never normalized (Ollama code review finding).
  const realCount = groupRows.filter((r) => !r.cached).length;
  const orderingAnomaly =
    (firstReal !== undefined && (firstRealIdx > 0 || realCount > 1)) ||
    groupRows.some((r) => r.cachedByAbsenceOnly);
  const { algorithm, hex } = groupRows[0].ctx;
  const rawValue = firstReal ? firstReal.feature : `hash:${algorithm}:${hex}`;
  const { text: value, truncated: valueTruncated } = clip(rawValue, MAX_VALUE_LEN);
  const filesize = firstReal?.ctx.filesize;
  const occurrences = groupRows.length;
  const cachedOccurrences = groupRows.filter((r) => r.cached).length;
  const toolFlag = firstReal ? toolFlagFor(recorder, firstReal.feature) : "none";

  // Distinct (rawOffset, context) citations, capped, with the first REAL row's citation leading so
  // `where` never cites a duplicate marker's offset as the object's location; then first-seen
  // order. Same key as url.txt so a cache hit at the same offset with a different reported size is
  // not silently collapsed.
  const seen = new Map<string, RecoveryCitation>();
  const keyOf = (r: Row) =>
    createHash("sha256").update(r.rawOffset).update("\n").update(r.context).digest("hex");
  const ordered = firstReal ? [firstReal, ...groupRows.filter((r) => r !== firstReal)] : groupRows;
  for (const r of ordered) {
    const k = keyOf(r);
    if (seen.has(k) || seen.size >= RECOVERY_CITATIONS_MAX) continue;
    const p = parseOffset(r.rawOffset);
    seen.set(
      k,
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
  const notCited = Math.max(0, new Set(groupRows.map(keyOf)).size - citations.length);

  const spec = PROMOTABLE[algorithm];
  const zeroByte = filesize === 0 || (spec !== undefined && hex === spec.empty);
  const sizeUnknown = filesize === undefined;
  // `degenerate` covers both a zero-byte object and an unknown size (schema comment) — neither is
  // promoted — but the body must say WHICH, never call an unknown size "zero-byte". An unknown
  // size has exactly two reachable causes and the body names the live one: the row regex makes
  // <filesize> mandatory, so "not reported" is never true here. With a first-sighting row the
  // digits were over the safe-integer range (parseContext dropped them) — a size no real image
  // can yield, so the sentence points at the reported value. Without one (all-cached anomaly)
  // the importer never read a size, though every marker row carried one.
  const degenerate = zeroByte || sizeUnknown;
  const promotable = spec !== undefined && hex.length === spec.len && !degenerate;

  const aggKey = boundedAggKey(`bulk-extractor-carved|${reportFingerprint}|${algorithm}|${hex}`);
  if (promotable) {
    const rowSink = new Map<string, SiemIoc>();
    addIoc(rowSink, "hash", hex);
    mergeRowIocs(sink, rowSink, aggKey);
  }

  const first = citations[0];
  const where =
    first?.parsed && first.path.length > 0
      ? `via ${first.path.map((h) => h.method).join("→")} decode at offset ${first.rootOffset}`
      : first?.parsed
        ? `at image offset ${first.rootOffset}`
        : `at recorded offset ${first?.rawOffset ?? "unknown"}`;
  const flagNote =
    toolFlag === "corrupted"
      ? "; the recorder itself flagged this object corrupted (filename suffix)"
      : toolFlag === "orphan-record"
        ? "; the recorder itself flagged this an orphan record (filename suffix)"
        : "";
  const cachedNote = cachedOccurrences
    ? ` (${cachedOccurrences} reported by the tool as an already-carved duplicate of this digest)`
    : "";
  const anomalyNote = allCachedAnomaly
    ? "; EVERY row was a tool-side duplicate marker — impossible for one pristine feature file, value is importer-synthesized"
    : orderingAnomaly
      ? "; row order/shape for this digest is one the tool never writes (edited, pruned or concatenated input)"
      : "";
  const promoNote = promotable
    ? ""
    : zeroByte
      ? "; zero-byte object, digest not promoted"
      : sizeUnknown
        ? firstReal
          ? "; reported object size exceeds the representable range, digest not promoted"
          : "; object size not read (no first-sighting row), digest not promoted"
        : spec === undefined
          ? "; digest algorithm not promotable"
          : "; digest length does not match its algorithm, not promoted";
  const reportTag = `; report ${reportFingerprint.slice(0, 16)}`;
  const body = clip(
    `Carved file (bulk_extractor, ${recorder}): ${value}${valueTruncated ? " [value truncated]" : ""} — ` +
      `${algorithm} ${hex}${filesize !== undefined ? `, ${filesize} bytes` : ""}; ${where}; ` +
      `${occurrences} occurrence(s) in this upload${cachedNote}${anomalyNote}${flagNote}${promoNote}; ` +
      `completeness not written by the tool as structured data; a recovered file object, not proof it existed as a named ` +
      `filesystem entry, was executed, opened, or belongs to any user; ` +
      `[undated: bulk_extractor's feature file carries no event time]`,
    600 - reportTag.length,
  ).text;

  return {
    promoted: promotable,
    event: {
      timestamp: "",
      description: `${body}${reportTag}`,
      severity: "Info",
      mitre: [],
      aggKey,
      sources: ["bulk_extractor"],
      canonical: createCanonicalEvent({
        event: { category: "file", type: "carved-file", action: "recovered" },
        time: { observed: "", normalized: "" },
        evidence: {
          rawRecords: [
            { source: "bulk-extractor-carved", locator: `${algorithm}:${hex}@${reportFingerprint}` },
          ],
        },
        producer: {
          importer: "bulk-extractor-carved",
          parserVersion: "1",
          mappingVersion: "bulk-extractor-carved-v1",
        },
        recoveredFragment: {
          tool: "bulk_extractor",
          kind: "carved-file",
          artifactClass: "carved-file",
          recorder: clip(recorder, MAX_RECORDER_LEN).text,
          producerVersion: version,
          value,
          valueTruncated,
          hash: { algorithm: clip(algorithm, MAX_HASH_ALGO_LEN).text, hex: clip(hex, MAX_HASH_HEX_LEN).text },
          hashScope: hashScopeFor(recorder),
          hashIocPromoted: promotable,
          hashPromotionCaveat: CARVED_HASH_PROMOTION_CAVEAT,
          ...(filesize !== undefined ? { filesize } : {}),
          degenerate,
          toolFlag,
          ...(sourceMedia ? { sourceMedia } : {}),
          reportFingerprint,
          citations,
          notCited,
          occurrences,
          cachedOccurrences,
          allCachedAnomaly,
          orderingAnomaly,
          completeness: CARVED_COMPLETENESS,
          structuralValidation: CARVED_STRUCTURAL_VALIDATION,
          dedupBasis: CARVED_DEDUP_BASIS,
          basis: CARVED_FILE_BASIS,
        },
      }),
    },
  };
}

export function parseBulkExtractorCarved(
  text: string,
  opts: BulkExtractorCarvedOptions = {},
): BulkExtractorCarvedResult | null {
  if (!isBulkExtractorCarvedFeatureFile(text)) return null;
  const header = headerBlock(text) ?? [];
  const recorder = recorderName(header)!;
  const version = producerVersion(header) ?? "unknown";
  // `# Filename:` only from the validated header block, never from a data row (#1115's own rule).
  const filenameLine = header.find((l) => /^#\s*Filename:/.test(l));
  // headerBlock already caps the whole header at 4096 bytes; bounded again here so the canonical
  // block's own limit is enforced at the source, not by a neighbour's cap.
  const sourceMediaRaw = filenameLine
    ? filenameLine.replace(/^#\s*Filename:\s*/, "").trim() || undefined
    : undefined;
  const sourceMedia = sourceMediaRaw ? clip(sourceMediaRaw, MAX_VALUE_LEN).text : undefined;
  const reportFingerprint = createHash("sha256").update(text).digest("hex");

  const stripped = text.startsWith("﻿") ? text.slice(1) : text;
  const { rows, malformedRows, truncatedScan } = scanRows(stripped.split(/\r\n|\r|\n/, MAX_ROWS_SCANNED + 1));

  // Group by digest — the tool's own identity for a carved object. Per-upload cap on distinct
  // digests; overflow is disclosed, never silently dropped.
  const groups = new Map<string, Row[]>();
  const overflowed = new Set<string>();
  let notCitedValues = 0;
  for (const r of rows) {
    const key = `${r.ctx.algorithm}:${r.ctx.hex}`;
    let g = groups.get(key);
    if (!g) {
      if (groups.size >= MAX_DISTINCT_VALUES) {
        if (!overflowed.has(key)) {
          overflowed.add(key);
          notCitedValues += 1;
        }
        continue;
      }
      g = [];
      groups.set(key, g);
    }
    g.push(r);
  }

  const sink = new Map<string, SiemIoc>();
  const mapped: MappedEvent[] = [];
  let unpromotedValues = 0;
  for (const g of groups.values()) {
    const { event, promoted } = mapGroup(g, recorder, version, reportFingerprint, sourceMedia, sink);
    if (!promoted) unpromotedValues += 1;
    mapped.push(event);
  }

  const { events, groups: groupCount } = aggregateEvents(mapped, {
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
    groups: groupCount,
    format: "BulkExtractorCarvedFeatureFile",
    recorder,
    malformedRows,
    notCitedValues,
    truncatedScan,
    unpromotedValues,
  };
}
