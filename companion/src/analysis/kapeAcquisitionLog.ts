// KAPE's own acquisition provenance (#932 item 1): what `_copylog.csv` /
// `_skiplog.csv` state about ONE collection run — every file the tool actually copied, or
// deliberately did not, with the tool's own hash/size/timestamp for each. A sibling to
// kapeImport.ts (#931 item 8's own "many small files" convention), never an addition to it: that
// file's own `PROFILES` shape assumes one row describes artifact CONTENT (a ShimCache entry, a
// Prefetch run); an acquisition-log row describes ACQUISITION of a file, a different concept.
//
// What this module never says: that a file being copied means it was later PARSED, or that its
// parser's output was ever IMPORTED into this case — "copied" is not "examined". It is never
// wired into refutationGate.ts's own refutation-downgrade logic; a real, SCOPED (host / volume /
// run / interval) version of that integration is #1101, filed separately after this design's own
// first draft tried to do it unsafely (Codex design review, RECOMMENDATION-932.1.md). A skipped
// file's own reason (Excluded / Deduped) is disclosed as a fact, never treated as proof anything
// was examined. Verified against KAPE's own documentation
// (github.com/EricZimmerman/KapeDocs, Pages/4.-Log-files.md) — not invented.
//
// This row is graded Info and goes through the SAME standard forensic/super-timeline demotion
// seam every other importer uses — no special storage tier. Codex's code review (High finding #1)
// correctly noted that a CUSTOM analyst-defined tag rule targeting KAPE sources could, in
// principle, promote it back into AI-visible state — but that risk is INHERENT to every
// Info-severity row this codebase already imports (Prefetch, Amcache, …), not something this PR
// introduces; no DEFAULT rule in data/tags.yaml matches (verified, and pinned by a test below).
// Building a whole new "provenance can never be promoted" storage tier, as the review's own
// recommendation suggested, is a much larger, cross-cutting change to the shared tagging/
// promotion/demotion pipeline every importer relies on — disproportionate to this one item, and
// not attempted here.

import { createHash } from "node:crypto";
import { parseCsv } from "./csvImport.js";
import {
  aggregateEvents,
  getCI,
  normalizeTime,
  str,
  type MappedEvent,
  type SiemEvent,
  type SiemIoc,
} from "./siemImport.js";
import { createCanonicalEvent } from "./canonicalEvent.js";
import type { AcquisitionFact, AcquisitionLogKind, AcquisitionSkipReason } from "./canonicalAcquisition.js";

type Row = Record<string, unknown>;

export const ACQUISITION_FACTS_MAX = 256;
const BASIS =
  "each file's own SHA-1, when recorded at the source by the acquisition tool; not a container or disk-image hash, and this log does not verify the destination copy against it" as const;

export interface KapeAcquisitionOptions {
  aggregate?: boolean;
  maxEvents?: number;
}

export interface KapeAcquisitionResult {
  events: SiemEvent[];
  iocs: SiemIoc[];
  total: number;
  kept: number;
  dropped: number;
  groups: number;
  artifact: string;
  format: string;
}

const COPYLOG_HEADERS = [
  "copiedtimestamp",
  "sourcefile",
  "destinationfile",
  "filesize",
  "sourcefilesha1",
  "deferredcopy",
  "createdonutc",
  "modifiedonutc",
  "lastaccessedonutc",
  "copyduration",
];
const SKIPLOG_HEADERS = ["sourcefile", "sourcefilesha1", "reason"];
const SKIP_REASONS: Record<string, AcquisitionSkipReason> = { excluded: "Excluded", deduped: "Deduped" };

/** All of KAPE's own documented copylog columns are present (#932 item 1, Codex design review
 * finding #9 — a loose 2-3 column signature risked misclaiming an unrelated CSV). */
export function isKapeCopyLog(headers: readonly string[]): boolean {
  const h = new Set(headers.map((x) => x.trim().toLowerCase()));
  return COPYLOG_HEADERS.every((c) => h.has(c));
}

/** All three documented skiplog columns are present. A header-only (zero-row) skiplog is a valid
 * match, same as a header-only copylog (#932 item 1, Codex code review finding #6 — the original
 * check rejected an empty skiplog, inconsistent with the copylog's own detection). Every row's own
 * `Reason` is validated during the actual SCAN (`scanSkipLog`), not sampled here — a 20-row sample
 * let a later row's unrecognized value slip through undetected (Codex code review finding #6). */
export function isKapeSkipLog(headers: readonly string[]): boolean {
  const h = new Set(headers.map((x) => x.trim().toLowerCase()));
  return SKIPLOG_HEADERS.every((c) => h.has(c));
}

function bool(v: unknown): boolean | undefined {
  const s = str(v).trim().toLowerCase();
  if (s === "true") return true;
  if (s === "false") return false;
  return undefined;
}

function num(v: unknown): number | undefined {
  const s = str(v).trim();
  if (!s) return undefined;
  const n = Number(s);
  return Number.isFinite(n) ? n : undefined;
}

interface Scanned {
  facts: AcquisitionFact[];
  notCited: number;
  malformedRows: number;
  first: string;
  last: string;
  /** Every valid row's own deferred/reason count, accumulated over ALL rows examined — never just
   * the bounded `facts` citation sample (#932 item 1, Codex code review finding #3: capping the
   * aggregate breakdown at the same 256-row bound as the citation list silently dropped whatever
   * came after it from the disclosed totals). */
  deferredCount: number;
  reasonCounts: Map<string, number>;
}

function scanCopyLog(rows: readonly Row[]): Scanned {
  const facts: AcquisitionFact[] = [];
  let notCited = 0;
  let malformedRows = 0;
  let deferredCount = 0;
  let first = "";
  let last = "";
  for (const r of rows) {
    const sourceFile = str(getCI(r, "SourceFile")).trim();
    if (!sourceFile) {
      malformedRows += 1;
      continue;
    }
    const t = str(getCI(r, "CopiedTimestamp")).trim();
    if (t) {
      const n = normalizeTime(t);
      if (!first || n < first) first = n;
      if (!last || n > last) last = n;
    }
    const deferredCopy = bool(getCI(r, "DeferredCopy"));
    if (deferredCopy) deferredCount += 1;
    if (facts.length < ACQUISITION_FACTS_MAX) {
      facts.push({
        // The FULL path is kept in canonical evidence — never truncated here (#932 item 1, Codex
        // code review finding #4: clipping the path made two distinct deep paths sharing a prefix
        // indistinguishable in stored evidence, with no disclosure that anything was lost). A
        // display surface may clip for rendering; this is the record itself.
        sourceFile,
        sha1: str(getCI(r, "SourceFileSha1")).trim() || undefined,
        fileSize: num(getCI(r, "FileSize")),
        deferredCopy,
      });
    } else notCited += 1;
  }
  return { facts, notCited, malformedRows, first, last, deferredCount, reasonCounts: new Map() };
}

function scanSkipLog(rows: readonly Row[]): Scanned {
  const facts: AcquisitionFact[] = [];
  let notCited = 0;
  let malformedRows = 0;
  const reasonCounts = new Map<string, number>();
  for (const r of rows) {
    const sourceFile = str(getCI(r, "SourceFile")).trim();
    const rawReason = str(getCI(r, "Reason")).trim();
    const reason = SKIP_REASONS[rawReason.toLowerCase()];
    if (!sourceFile || !reason) {
      malformedRows += 1;
      continue;
    }
    reasonCounts.set(reason, (reasonCounts.get(reason) ?? 0) + 1);
    if (facts.length < ACQUISITION_FACTS_MAX) {
      facts.push({
        sourceFile,
        sha1: str(getCI(r, "SourceFileSha1")).trim() || undefined,
        reason,
      });
    } else notCited += 1;
  }
  return { facts, notCited, malformedRows, first: "", last: "", deferredCount: 0, reasonCounts };
}

function toRows(headers: string[], rawRows: string[][]): Row[] {
  return rawRows.map((cols) => {
    const row: Row = {};
    headers.forEach((h, i) => {
      row[h.trim()] = cols[i] ?? "";
    });
    return row;
  });
}

function summarize(logKind: AcquisitionLogKind, scanned: Scanned, uploadId: string): { event: MappedEvent } {
  const { facts, notCited, malformedRows, deferredCount, reasonCounts } = scanned;
  const validRows = facts.length + notCited;

  const head =
    logKind === "copied"
      ? `KAPE acquisition: ${validRows} file(s) copied`
      : `KAPE acquisition: ${validRows} file(s) skipped`;
  const parts = [
    logKind === "copied" && deferredCount
      ? `${deferredCount} via a deferred (raw-disk) read — the source was locked`
      : "",
    logKind === "skipped" ? [...reasonCounts.entries()].map(([r, n]) => `${n} ${r}`).join(", ") : "",
    scanned.first && scanned.last ? `collected ${scanned.first} – ${scanned.last}` : "",
    malformedRows
      ? `${malformedRows} row(s) in this log named no source file${logKind === "skipped" ? " or no recognized reason" : ""} — not counted`
      : "",
    notCited ? `${notCited} further file(s) not individually cited` : "",
    // A short fingerprint of THIS upload's own content — never omitted, even when two distinct
    // logs happen to produce identical counts (#932 item 1, Codex code review finding #2: without
    // this, two DIFFERENT skiplogs with the same resulting counts produced byte-identical
    // descriptions, and — paired with the same fallback "no coverage time" timestamp every
    // skiplog got — correlate.ts's own "same time + same description = exact duplicate" merge
    // silently folded one log's facts into the other's).
    `log ${uploadId.slice(0, 8)}`,
  ].filter(Boolean);
  const description = `${head} — ${parts.join("; ")}`.slice(0, 600);

  // copylog has a real "collected" interval from CopiedTimestamp; skiplog has none (KAPE's own
  // schema carries no timestamp for a skip decision) — the import's OWN wall-clock time is used
  // instead of a fixed placeholder, so two skiplogs uploaded at different times don't collide on
  // the SAME degenerate timestamp too (Codex code review finding #2, same root cause as above).
  const observed = scanned.first || new Date().toISOString();
  // A log containing rows but extracting ZERO valid facts establishes nothing — never claimed as a
  // successful acquisition (#932 item 1, Codex code review finding #7).
  const outcome = validRows > 0 ? "success" : "unknown";
  const event: MappedEvent = {
    timestamp: normalizeTime(observed) || "",
    description,
    severity: "Info",
    mitre: [],
    aggKey: `kape-acquisition|${logKind}|${uploadId}`,
    sources: ["KAPE"],
    artifactName: logKind === "copied" ? "KAPE.Acquisition.CopyLog" : "KAPE.Acquisition.SkipLog",
    canonical: createCanonicalEvent({
      event: { category: "file", type: "acquisition", action: logKind, outcome },
      time: { observed, normalized: normalizeTime(observed) || "" },
      evidence: { rawRecords: [{ source: "kape-acquisition", locator: uploadId }] },
      producer: {
        importer: "kape-acquisition",
        parserVersion: "1",
        mappingVersion: "kape-acquisition-v1",
      },
      acquisitionCoverage: {
        tool: "kape",
        logKind,
        facts,
        notCited,
        malformedRows,
        ...(logKind === "copied" && scanned.first
          ? { coverage: { first: scanned.first, last: scanned.last } }
          : {}),
        basis: BASIS,
      },
    }),
  };
  return { event };
}

/** The shared implementation, taking ALREADY-PARSED CSV output — `kapeImport.ts`'s own
 * `parseKapeCsv` calls this directly with its own single `parseCsv(text)` result, so a large
 * existing artifact CSV (an MFT/UsnJrnl export can run to millions of rows) is never parsed
 * TWICE just to learn it is not an acquisition log (#932 item 1, Codex code review finding #5).
 * `parseKapeAcquisitionLog` below is the standalone, single-parse convenience wrapper for callers
 * (tests, other future callers) that only have raw text. */
export function parseKapeAcquisitionRows(
  headers: string[],
  rawRows: string[][],
  opts: KapeAcquisitionOptions = {},
): KapeAcquisitionResult | null {
  if (!headers.length) return null;
  const isCopy = isKapeCopyLog(headers);
  const isSkip = !isCopy && isKapeSkipLog(headers);
  if (!isCopy && !isSkip) return null;

  const uploadId = createHash("sha256")
    .update(headers.join(","))
    .update(rawRows.map((r) => r.join(",")).join("\n"))
    .digest("hex")
    .slice(0, 16);
  const rows = toRows(headers, rawRows);
  const scanned = isCopy ? scanCopyLog(rows) : scanSkipLog(rows);
  const { event } = summarize(isCopy ? "copied" : "skipped", scanned, uploadId);
  const mapped: MappedEvent[] = [event];
  const { events, groups } = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: "Info",
    maxEvents: opts.maxEvents ?? 1,
  });
  const artifact = isCopy ? "KapeAcquisitionCopyLog" : "KapeAcquisitionSkipLog";
  return {
    events,
    iocs: [],
    total: rawRows.length,
    kept: events.length,
    dropped: 0,
    groups,
    artifact,
    format: artifact,
  };
}

/** A KAPE `_copylog.csv` or `_skiplog.csv`, or null when neither log's own header matches. */
export function parseKapeAcquisitionLog(
  text: string,
  opts: KapeAcquisitionOptions = {},
): KapeAcquisitionResult | null {
  const { headers, rows } = parseCsv(text);
  return parseKapeAcquisitionRows(headers, rows, opts);
}
