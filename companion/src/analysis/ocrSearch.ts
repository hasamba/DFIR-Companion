import type { OcrWord } from "./ocrRedact.js";
import { DEFAULT_CONFIDENCE_THRESHOLD } from "./ocrRedact.js";

// Screenshot OCR full-text search (#176). A LOCAL, opt-out index over the text Tesseract
// reads from each captured screenshot, so an analyst can recall "where did I see 'mimikatz'?"
// across a whole case instead of opening screenshots one by one. Pure logic only — the OCR
// engine (TesseractOcrRunner) and persistence (CaseStore) live elsewhere; this module just
// turns recognized words into searchable text and scans the index. No AI, no network.

/** One indexed screenshot: the flat OCR text plus provenance for the search hit. */
export interface OcrIndexEntry {
  /** Relative screenshot filename within the case's screenshots/ dir — the join key + link target. */
  screenshotFile: string;
  /** The OCR'd text, space-joined, lower-confidence words dropped. */
  text: string;
  /** When OCR ran (ISO-8601). */
  ocrAt: string;
  /** How many words survived the confidence filter (0 = OCR ran but read nothing legible). */
  wordCount: number;
}

/** The whole per-case index, keyed by screenshotFile so re-OCR replaces (never duplicates) a row. */
export type OcrIndex = Record<string, OcrIndexEntry>;

/** A search match: which screenshot, a snippet around the first hit, and how many times it matched. */
export interface OcrSearchHit {
  screenshotFile: string;
  snippet: string;
  matchCount: number;
}

/**
 * Is OCR full-text search enabled? Default ON. `DFIR_OCR_SEARCH=off` (also false/no/0)
 * turns it off so no OCR runs on the capture path and the index stays empty. Read per call
 * so a restart picks up the change. Mirrors `isDedupEnabled` in captureIngest.ts.
 */
export function isOcrSearchEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  const sw = (env.DFIR_OCR_SEARCH ?? "").trim().toLowerCase();
  return !(sw === "off" || sw === "false" || sw === "no" || sw === "0");
}

/**
 * Flatten the words OCR read into one searchable string. Words below the confidence
 * threshold (default 60, same bar the redactor uses) or empty after trimming are dropped,
 * so the index holds legible text rather than OCR noise.
 */
export function extractOcrText(
  words: OcrWord[],
  confidenceThreshold = DEFAULT_CONFIDENCE_THRESHOLD,
): string {
  return words
    .filter((w) => w.confidence >= confidenceThreshold)
    .map((w) => w.text.trim())
    .filter((t) => t.length > 0)
    .join(" ");
}

/** Count non-overlapping occurrences of `needle` in `haystack` (both already lower-cased). */
function countMatches(haystack: string, needle: string): number {
  if (needle.length === 0) return 0;
  let count = 0;
  let from = 0;
  for (;;) {
    const at = haystack.indexOf(needle, from);
    if (at === -1) return count;
    count++;
    from = at + needle.length;
  }
}

/** A ±context-char window around the first match, with ellipses when the text is clipped. */
function snippetAround(text: string, matchAt: number, queryLen: number, context: number): string {
  const start = Math.max(0, matchAt - context);
  const end = Math.min(text.length, matchAt + queryLen + context);
  const core = text.slice(start, end).trim();
  return `${start > 0 ? "…" : ""}${core}${end < text.length ? "…" : ""}`;
}

/**
 * Scan the index for `query` (case-insensitive substring) and return one hit per matching
 * screenshot, ranked most-matches-first. A blank query returns nothing. The corpus is a
 * single case's screenshots, so a plain substring scan is plenty — no FTS engine needed.
 */
export function searchOcrIndex(
  index: OcrIndex,
  query: string,
  opts: { maxSnippet?: number } = {},
): OcrSearchHit[] {
  const needle = query.trim().toLowerCase();
  if (needle.length === 0) return [];
  const context = opts.maxSnippet ?? 60;

  const hits: OcrSearchHit[] = [];
  for (const entry of Object.values(index)) {
    const hay = entry.text.toLowerCase();
    const matchAt = hay.indexOf(needle);
    if (matchAt === -1) continue;
    hits.push({
      screenshotFile: entry.screenshotFile,
      snippet: snippetAround(entry.text, matchAt, needle.length, context),
      matchCount: countMatches(hay, needle),
    });
  }
  // Most relevant first; tie-break by filename so the ordering is stable/deterministic.
  hits.sort((a, b) =>
    b.matchCount - a.matchCount || a.screenshotFile.localeCompare(b.screenshotFile),
  );
  return hits;
}
