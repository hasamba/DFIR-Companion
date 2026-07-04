// Deterministic "find similar items" scorer for the false-positive feedback loop (issue #227).
// Given one anchor item the analyst just marked false-positive, ranks OTHER findings/events in the
// same case by shared signals (MITRE technique, process name, hash, source, asset, related IOCs) so
// the mark-FP dialog can suggest — never auto-apply — likely duplicates of the same pattern.
//
// Pure, offline, no I/O — unit-tested independently (same shape as adversaryHints.ts).

import type { ForensicEvent, Finding } from "./stateTypes.js";

export interface FalsePositiveCandidate {
  id: string;
  kind: "finding" | "event";
  label: string;      // title (finding) or description (event), for display
  score: number;
  reasons: string[];  // human-readable matched signals, e.g. "same MITRE T1569.002"
}

export interface SimilarityOptions {
  minScore?: number;   // default 2 — a single weak signal alone won't surface a candidate
  maxResults?: number; // default 20
}

const WEIGHT = { mitre: 2, processName: 2, hash: 3, source: 1, asset: 1, relatedIoc: 1, titleWords: 1 } as const;
const DEFAULT_MIN_SCORE = 2;
const DEFAULT_MAX_RESULTS = 20;

function sharedTechniques(a: readonly string[], b: readonly string[]): string[] {
  const bSet = new Set(b);
  return a.filter((t) => bSet.has(t));
}

export function findSimilarEvents(
  anchor: ForensicEvent,
  candidates: readonly ForensicEvent[],
  opts: SimilarityOptions = {},
): FalsePositiveCandidate[] {
  const minScore = opts.minScore ?? DEFAULT_MIN_SCORE;
  const maxResults = opts.maxResults ?? DEFAULT_MAX_RESULTS;
  const anchorSources = new Set(anchor.sources ?? []);

  const out: FalsePositiveCandidate[] = [];
  for (const c of candidates) {
    if (c.id === anchor.id) continue;
    let score = 0;
    const reasons: string[] = [];

    const mitre = sharedTechniques(anchor.mitreTechniques ?? [], c.mitreTechniques ?? []);
    if (mitre.length) { score += WEIGHT.mitre; reasons.push(`same MITRE ${mitre.join(", ")}`); }

    if (anchor.processName && c.processName && anchor.processName.toLowerCase() === c.processName.toLowerCase()) {
      score += WEIGHT.processName;
      reasons.push(`same process ${c.processName}`);
    }

    if (anchor.sha256 && c.sha256 && anchor.sha256.toLowerCase() === c.sha256.toLowerCase()) {
      score += WEIGHT.hash;
      reasons.push("same sha256 hash");
    } else if (anchor.md5 && c.md5 && anchor.md5.toLowerCase() === c.md5.toLowerCase()) {
      score += WEIGHT.hash;
      reasons.push("same md5 hash");
    }

    if (anchor.asset && c.asset && anchor.asset.toLowerCase() === c.asset.toLowerCase()) {
      score += WEIGHT.asset;
      reasons.push(`same asset ${c.asset}`);
    }

    if ((c.sources ?? []).some((s) => anchorSources.has(s))) {
      score += WEIGHT.source;
      reasons.push("same source tool");
    }

    if (score >= minScore) out.push({ id: c.id, kind: "event", label: c.description, score, reasons });
  }

  out.sort((a, b) => b.score - a.score || a.id.localeCompare(b.id));
  return out.slice(0, maxResults);
}

const STOPWORD_MIN_LEN = 4; // skip short/common words so title overlap needs real shared terms

function titleWords(title: string): Set<string> {
  return new Set(title.toLowerCase().split(/\W+/).filter((w) => w.length >= STOPWORD_MIN_LEN));
}

export function findSimilarFindings(
  anchor: Finding,
  candidates: readonly Finding[],
  opts: SimilarityOptions = {},
): FalsePositiveCandidate[] {
  const minScore = opts.minScore ?? DEFAULT_MIN_SCORE;
  const maxResults = opts.maxResults ?? DEFAULT_MAX_RESULTS;
  const anchorIocs = new Set(anchor.relatedIocs ?? []);
  const anchorWords = titleWords(anchor.title);

  const out: FalsePositiveCandidate[] = [];
  for (const c of candidates) {
    if (c.id === anchor.id) continue;
    let score = 0;
    const reasons: string[] = [];

    const mitre = sharedTechniques(anchor.mitreTechniques ?? [], c.mitreTechniques ?? []);
    if (mitre.length) { score += WEIGHT.mitre; reasons.push(`same MITRE ${mitre.join(", ")}`); }

    const sharedIocs = (c.relatedIocs ?? []).filter((i) => anchorIocs.has(i));
    if (sharedIocs.length) {
      score += WEIGHT.relatedIoc * sharedIocs.length;
      reasons.push(`shares ${sharedIocs.length} related IOC(s)`);
    }

    const overlap = [...titleWords(c.title)].filter((w) => anchorWords.has(w));
    if (overlap.length >= 2) {
      score += WEIGHT.titleWords;
      reasons.push(`similar title ("${overlap.join(", ")}")`);
    }

    if (score >= minScore) out.push({ id: c.id, kind: "finding", label: c.title, score, reasons });
  }

  out.sort((a, b) => b.score - a.score || a.id.localeCompare(b.id));
  return out.slice(0, maxResults);
}
