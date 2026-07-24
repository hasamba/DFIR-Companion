// Attack-sequence matching against known ransomware / intrusion playbooks (issue #230).
//
// Synthesis and the adversary-group hints tell the analyst WHICH techniques a case used, but not
// whether the observed techniques form a known actor's ORDERED kill chain. This module compares
// the case's chronological technique sequence against a small catalog of canonical playbooks
// (Conti, LockBit, BlackCat, Akira, …) and ranks each by a FUZZY SUBSEQUENCE match — the fraction
// of playbook steps that appear in the observed sequence IN ORDER, allowing unrelated techniques
// in between (an attacker's real timeline is noisy and incomplete). Pure and OFFLINE: the dataset
// is loaded separately (loadKnownPlaybooks) so this logic stays trivially testable.
//
// MATCHING is sub-technique aware, mirroring adversaryHints.ts: an observed technique matches a
// playbook step at the EXACT id (T1059.001 == T1059.001, strong) or at the BASE technique
// (T1059.001 vs playbook T1059.003, partial). The subsequence walk advances the playbook cursor
// on the first hit (exact preferred over partial) so each step is matched at most once; a step
// that never appears in order is `missing`. `score` is the in-order fraction (matched / steps),
// weighted so exact matches count fully and base-only partial matches count at BASE_MATCH_WEIGHT.

import { baseTechniqueId, normalizeTechniqueId } from "./adversaryHints.js";
import type { ForensicEvent } from "./stateTypes.js";

// One ordered step in a canonical attack playbook.
export interface PlaybookStep {
  technique: string; // ATT&CK id, full granularity where mapped, e.g. "T1059.001"
  name: string; // human label, e.g. "PowerShell"
}

// A canonical playbook: an ordered technique chain attributed to a ransomware group / intrusion set.
export interface Playbook {
  name: string;
  description: string;
  steps: PlaybookStep[];
}

// The shape of the bundled JSON dataset (companion/data/known-playbooks.json).
export interface KnownPlaybooksDataset {
  source: string;
  generated: string;
  playbooks: Playbook[];
}

// Per-step match result for a single playbook vs the observed sequence.
export interface PlaybookStepMatch {
  step: PlaybookStep;
  status: "matched" | "missing" | "out-of-order";
  matchedTechnique?: string; // the observed technique id that matched this step (when matched)
  matchKind?: "exact" | "base"; // granularity of the match (when matched)
}

// One ranked playbook match.
export interface PlaybookMatch {
  name: string;
  description: string;
  score: number; // 0–100: in-order matched fraction (exact full, base partial), of the playbook steps
  matchedCount: number; // steps observed in order (exact + partial)
  exactCount: number; // steps matched at the exact sub-technique
  missingCount: number; // steps never observed in order
  steps: PlaybookStepMatch[]; // per-step breakdown, in playbook order
}

export interface PlaybookMatchOptions {
  topN?: number; // cap on how many ranked playbooks to return (default 3)
}

export const DEFAULT_TOP_N = 3;

// Credit for a match that agrees only at the base technique, not the exact sub-technique. Half of
// an exact match — enough to keep coarse-but-real overlaps ranked, not enough to outweigh precise ones.
export const BASE_MATCH_WEIGHT = 0.5;

// The ordered list of observed ATT&CK technique ids derived from a case's forensic timeline, in
// chronological order. Each event may carry several techniques (all at the same timestamp); they
// are emitted in array order, deduped only against the immediately-preceding technique so a later
// real occurrence of the same technique still advances the sequence. Events with no parseable
// technique id contribute nothing. Sorting is by timestamp (ascending); ties keep insertion order.
export function observedTechniqueSequence(events: readonly ForensicEvent[]): string[] {
  const sorted = [...events].sort((a, b) => a.timestamp.localeCompare(b.timestamp));
  const seq: string[] = [];
  let last: string | null = null;
  for (const e of sorted) {
    for (const raw of e.mitreTechniques ?? []) {
      const id = normalizeTechniqueId(raw);
      if (!id) continue;
      if (id === last) continue;
      seq.push(id);
      last = id;
    }
  }
  return seq;
}

// Try to match a single playbook step against the observed sequence from a cursor onward, returning
// the matched technique + kind + the next cursor, or null when no in-order match exists. An exact
// (full-id) match is preferred over a base-only match at the same cursor position: the walk looks
// ahead for an exact match before accepting a partial one, so a coarse tag doesn't mask a precise one.
function matchStep(
  step: PlaybookStep,
  observed: readonly string[],
  from: number,
): { technique: string; kind: "exact" | "base"; next: number } | null {
  const stepId = normalizeTechniqueId(step.technique);
  const stepBase = stepId ? baseTechniqueId(stepId) : null;
  if (!stepId) return null;
  let partial: { technique: string; next: number } | null = null;
  for (let i = from; i < observed.length; i++) {
    const obs = observed[i];
    if (obs === stepId) return { technique: obs, kind: "exact", next: i + 1 };
    if (stepBase && baseTechniqueId(obs) === stepBase) {
      if (!partial) partial = { technique: obs, next: i + 1 };
    }
  }
  return partial ? { technique: partial.technique, kind: "base", next: partial.next } : null;
}

// Score one playbook against the observed sequence: walk the steps in order, advancing the cursor on
// each in-order match. A step is `matched` when found in order, `missing` when never seen, and
// `out-of-order` when the technique IS observed but only AFTER the cursor already passed it (i.e. it
// appears in the sequence but not in a position that keeps the chain). The score is the in-order
// matched fraction weighted by match kind (exact = 1, base = BASE_MATCH_WEIGHT).
export function matchPlaybook(
  playbook: Playbook,
  observed: readonly string[],
): PlaybookMatch {
  const steps: PlaybookStepMatch[] = [];
  let cursor = 0;
  let matched = 0;
  let exact = 0;
  let weighted = 0;

  for (const step of playbook.steps) {
    const m = matchStep(step, observed, cursor);
    if (m) {
      steps.push({ step, status: "matched", matchedTechnique: m.technique, matchKind: m.kind });
      matched++;
      if (m.kind === "exact") exact++;
      weighted += m.kind === "exact" ? 1 : BASE_MATCH_WEIGHT;
      cursor = m.next;
    } else {
      // The technique exists somewhere but appeared before the cursor (already consumed) → out-of-order;
      // never observed at all → missing.
      const stepId = normalizeTechniqueId(step.technique);
      const stepBase = stepId ? baseTechniqueId(stepId) : null;
      const seenSomewhere = observed.some(
        (o) => o === stepId || (!!stepBase && baseTechniqueId(o) === stepBase),
      );
      steps.push({ step, status: seenSomewhere ? "out-of-order" : "missing" });
    }
  }

  const denom = Math.max(1, playbook.steps.length);
  const score = Math.round((weighted / denom) * 100);
  return {
    name: playbook.name,
    description: playbook.description,
    score,
    matchedCount: matched,
    exactCount: exact,
    missingCount: playbook.steps.length - matched,
    steps,
  };
}

// Rank all playbooks against the observed sequence and return the top-N by score, then by exact
// matches, then by name for deterministic output. Playbooks scoring 0 are excluded (no overlap).
export function rankPlaybooks(
  playbooks: readonly Playbook[],
  observed: readonly string[],
  opts: PlaybookMatchOptions = {},
): PlaybookMatch[] {
  const topN = Math.max(1, Math.floor(opts.topN ?? DEFAULT_TOP_N));
  if (observed.length === 0) return [];
  const matches = playbooks
    .map((p) => matchPlaybook(p, observed))
    .filter((m) => m.matchedCount > 0);
  matches.sort(
    (a, b) =>
      b.score - a.score ||
      b.exactCount - a.exactCount ||
      b.matchedCount - a.matchedCount ||
      a.name.localeCompare(b.name),
  );
  return matches.slice(0, topN);
}

// Build the full result from a case's forensic timeline + a loaded dataset. Pure: the dataset and
// the events are passed in, so the route and the tests share one code path. The observed sequence
// is derived chronologically from the forensic timeline events (mitreTechniques), per
// observedTechniqueSequence.
export function buildPlaybookMatchResult(
  events: readonly ForensicEvent[],
  dataset: KnownPlaybooksDataset,
  opts: PlaybookMatchOptions = {},
): { observed: string[]; matches: PlaybookMatch[]; source: string; generated: string } {
  const observed = observedTechniqueSequence(events);
  const matches = rankPlaybooks(dataset.playbooks, observed, opts);
  return { observed, matches, source: dataset.source, generated: dataset.generated };
}
