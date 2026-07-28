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
//
// SCOPES (#230 asks for the sequence "per session/host"). A case's flat timeline interleaves every
// host, so a two-host incident produces an order no single attacker ever executed. But a ransomware
// playbook is by definition cross-host — lateral movement then fleet-wide encryption — so matching
// ONLY per host would break every chain the feature exists to find. Each playbook is therefore
// matched against BOTH the whole-case sequence AND each known host's slice of it, and keeps its
// best-scoring scope (reported as `scope`/`host`). Events with no recorded `asset` get no host
// scope of their own: that bucket can hold several machines (see sessionSegmentation's UNKNOWN_HOST
// note), so treating it as one host would invent a chain. They still count in the case scope.
//
// NOT ATTRIBUTION. A sequence match says the case resembles a published playbook, not that the
// named group did it — see PLAYBOOK_MATCH_CAVEAT, which every surface must render.

import { baseTechniqueId, normalizeTechniqueId, BASE_MATCH_WEIGHT } from "./adversaryHints.js";
import { sortByEventTime } from "./forensicSort.js";
import { UNKNOWN_HOST } from "./sessionSegmentation.js";
import type { ForensicEvent } from "./stateTypes.js";

export { BASE_MATCH_WEIGHT };

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

// One observed technique, tied back to the event that produced it so the UI can jump from a matched
// playbook step straight to the evidence (#230: "click a step → jump to the events that match it").
export interface ObservedTechnique {
  technique: string; // normalized ATT&CK id, full granularity
  eventId: string; // the ForensicEvent this technique was tagged on
}

// A chronological technique sequence over some slice of the timeline: the whole case, or one host.
export interface ObservedSequence {
  scope: "case" | "host";
  host?: string; // the asset, when scope === "host"
  techniques: ObservedTechnique[];
}

// Per-step match result for a single playbook vs the observed sequence.
export interface PlaybookStepMatch {
  step: PlaybookStep;
  status: "matched" | "missing" | "out-of-order";
  matchedTechnique?: string; // the observed technique id that matched this step (when matched)
  matchedEventId?: string; // the forensic event that carried it — the UI's jump target (when matched)
  matchKind?: "exact" | "base"; // granularity of the match (when matched)
}

// One ranked playbook match.
export interface PlaybookMatch {
  name: string;
  description: string;
  score: number; // 0–100: in-order matched fraction (exact full, base partial), of the playbook steps
  matchedCount: number; // steps observed in order (exact + partial)
  exactCount: number; // steps matched at the exact sub-technique
  outOfOrderCount: number; // steps whose technique IS in this scope, but not at a position that keeps the chain
  missingCount: number; // steps whose technique never appears in this scope at all
  scope: "case" | "host"; // the slice that produced this (best-scoring) match
  host?: string; // the asset, when scope === "host"
  steps: PlaybookStepMatch[]; // per-step breakdown, in playbook order
}

export interface PlaybookMatchOptions {
  topN?: number; // cap on how many ranked playbooks to return (default DEFAULT_TOP_N)
  minScore?: number; // drop matches scoring below this (default DEFAULT_MIN_SCORE)
}

export const DEFAULT_TOP_N = 3;

// Floor on a reported match. Without one, a case that only ever observed T1486 (encryption — the
// one step EVERY ransomware playbook ends on) comes back as a ~20% "match" to all four playbooks,
// which reads as weak attribution rather than the non-signal it is. 40 = at least two of a five-step
// chain, exactly. Overridable per call and via DFIR_PLAYBOOK_MIN_SCORE.
export const DEFAULT_MIN_SCORE = 40;

// A single shared technique is an overlap, not a SEQUENCE: order needs at least two points to exist.
// Structural, so unlike minScore it is not tunable.
export const MIN_MATCHED_STEPS = 2;

// One wording for the disclaimer, shared by every surface that renders a match — mirrors
// ADVERSARY_HINTS_CAVEAT (#46). The panel says "matches playbook", never "is Conti".
export const PLAYBOOK_MATCH_CAVEAT =
  "Sequence similarity to a published playbook — not attribution.";

// Env-derived options, so the route, the report section and the dashboard panel all rank with the
// SAME threshold. `|| DEFAULT` deliberately also catches NaN from a typo'd value; an explicit 0 is
// honoured via the isFinite check so an operator can genuinely turn the floor off.
export function playbookMatchEnvOptions(): Required<PlaybookMatchOptions> {
  const rawMin = process.env.DFIR_PLAYBOOK_MIN_SCORE;
  return {
    topN: Number(process.env.DFIR_PLAYBOOK_TOP_N) || DEFAULT_TOP_N,
    minScore:
      rawMin !== undefined && Number.isFinite(Number(rawMin)) ? Number(rawMin) : DEFAULT_MIN_SCORE,
  };
}

// The ordered list of observed ATT&CK techniques derived from a case's forensic timeline, in
// chronological order, each carrying the event id it came from. Each event may contribute several
// techniques (all at the same instant); they are emitted in array order, deduped only against the
// immediately-preceding technique so a later real occurrence of the same technique still advances
// the sequence. Events with no parseable technique id contribute nothing. Ordering uses the shared
// sortByEventTime, which PARSES the timestamps — a plain string sort silently mis-orders mixed UTC
// offsets and floats empty timestamps to the front, and order is the whole point of this module.
export function observedTechniqueSequence(events: readonly ForensicEvent[]): ObservedTechnique[] {
  const seq: ObservedTechnique[] = [];
  let last: string | null = null;
  for (const e of sortByEventTime([...events])) {
    for (const raw of e.mitreTechniques ?? []) {
      const id = normalizeTechniqueId(raw);
      if (!id) continue;
      if (id === last) continue;
      seq.push({ technique: id, eventId: e.id });
      last = id;
    }
  }
  return seq;
}

// The scopes a case is matched at: the whole timeline, plus one slice per NAMED host. See the scope
// note at the top of the file for why both exist and why the unknown-asset bucket gets no slice.
// A single-host case gets no host scopes at all — they would duplicate the case scope exactly.
export function observedSequences(events: readonly ForensicEvent[]): ObservedSequence[] {
  const sequences: ObservedSequence[] = [{ scope: "case", techniques: observedTechniqueSequence(events) }];

  const byHost = new Map<string, ForensicEvent[]>();
  let unknownHostEvents = 0;
  for (const e of events) {
    const host = e.asset || UNKNOWN_HOST; // `||` not `??`: an empty-string asset means "unrecorded"
    if (host === UNKNOWN_HOST) {
      unknownHostEvents++;
      continue;
    }
    const bucket = byHost.get(host);
    if (bucket) bucket.push(e);
    else byHost.set(host, [e]);
  }
  // Every event on one named host ⇒ the host slice IS the case slice; skip the duplicate.
  if (byHost.size === 1 && unknownHostEvents === 0) return sequences;

  for (const [host, hostEvents] of [...byHost.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
    const techniques = observedTechniqueSequence(hostEvents);
    if (techniques.length === 0) continue;
    sequences.push({ scope: "host", host, techniques });
  }
  return sequences;
}

// Try to match a single playbook step against the observed sequence from a cursor onward, returning
// the matched technique + kind + the next cursor, or null when no in-order match exists. An exact
// (full-id) match is preferred over a base-only match at the same cursor position: the walk looks
// ahead for an exact match before accepting a partial one, so a coarse tag doesn't mask a precise one.
function matchStep(
  step: PlaybookStep,
  observed: readonly ObservedTechnique[],
  from: number,
): { observed: ObservedTechnique; kind: "exact" | "base"; next: number } | null {
  const stepId = normalizeTechniqueId(step.technique);
  const stepBase = stepId ? baseTechniqueId(stepId) : null;
  if (!stepId) return null;
  let partial: { observed: ObservedTechnique; next: number } | null = null;
  for (let i = from; i < observed.length; i++) {
    const obs = observed[i];
    if (obs.technique === stepId) return { observed: obs, kind: "exact", next: i + 1 };
    if (stepBase && baseTechniqueId(obs.technique) === stepBase) {
      if (!partial) partial = { observed: obs, next: i + 1 };
    }
  }
  return partial ? { observed: partial.observed, kind: "base", next: partial.next } : null;
}

// Score one playbook against one observed sequence: walk the steps in order, advancing the cursor on
// each in-order match. A step is `matched` when found in order, `missing` when its technique never
// appears in this scope at all, and `out-of-order` when the technique IS present but only BEFORE the
// cursor reached it (it exists, just not at a position that keeps the chain). The score is the
// in-order matched fraction weighted by match kind (exact = 1, base = BASE_MATCH_WEIGHT).
export function matchPlaybook(playbook: Playbook, sequence: ObservedSequence): PlaybookMatch {
  const observed = sequence.techniques;
  const steps: PlaybookStepMatch[] = [];
  let cursor = 0;
  let matched = 0;
  let exact = 0;
  let outOfOrder = 0;
  let weighted = 0;

  for (const step of playbook.steps) {
    const m = matchStep(step, observed, cursor);
    if (m) {
      steps.push({
        step,
        status: "matched",
        matchedTechnique: m.observed.technique,
        matchedEventId: m.observed.eventId,
        matchKind: m.kind,
      });
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
        (o) => o.technique === stepId || (!!stepBase && baseTechniqueId(o.technique) === stepBase),
      );
      if (seenSomewhere) outOfOrder++;
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
    outOfOrderCount: outOfOrder,
    missingCount: playbook.steps.length - matched - outOfOrder,
    scope: sequence.scope,
    ...(sequence.host ? { host: sequence.host } : {}),
    steps,
  };
}

// Order two candidate matches best-first: score, then exact agreement, then breadth, then name for
// deterministic output. Shared by the per-playbook best-scope pick and the final ranking so a
// "better match" means the same thing in both.
function betterMatch(a: PlaybookMatch, b: PlaybookMatch): number {
  return (
    b.score - a.score ||
    b.exactCount - a.exactCount ||
    b.matchedCount - a.matchedCount ||
    a.name.localeCompare(b.name)
  );
}

// Rank all playbooks and return the top-N. Each playbook is scored against EVERY scope and keeps its
// best (see the scope note above), then the survivors are ranked. A playbook is dropped unless it
// clears both the structural MIN_MATCHED_STEPS floor and `minScore` — see DEFAULT_MIN_SCORE for why
// a bare one-technique overlap must not surface as a match.
export function rankPlaybooks(
  playbooks: readonly Playbook[],
  sequences: readonly ObservedSequence[],
  opts: PlaybookMatchOptions = {},
): PlaybookMatch[] {
  const topN = Math.max(1, Math.floor(opts.topN ?? DEFAULT_TOP_N));
  const minScore = opts.minScore ?? DEFAULT_MIN_SCORE;
  const usable = sequences.filter((s) => s.techniques.length > 0);
  if (usable.length === 0) return [];

  const matches: PlaybookMatch[] = [];
  for (const p of playbooks) {
    const best = usable.map((s) => matchPlaybook(p, s)).sort(betterMatch)[0];
    if (!best) continue;
    if (best.matchedCount < MIN_MATCHED_STEPS) continue;
    if (best.score < minScore) continue;
    matches.push(best);
  }
  matches.sort(betterMatch);
  return matches.slice(0, topN);
}

export interface PlaybookMatchResult {
  observed: string[]; // the whole-case technique sequence, chronological (what the analyst reads as "the chain")
  scopes: ObservedSequence[]; // every slice matching ran over: the case, plus one per named host
  matches: PlaybookMatch[];
  minScore: number; // the floor applied, so a surface can say "nothing above N%" rather than "nothing"
  caveat: string; // PLAYBOOK_MATCH_CAVEAT — render it wherever matches are shown
  source: string;
  generated: string;
}

// Build the full result from a case's forensic timeline + a loaded dataset. Pure: the dataset and
// the events are passed in, so the route and the tests share one code path.
export function buildPlaybookMatchResult(
  events: readonly ForensicEvent[],
  dataset: KnownPlaybooksDataset,
  opts: PlaybookMatchOptions = {},
): PlaybookMatchResult {
  const scopes = observedSequences(events);
  const minScore = opts.minScore ?? DEFAULT_MIN_SCORE;
  const matches = rankPlaybooks(dataset.playbooks, scopes, { ...opts, minScore });
  return {
    observed: (scopes.find((s) => s.scope === "case")?.techniques ?? []).map((t) => t.technique),
    scopes,
    matches,
    minScore,
    caveat: PLAYBOOK_MATCH_CAVEAT,
    source: dataset.source,
    generated: dataset.generated,
  };
}
