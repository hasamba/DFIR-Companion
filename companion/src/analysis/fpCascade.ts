// Immediate false-positive cascade (investigation-guidance #12). Marking a finding/IOC/event false
// positive only takes effect at the NEXT synthesis today, so between the mark and the (seconds-long,
// async) re-synthesis the dashboard keeps showing answers and next-steps that rested on the rejected
// finding. This module is the PURE core of a synchronous reconsideration the FP-mark route runs the
// instant a marker is saved: any key question or next-step that depended on a now-rejected finding is
// flipped to a neutral "re-evaluate" state and badged "stale — re-synthesis queued", so the analyst is
// never shown a conclusion the evidence no longer supports.
//
// The SAME reconsiderKeyQuestions transform is reused by synthesize() (its long-standing deterministic
// backstop that a key question can never keep citing a finding that's gone) — with staleReSynth off,
// since that path IS the authoritative recompute, not an interim.

import type { InvestigationQuestion, NextStep } from "./stateTypes.js";

// Pointer text shown on a question whose supporting finding was rejected. Identical wording the
// synthesize() backstop has always used, so the two paths read the same.
export const FP_RESET_POINTER =
  "re-evaluate — the finding(s) that supported this answer were marked false positive";

// Whole-word (id-boundary) match of a finding id inside free text — catches a question/step's dependency
// on a finding via its 'pointer'/'answer'/'action' prose (e.g. "Findings f1 and f2") when there is no
// structured relatedFindingIds link (the item predates that field, or the model only named it in prose).
// Escapes regex metacharacters since ids can contain them (e.g. "f-auto-e1").
export function textMentionsFindingId(text: string | undefined, findingId: string): boolean {
  if (!text) return false;
  const escaped = findingId.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`(?<![\\w-])${escaped}(?![\\w-])`, "i").test(text);
}

export interface ReconsiderQuestionsInput {
  survivingFindingIds: ReadonlySet<string>; // finding ids that REMAIN (after FP removal / after synthesis)
  priorFindingIds: readonly string[];       // finding ids that existed going in (to catch prose mentions)
  staleReSynth?: boolean;                    // true for the synchronous FP-route pass → badge the reset
}

export interface ReconsiderQuestionsResult {
  questions: InvestigationQuestion[];
  changed: boolean;
}

// Reset any key question that depends — structurally (relatedFindingIds) OR texturally (pointer/answer
// prose) — on a finding that is no longer among the surviving set. ANY dependency on a rejected finding
// forces the reset (not just total loss of support): a partial answer still naming a finding the analyst
// just rejected is misleading even when another finding also backs it, and we can't safely guess the
// finding-minus-the-rejected-one answer without asking the model again. Pure + idempotent; dead
// relatedFindingIds links are always pruned. `staleReSynth` badges the reset for the interim FP-route
// pass and is CLEARED on every question on the authoritative synthesize pass (staleReSynth falsey).
export function reconsiderKeyQuestions(
  questions: readonly InvestigationQuestion[],
  input: ReconsiderQuestionsInput,
): ReconsiderQuestionsResult {
  const prior = input.priorFindingIds;
  let changed = false;
  const next = questions.map((q) => {
    // Drop staleReSynth from the carried-over fields; it's re-added below only when this pass sets it,
    // so the authoritative synthesize pass always clears a stale badge left by an earlier interim pass.
    const { staleReSynth: _prevStale, ...rest } = q;
    const related = (q.relatedFindingIds ?? []).filter((id) => input.survivingFindingIds.has(id));
    const structuralLoss = (q.relatedFindingIds ?? []).some((id) => !input.survivingFindingIds.has(id));
    const textualLoss = prior.some(
      (id) => !input.survivingFindingIds.has(id) && (textMentionsFindingId(q.pointer, id) || textMentionsFindingId(q.answer, id)),
    );
    const isReset = (structuralLoss || textualLoss) && q.status !== "unknown";
    if (isReset) {
      changed = true;
      return {
        ...rest,
        relatedFindingIds: related,
        status: "unknown" as const,
        answer: "",
        pointer: FP_RESET_POINTER,
        ...(input.staleReSynth ? { staleReSynth: true } : {}),
      };
    }
    // No reset: prune dead links, and if this removed any link or cleared a prior stale badge, that's a
    // change worth persisting.
    if (related.length !== (q.relatedFindingIds ?? []).length || _prevStale) changed = true;
    return { ...rest, relatedFindingIds: related };
  });
  return { questions: next, changed };
}

export interface ReconsiderStepsInput {
  removedFindingIds: ReadonlySet<string>; // finding ids rejected by the new markers
  staleReSynth?: boolean;
}

export interface ReconsiderStepsResult {
  steps: NextStep[];
  changed: boolean;
}

// Badge any next-step that advances a now-rejected finding (structural relatedFindingIds link OR a prose
// mention in action/pointer/rationale) as stale, so the dashboard stops presenting "do X to confirm
// finding fN" once fN is gone. Non-destructive — the step text is untouched; only the badge is added
// (the model rewrites the list wholesale on the next synthesis). Pure + idempotent.
export function reconsiderNextSteps(
  steps: readonly NextStep[],
  input: ReconsiderStepsInput,
): ReconsiderStepsResult {
  if (!input.removedFindingIds.size) {
    // Nothing rejected → only clear any lingering stale badge.
    let cleared = false;
    const next = steps.map((s) => {
      if (!s.staleReSynth) return s;
      cleared = true;
      const { staleReSynth: _drop, ...rest } = s;
      return rest;
    });
    return { steps: next, changed: cleared };
  }
  let changed = false;
  const removed = [...input.removedFindingIds];
  const next = steps.map((s) => {
    const { staleReSynth: _prevStale, ...rest } = s;
    const structural = (s.relatedFindingIds ?? []).some((id) => input.removedFindingIds.has(id));
    const textual = removed.some(
      (id) => textMentionsFindingId(s.action, id) || textMentionsFindingId(s.pointer, id) || textMentionsFindingId(s.rationale, id),
    );
    const stale = structural || textual;
    if (stale && input.staleReSynth) {
      changed = true;
      return { ...rest, staleReSynth: true };
    }
    if (_prevStale) changed = true; // clear a stale badge that no longer applies
    return rest;
  });
  return { steps: next, changed };
}
