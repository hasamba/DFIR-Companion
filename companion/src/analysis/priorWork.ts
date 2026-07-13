// Condition synthesis on what the investigator has ALREADY done (investigation-guidance #2). The one
// AI call that writes findings / nextSteps / keyQuestions currently sees the notebook and OPEN analyst
// hypotheses, but NOT: which playbook tasks are done/skipped, and which hypotheses the analyst REFUTED.
// So it re-recommends completed work and re-asserts ruled-out theories — wasting the analyst's time.
// The hunt-outcome block (huntOutcomes.renderPriorHuntsBlock, #157) already proved this feedback shape
// works; this module adds the two missing negative-knowledge blocks plus a deterministic post-parse
// safety net that demotes a returned nextStep which merely repeats a completed task.
//
// PURE — no I/O, no clock. Rendered blocks end in a blank line so they concatenate cleanly, and return
// "" when there is nothing to add (costing zero tokens on a fresh case). Unit-tested in isolation.

import type { PlaybookTask } from "./playbook.js";
import type { Hypothesis } from "./hypothesis.js";
import type { NextStep } from "./stateTypes.js";

const MAX_PLAYBOOK_LINES = 20;   // a compact digest — the analyst's whole board would bloat the prompt
const MAX_REFUTED = 15;          // bound the negative-knowledge block; refuted theories are few in practice

// The playbook DONE/SKIPPED digest. DONE tasks are results to BUILD ON (do not re-recommend); SKIPPED
// tasks were deliberately not investigated (may be re-raised only if new evidence warrants) — the two
// must not be conflated, or the model would treat a skipped lead as a closed one. "" when nothing is
// done or skipped (todo/in-progress tasks are the analyst's live queue, not prior work).
export function renderPlaybookProgressBlock(tasks: readonly PlaybookTask[], limit = MAX_PLAYBOOK_LINES): string {
  const done = (tasks ?? []).filter((t) => t.status === "done");
  const skipped = (tasks ?? []).filter((t) => t.status === "skipped");
  if (!done.length && !skipped.length) return "";
  const cap = Math.max(1, Math.floor(limit));
  const lines: string[] = [];
  for (const t of done.slice(0, cap)) lines.push(`- [DONE] ${t.title}`);
  for (const t of skipped.slice(0, Math.max(0, cap - done.length))) lines.push(`- [SKIPPED] ${t.title}`);
  return (
    "PLAYBOOK PROGRESS (work the investigator has already actioned — do NOT re-recommend a [DONE] task " +
    "as a nextStep; build on its result instead. A [SKIPPED] task was deliberately not pursued — re-raise " +
    "it only if new evidence now warrants):\n" +
    lines.join("\n") + "\n\n"
  );
}

// The NEGATIVE KNOWLEDGE block: hypotheses the analyst REFUTED (or that reached a refuted state and the
// analyst has touched — never model-only refutations, which would let synthesis reinforce its own
// mistakes). Telling the model a theory is dead stops it re-opening threads / deriving findings for it.
// "" when there are no analyst-refuted hypotheses.
export function renderRefutedHypothesesBlock(hypotheses: readonly Hypothesis[], limit = MAX_REFUTED): string {
  const refuted = (hypotheses ?? []).filter(
    (h) => h.status === "refuted" && (h.source === "analyst" || h.analystTouched),
  );
  // ACH exhaustion (investigation-guidance #14): a hypothesis whose hunts all came back empty is
  // negative knowledge too — the model should stop deriving findings for a theory the evidence hunt
  // exhausted, exactly like a refuted one. `exhausted` is set deterministically (markExhaustedHypotheses)
  // so it needs no analyst-touch gate.
  const exhausted = (hypotheses ?? []).filter((h) => h.exhausted && h.status !== "refuted");
  if (!refuted.length && !exhausted.length) return "";
  const cap = Math.max(1, Math.floor(limit));
  const refutedLines = refuted.slice(0, cap).map((h) => {
    const note = (h.notes ?? "").replace(/\s+/g, " ").trim().slice(0, 160);
    return `- [refuted] ${h.title}${note ? ` — ${note}` : ""}`;
  });
  const exhaustedLines = exhausted.slice(0, cap).map((h) => {
    const why = (h.exhaustedReason ?? "").replace(/\s+/g, " ").trim().slice(0, 160);
    return `- [exhausted] ${h.title}${why ? ` — ${why}` : ""}`;
  });
  return (
    "REFUTED / EXHAUSTED HYPOTHESES (the investigator ruled these out, or hunts for them came back empty — " +
    "do NOT re-assert them, re-open threads for them, or derive findings/nextSteps from them; treat each as " +
    "settled negative knowledge):\n" +
    [...refutedLines, ...exhaustedLines].join("\n") + "\n\n"
  );
}

// --- Post-parse safety net: demote a nextStep that just repeats a completed task --------------------

const GENERIC_MIN_LEN = 4; // ignore short/common words when measuring overlap (mirrors falsePositiveSimilarity)

function significantWords(text: string): Set<string> {
  return new Set(String(text ?? "").toLowerCase().split(/[^a-z0-9.\\/_-]+/i).filter((w) => w.length >= GENERIC_MIN_LEN));
}

// A "specific" token names a concrete collection TARGET — a host, artifact, filename, event id, path —
// not a generic verb ("pull", "review"). Heuristic: contains a digit, a dot, or a path separator. Two
// steps that share a specific token AND enough generic overlap are almost certainly the same task.
function isSpecificToken(tok: string): boolean {
  return /[0-9]/.test(tok) || tok.includes(".") || tok.includes("\\") || tok.includes("/");
}

// The text of a nextStep that identifies its target: action + pointer (the pointer carries the host/
// artifact when the action is generic).
function stepTargetText(s: NextStep): string {
  return `${s.action} ${s.pointer}`;
}

export interface DemoteResult {
  steps: NextStep[];
  demotedIds: string[]; // ids of steps that were demoted (for logging / meta)
}

// Demote (never silently drop) any returned nextStep that repeats a COMPLETED playbook task: it must
// share ≥2 significant words AND at least one SPECIFIC (host/artifact/id-like) token with a done task,
// so "pull Security.evtx on ALCLIENT07" (done) suppresses a repeat but NOT "pull Security.evtx on
// ALCLIENT09" (different host — the specific token 'alclient09' isn't shared). A demoted step drops to
// priority "low" and its rationale is annotated, so the analyst still sees it — just not near the top.
// Pure: returns new NextStep objects, never mutates the inputs.
export function demoteCompletedNextSteps(
  nextSteps: readonly NextStep[],
  doneTaskTitles: readonly string[],
): DemoteResult {
  const doneWordSets = (doneTaskTitles ?? [])
    .map((t) => ({ title: t, words: significantWords(t) }))
    .filter((d) => d.words.size > 0);
  if (!doneWordSets.length) return { steps: [...(nextSteps ?? [])], demotedIds: [] };

  const demotedIds: string[] = [];
  const steps = (nextSteps ?? []).map((s) => {
    const stepWords = significantWords(stepTargetText(s));
    const stepSpecific = [...stepWords].filter(isSpecificToken);
    for (const done of doneWordSets) {
      const shared = [...stepWords].filter((w) => done.words.has(w));
      const sharedSpecific = shared.some(isSpecificToken);
      // The step must introduce NO specific token the done task lacks — a new host/artifact/id token
      // (e.g. ALCLIENT09 vs the done ALCLIENT07) means a genuinely different target, so it survives
      // even though it shares the artifact/event-id tokens (security.evtx, 4624). This is what keeps a
      // same-verb, different-host recommendation alive instead of being wrongly suppressed.
      const introducesNewTarget = stepSpecific.some((t) => !done.words.has(t));
      if (shared.length >= 2 && sharedSpecific && !introducesNewTarget) {
        demotedIds.push(s.id);
        const note = `[likely already done — matches completed task: "${done.title.slice(0, 120)}"]`;
        return {
          ...s,
          priority: "low" as const,
          rationale: s.rationale ? `${s.rationale} ${note}` : note,
        };
      }
    }
    return s;
  });
  return { steps, demotedIds };
}
