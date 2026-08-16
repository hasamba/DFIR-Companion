import { detectBeacons, beaconEnvOptions } from "../beaconDetect.js";
import { buildAttackPhases } from "../burstDetect.js";
import { detectSatisfiedCollections, buildSatisfiedCollectionsBlock } from "../collectSatisfaction.js";
import {
  applyFalsePositive,
  buildFalsePositiveContext,
  buildAuthorizedContextBlock,
  type FalsePositiveMarker,
} from "../falsePositive.js";
import { corroborationLabel } from "../findingGrounding.js";
import { textMentionsFindingId } from "../fpCascade.js";
import { buildGraphContext, DEFAULT_MAX_GRAPH_EDGES } from "../graphContext.js";
import type { HostAliasIndex } from "../hostAlias.js";
import type { LearnedPatternStore } from "../learnedPatternStore.js";
import { buildLearnedPatternsBlock } from "../learnedPatterns.js";
import { hasScope, type ScopeWindow } from "../scope.js";
import type { ForensicEvent, InvestigationState } from "../stateTypes.js";
import { buildBeaconDigest, buildAttackPhaseDigest } from "../synthEvidence.js";
import { buildSynthesisContext } from "../synthSelect.js";
import { adversaryHintBlock, knownUnknownsBlock, type PromptBlockContext } from "./promptBlocks.js";

/**
 * The narrative blocks that surround the synthesis timeline, and the two places they are
 * concatenated (#453, split from `buildSynthesisPrompt`).
 *
 * Sibling to `synthesisPromptEvents.ts`, which owns the timeline itself. Everything here is a block
 * of prose or a rendered list; nothing here decides which events the model sees.
 *
 * WHY THE TWO CONCATENATIONS LIVE TOGETHER. The blocks are joined twice — once to size the fixed
 * overhead against the token budget, once to build the prompt actually sent — and the two orders
 * must agree or the budget is measured against a prompt that was never assembled. `estimateTokens`
 * is `ceil(length / 4)`, so summing per-block estimates is NOT the same number as estimating the
 * joined string; both callers must therefore join the same way. `leadingBlocks` is the shared
 * prefix, which is what makes that agreement structural rather than a comment asking you to notice.
 */

/** What the block builders need: the KEV catalog, the learned-pattern store, and the gap blocks. */
export interface SynthesisPromptContext extends PromptBlockContext {
  readonly opts: PromptBlockContext["opts"] & { learnedPatternStore?: LearnedPatternStore };
}

/** Every block, in the order they are concatenated. Field order here IS the prompt order. */
export interface SynthesisBlocks {
  incidentTypeBlock: string;
  scopeNote: string;
  contextBlock: string;
  graphBlock: string;
  beaconBlock: string;
  attackPhaseBlock: string;
  unknownsBlock: string;
  adversaryBlock: string;
  notebookBlock: string;
  analystHypothesesBlock: string;
  refutedHypothesesBlock: string;
  priorHuntsBlock: string;
  playbookProgressBlock: string;
  satisfiedBlock: string;
  pinnedBlock: string;
  reanswerBlock: string;
  observationsBlock: string;
  existingFindings: string;
  openThreads: string;
  falsePositiveBlock: string;
  authorizedContextBlock: string;
  learnedPatternsBlock: string;
}

/** The blocks the caller loads before the skip-hash, passed through unchanged. */
export interface PreloadedBlocks {
  observationsBlock: string;
  notebookBlock: string;
  analystHypothesesBlock: string;
  refutedHypothesesBlock: string;
  priorHuntsBlock: string;
  playbookProgressBlock: string;
  incidentTypeBlock: string;
}

export interface BlockInput {
  caseId: string;
  state: InvestigationState;
  scope: ScopeWindow;
  markers: FalsePositiveMarker[];
  scopedEvents: ForensicEvent[];
  preloaded: PreloadedBlocks;
  /** Canonical host identity for this run — forwarded to every block that renders or ranks a host. */
  aliasIndex?: HostAliasIndex;
}

/**
 * Build every derived block. The DERIVED ones (graph, beacons, phases, unknowns, adversary,
 * satisfied) are computed AFTER the skip-hash by construction — they are made here, and the hash is
 * taken over `preloaded` — so they never affect skip-if-unchanged.
 */
export async function buildSynthesisBlocks(
  ctx: SynthesisPromptContext,
  input: BlockInput,
): Promise<SynthesisBlocks> {
  const { caseId, state, scope, markers, scopedEvents, preloaded, aliasIndex } = input;
  // Loaded FIRST, before getKevCatalog() and knownUnknownsBlock(), because that is where the
  // original read it. A dismissal recorded during those awaits would otherwise land in this block
  // while the rest of the run reflects the earlier snapshot — and a load failure would now surface
  // after the KEV work rather than instead of it.
  const learnedPatternsBlock = await buildLearnedPatterns(ctx, caseId);
  const satisfied = buildSatisfiedBlock(state, scopedEvents);
  return {
    ...preloaded,
    scopeNote: buildScopeNote(scope),
    // Compact, corroborated context (compromised assets + threat-intel verdicts + KEV hits) so the
    // model grounds findings/attacker-path in structure instead of inferring blind.
    contextBlock: buildSynthesisContext(state, scopedEvents, await ctx.getKevCatalog(), aliasIndex),
    // Structured causal evidence (investigation-guidance #5): the deterministic ATTACK GRAPH
    // (spawn/file-lineage/lateral/network edges with confidence+rule — previously fed only to
    // ask()/suggestHunts(), never the call that writes findings), the statistically-confirmed
    // periodic-beacon candidates, and the activity-phase digest. These give synthesis the cross-host
    // structure it was inferring blind from truncated prose.
    graphBlock: buildGraphContext(
      { ...state, forensicTimeline: scopedEvents },
      { maxEdges: DEFAULT_MAX_GRAPH_EDGES },
    ),
    beaconBlock: buildBeaconDigest(detectBeacons(scopedEvents, beaconEnvOptions())),
    attackPhaseBlock: buildAttackPhaseDigest(buildAttackPhases(scopedEvents)),
    // Known unknowns (#165): the gaps in the story (silent windows, uncovered ATT&CK phases,
    // likely-next techniques) so the model builds on what's MISSING instead of glossing over it.
    // Plus the (env-gated, default OFF) candidate-actor block.
    unknownsBlock: await knownUnknownsBlock(ctx, state, scopedEvents, caseId, aliasIndex),
    adversaryBlock: adversaryHintBlock(state),
    satisfiedBlock: satisfied.block,
    pinnedBlock: buildPinnedBlock(state),
    reanswerBlock: buildReanswerBlock(state, markers, satisfied.questionIds),
    existingFindings: buildFindingsEcho(state),
    openThreads: buildOpenThreads(state),
    falsePositiveBlock: buildFalsePositiveContext(markers),
    // Rabbit-hole detection (#13): authorized-test / known-good-tool markers are RETAINED as shaping
    // context (a sanctioned pentest during the window is signal, not just noise), not merely erased.
    authorizedContextBlock: buildAuthorizedContextBlock(markers),
    learnedPatternsBlock,
  };
}

function buildScopeNote(scope: ScopeWindow): string {
  if (!hasScope(scope)) return "";
  return (
    `INVESTIGATION SCOPE: only consider activity from ${scope.start ?? "the beginning"} to ` +
    `${scope.end ?? "now"}. Events outside this window have already been removed below.\n\n`
  );
}

/**
 * Cap the existing-findings echo (a big import can produce 100s of auto-findings). Append the prior
 * run's corroboration label (investigation-guidance #6) so the model sees which of its own earlier
 * claims were weak/uncorroborated and can strengthen or drop them this run.
 */
function buildFindingsEcho(state: InvestigationState): string {
  return (
    state.findings
      .slice(0, 150)
      .map((f) => {
        const corr = corroborationLabel(f);
        return `[${f.id}] ${f.title}${corr ? ` — ${corr}` : ""}`;
      })
      .join("\n") || "(none yet)"
  );
}

function buildOpenThreads(state: InvestigationState): string {
  return (
    state.openThreads
      .filter((t) => t.status === "open")
      .map((t) => `[${t.id}] ${t.description}`)
      .join("\n") || "(none open)"
  );
}

/**
 * Learn from dismissals (#65): recurring reasoned dismissals → a "PREVIOUSLY DISMISSED PATTERNS"
 * block that DOWN-WEIGHTS (not excludes) new look-alike activity. Distinct from the false-positive
 * and authorized-context blocks: those act on EXACT current markers; this generalizes. Env-tunable
 * recurrence floor. Best-effort/optional — no store configured means no block.
 */
async function buildLearnedPatterns(ctx: SynthesisPromptContext, caseId: string): Promise<string> {
  const store = ctx.opts.learnedPatternStore;
  if (!store) return "";
  const minCount = Number(process.env.DFIR_LEARNED_PATTERN_MIN_COUNT) || undefined;
  return buildLearnedPatternsBlock(await store.load(caseId), minCount);
}

/**
 * Import-satisfaction (investigation-guidance #8, phase 2): a collection this case previously
 * recommended (prior nextSteps / unknown questions carrying a structured collect target) whose host
 * now HAS matching events was fulfilled — stop re-recommending it and re-evaluate the question it
 * served. The served question ids join the re-answer set so the model reconsiders them with the new
 * evidence.
 */
function buildSatisfiedBlock(
  state: InvestigationState,
  scopedEvents: ForensicEvent[],
): { block: string; questionIds: Set<string> } {
  const satisfied = detectSatisfiedCollections(state, scopedEvents);
  return {
    block: buildSatisfiedCollectionsBlock(satisfied),
    questionIds: new Set(satisfied.filter((s) => s.target.from === "question").map((s) => s.target.refId)),
  };
}

/**
 * Analyst-pinned open questions: tell the model to address each (answer when the evidence now
 * supports it) and keep them. They're re-merged into the output downstream so they persist.
 */
function buildPinnedBlock(state: InvestigationState): string {
  const pinned = state.keyQuestions.filter((q) => q.pinned);
  if (!pinned.length) return "";
  return (
    `OPEN QUESTIONS TO ADDRESS (include EACH in keyQuestions with the SAME id; answer with ` +
    `status/answer + supporting relatedEventIds if the evidence now supports it, else status ` +
    `"unknown" with a 'pointer' to the artifact to collect):\n` +
    pinned.map((q) => `[${q.id}] ${q.question}`).join("\n") +
    "\n\n"
  );
}

/**
 * A finding just confirmed false-positive forces a re-answer of any key question that cited it as
 * support — otherwise a question "answered" from a finding the analyst just rejected would keep
 * looking answered until the model happens to reconsider it unprompted. The sanitize pass after the
 * AI call is the deterministic backstop for when the model ignores this and echoes the stale answer.
 */
function buildReanswerBlock(
  state: InvestigationState,
  markers: FalsePositiveMarker[],
  satisfiedQuestionIds: Set<string>,
): string {
  const kept = applyFalsePositive(state, markers).findings;
  const droppedFindingIds = new Set(
    state.findings.filter((f) => !kept.some((k) => k.id === f.id)).map((f) => f.id),
  );
  const toReanswer = state.keyQuestions.filter((q) => {
    if (q.pinned) return false;
    // A question whose recommended collection was just satisfied (#8 phase 2) must be re-evaluated
    // with the evidence now present, not left showing its old "unknown".
    if (satisfiedQuestionIds.has(q.id)) return true;
    if ((q.relatedFindingIds ?? []).some((id) => droppedFindingIds.has(id))) return true;
    // Fallback for a question that predates relatedFindingIds (or whose answer only ever named the
    // finding in prose): its free-text pointer/answer still cites the now-rejected finding.
    return [...droppedFindingIds].some(
      (id) => textMentionsFindingId(q.pointer, id) || textMentionsFindingId(q.answer, id),
    );
  });
  if (!toReanswer.length) return "";
  return (
    `QUESTIONS TO RE-ANSWER (a finding backing this answer was just confirmed a FALSE POSITIVE — ` +
    `re-evaluate using ONLY the CURRENT findings/evidence, ignoring the rejected finding entirely; ` +
    `if nothing else supports it, set status "unknown", clear the answer, and set relatedFindingIds ` +
    `to []):\n` +
    toReanswer.map((q) => `[${q.id}] ${q.question} (previously: "${q.answer}")`).join("\n") +
    "\n\n"
  );
}

/** The blocks that precede the timeline, in prompt order. Shared by both concatenations below. */
function leadingBlocks(b: SynthesisBlocks): string {
  return (
    b.incidentTypeBlock +
    b.scopeNote +
    b.contextBlock +
    b.graphBlock +
    b.beaconBlock +
    b.attackPhaseBlock +
    b.unknownsBlock +
    b.adversaryBlock +
    b.notebookBlock +
    b.analystHypothesesBlock +
    b.refutedHypothesesBlock +
    b.priorHuntsBlock +
    b.playbookProgressBlock +
    b.satisfiedBlock +
    b.pinnedBlock +
    b.reanswerBlock +
    b.observationsBlock
  );
}

/**
 * The fixed overhead the timeline has to fit around: every block plus the running notes, WITHOUT
 * the section headers. Estimated as one joined string because `estimateTokens` rounds up per call.
 */
export function overheadSourceText(b: SynthesisBlocks, lastSummary: string): string {
  return (
    leadingBlocks(b) +
    b.existingFindings +
    b.openThreads +
    b.falsePositiveBlock +
    b.authorizedContextBlock +
    b.learnedPatternsBlock +
    lastSummary
  );
}

export interface TimelineSection {
  timelineText: string;
  /** The scoped total, which the header reports against what was actually shown. */
  scopedCount: number;
  truncatedNote: string;
  contextLegend: string;
  lastSummary: string;
}

export function assembleUserPrompt(b: SynthesisBlocks, t: TimelineSection): string {
  return (
    leadingBlocks(b) +
    `FORENSIC TIMELINE (${t.scopedCount} dated events${t.truncatedNote}).${t.contextLegend}\n${t.timelineText}\n\n` +
    `EXISTING FINDINGS (update by id, do not duplicate):\n${b.existingFindings}\n\n` +
    `CURRENTLY OPEN THREADS (close by id in threadsClosed when the evidence resolves them):\n${b.openThreads}\n\n` +
    (b.falsePositiveBlock ? `${b.falsePositiveBlock}\n\n` : "") +
    (b.authorizedContextBlock ? `${b.authorizedContextBlock}\n\n` : "") +
    (b.learnedPatternsBlock ? `${b.learnedPatternsBlock}\n\n` : "") +
    `Running notes: ${t.lastSummary || "(none)"}\n\nReturn the JSON conclusions.`
  );
}
