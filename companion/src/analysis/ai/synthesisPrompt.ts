import { buildAttackPhases } from "../burstDetect.js";
import { detectBeacons, beaconEnvOptions } from "../beaconDetect.js";
import { detectSatisfiedCollections, buildSatisfiedCollectionsBlock } from "../collectSatisfaction.js";
import {
  applyFalsePositive,
  buildFalsePositiveContext,
  buildAuthorizedContextBlock,
  type FalsePositiveMarker,
} from "../falsePositive.js";
import { textMentionsFindingId } from "../fpCascade.js";
import { corroborationLabel } from "../findingGrounding.js";
import { buildGraphContext, DEFAULT_MAX_GRAPH_EDGES } from "../graphContext.js";
import { buildLearnedPatternsBlock } from "../learnedPatterns.js";
import type { LearnedPatternStore } from "../learnedPatternStore.js";
import { buildPrevalenceIndex, eventPrevalence, prevalenceTag, rarityScore } from "../prevalence.js";
import { estimateTokens, inputTokenBudget, fitItemsToBudget } from "../promptBudget.js";
import { hasScope, type ScopeWindow } from "../scope.js";
import type { ForensicEvent, InvestigationState } from "../stateTypes.js";
import { renderStructuredTags, buildBeaconDigest, buildAttackPhaseDigest } from "../synthEvidence.js";
import {
  collapseForPrompt,
  renderGroupSuffix,
  groupEnvOptions,
  groupingEnabled,
  maxPromptEvents,
  promptCandidates,
  type CollapsedPrompt,
} from "../synthGroup.js";
import { buildSynthesisCoverage, type SynthesisCoverage } from "../synthMeta.js";
import {
  buildSynthesisContext,
  selectSynthesisEventsAnnotated,
  type SelectionClass,
} from "../synthSelect.js";
import { getSynthesisPrompt } from "./prompts/index.js";
import type { AiCallContext } from "./aiContext.js";
import { adversaryHintBlock, knownUnknownsBlock, type PromptBlockContext } from "./promptBlocks.js";

/**
 * Synthesis prompt construction and the coverage audit that describes it (#418).
 *
 * Split out of `synthesize` because it is a different KIND of work from the rest of that function:
 * everything here is a pure-ish transformation of an already-loaded case into one string, whereas
 * the orchestration around it loads stores, calls a model and writes state. Keeping them together is
 * what made the 695-line version impossible to review — a change to how an event row renders sat 400
 * lines away from the lock that protects the write.
 *
 * The coverage audit (#62) is computed HERE and not by the caller, and that is deliberate: it must
 * describe the prompt that was actually sent. Every omission it reports — out of scope, confirmed
 * legitimate, Info-severity, over the size budget — is a decision made in this file, and a
 * denominator computed anywhere else would eventually stop matching them.
 */

/** Everything the prompt builder consumes. The blocks are loaded by the caller BEFORE the skip-hash. */
export interface SynthesisPromptInput {
  caseId: string;
  /** The correlated state this run is reasoning over (not the raw snapshot). */
  state: InvestigationState;
  scope: ScopeWindow;
  markers: FalsePositiveMarker[];
  /** After the scope filter only — the coverage audit needs it separately from `scopedEvents`. */
  inWindowEvents: ForensicEvent[];
  scopedEvents: ForensicEvent[];
  /** The blocks that are also hashed for skip-if-unchanged, so they are loaded before this runs. */
  observationsBlock: string;
  notebookBlock: string;
  analystHypothesesBlock: string;
  refutedHypothesesBlock: string;
  priorHuntsBlock: string;
  playbookProgressBlock: string;
  incidentTypeBlock: string;
}

/** The prompt, plus what the run record and the second-look sweep need to describe it. */
export interface SynthesisPromptResult {
  userPrompt: string;
  /** The rows the model was shown. A grouped row stands for its whole burst. */
  promptEvents: ForensicEvent[];
  /** Every scoped event the model saw, INCLUDING the members a grouped row represents. */
  representedEvents: ForensicEvent[];
  shownIds: Set<string>;
  selection: ReturnType<typeof selectSynthesisEventsAnnotated>;
  coverage: SynthesisCoverage;
  maxEvents: number;
  omittedInfo: number;
}

/** What the prompt builder needs: the KEV catalog, the learned-pattern store, and the gap blocks. */
export interface SynthesisPromptContext extends PromptBlockContext {
  readonly opts: PromptBlockContext["opts"] & { learnedPatternStore?: LearnedPatternStore };
}

export async function buildSynthesisPrompt(
  ctx: SynthesisPromptContext,
  input: SynthesisPromptInput,
): Promise<SynthesisPromptResult> {
  const {
    caseId,
    state,
    scope,
    markers,
    inWindowEvents,
    scopedEvents,
    observationsBlock,
    notebookBlock,
    analystHypothesesBlock,
    refutedHypothesesBlock,
    priorHuntsBlock,
    playbookProgressBlock,
    incidentTypeBlock,
  } = input;

  // Detection-burst grouping (spec 2026-07-21): the same Sigma/YARA detection firing hundreds of
  // times used to consume hundreds of prompt seats. Collapse each burst to ONE representative row so
  // every DISTINCT detection reaches the model. Prompt-only and derived on read — `scopedEvents` (and
  // therefore the case, the coverage denominators and the high-severity backfill) is untouched.
  // The explicit CollapsedPrompt annotation matters: without it the disabled branch's bare `new Map()`
  // infers Map<unknown, unknown> and every later `grouping.groupById.get(...)` fails to typecheck.
  // Info-severity events don't get prompt seats (DFIR_SYNTH_INCLUDE_INFO=1 restores them): on a real
  // case 213 Info rows pushed the prompt from 546 to 759 entries, past the cap, costing 26 GRADED
  // detections their place. They remain in the case, the timeline and the coverage denominators —
  // this only decides who gets budget.
  const eligibleForPrompt = promptCandidates(scopedEvents);
  const omittedInfo = scopedEvents.length - eligibleForPrompt.length;
  const grouping: CollapsedPrompt = groupingEnabled()
    ? collapseForPrompt(eligibleForPrompt, groupEnvOptions())
    : { events: [...eligibleForPrompt], groupById: new Map(), memberIdsByRepresentative: new Map() };
  const collapsedEvents = grouping.events;

  // Bound the prompt for large imports (e.g. THOR: hundreds of events + auto-findings).
  // Send the MOST SEVERE events (then most recent) up to a cap, and truncate each
  // description — this keeps the request affordable (avoids OpenRouter 402 on a giant
  // request) and inside the model's context. The deterministic high-severity backfill
  // still creates findings for any Critical/High event NOT shown here (eligibleIds below
  // is the full scoped set), so capping the prompt never loses a severe detection.
  const SYNTH_MAX_EVENTS = maxPromptEvents();
  // Per-case prevalence/baseline (investigation-guidance #15): how common each activity PATTERN is
  // across the WHOLE case timeline (not just the scoped subset — the baseline is a property of the
  // corpus). Feeds a rarity bias into the selection fill (a 1-off wins a seat over 500× noise) and a
  // common/rare tag into each rendered event so the model gets explicit baseline context.
  const prevalenceIndex = buildPrevalenceIndex(state.forensicTimeline);
  const rarityOf = (e: ForensicEvent): number => rarityScore(e, prevalenceIndex);
  // Stratified selection: all Critical/High + the earliest (initial-access) + an even
  // time-spread sample, chronologically — better kill-chain coverage than severity-only. The ANNOTATED
  // form (investigation-guidance #4) exposes which CLASS claimed each event, so renderEvent can prefix
  // context-only rows with "~" (the model reads anchors vs supporting context) and the synth-meta card
  // can show the analyst what evidence classes the model actually saw.
  let selection = selectSynthesisEventsAnnotated(collapsedEvents, SYNTH_MAX_EVENTS, rarityOf);
  let promptEvents = selection.events;
  // Context classes: everything that is NOT a primary verdict-bearing anchor / initial-access event —
  // these are the supporting rows the model should read as context, marked "~" in the timeline.
  const CONTEXT_CLASSES = new Set<SelectionClass>([
    "anchor_context",
    "corroborated",
    "technique",
    "rare",
    "spread",
  ]);
  const isContext = (id: string): boolean => CONTEXT_CLASSES.has(selection.classOf.get(id) as SelectionClass);

  const scopeNote = hasScope(scope)
    ? `INVESTIGATION SCOPE: only consider activity from ${scope.start ?? "the beginning"} to ${scope.end ?? "now"}. ` +
      `Events outside this window have already been removed below.\n\n`
    : "";
  // Cap the existing-findings echo too (a big import can produce 100s of auto-findings). Append the
  // prior run's corroboration label (investigation-guidance #6) so the model sees which of its own
  // earlier claims were weak/uncorroborated and can strengthen or drop them this run.
  const existingFindings =
    state.findings
      .slice(0, 150)
      .map((f) => {
        const corr = corroborationLabel(f);
        return `[${f.id}] ${f.title}${corr ? ` — ${corr}` : ""}`;
      })
      .join("\n") || "(none yet)";
  const openThreads =
    state.openThreads
      .filter((t) => t.status === "open")
      .map((t) => `[${t.id}] ${t.description}`)
      .join("\n") || "(none open)";
  const falsePositiveBlock = buildFalsePositiveContext(markers);
  // Rabbit-hole detection (#13): authorized-test / known-good-tool markers are RETAINED as shaping
  // context (a sanctioned pentest during the window is signal, not just noise), not merely erased.
  const authorizedContextBlock = buildAuthorizedContextBlock(markers);
  // Learn from dismissals (#65): recurring reasoned dismissals → a "PREVIOUSLY DISMISSED PATTERNS" block
  // that DOWN-WEIGHTS (not excludes) new look-alike activity. Distinct from the two blocks above: those
  // act on EXACT current markers; this generalizes. Env-tunable recurrence floor. Best-effort/optional.
  let learnedPatternsBlock = "";
  if (ctx.opts.learnedPatternStore) {
    const minCount = Number(process.env.DFIR_LEARNED_PATTERN_MIN_COUNT) || undefined;
    learnedPatternsBlock = buildLearnedPatternsBlock(
      await ctx.opts.learnedPatternStore.load(caseId),
      minCount,
    );
  }
  // Compact, corroborated context (compromised assets + threat-intel verdicts + KEV hits)
  // so the model grounds findings/attacker-path in structure instead of inferring blind.
  const kevCatalog = await ctx.getKevCatalog();
  const contextBlock = buildSynthesisContext(state, scopedEvents, kevCatalog);
  // Known unknowns (#165): the gaps in the story (silent windows, uncovered ATT&CK phases, likely-
  // next techniques) so the model builds on what's MISSING instead of glossing over it. Plus the
  // (env-gated, default OFF) candidate-actor block. Both DERIVED — computed AFTER the skip-hash
  // above, so they never affect skip-if-unchanged.
  const unknownsBlock = await knownUnknownsBlock(ctx, state, scopedEvents, caseId);
  const adversaryBlock = adversaryHintBlock(state);
  // Structured causal evidence (investigation-guidance #5), all DERIVED after the skip-hash so they
  // never affect skip-if-unchanged: the deterministic ATTACK GRAPH (spawn/file-lineage/lateral/network
  // edges with confidence+rule — previously fed only to ask()/suggestHunts(), never the call that
  // writes findings), the statistically-confirmed periodic-beacon candidates, and the activity-phase
  // digest. These give synthesis the cross-host structure it was inferring blind from truncated prose.
  const graphBlock = buildGraphContext(
    { ...state, forensicTimeline: scopedEvents },
    { maxEdges: DEFAULT_MAX_GRAPH_EDGES },
  );
  const beaconBlock = buildBeaconDigest(detectBeacons(scopedEvents, beaconEnvOptions()));
  const attackPhaseBlock = buildAttackPhaseDigest(buildAttackPhases(scopedEvents));
  // Import-satisfaction (investigation-guidance #8, phase 2): a collection this case previously
  // recommended (prior nextSteps / unknown questions carrying a structured collect target) whose host
  // now HAS matching events was fulfilled — stop re-recommending it and re-evaluate the question it
  // served. Derived from the PRIOR run's guidance vs the current events; the served questions are
  // added to the re-answer set below so the model reconsiders them with the new evidence.
  const satisfiedCollections = detectSatisfiedCollections(state, scopedEvents);
  const satisfiedBlock = buildSatisfiedCollectionsBlock(satisfiedCollections);
  const satisfiedQuestionIds = new Set(
    satisfiedCollections.filter((s) => s.target.from === "question").map((s) => s.target.refId),
  );
  // Analyst-pinned open questions: tell the model to address each (answer when the evidence
  // now supports it) and keep them. They're re-merged into the output below so they persist.
  const pinnedQuestions = state.keyQuestions.filter((q) => q.pinned);
  const pinnedBlock = pinnedQuestions.length
    ? `OPEN QUESTIONS TO ADDRESS (include EACH in keyQuestions with the SAME id; answer with ` +
      `status/answer + supporting relatedEventIds if the evidence now supports it, else status ` +
      `"unknown" with a 'pointer' to the artifact to collect):\n` +
      pinnedQuestions.map((q) => `[${q.id}] ${q.question}`).join("\n") +
      "\n\n"
    : "";
  // A finding just confirmed false-positive forces a re-answer of any key question that cited it
  // as support — otherwise a question "answered" from a finding the analyst just rejected would
  // keep looking answered until the model happens to reconsider it unprompted. The sanitize pass
  // after the AI call (below, near applyFalsePositive) is the deterministic backstop for when the
  // model ignores this and echoes the stale answer back.
  const droppedFindingIds = new Set(
    state.findings
      .filter((f) => !applyFalsePositive(state, markers).findings.some((k) => k.id === f.id))
      .map((f) => f.id),
  );
  const questionsToReanswer = state.keyQuestions.filter((q) => {
    if (q.pinned) return false;
    // A question whose recommended collection was just satisfied (#8 phase 2) must be re-evaluated
    // with the evidence now present, not left showing its old "unknown".
    if (satisfiedQuestionIds.has(q.id)) return true;
    if ((q.relatedFindingIds ?? []).some((id) => droppedFindingIds.has(id))) return true;
    // Fallback for a question that predates relatedFindingIds (or whose answer only ever named
    // the finding in prose): its free-text pointer/answer still cites the now-rejected finding.
    return [...droppedFindingIds].some(
      (id) => textMentionsFindingId(q.pointer, id) || textMentionsFindingId(q.answer, id),
    );
  });
  const reanswerBlock = questionsToReanswer.length
    ? `QUESTIONS TO RE-ANSWER (a finding backing this answer was just confirmed a FALSE POSITIVE — ` +
      `re-evaluate using ONLY the CURRENT findings/evidence, ignoring the rejected finding entirely; ` +
      `if nothing else supports it, set status "unknown", clear the answer, and set relatedFindingIds ` +
      `to []):\n` +
      questionsToReanswer.map((q) => `[${q.id}] ${q.question} (previously: "${q.answer}")`).join("\n") +
      "\n\n"
    : "";

  // Token budget: trim the timeline so the WHOLE prompt fits the model context — the rest
  // (context block, findings echo, system prompt) is the fixed overhead. Re-select for the
  // smaller count so the kept events stay the most important; the high-severity backfill
  // still creates findings for any Critical/High event dropped here.
  // Each event carries its structured tags (host / process lineage / src→dst / corroborating-source
  // count) after the prose (investigation-guidance #5) — only when set, so a bare event costs no extra
  // tokens. This is what lets the model connect cross-host activity instead of guessing from prose.
  const renderEvent = (e: ForensicEvent) => {
    // Grouped rows carry their own count/host-spread/span suffix, which supersedes the prevalence
    // tag — showing both would state the same repetition twice in different words.
    const group = grouping.groupById.get(e.id);
    const groupTag = group ? renderGroupSuffix(group) : "";
    // Prevalence baseline tag (#15): only the informative extremes (clearly common / clearly rare) are
    // tagged, so the model knows a 500× pattern is routine and a 1-off is anomalous.
    const p = group ? null : eventPrevalence(e, prevalenceIndex);
    const prevTag = p ? prevalenceTag(p) : "";
    // "~" prefix (investigation-guidance #4): this row is supporting CONTEXT (pulled in to explain an
    // anchor), not itself a primary verdict-bearing event — so the model weights it as background.
    const ctx = isContext(e.id) ? "~" : "";
    return `${ctx}[${e.id}] ${e.timestamp || "(undated)"} [${e.severity}] ${e.description.slice(0, 240)}${renderStructuredTags(e)}${groupTag}${prevTag ? ` ⟨${prevTag}⟩` : ""}`;
  };
  const synthOverhead =
    estimateTokens(getSynthesisPrompt()) +
    estimateTokens(
      incidentTypeBlock +
        scopeNote +
        contextBlock +
        graphBlock +
        beaconBlock +
        attackPhaseBlock +
        unknownsBlock +
        adversaryBlock +
        notebookBlock +
        analystHypothesesBlock +
        refutedHypothesesBlock +
        priorHuntsBlock +
        playbookProgressBlock +
        satisfiedBlock +
        pinnedBlock +
        reanswerBlock +
        observationsBlock +
        existingFindings +
        openThreads +
        falsePositiveBlock +
        authorizedContextBlock +
        learnedPatternsBlock +
        (state.lastSummary || ""),
    ) +
    400;
  const fit = fitItemsToBudget(promptEvents, renderEvent, Math.max(0, inputTokenBudget() - synthOverhead));
  if (fit < promptEvents.length) {
    selection = selectSynthesisEventsAnnotated(collapsedEvents, fit, rarityOf);
    promptEvents = selection.events;
  }

  const timelineText = promptEvents.map(renderEvent).join("\n");
  // Coverage audit (#62): what the model actually saw this run vs what was left out and why. Computed
  // here where promptEvents + the token overhead are final. Of the budget-omitted events, the safety-net
  // backfill (below) still guarantees a finding for any Critical/High, so surface that count too.
  // A grouped row stands for every member of its burst, so all of those events were SEEN by the model —
  // counting only the representative would report the rest as "omitted for the size limit", the
  // opposite of the truth.
  const shownIds = new Set<string>();
  let groupEntries = 0;
  let groupedEvents = 0;
  for (const e of promptEvents) {
    shownIds.add(e.id);
    const members = grouping.memberIdsByRepresentative.get(e.id);
    if (!members) continue;
    groupEntries += 1;
    groupedEvents += members.length;
    for (const id of members) shownIds.add(id);
  }
  const representedEvents = scopedEvents.filter((e) => shownIds.has(e.id));
  const omittedHighSeverity = scopedEvents.filter(
    (e) => !shownIds.has(e.id) && (e.severity === "Critical" || e.severity === "High"),
  ).length;
  const synthCoverage: SynthesisCoverage = buildSynthesisCoverage({
    totalEvents: state.forensicTimeline.length,
    inWindow: inWindowEvents.length,
    scoped: scopedEvents.length,
    considered: shownIds.size,
    groupEntries,
    groupedEvents,
    omittedInfo,
    omittedHighSeverity,
    promptTokensEstimate: synthOverhead + estimateTokens(timelineText),
  });
  const truncatedNote =
    scopedEvents.length > shownIds.size
      ? ` — showing ${shownIds.size} of ${scopedEvents.length}; ${scopedEvents.length - shownIds.size} event(s) omitted from this prompt but still in the case`
      : "";
  // Legend for the "~" context prefix (investigation-guidance #4) — only when at least one context row
  // is present, so it costs nothing on a small case.
  const contextLegend = promptEvents.some((e) => isContext(e.id))
    ? ' Rows prefixed "~" are SUPPORTING CONTEXT (pulled in to explain a nearby anchor), not primary findings — weight them as background.'
    : "";
  const userPrompt =
    incidentTypeBlock +
    scopeNote +
    contextBlock +
    graphBlock +
    beaconBlock +
    attackPhaseBlock +
    unknownsBlock +
    adversaryBlock +
    notebookBlock +
    analystHypothesesBlock +
    refutedHypothesesBlock +
    priorHuntsBlock +
    playbookProgressBlock +
    satisfiedBlock +
    pinnedBlock +
    reanswerBlock +
    observationsBlock +
    `FORENSIC TIMELINE (${scopedEvents.length} dated events${truncatedNote}).${contextLegend}\n${timelineText}\n\n` +
    `EXISTING FINDINGS (update by id, do not duplicate):\n${existingFindings}\n\n` +
    `CURRENTLY OPEN THREADS (close by id in threadsClosed when the evidence resolves them):\n${openThreads}\n\n` +
    (falsePositiveBlock ? `${falsePositiveBlock}\n\n` : "") +
    (authorizedContextBlock ? `${authorizedContextBlock}\n\n` : "") +
    (learnedPatternsBlock ? `${learnedPatternsBlock}\n\n` : "") +
    `Running notes: ${state.lastSummary || "(none)"}\n\nReturn the JSON conclusions.`;

  return {
    userPrompt,
    promptEvents,
    representedEvents,
    shownIds,
    selection,
    coverage: synthCoverage,
    maxEvents: SYNTH_MAX_EVENTS,
    omittedInfo,
  };
}

// Satisfies the AiCallContext constraint without widening it here — the context this module
// declares is a superset, and TypeScript checks the assignment at every call site.
export type { AiCallContext };
