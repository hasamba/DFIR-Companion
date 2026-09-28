import type { VeloHuntJob, VeloHuntStore } from "../veloHuntStore.js";
import {
  buildCollectionInventory,
  inventorySignature,
  renderCollectionInventory,
  sanitizeHuntJobs,
  type CollectionInventory,
} from "../collectionInventory.js";
import type { AIProvider } from "../../providers/provider.js";
import type { SynthesisFallback } from "./synthesisFallback.js";
import type { Logger } from "../../logging/logger.js";
import { recordSynthesisRun } from "../analysisRunRecorders.js";
import { noteSessionCommands } from "./sessionCommandNotes.js";
import type { AnalysisRunStore } from "../analysisRunStore.js";
import { toAnonPolicy, type AnonControlStore } from "../anonControl.js";
import type { AssetOverridesStore } from "../assetOverrides.js";
import type { VelociraptorClientStore } from "../velociraptorClientStore.js";
import type { HostDuplicateDismissalStore } from "../hostDuplicateDismissals.js";
import type { EvidenceAttestationStore } from "../evidenceAttestationStore.js";
import { alignedEpoch, detectClockSkew, detectHostTimeGaps, effectiveOffsets } from "../clockSkew.js";
import type { ClockSkewStore } from "../clockSkewStore.js";
import { correlateEventsTracked, correlationGroups, type CorrelateOptions } from "../correlate.js";
import { remapAbsorbedEventIds } from "../absorbedCitations.js";
import { repairBuildTimeRows } from "../buildTimeWindow.js";
import { CorrelationProfileStore } from "../correlationProfile.js";
import { filterFalsePositiveEvents, type FalsePositiveMarker } from "../falsePositive.js";
import { diffFindings, type FindingsDiff } from "../findingsDiff.js";
import { resolveHost, type HostAliasIndex } from "../hostAlias.js";
import { loadHostAliasIndex } from "../hostScopeLoad.js";
import {
  HostMergeDecisionRequired,
  hostNamesFromState,
  pendingNearDuplicates,
} from "../hostDuplicateGate.js";
import { autoGenerateHypotheses } from "./synthesisHypotheses.js";
import type { PlaybookTask } from "../playbook.js";
import { stripAiExtractedFrom } from "../responseSchema.js";
import { filterEventsByScope, NO_SCOPE, type ScopeWindow } from "../scope.js";
import { applyAcceptedSecondOpinion } from "../secondOpinion.js";
import type { SecondOpinionStore } from "../secondOpinionStore.js";
import { effectiveTrustMap, type SourceTrustMap } from "../sourceTrust.js";
import type { SourceTrustStore } from "../sourceTrustStore.js";
import type { StateLock } from "../stateLock.js";
import { mergeDelta, type WindowContext } from "../stateMerge.js";
import type { ForensicEvent, InvestigationState } from "../stateTypes.js";
import type { SuperTimelineStore } from "../superTimelineStore.js";
import type { SynthMetaStore } from "../synthMeta.js";
import type { SynthThinkingInput } from "../synthThinking.js";
import { getSynthesisPrompt } from "./prompts/index.js";
import type { AiCallContext } from "./aiContext.js";
import { type HuntContext } from "./hunts.js";
import { buildSynthesisPrompt, type SynthesisPromptContext } from "./synthesisPrompt.js";
import { newPromotedIds, nextPromotedSeen, promotedSignature } from "./promotedEvidence.js";
import { writeFindingTasks } from "./findingTaskPass.js";
import type { FindingTaskStore } from "../findingTaskStore.js";
import {
  computeSynthHash,
  loadSynthesisInputs,
  type SynthesisInputBlocks,
  type SynthesisInputContext,
} from "./synthesisInputs.js";
import { carryOutOfWindowFindings, foldSynthesisDelta, gradeFindings } from "./synthesisMerge.js";
import { persistSynthesis } from "./synthesisPersist.js";
import { callSynthesisModel, throwIfSuperseded, type SynthesisCall } from "./synthesisCall.js";
import { citationRunWarnings } from "./findingCitations.js";
import { skipEmptyTimeline, type SynthesisSkipReason } from "./synthesisSkip.js";
import { reconcileSimulationVerdict } from "../simulationVerdict.js";
import { stampCollectDirectives } from "../collectSatisfaction.js";
import type { PromotionIntent } from "../ingest/timelineImports.js";

/**
 * Synthesis: the AI call that turns the case's timeline into its conclusions (#418).
 *
 * The last and hardest of the extractions this issue owns, and the one #384 stopped short of. It is
 * hard because this is not a report — it REWRITES the case. Findings and ATT&CK techniques are
 * replaced wholesale, key questions are re-answered, IOCs are preserved and merged, and the write
 * has to survive whatever an import or an analyst did during the seconds the model was thinking.
 *
 * Prompt construction and the coverage audit live in ai/synthesisPrompt.ts. What is left here is the
 * orchestration: load, correlate, decide whether to run at all, call, fold the delta back in,
 * persist under the lock, record and notify. It writes the case ONCE, from one model call: the
 * second look that used to re-query the raw record and re-synthesize at the tail of every run is now
 * an analyst-pressed button in ai/secondLookRun.ts (#1554).
 *
 * WHY THE CONTEXT IS SO WIDE. Every other family in this directory takes a narrow interface because
 * a report genuinely touches little. Synthesis touches most of PipelineOptions, and pretending
 * otherwise by threading twenty parameters would hide that rather than fix it. The interface still
 * earns its place: it names exactly which stores participate, so adding one to synthesis becomes a
 * visible edit here instead of an invisible reach through `this`.
 */

/** What synthesis needs. Wide by nature — see the note above. */
export interface SynthesisContext
  extends AiCallContext, HuntContext, SynthesisPromptContext, SynthesisInputContext {
  readonly log: Logger;
  readonly opts: AiCallContext["opts"] &
    HuntContext["opts"] &
    SynthesisPromptContext["opts"] &
    // The notebook / hypothesis / playbook / incident-type stores come from here — they are the
    // pure-input stores, and synthesisInputs.ts is what reads them.
    SynthesisInputContext["opts"] & {
      provider?: AIProvider;
      correlationProfileStore?: CorrelationProfileStore;
      sourceTrustStore?: SourceTrustStore;
      clockSkewStore?: ClockSkewStore;
      secondOpinionStore?: SecondOpinionStore;
      superTimelineStore?: SuperTimelineStore;
      synthMetaStore?: SynthMetaStore;
      veloHuntStore?: VeloHuntStore;
      analysisRunStore?: AnalysisRunStore;
      anonStore?: AnonControlStore;
      stateLock?: StateLock;
      synthesisModelLabel?: string;
      synthesisFallback?: SynthesisFallback; // #1734
      synthesisSafetyRetries?: number; // #1740
      onSynth?: (caseId: string, diff: FindingsDiff, state: InvestigationState) => void;
      onState?: (state: InvestigationState) => void;
      assetOverridesStore?: AssetOverridesStore;
      velociraptorClientStore?: VelociraptorClientStore;
      hostDuplicateDismissalStore?: HostDuplicateDismissalStore;
      evidenceAttestationStore?: EvidenceAttestationStore;
      findingTaskStore?: FindingTaskStore;
    };
  /** mergeDelta plus the case's analyst IOC-merge aliases (#82). */
  mergeWithAliases(
    state: InvestigationState,
    delta: Parameters<typeof mergeDelta>[1],
    ctx: WindowContext,
  ): Promise<InvestigationState>;
  /** Promote raw super-timeline rows into the forensic timeline — the second-look button's seam. */
  promoteSuperTimeline(
    caseId: string,
    events: ForensicEvent[],
    opts: { importedAt: string; intent: PromotionIntent; tagById?: Record<string, string[]>; note?: string },
  ): Promise<InvestigationState>;
  /** Once per process: warn that a configured prompt override is missing shipped capabilities. */
  warnOnPromptDrift(): void;
  /**
   * Hash of the last successfully-synthesized inputs per case. Owned by the pipeline so it lives as
   * long as the process does: a fresh process (or an explicit `force`) always synthesizes.
   */
  readonly lastSynthHash: Map<string, string>;
}

async function detectSkew(
  ctx: SynthesisContext,
  caseId: string,
  preMerge: ForensicEvent[],
  opts: CorrelateOptions,
): Promise<((e: ForensicEvent) => number | undefined) | undefined> {
  const store = ctx.opts.clockSkewStore;
  if (!store) return undefined;
  let record;
  try {
    const report = detectClockSkew(correlationGroups(preMerge, { ...opts, crossHostArtifacts: true }), opts);
    // Measured offsets need a second clock; the gap warning does not (#740). Compute it from the
    // same PRE-merge timeline so a host whose clock is months out is reported even when the case has
    // no cross-host anchor at all — the silence that let INC-2026-020 through.
    record = await store.recordDetection(caseId, { ...report, timeGaps: detectHostTimeGaps(preMerge) });
  } catch {
    try {
      record = await store.load(caseId);
    } catch {
      return undefined;
    }
  }
  if (!record.alignEnabled) return undefined;
  const offsets = effectiveOffsets(record.results, record.overrides);
  if (offsets.size === 0) return undefined;
  return (e: ForensicEvent) => alignedEpoch(e, offsets);
}

interface PreparedRun {
  /** The correlated state. NOT the raw snapshot — the lost-update guard needs that separately. */
  state: InvestigationState;
  sourceTrust: SourceTrustMap;
  windowSeconds: number;
  markers: FalsePositiveMarker[];
  scope: ScopeWindow;
  /** After the scope filter only. */
  inWindowEvents: ForensicEvent[];
  /** After the additional false-positive/legitimate filter. */
  scopedEvents: ForensicEvent[];
  blocks: SynthesisInputBlocks;
  playbookTasks: PlaybookTask[];
  synthHash: string;
  /** The seen-set the last persisted run left, and the promoted rows new against it (#1586). */
  promotedSeen: string[];
  newPromotedIds: Set<string>;
  /** What the case holds, per source and host (#1588) — the prompt block and the backstop share it. */
  inventory: CollectionInventory;
}

/**
 * Everything a run needs decided before it can decide whether to run at all.
 *
 * Scope: only events inside the investigation window feed synthesis, so findings, IOCs, the attacker
 * path and the key questions reflect only in-scope activity. Events the analyst confirmed legitimate
 * are then dropped so the model never derives conclusions from benign activity — the raw events stay
 * in state, so it is reversible.
 *
 * The two filter stages stay separate so the coverage audit (#62) can attribute omissions:
 * `inWindowEvents` is after the scope filter, `scopedEvents` after the false-positive filter. The
 * prompt's token budget drops the rest.
 */
async function prepareSynthesisRun(
  ctx: SynthesisContext,
  caseId: string,
  loaded: InvestigationState,
  observationsBlock: string,
  aliasIndex?: HostAliasIndex,
): Promise<PreparedRun> {
  const { state, sourceTrust, windowSeconds } = await correlateForSynthesis(ctx, caseId, loaded);
  const markers = ctx.opts.falsePositiveStore ? await ctx.opts.falsePositiveStore.load(caseId) : [];
  const scope = ctx.opts.scopeStore ? await ctx.opts.scopeStore.load(caseId) : NO_SCOPE;
  const inWindowEvents = filterEventsByScope(state.forensicTimeline, scope);
  const scopedEvents = filterFalsePositiveEvents(inWindowEvents, markers);
  // The pure inputs — notebook, hypotheses, prior work, incident type — all loaded BEFORE the hash
  // so changing any of them triggers a fresh synthesis rather than a skip.
  const { blocks, playbookTasks } = await loadSynthesisInputs(ctx, caseId);
  const promotedSeen = await loadPromotedSeen(ctx, caseId);
  const hunts = await loadHuntJobs(ctx, caseId);
  // In-window, BEFORE the false-positive filter: a row marked benign still proves its source was
  // collected (#1588).
  const inventory = buildCollectionInventory({ events: inWindowEvents, hunts, aliasIndex });
  return {
    promotedSeen,
    inventory,
    newPromotedIds: newPromotedIds(scopedEvents, promotedSeen),
    state,
    sourceTrust,
    windowSeconds,
    markers,
    scope,
    inWindowEvents,
    scopedEvents,
    blocks,
    playbookTasks,
    synthHash: computeSynthHash({
      scopedEvents,
      iocs: state.iocs,
      scope,
      markers,
      blocks,
      observationsBlock,
      promoted: promotedSignature(scopedEvents),
      // The inventory can change with no new row — a hunt came back empty, a host alias merged two
      // spellings, a row's provenance changed — so the whole rendered inventory is hashed (#1588).
      inventory: `${renderCollectionInventory(inventory)}\n${inventorySignature(hunts)}`,
    }),
  };
}

/** Fail-soft: hunt metadata is supplemental — unreadable means no hunt lines, never a failed run. */
async function loadHuntJobs(ctx: SynthesisContext, caseId: string): Promise<VeloHuntJob[]> {
  try {
    return sanitizeHuntJobs((await ctx.opts.veloHuntStore?.list(caseId)) ?? []);
  } catch (err) {
    ctx.log.warn(
      `[synthesis] velo-hunt.json unreadable, inventory has no hunt lines: ${(err as Error).message}`,
      {
        caseId,
      },
    );
    return [];
  }
}

/**
 * Fail-soft: synth-meta is an optional side file. A missing or unreadable one means no promoted row
 * has been seen, so every promoted row counts as new (capped) — the safe direction for evidence.
 */
async function loadPromotedSeen(ctx: SynthesisContext, caseId: string): Promise<string[]> {
  try {
    return (await ctx.opts.synthMetaStore?.load(caseId))?.promotedShown ?? [];
  } catch (err) {
    ctx.log.warn(
      `[synthesis] synth-meta unreadable, treating promoted rows as new: ${(err as Error).message}`,
      {
        caseId,
      },
    );
    return [];
  }
}

/**
 * Bring the finding set to its final form, in the one order that is correct.
 *
 * Durability first (issue #116): re-apply any analyst-ACCEPTED second-opinion deltas after the
 * wholesale findings rewrite, so a confirmed model-B finding/severity/technique is never lost on
 * re-synthesis. Pure + idempotent; a no-op when the store or record is absent or empty.
 *
 * Then per-finding grounding + corroboration (investigation-guidance #6): resolve each finding's
 * supporting in-scope events (forward relatedEventIds AND reverse forensicTimeline links, so the
 * deterministic backfill findings ground correctly), roll up { tools, hosts, intel, graph-linked },
 * flag an uncited finding as `ungrounded`, and CAP an ungrounded/single-source finding's confidence.
 * It also catches the subtler case where cited ids resolve but the finding's own claimed IP never
 * appears in their text (`contentMismatch`) — flooring High/Critical to Medium (veridia-deep-pass
 * 2026-07-22).
 *
 * Grading runs LAST so it sees the final set, backfills and accepted second-opinion deltas included.
 * Deterministic + idempotent; it only ever lowers a confidence or a severity.
 */
async function finalizeFindings(
  ctx: SynthesisContext,
  caseId: string,
  folded: InvestigationState,
  input: {
    delta: ReturnType<typeof stripAiExtractedFrom>;
    surviving: Set<string>;
    eligibleIds: Set<string>;
    sourceTrust: SourceTrustMap;
    aliasIndex: HostAliasIndex;
  },
): Promise<InvestigationState> {
  const withAccepted = ctx.opts.secondOpinionStore
    ? applyAcceptedSecondOpinion(folded, await ctx.opts.secondOpinionStore.load(caseId))
    : folded;
  const graded = gradeFindings({
    next: withAccepted,
    delta: input.delta,
    surviving: input.surviving,
    eligibleIds: input.eligibleIds,
    sourceTrust: input.sourceTrust,
    kevCatalog: await ctx.getKevCatalog(),
    aliasIndex: input.aliasIndex,
  });
  // #1595: after grading, which only lowers — the simulation verdict RAISES its own finding. It
  // judges the verdict on the model's own confidence, which grading may have capped.
  const modelConfidence = new Map(
    withAccepted.findings.flatMap((f) => (f.confidence !== undefined ? [[f.id, f.confidence] as const] : [])),
  );
  return reconcileSimulation(ctx, caseId, graded, input.aliasIndex, modelConfidence);
}

/** The simulation verdict (#1595) with the analyst's override read fresh. No store: never overridden. */
async function reconcileSimulation(
  ctx: SynthesisContext,
  caseId: string,
  state: InvestigationState,
  aliasIndex: HostAliasIndex,
  modelConfidence?: ReadonlyMap<string, number>,
): Promise<InvestigationState> {
  const treatAsReal = (await ctx.opts.synthMetaStore?.treatAsReal(caseId)) ?? false;
  return reconcileSimulationVerdict(state, {
    treatAsReal,
    aliasIndex,
    ...(modelConfidence ? { modelConfidence } : {}),
  });
}

interface SynthesisOutcome {
  /** The state as persisted. */
  next: InvestigationState;
  /** What the run decided before calling: the correlated state, scope, markers, window. */
  run: PreparedRun;
  call: SynthesisCall;
  prompt: Awaited<ReturnType<typeof buildSynthesisPrompt>>;
  findingsDiff: FindingsDiff;
  synthProvider: AIProvider;
  synthStart: number;
  highSeverityBackfillCount: number;
  observationsBlock: string;
  parentRunId: string | undefined;
  /** #1599: the out-of-date revision read before the case load — see SynthMetaStore.record. */
  startRevision: number;
  /** #1754: the run-record warnings for findings that cite no event. */
  citationWarnings: string[];
}

/**
 * The two durable records of a real run: the synth-meta card the dashboard reads, and the full
 * analysis-run row. Only reached on a real run — a skipped one returns before the model call.
 */
/**
 * The model's surviving findings that ground on no event after the fold and grading (#1754): logged by
 * id, and worded for the run record. Deterministic backfills are not the model's and are not counted.
 */
function uncitedFindingWarnings(
  ctx: SynthesisContext,
  caseId: string,
  next: InvestigationState,
  delta: SynthesisCall["delta"],
  surviving: ReadonlySet<string>,
  call: SynthesisCall,
): string[] {
  const modelIds = new Set(delta.findings.map((f) => f.id).filter((id) => surviving.has(id)));
  const model = next.findings.filter((f) => modelIds.has(f.id));
  const uncited = model.filter((f) => !(f.relatedEventIds ?? []).length).map((f) => f.id);
  if (uncited.length)
    ctx.log.warn(
      `[synthesis] ${uncited.length} of ${model.length} findings cite no event: ${uncited.join(", ")}`,
      {
        caseId,
      },
    );
  return citationRunWarnings({
    uncited: uncited.length,
    total: model.length,
    ...(call.citationRetriedAfter ? { retriedAfter: call.citationRetriedAfter } : {}),
  });
}

async function recordSynthesisOutcome(
  ctx: SynthesisContext,
  caseId: string,
  o: SynthesisOutcome,
): Promise<void> {
  await ctx.opts.synthMetaStore?.record(caseId, o.findingsDiff, new Date().toISOString(), {
    durationMs: Date.now() - o.synthStart,
    eventCount: o.next.forensicTimeline.length,
    iocCount: o.next.iocs.length,
    // #4: the evidence mix the model saw. Pinned new promoted rows (#1586) are not picked by the
    // stratifier, so they are counted beside its seven classes rather than hidden from the mix.
    selectionCounts: {
      ...o.prompt.selection.counts,
      ...(o.prompt.promotedPinned ? { promoted: o.prompt.promotedPinned } : {}),
    },
    // #1586: only rows shown on their OWN line count as seen — a member folded into a burst row was
    // never presented to the model as the new evidence it is.
    promotedShown: nextPromotedSeen(
      o.run.promotedSeen,
      o.next.forensicTimeline,
      new Set(o.prompt.promptEvents.map((e) => e.id)),
    ),
    coverage: o.prompt.coverage, // #62: included/omitted coverage audit
    synthModel: o.call.answeredByLabel, // #74; the fallback's label after a #1734 safety stop
    findingsCount: o.next.findings.length, // #74
    highSeverityBackfillCount: o.highSeverityBackfillCount, // #74
    parseRetries: o.call.parseRetries, // #74
    startRevision: o.startRevision, // #1599: not persisted — decides whether the out-of-date mark survives
    // #1554: the model's own "I was not shown this" requests. Persisted because the second-look
    // sweep no longer runs inside this call — the analyst presses it later, from another process.
    modelEvidenceRequests: (o.call.delta.evidenceRequests ?? []).map((r) => ({
      keywords: r.keywords,
      reason: r.reason,
      ...(r.host ? { host: r.host } : {}),
      ...(r.timeWindow ? { timeWindow: r.timeWindow } : {}),
    })),
  });
  const anonPolicy = toAnonPolicy(ctx.opts.anonStore ? await ctx.opts.anonStore.load(caseId) : null);
  await recordSynthesisRun(ctx.opts.analysisRunStore, caseId, {
    parentRunId: o.parentRunId,
    startedAt: new Date(o.synthStart).toISOString(),
    provider: o.call.answeredBy.name, // #1734: the provider whose answer was accepted
    model: o.call.answeredBy.model,
    ...(o.call.resolvedModel ? { resolvedModel: o.call.resolvedModel } : {}),
    eventIds: [...o.prompt.shownIds],
    inputState: o.run.state,
    outputState: o.next,
    prompt: getSynthesisPrompt(),
    maxEvents: o.prompt.maxEvents,
    thinkingTokens: o.call.thinkingTokens,
    thinkingSource: o.call.thinkingSource,
    correlationWindowSeconds: o.run.windowSeconds,
    anonymizationPolicy: anonPolicy,
    scope: o.run.scope,
    falsePositiveMarkers: o.run.markers.length,
    infoEventsExcluded: o.prompt.omittedInfo > 0,
    observationsIncluded: o.observationsBlock.length > 0,
    // The run's retries are every extra model call: parse retries and the #1754 citation retry.
    parseRetries: o.call.parseRetries + o.call.citationRetries,
    coverage: o.prompt.coverage,
    citationWarnings: o.citationWarnings,
  });
}

/**
 * Correlate the same artifact across tools: deduplicate into one corroborated event carrying both
 * sources. Idempotent, and the correlated timeline is what gets persisted.
 *
 * Clock skew is measured PRE-merge (#228), before correlation erases the disagreeing anchors that
 * reveal it. Aligned times guide the correlation windows; persisted events keep their recorded
 * timestamps. Source trust (#66) both selects the merge wording and later caps low-trust-only
 * findings, so it is resolved here and handed on.
 */
async function correlateForSynthesis(
  ctx: SynthesisContext,
  caseId: string,
  loaded: InvestigationState,
): Promise<{ state: InvestigationState; sourceTrust: SourceTrustMap; windowSeconds: number }> {
  const envWindow = Number(process.env.DFIR_CORRELATE_WINDOW_S);
  const corrProfile = await ctx.opts.correlationProfileStore?.load(caseId);
  const windowSeconds = Number.isFinite(envWindow) ? envWindow : (corrProfile?.windowSeconds ?? 2);
  const trustOverrides = ctx.opts.sourceTrustStore ? await ctx.opts.sourceTrustStore.load(caseId) : undefined;
  const sourceTrust = effectiveTrustMap(trustOverrides);
  const skew = await detectSkew(ctx, caseId, loaded.forensicTimeline, { windowSeconds, sourceTrust });
  // The case's own window and clock-skew alignment can fold rows the import did not; every citation
  // of a folded-away id follows it to the survivor before grading reads it (#1714).
  const { events, absorbedInto } = correlateEventsTracked(loaded.forensicTimeline, {
    windowSeconds,
    sourceTrust,
    epochOf: skew,
  });
  const correlated = remapAbsorbedEventIds({ ...loaded, forensicTimeline: events }, absorbedInto);
  // Correlation merges rows, and this timeline is persisted (#1698). A repair, not the import-time cap:
  // windows are found at the import seam before demote, and this record no longer holds the Info
  // markers that opened them, so recomputing here could lift a valid cap. It also repairs a case
  // correlated before this rule, on its next synthesis rather than its next import.
  return { windowSeconds, sourceTrust, state: repairBuildTimeRows(correlated).state };
}

// The pre-synthesis merge gate. Runs before the prompt is built so a blocked run spends no tokens
// and writes no state.
//
// RETURNS the index it had to build anyway, because every downstream render site needs the same one
// and rebuilding it per site would re-read both stores a dozen times per run. The GATE is enabled
// only when the dismissal store is wired (see PipelineOptions), but the INDEX is always built — a
// merge must still resolve host names even on an install running with the gate off.
async function resolveHostsOrThrow(
  ctx: SynthesisContext,
  caseId: string,
  state: InvestigationState,
): Promise<HostAliasIndex> {
  const aliasIndex = await loadHostAliasIndex(
    {
      ...(ctx.opts.assetOverridesStore ? { assetOverrides: ctx.opts.assetOverridesStore } : {}),
      ...(ctx.opts.velociraptorClientStore ? { fleet: ctx.opts.velociraptorClientStore } : {}),
    },
    caseId,
  );
  const dismissalStore = ctx.opts.hostDuplicateDismissalStore;
  if (!dismissalStore) return aliasIndex;
  const pending = pendingNearDuplicates(
    hostNamesFromState(state),
    aliasIndex,
    await dismissalStore.load(caseId),
  );
  if (pending.length) throw new HostMergeDecisionRequired(pending);
  return aliasIndex;
}

/**
 * ABOVE 50 LINES ON PURPOSE (#453). Everything here is a single named step and a hand-off of its
 * result to the next one: load, prepare, decide-to-run, prompt, call, fold, finalize, persist,
 * record, notify. Each step's DETAIL lives in its own function or module; what is left is the
 * ORDER, and the order is the thing most likely to be got wrong.
 *
 * Splitting this further would mean inventing a "commit phase" or a "post-call phase" — groupings
 * with no meaning outside the split itself — and would put the fold, the grading and the write in
 * three places, when the whole reason the lost-update guard is correct is that you can see it
 * happens AFTER grading and BEFORE the run record. A reader who needs to know what synthesis does,
 * in order, should need exactly one screen and no jumps. That is what this is.
 */
// #1734/#1740: the Investigation-Log note for a synthesis the safety filter stopped at least once.
function safetyLogNote(call: SynthesisCall): string {
  const times = `${call.safetyStops} ${call.safetyStops === 1 ? "time" : "times"}`;
  if (call.fallbackFrom)
    return `written by the fallback model ${call.answeredByLabel} after ${call.fallbackFrom}'s safety filter stopped the answer ${times}`;
  return `${call.primaryLabel}'s safety filter stopped the answer ${times}; it passed on retry`;
}

export async function synthesize(
  ctx: SynthesisContext,
  caseId: string,
  opts: {
    force?: boolean;
    dryRun?: boolean;
    provider?: AIProvider;
    signal?: AbortSignal;
    observationsBlock?: string;
    analysisParentRunId?: string;
    /** #1676: called when the run stops before any model call because there is nothing to synthesize. */
    onSkip?: (reason: SynthesisSkipReason) => void;
  } & SynthThinkingInput = {},
): Promise<InvestigationState> {
  const observationsBlock = opts.observationsBlock ?? "";
  const synthProvider = opts.provider ?? ctx.opts.synthesisProvider ?? ctx.requireProvider("synthesis");
  ctx.warnOnPromptDrift(); // once per process: a stale synthesis-prompt override silently drops shipped capabilities
  throwIfSuperseded(opts.signal); // a run superseded before it started spends no state load and no prompt
  // #1599: read BEFORE the case load, so a change marked after this point is one this run cannot see
  // and its "conclusions out of date" marker survives the run's record.
  const startRevision = (await ctx.opts.synthMetaStore?.revision(caseId)) ?? 0;
  const loaded = await ctx.opts.stateStore.load(caseId);
  if (loaded.forensicTimeline.length === 0)
    return skipEmptyTimeline(ctx.opts.synthMetaStore, caseId, loaded, startRevision, opts);
  const aliasIndex = await resolveHostsOrThrow(ctx, caseId, loaded);

  const run = await prepareSynthesisRun(ctx, caseId, loaded, observationsBlock, aliasIndex);
  const { state, sourceTrust, markers, scope, scopedEvents, synthHash } = run;
  if (!opts.force && !opts.dryRun && ctx.lastSynthHash.get(caseId) === synthHash) return loaded;

  // The prompt, and the coverage audit that describes exactly what it showed the model. Kept whole
  // because the run record describes the prompt, so it wants nearly every field.
  const prompt = await buildSynthesisPrompt(ctx, {
    caseId,
    state,
    scope,
    markers,
    inWindowEvents: run.inWindowEvents,
    scopedEvents,
    observationsBlock,
    aliasIndex,
    newPromotedIds: run.newPromotedIds,
    collectionInventory: run.inventory,
    ...run.blocks,
  });

  const synthStart = Date.now();
  throwIfSuperseded(opts.signal); // building the prompt takes seconds on a large case
  const call = await callSynthesisModel(ctx, caseId, state, synthProvider, prompt.userPrompt, {
    ...opts,
    shownEventIds: prompt.shownIds,
  });
  const { delta } = call;

  // THE ONE THAT MATTERS. Everything below writes: the fold grades findings, persistSynthesis saves
  // the case, and recordSynthesisOutcome appends a run to the manifest chain. A superseded run that
  // gets past here overwrites the run that replaced it.
  throwIfSuperseded(opts.signal);

  const {
    next: folded,
    highSeverityBackfillCount,
    eligibleIds,
    surviving,
    // The fold's delta, not this scope's: an invented deterministic id was renamed on the way in
    // (#787), and grading keys the model's relevance verdict on the id the case now holds.
    delta: foldedDelta,
    recoveredCitations,
  } = await foldSynthesisDelta(ctx, {
    caseId,
    state,
    delta,
    markers,
    scopedEvents,
    playbookTasks: run.playbookTasks,
    inventory: run.inventory,
    hostOf: (raw) => resolveHost(aliasIndex, raw),
    membersOf: prompt.membersOf,
    promptEventIds: new Set(prompt.promptEvents.map((e) => e.id)),
  });
  for (const r of recoveredCitations)
    ctx.log.warn(
      `[synthesis] ${r.findingId} cited no event; recovered ${r.eventIds.join(", ")} from its text`,
      {
        caseId,
      },
    );
  let next = folded;
  if (opts.dryRun) return next;

  next = await finalizeFindings(ctx, caseId, next, {
    delta: foldedDelta,
    surviving,
    eligibleIds,
    sourceTrust,
    aliasIndex,
  });
  // Quiet session commands no finding names (#1594): a structured note, set AFTER grading because it
  // is not evidence the finding claims. Reads the scoped forensic timeline only.
  next = noteSessionCommands(next, { scopedEvents, hostOf: (raw) => resolveHost(aliasIndex, raw) });

  // Scope is a lens, not a shredder (#751). This run rebuilt its conclusions from an empty base over
  // the events inside the window, so a narrowed window would otherwise DELETE the deterministic
  // findings a wider earlier run had persisted outside it — irreversibly, since widening again gives
  // the backfills nothing to re-derive them from. Re-attach those, untouched and with their event
  // links, and let projectScope hide them for as long as the narrow window is set. AFTER grading, so
  // a carried finding keeps the confidence it was stored with; a no-op when no scope is set.
  next = carryOutOfWindowFindings(next, { prior: state, inWindowEvents: run.inWindowEvents, markers });

  // Every collection request this run is about to persist — the model's, and the corroboration steps
  // grading just added — is stamped with the import high-water mark it was issued against, so the
  // next run's SATISFIED COLLECTIONS block can only cite evidence that arrived AFTER the request. The
  // evidence a request was written about must never be handed back as its result
  // (collectSatisfaction.ts). LAST, after grading, so nothing downstream adds an unstamped request;
  // against `loaded` — the persisted case, every import, before correlation merged any row.
  next = stampCollectDirectives(next, loaded);

  // What this run changed vs the pre-AI findings. Findings are FINAL here — neither persistLatest
  // nor the hypothesis auto-gen below touch them — so it's computed once and reused for the
  // Investigation-Log entry (#165), the synth-meta record, and the notify hook.
  const findingsDiff = diffFindings(loaded.findings, next.findings);

  // Lost-update guard (mirrors the pinned-questions re-load in the delta fold): a manual
  // event/IOC/thread added DURING the seconds-long AI call would otherwise be clobbered by this
  // write, because `next` was derived from the snapshot taken before the call.
  throwIfSuperseded(opts.signal); // #1608: superseded during the async fold and grading above
  next = await persistSynthesis(ctx, caseId, {
    loaded,
    next,
    findingsDiff,
    reconcile: (merged) => reconcileSimulation(ctx, caseId, merged, aliasIndex),
    ...(call.safetyStops > 0 ? { logNote: safetyLogNote(call) } : {}),
  });
  // #1608: superseded while persisting — the newer run owns hypotheses, finding tasks, the record.
  throwIfSuperseded(opts.signal);
  await autoGenerateHypotheses(ctx, caseId, foldedDelta.hypotheses, next, markers, aliasIndex);
  // #1418: one more call turns each Critical/High finding into an analyst task for the playbook.
  await writeFindingTasks(ctx, caseId, next, { provider: synthProvider });

  ctx.lastSynthHash.set(caseId, synthHash); // remember these inputs so an identical re-run skips the AI call
  await recordSynthesisOutcome(ctx, caseId, {
    next,
    run,
    call,
    prompt,
    findingsDiff,
    synthProvider,
    synthStart,
    highSeverityBackfillCount,
    observationsBlock,
    parentRunId: opts.analysisParentRunId,
    startRevision,
    citationWarnings: uncitedFindingWarnings(ctx, caseId, next, foldedDelta, surviving, call),
  });
  // Notify on new/escalated findings (issue #58). Best-effort, fire-and-forget — never blocks or
  // fails synthesis. Only on a real run, so a skipped (unchanged) re-synthesis sends nothing.
  ctx.opts.onSynth?.(caseId, findingsDiff, next);
  ctx.opts.onState?.(next);

  return next;
}
