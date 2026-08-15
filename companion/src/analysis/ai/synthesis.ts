import type { AIProvider } from "../../providers/provider.js";
import type { Logger } from "../../logging/logger.js";
import { recordSynthesisRun } from "../analysisRunRecorders.js";
import type { AnalysisRunStore } from "../analysisRunStore.js";
import { toAnonPolicy, type AnonControlStore } from "../anonControl.js";
import type { AssetOverridesStore } from "../assetOverrides.js";
import type { VelociraptorClientStore } from "../velociraptorClientStore.js";
import type { HostDuplicateDismissalStore } from "../hostDuplicateDismissals.js";
import { alignedEpoch, detectClockSkew, effectiveOffsets } from "../clockSkew.js";
import type { ClockSkewStore } from "../clockSkewStore.js";
import { correlateEvents, correlationGroups, type CorrelateOptions } from "../correlate.js";
import { CorrelationProfileStore } from "../correlationProfile.js";
import { filterFalsePositiveEvents, type FalsePositiveMarker } from "../falsePositive.js";
import { diffFindings, type FindingsDiff } from "../findingsDiff.js";
import { type HostAliasIndex } from "../hostAlias.js";
import { loadHostAliasIndex } from "../hostScopeLoad.js";
import {
  HostMergeDecisionRequired,
  hostNamesFromState,
  pendingNearDuplicates,
} from "../hostDuplicateGate.js";
import { sanitizeHypotheses } from "../hypothesis.js";
import { rankConnectiveIocs } from "../iocAnchors.js";
import type { PlaybookTask } from "../playbook.js";
import { deltaSchema, stripAiExtractedFrom } from "../responseSchema.js";
import { filterEventsByScope, hasScope, NO_SCOPE, type ScopeWindow } from "../scope.js";
import {
  buildSecondLookPlan,
  buildSecondLookRequests,
  deriveWindow,
  resolveSecondLookRequests,
  summarizeSecondLook,
  type ModelEvidenceRequest,
} from "../secondLook.js";
import { applyAcceptedSecondOpinion } from "../secondOpinion.js";
import type { SecondOpinionStore } from "../secondOpinionStore.js";
import { effectiveTrustMap, type SourceTrustMap } from "../sourceTrust.js";
import type { SourceTrustStore } from "../sourceTrustStore.js";
import type { StateLock } from "../stateLock.js";
import { mergeDelta, type WindowContext } from "../stateMerge.js";
import type { ForensicEvent, InvestigationState } from "../stateTypes.js";
import type { SuperTimelineStore } from "../superTimelineStore.js";
import type { SecondLookMeta, SynthMetaStore } from "../synthMeta.js";
import { resolveSynthThinkingBudget, type SynthThinkingInput } from "../synthThinking.js";
import { getSynthesisPrompt } from "./prompts/index.js";
import type { AiCallContext } from "./aiContext.js";
import { type HuntContext } from "./hunts.js";
import { buildSynthesisPrompt, type SynthesisPromptContext } from "./synthesisPrompt.js";
import {
  computeSynthHash,
  loadSynthesisInputs,
  type SynthesisInputBlocks,
  type SynthesisInputContext,
} from "./synthesisInputs.js";
import { foldSynthesisDelta, gradeFindings } from "./synthesisMerge.js";
import { persistSynthesis } from "./synthesisPersist.js";

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
 * persist under the lock, record, notify, and sweep once for what the sampler did not show.
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
      analysisRunStore?: AnalysisRunStore;
      anonStore?: AnonControlStore;
      stateLock?: StateLock;
      synthesisModelLabel?: string;
      onSynth?: (caseId: string, diff: FindingsDiff, state: InvestigationState) => void;
      onState?: (state: InvestigationState) => void;
      assetOverridesStore?: AssetOverridesStore;
      velociraptorClientStore?: VelociraptorClientStore;
      hostDuplicateDismissalStore?: HostDuplicateDismissalStore;
    };
  /** mergeDelta plus the case's analyst IOC-merge aliases (#82). */
  mergeWithAliases(
    state: InvestigationState,
    delta: Parameters<typeof mergeDelta>[1],
    ctx: WindowContext,
  ): Promise<InvestigationState>;
  /** Promote raw super-timeline rows into the forensic timeline — the second-look sweep's seam. */
  promoteSuperTimeline(
    caseId: string,
    events: ForensicEvent[],
    opts: { importedAt: string; tagById?: Record<string, string[]>; note?: string },
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
    record = await store.recordDetection(caseId, report);
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
): Promise<PreparedRun> {
  const { state, sourceTrust, windowSeconds } = await correlateForSynthesis(ctx, caseId, loaded);
  const markers = ctx.opts.falsePositiveStore ? await ctx.opts.falsePositiveStore.load(caseId) : [];
  const scope = ctx.opts.scopeStore ? await ctx.opts.scopeStore.load(caseId) : NO_SCOPE;
  const inWindowEvents = filterEventsByScope(state.forensicTimeline, scope);
  const scopedEvents = filterFalsePositiveEvents(inWindowEvents, markers);
  // The pure inputs — notebook, hypotheses, prior work, incident type — all loaded BEFORE the hash
  // so changing any of them triggers a fresh synthesis rather than a skip.
  const { blocks, playbookTasks } = await loadSynthesisInputs(ctx, caseId);
  return {
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
    }),
  };
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
  },
): Promise<InvestigationState> {
  const withAccepted = ctx.opts.secondOpinionStore
    ? applyAcceptedSecondOpinion(folded, await ctx.opts.secondOpinionStore.load(caseId))
    : folded;
  return gradeFindings({
    next: withAccepted,
    delta: input.delta,
    surviving: input.surviving,
    eligibleIds: input.eligibleIds,
    sourceTrust: input.sourceTrust,
    kevCatalog: await ctx.getKevCatalog(),
  });
}

/**
 * Auto-generate hypotheses (issue #140). Merge the model's hypotheses into the per-case store,
 * refreshing pristine auto ones and FREEZING any the analyst touched (see mergeHypotheses). Only
 * when the model actually returned some — an omitted field must never prune the analyst's set.
 *
 * Sanitized against the FINAL event/IOC ids so evidence links can't dangle. A side store, not part
 * of InvestigationState, and it runs after the state is persisted so a failure here cannot lose the
 * synthesis.
 */
async function autoGenerateHypotheses(
  ctx: SynthesisContext,
  caseId: string,
  hypotheses: ReturnType<typeof stripAiExtractedFrom>["hypotheses"],
  next: InvestigationState,
): Promise<void> {
  if (!ctx.opts.hypothesisStore || !hypotheses || !hypotheses.length) return;
  const validEventIds = new Set(next.forensicTimeline.map((e) => e.id));
  const validIocIds = new Set(next.iocs.map((i) => i.id));
  const seeds = sanitizeHypotheses(hypotheses, validEventIds, validIocIds);
  await ctx.opts.hypothesisStore.applyAutoGenerated(caseId, seeds, new Date().toISOString());
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
}

/**
 * The two durable records of a real run: the synth-meta card the dashboard reads, and the full
 * analysis-run row. Only reached on a real run — a skipped one returns before the model call.
 */
async function recordSynthesisOutcome(
  ctx: SynthesisContext,
  caseId: string,
  o: SynthesisOutcome,
): Promise<void> {
  await ctx.opts.synthMetaStore?.record(caseId, o.findingsDiff, new Date().toISOString(), {
    durationMs: Date.now() - o.synthStart,
    eventCount: o.next.forensicTimeline.length,
    iocCount: o.next.iocs.length,
    selectionCounts: { ...o.prompt.selection.counts }, // #4: the evidence mix the model saw
    coverage: o.prompt.coverage, // #62: included/omitted coverage audit
    synthModel: ctx.opts.synthesisModelLabel ?? `${o.synthProvider.name}/${o.synthProvider.model}`, // #74
    findingsCount: o.next.findings.length, // #74
    highSeverityBackfillCount: o.highSeverityBackfillCount, // #74
    parseRetries: o.call.parseRetries, // #74
  });
  const anonPolicy = toAnonPolicy(ctx.opts.anonStore ? await ctx.opts.anonStore.load(caseId) : null);
  await recordSynthesisRun(ctx.opts.analysisRunStore, caseId, {
    parentRunId: o.parentRunId,
    startedAt: new Date(o.synthStart).toISOString(),
    provider: o.synthProvider.name,
    model: o.synthProvider.model,
    eventIds: [...o.prompt.shownIds],
    inputState: o.run.state,
    outputState: o.next,
    prompt: getSynthesisPrompt(),
    maxEvents: o.prompt.maxEvents,
    thinkingTokens: o.call.thinkingTokens,
    correlationWindowSeconds: o.run.windowSeconds,
    anonymizationPolicy: anonPolicy,
    scope: o.run.scope,
    falsePositiveMarkers: o.run.markers.length,
    infoEventsExcluded: o.prompt.omittedInfo > 0,
    observationsIncluded: o.observationsBlock.length > 0,
    parseRetries: o.call.parseRetries,
    coverage: o.prompt.coverage,
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
  return {
    windowSeconds,
    sourceTrust,
    state: {
      ...loaded,
      forensicTimeline: correlateEvents(loaded.forensicTimeline, {
        windowSeconds,
        sourceTrust,
        epochOf: skew,
      }),
    },
  };
}

/**
 * The synthesis model call, with its two per-run knobs.
 *
 * Chain-of-Thought / extended thinking (issue #121, feature 1) is resolved per run: an explicit
 * value or the dashboard "deep reasoning" toggle wins, else the global
 * DFIR_AI_SYNTH_THINKING_TOKENS default (off when unset). The Anthropic provider maps it to
 * extended thinking; OpenRouter to its unified `reasoning`; other providers ignore it. Only
 * synthesis reasons step-by-step — extraction stays cheap.
 *
 * Per-model quality telemetry (#74) counts the retries this call actually needed (a failed
 * parse/schema-mismatch attempt increments it). Counted on catch INSIDE the retried closure rather
 * than via ctx.withRetry's onRetry hook, because that hook is the shared server-logging callback —
 * routing through ctx.withRetry keeps the per-attempt WARN logging intact while the local catch
 * keeps the count. Surfaced on synth-meta so a flaky model shows up empirically.
 */
interface SynthesisCall {
  delta: ReturnType<typeof stripAiExtractedFrom>;
  thinkingTokens: number;
  parseRetries: number;
}

async function callSynthesisModel(
  ctx: SynthesisContext,
  caseId: string,
  state: InvestigationState,
  provider: AIProvider,
  userPrompt: string,
  opts: { signal?: AbortSignal } & SynthThinkingInput,
): Promise<SynthesisCall> {
  const thinkingTokens = resolveSynthThinkingBudget(
    opts,
    Number(process.env.DFIR_AI_SYNTH_THINKING_TOKENS) || 0,
  );
  let parseRetries = 0;
  const delta = await ctx.withRetry(
    caseId,
    "synthesis",
    async () => {
      try {
        const parsed = await ctx.analyzeRestored(
          caseId,
          state,
          provider,
          {
            systemPrompt: getSynthesisPrompt(),
            userPrompt,
            images: [],
            ...(thinkingTokens > 0 ? { thinkingTokens } : {}),
            ...(opts.signal ? { signal: opts.signal } : {}),
          },
          "synthesis",
        );
        return stripAiExtractedFrom(deltaSchema.parse(parsed));
      } catch (err) {
        parseRetries++;
        throw err;
      }
    },
    ctx.opts.retries ?? 3,
    ctx.opts.backoffMs ?? 500,
  );
  return { delta, thinkingTokens, parseRetries };
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
 * record, notify, sweep. Each step's DETAIL lives in its own function or module; what is left is the
 * ORDER, and the order is the thing most likely to be got wrong.
 *
 * Splitting this further would mean inventing a "commit phase" or a "post-call phase" — groupings
 * with no meaning outside the split itself — and would put the fold, the grading and the write in
 * three places, when the whole reason the lost-update guard is correct is that you can see it
 * happens AFTER grading and BEFORE the run record. A reader who needs to know what synthesis does,
 * in order, should need exactly one screen and no jumps. That is what this is.
 */
export async function synthesize(
  ctx: SynthesisContext,
  caseId: string,
  opts: {
    force?: boolean;
    dryRun?: boolean;
    provider?: AIProvider;
    signal?: AbortSignal;
    skipSecondLook?: boolean;
    observationsBlock?: string;
    analysisParentRunId?: string;
  } & SynthThinkingInput = {},
): Promise<InvestigationState> {
  const observationsBlock = opts.observationsBlock ?? "";
  const synthProvider = opts.provider ?? ctx.opts.synthesisProvider ?? ctx.requireProvider("synthesis");
  ctx.warnOnPromptDrift(); // once per process: a stale synthesis-prompt override silently drops shipped capabilities
  const loaded = await ctx.opts.stateStore.load(caseId);
  if (loaded.forensicTimeline.length === 0) return loaded;
  await resolveHostsOrThrow(ctx, caseId, loaded);

  const run = await prepareSynthesisRun(ctx, caseId, loaded, observationsBlock);
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
    ...run.blocks,
  });

  const synthStart = Date.now();
  const call = await callSynthesisModel(ctx, caseId, state, synthProvider, prompt.userPrompt, opts);
  const { delta } = call;

  const {
    next: folded,
    highSeverityBackfillCount,
    eligibleIds,
    surviving,
  } = await foldSynthesisDelta(ctx, {
    caseId,
    state,
    delta,
    markers,
    scopedEvents,
    playbookTasks: run.playbookTasks,
  });
  let next = folded;
  if (opts.dryRun) return next;

  next = await finalizeFindings(ctx, caseId, next, { delta, surviving, eligibleIds, sourceTrust });

  // What this run changed vs the pre-AI findings. Findings are FINAL here — neither persistLatest
  // nor the hypothesis auto-gen below touch them — so it's computed once and reused for the
  // Investigation-Log entry (#165), the synth-meta record, and the notify hook.
  const findingsDiff = diffFindings(loaded.findings, next.findings);

  // Lost-update guard (mirrors the pinned-questions re-load in the delta fold): a manual
  // event/IOC/thread added DURING the seconds-long AI call would otherwise be clobbered by this
  // write, because `next` was derived from the snapshot taken before the call.
  next = await persistSynthesis(ctx, caseId, { loaded, next, findingsDiff });

  await autoGenerateHypotheses(ctx, caseId, delta.hypotheses, next);

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
  });
  // Notify on new/escalated findings (issue #58). Best-effort, fire-and-forget — never blocks or
  // fails synthesis. Only on a real run, so a skipped (unchanged) re-synthesis sends nothing.
  ctx.opts.onSynth?.(caseId, findingsDiff, next);
  ctx.opts.onState?.(next);

  return (await sweepSecondLook(ctx, caseId, opts, { next, scopedEvents, scope, prompt, delta })) ?? next;
}

/**
 * Second-look loop (investigation-guidance #11): now that this run has conclusions, open hypotheses
 * and key questions, re-query the COMPLETE raw record — the super-timeline plus the scoped events
 * the sampler omitted — for the terms those open questions imply, promote the matches, and trigger
 * EXACTLY ONE bounded re-synthesis so the conclusions fold them in.
 *
 * `skipSecondLook` on that re-synthesis (and on the second-opinion dryRun path, which returns before
 * reaching here) is the one-iteration guard that makes this terminate.
 *
 * Returns the re-synthesized state when a sweep promoted something, else null for "keep what you
 * have". Best-effort throughout: a sweep failure must never fail the synthesis that produced it.
 */
async function sweepSecondLook(
  ctx: SynthesisContext,
  caseId: string,
  opts: { skipSecondLook?: boolean; signal?: AbortSignal },
  input: {
    next: InvestigationState;
    scopedEvents: ForensicEvent[];
    scope: ScopeWindow;
    prompt: Awaited<ReturnType<typeof buildSynthesisPrompt>>;
    delta: ReturnType<typeof stripAiExtractedFrom>;
  },
): Promise<InvestigationState | null> {
  if (opts.skipSecondLook || !ctx.opts.superTimelineStore) return null;
  try {
    const outcome = await runSecondLook(ctx, caseId, {
      // The sweep treats anything not in `promptEvents` as a candidate to re-discover; events
      // already covered by a grouped row HAVE been seen, so hand it the expanded set.
      next: input.next,
      scopedEvents: input.scopedEvents,
      promptEvents: input.prompt.representedEvents,
      scope: input.scope,
      evidenceRequests: input.delta.evidenceRequests,
    });
    if (!outcome) return null;
    // Nothing new to promote still records — empty requests are surfaced as collection leads.
    if (outcome.meta.promoted === 0) {
      await ctx.opts.synthMetaStore?.recordSecondLook(caseId, outcome.meta);
      return null;
    }
    // Promotion changed the in-scope timeline → the synthHash differs → this re-synthesis runs (not
    // skipped) and, with skipSecondLook, does NOT sweep again. Bounded to one extra AI call.
    const resynth = await synthesize(ctx, caseId, {
      force: true,
      skipSecondLook: true,
      ...(opts.signal ? { signal: opts.signal } : {}),
    });
    await ctx.opts.synthMetaStore?.recordSecondLook(caseId, outcome.meta);
    return resynth;
  } catch (err) {
    console.warn(`[DFIR] second-look sweep failed for case ${caseId}: ${(err as Error).message}`);
    return null;
  }
}

/**
 * The explicit scope when the analyst set one, else the span of the dated in-scope events. Bounds
 * the raw re-query so a huge super-timeline is searched only over the incident window.
 */
function activeWindow(scope: ScopeWindow, scopedEvents: ForensicEvent[]): { from?: string; to?: string } {
  return hasScope(scope)
    ? { from: scope.start ?? undefined, to: scope.end ?? undefined }
    : deriveWindow(scopedEvents);
}

/**
 * The pool the second look searches: the scoped events the sampler OMITTED from the prompt, plus the
 * super-timeline rows inside the active window, deduped by id.
 *
 * A super row that is a copy of a forensic event shares its id, so the caller's `forensicEventIds`
 * check correctly marks it non-promotable — only genuinely-new raw rows are ever promoted.
 */
async function collectSecondLookCandidates(
  superStore: NonNullable<SynthesisContext["opts"]["superTimelineStore"]>,
  caseId: string,
  window: { from?: string; to?: string },
  input: { scopedEvents: ForensicEvent[]; promptEvents: ForensicEvent[] },
): Promise<ForensicEvent[]> {
  const shownIds = new Set(input.promptEvents.map((e) => e.id));
  const omitted = input.scopedEvents.filter((e) => !shownIds.has(e.id));
  const superRows = (await superStore.query(caseId, { from: window.from, to: window.to })).events;
  const byId = new Map<string, ForensicEvent>();
  for (const e of [...omitted, ...superRows]) if (!byId.has(e.id)) byId.set(e.id, e);
  return [...byId.values()];
}

// Second-look sweep (investigation-guidance #11) — the impure orchestration around the pure secondLook
// module. Mines the case's OPEN questions (open hypotheses, unknown/partial key questions with a
// collect target, top connective IOCs) plus the model's own evidenceRequests into concrete searches,
// resolves them against the omitted scoped events AND the super-timeline within the active window,
// promotes the not-yet-analyzed matches (capped, tagged with provenance), and returns a meta summary.
// Returns null when there was nothing to search for. Never re-synthesizes itself — the caller does.
async function runSecondLook(
  ctx: SynthesisContext,
  caseId: string,
  input: {
    next: InvestigationState;
    scopedEvents: ForensicEvent[];
    promptEvents: ForensicEvent[];
    scope: ScopeWindow;
    evidenceRequests?: ModelEvidenceRequest[];
  },
): Promise<{ meta: SecondLookMeta } | null> {
  const superStore = ctx.opts.superTimelineStore;
  if (!superStore) return null;

  const window = activeWindow(input.scope, input.scopedEvents);

  const requests = buildSecondLookRequests({
    hypotheses: ctx.opts.hypothesisStore ? await ctx.opts.hypothesisStore.load(caseId) : [],
    iocValueById: new Map(input.next.iocs.map((i) => [i.id, i.value] as const)),
    keyQuestions: input.next.keyQuestions,
    connectiveIocs: rankConnectiveIocs(input.next, input.scopedEvents, { max: 5 }),
    modelRequests: input.evidenceRequests,
    window,
  });
  if (!requests.length) return null;

  const candidates = await collectSecondLookCandidates(superStore, caseId, window, input);
  const forensicEventIds = new Set(input.next.forensicTimeline.map((e) => e.id));
  const resolutions = resolveSecondLookRequests(requests, candidates, forensicEventIds);
  const plan = buildSecondLookPlan(resolutions);

  if (plan.promotions.length) {
    await ctx.promoteSuperTimeline(caseId, plan.promotions, {
      importedAt: new Date().toISOString(),
      tagById: plan.tagById,
      note: `Second look: promoted ${plan.promotions.length} raw event(s) matching open questions`,
    });
  }

  return {
    meta: {
      promoted: plan.promotions.length,
      requests: requests.length,
      matched: resolutions.filter((r) => r.matchedEventIds.length > 0).length,
      leads: plan.leads.map((l) => l.reason).slice(0, 10),
      summary: summarizeSecondLook(plan),
      at: new Date().toISOString(),
    },
  };
}
