import { createHash, randomUUID } from "node:crypto";
import type { AIProvider } from "../../providers/provider.js";
import { recordDeepPassRun } from "../analysisRunRecorders.js";
import {
  previewFloors,
  planBatches,
  floorsWithinBudget,
  renderObservationDigest,
  DEFAULT_MAX_BATCHES,
  type DeepPassCheckpoint,
  type FloorOption,
  type Observation,
} from "../deepPass.js";
import { executeDeepPassBatches } from "../deepPassExecution.js";
import { filterFalsePositiveEvents, type FalsePositiveMarker } from "../falsePositive.js";
import { filterEventsByScope, NO_SCOPE, type ScopeWindow } from "../scope.js";
import { applySeverityFloor } from "../severityFloor.js";
import type { ForensicEvent, InvestigationState, Severity } from "../stateTypes.js";
import { renderStructuredTags } from "../synthEvidence.js";
import { collapseForPrompt, groupEnvOptions, maxPromptEvents, promptCandidates } from "../synthGroup.js";
import { inputTokenBudget } from "../promptBudget.js";
import { getObservePrompt, getSynthesisPrompt } from "./prompts/index.js";
import { synthesize, type SynthesisContext } from "./synthesis.js";

/**
 * Deep Pass (#418): read the whole graded timeline in batches, then synthesize over the digest.
 *
 * Moved from AnalysisPipeline. Ordinary synthesis shows the model a stratified SAMPLE of the
 * timeline — enough for the conclusions, but it means a detection that lost its prompt seat was
 * never read at all. Deep Pass is the analyst spending real money to close that gap: every event at
 * or above a chosen floor is observed in a bounded number of batches, and the observations become
 * one `observationsBlock` fed into a forced synthesis.
 *
 * It sits in its own module rather than inside ai/synthesis.ts because the dependency runs one way:
 * Deep Pass calls synthesis, synthesis knows nothing about Deep Pass beyond the block of text it is
 * handed. Filing it here keeps that direction visible and the import graph acyclic.
 */

/** What one deep-pass run did, for the analyst and the route response. */
export interface DeepPassResult {
  aborted: boolean;
  floor: Severity; // the minimum severity that was read
  events: number; // graded events at or above the floor
  rows: number; // prompt rows after detection-burst grouping
  batches: number; // observation calls made
  batchesFailed: number; // batches whose response never parsed — that slice went unread
  observations: number; // observations that survived sanitising
}

/** Deep Pass drives a full synthesis at the end, so it needs everything synthesis needs. */
export type DeepPassContext = SynthesisContext;

// Observation rows match synthesis timeline rows, minus the selection-class prefix.
function renderBatchRows(rows: readonly ForensicEvent[]): string {
  return rows
    .map(
      (e) =>
        `[${e.id}] ${e.timestamp || "(undated)"} [${e.severity}] ${e.description.slice(0, 240)}${renderStructuredTags(e)}`,
    )
    .join("\n");
}

/** Estimate each Deep Pass severity floor against this case before the analyst spends credits. */
export async function deepPassPreview(
  ctx: DeepPassContext,
  caseId: string,
): Promise<{ cap: number; floors: FloorOption[] }> {
  const state = await ctx.opts.stateStore.load(caseId);
  const { scopedEvents } = await scopeForDeepPass(ctx, caseId, state);
  const cap = maxPromptEvents();
  return { cap, floors: previewFloors(scopedEvents, { cap }) };
}

/** The in-scope, non-false-positive events a deep pass may look at. Shared by preview and run. */
async function scopeForDeepPass(
  ctx: DeepPassContext,
  caseId: string,
  state: InvestigationState,
): Promise<{ scope: ScopeWindow; markers: FalsePositiveMarker[]; scopedEvents: ForensicEvent[] }> {
  const markers = ctx.opts.falsePositiveStore ? await ctx.opts.falsePositiveStore.load(caseId) : [];
  const scope = ctx.opts.scopeStore ? await ctx.opts.scopeStore.load(caseId) : NO_SCOPE;
  return {
    scope,
    markers,
    scopedEvents: filterFalsePositiveEvents(filterEventsByScope(state.forensicTimeline, scope), markers),
  };
}

interface DeepPassPlan {
  scope: ScopeWindow;
  markers: FalsePositiveMarker[];
  /** Events above the severity floor, before burst collapsing — the run record's event set. */
  floored: ForensicEvent[];
  /** Prompt rows after collapsing; a grouped row stands for its whole burst. */
  rows: ForensicEvent[];
  batches: ForensicEvent[][];
  selectionHash: string;
  cap: number;
  ceiling: number;
}

/**
 * Decide what this deep pass will read, and REFUSE rather than quietly starting a very expensive
 * job. The refusal names a floor that would fit, so the analyst gets an action and not just a "no".
 */
async function planDeepPass(
  ctx: DeepPassContext,
  caseId: string,
  state: InvestigationState,
  minSeverity: Severity,
  maxBatches: number | undefined,
): Promise<DeepPassPlan> {
  const { scope, markers, scopedEvents } = await scopeForDeepPass(ctx, caseId, state);
  const cap = maxPromptEvents();
  const floored = applySeverityFloor([...promptCandidates(scopedEvents)], minSeverity);
  const { events: rows } = collapseForPrompt(floored, groupEnvOptions());
  const batches = planBatches(rows, cap);
  const ceiling = maxBatches ?? (Number(process.env.DFIR_DEEP_PASS_MAX_BATCHES) || DEFAULT_MAX_BATCHES);
  if (batches.length > ceiling) {
    const fits = floorsWithinBudget(previewFloors(scopedEvents, { cap }), ceiling);
    throw new Error(
      `deep pass needs ${batches.length} batches, above the ${ceiling} limit. ` +
        (fits.length
          ? `Raise the floor to ${fits[fits.length - 1]} or above.`
          : "Raise DFIR_DEEP_PASS_MAX_BATCHES."),
    );
  }
  return {
    scope,
    markers,
    floored,
    rows,
    batches,
    cap,
    ceiling,
    selectionHash: createHash("sha256")
      .update(JSON.stringify(rows.map((event) => event.id)))
      .digest("hex"),
  };
}

/**
 * Run the observe pass over every batch.
 *
 * The digest budget is a QUARTER of the input budget: the observations this returns become the
 * `observationsBlock` of a later synthesis prompt, which still has to fit the timeline alongside
 * them. Spending the whole budget here would produce a digest that cannot be used.
 */
async function observeAllBatches(
  ctx: DeepPassContext,
  caseId: string,
  state: InvestigationState,
  provider: AIProvider,
  plan: DeepPassPlan,
  opts: {
    minSeverity: Severity;
    signal?: AbortSignal;
    onProgress?: (done: number, total: number, detail: string) => void;
    onCheckpoint?: (checkpoint: DeepPassCheckpoint) => Promise<void>;
    resumeFrom?: DeepPassCheckpoint;
  },
): Promise<Awaited<ReturnType<typeof executeDeepPassBatches>>> {
  const retries = ctx.opts.retries ?? 3;
  const backoffMs = ctx.opts.backoffMs ?? 500;
  return executeDeepPassBatches({
    batches: plan.batches,
    floor: opts.minSeverity,
    selectionHash: plan.selectionHash,
    validEventIds: new Set(state.forensicTimeline.map((event) => event.id)),
    digestBudget: Math.max(0, Math.floor(inputTokenBudget() * 0.25)),
    ...(opts.resumeFrom ? { resumeFrom: opts.resumeFrom } : {}),
    ...(opts.signal ? { signal: opts.signal } : {}),
    ...(opts.onProgress ? { onProgress: opts.onProgress } : {}),
    ...(opts.onCheckpoint ? { onCheckpoint: opts.onCheckpoint } : {}),
    renderBatch: (batch) => renderBatchRows(batch),
    observe: (userPrompt) =>
      ctx.withRetry(
        caseId,
        "deep-pass-observe",
        () =>
          ctx.analyzeRestored(
            caseId,
            state,
            provider,
            {
              systemPrompt: getObservePrompt(),
              userPrompt,
              images: [],
              ...(opts.signal ? { signal: opts.signal } : {}),
            },
            "deep-pass-observe",
          ),
        retries,
        backoffMs,
      ),
    onFailure: (message) => ctx.log.warn(`deep pass: ${message}`, { caseId }),
  });
}

/** The analysis-run row describing WHAT this deep pass read and under which knobs. */
function buildRunRecord(
  plan: DeepPassPlan,
  provider: AIProvider,
  run: {
    runId: string;
    runStartedAt: string;
    minSeverity: Severity;
    batchesFailed: number;
    parentRunId: string | undefined;
  },
) {
  return {
    id: run.runId,
    parentRunId: run.parentRunId,
    startedAt: run.runStartedAt,
    provider: provider.name,
    model: provider.model,
    eventIds: plan.floored.map((event) => event.id),
    minSeverity: run.minSeverity,
    maxBatches: plan.ceiling,
    rowsPerBatch: plan.cap,
    scope: plan.scope,
    batchesFailed: run.batchesFailed,
    falsePositiveMarkers: plan.markers.length,
    observePrompt: getObservePrompt(),
    synthesisPrompt: getSynthesisPrompt(),
  };
}

export interface DeepPassOptions {
  minSeverity: Severity;
  provider?: AIProvider;
  signal?: AbortSignal;
  maxBatches?: number;
  onProgress?: (done: number, total: number, detail: string) => void;
  onCheckpoint?: (checkpoint: DeepPassCheckpoint) => Promise<void>;
  resumeFrom?: DeepPassCheckpoint;
  analysisParentRunId?: string;
}

export async function deepPass(
  ctx: DeepPassContext,
  caseId: string,
  opts: DeepPassOptions,
): Promise<DeepPassResult> {
  const runStartedAt = new Date().toISOString();
  const runId = `${runStartedAt.replace(/[:.]/g, "-")}-${randomUUID().slice(0, 8)}`;
  const state = await ctx.opts.stateStore.load(caseId);
  const provider = opts.provider ?? ctx.opts.synthesisProvider ?? ctx.opts.provider;
  if (!provider) throw new Error("no synthesis provider configured");

  const plan = await planDeepPass(ctx, caseId, state, opts.minSeverity, opts.maxBatches);
  const run = await observeAllBatches(ctx, caseId, state, provider, plan, opts);
  const { observations, batchesFailed, aborted } = run;

  const summary: DeepPassResult = {
    aborted,
    floor: opts.minSeverity,
    events: plan.floored.length,
    rows: plan.rows.length,
    batches: plan.batches.length,
    batchesFailed,
    observations: observations.length,
  };  const runRecord = buildRunRecord(plan, provider, {
    runId,
    runStartedAt,
    minSeverity: opts.minSeverity,
    batchesFailed,
    parentRunId: opts.analysisParentRunId,
  });
  if (aborted) {
    // Recorded as FAILED with the pre-run state as its output: recording a success would leave an
    // analysis-run row claiming conclusions that were never synthesized.
    await recordDeepPassRun(ctx.opts.analysisRunStore, caseId, {
      ...runRecord,
      status: "failed",
      error: "cancelled before final synthesis",
      output: state,
    });
    return summary;
  }

  opts.onProgress?.(plan.batches.length, plan.batches.length, "synthesizing");
  await synthesizeWithObservations(ctx, caseId, runId, observations, opts);
  const finalState = await ctx.opts.stateStore.load(caseId);
  await recordDeepPassRun(ctx.opts.analysisRunStore, caseId, { ...runRecord, output: finalState });
  return summary;
}

/**
 * The final synthesis, carrying the deep pass's observations as a prompt block.
 *
 * `force: true` because the timeline itself has not changed — only what the deep pass NOTICED about
 * it has — and the skip-hash would otherwise see identical inputs and decline to run. The
 * observations are a hashed input precisely so a re-run carrying fresh ones is never skipped;
 * forcing is what makes the first one happen.
 */
async function synthesizeWithObservations(
  ctx: DeepPassContext,
  caseId: string,
  runId: string,
  observations: Observation[],
  opts: { signal?: AbortSignal; provider?: AIProvider },
): Promise<void> {
  await synthesize(ctx, caseId, {
    force: true,
    ...(opts.signal ? { signal: opts.signal } : {}),
    ...(opts.provider ? { provider: opts.provider } : {}),
    observationsBlock: renderObservationDigest(observations),
    analysisParentRunId: runId,
  });
}
