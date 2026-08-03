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
} from "../deepPass.js";
import { executeDeepPassBatches } from "../deepPassExecution.js";
import { filterFalsePositiveEvents } from "../falsePositive.js";
import { filterEventsByScope, NO_SCOPE } from "../scope.js";
import { applySeverityFloor } from "../severityFloor.js";
import type { ForensicEvent, Severity } from "../stateTypes.js";
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
  const markers = ctx.opts.falsePositiveStore ? await ctx.opts.falsePositiveStore.load(caseId) : [];
  const scope = ctx.opts.scopeStore ? await ctx.opts.scopeStore.load(caseId) : NO_SCOPE;
  const scopedEvents = filterFalsePositiveEvents(filterEventsByScope(state.forensicTimeline, scope), markers);
  const cap = maxPromptEvents();
  return { cap, floors: previewFloors(scopedEvents, { cap }) };
}

export async function deepPass(
  ctx: DeepPassContext,
  caseId: string,
  opts: {
    minSeverity: Severity;
    provider?: AIProvider;
    signal?: AbortSignal;
    maxBatches?: number;
    onProgress?: (done: number, total: number, detail: string) => void;
    onCheckpoint?: (checkpoint: DeepPassCheckpoint) => Promise<void>;
    resumeFrom?: DeepPassCheckpoint;
    analysisParentRunId?: string;
  },
): Promise<DeepPassResult> {
  const runStartedAt = new Date().toISOString();
  const runId = `${runStartedAt.replace(/[:.]/g, "-")}-${randomUUID().slice(0, 8)}`;
  const state = await ctx.opts.stateStore.load(caseId);
  const provider = opts.provider ?? ctx.opts.synthesisProvider ?? ctx.opts.provider;
  if (!provider) throw new Error("no synthesis provider configured");

  const markers = ctx.opts.falsePositiveStore ? await ctx.opts.falsePositiveStore.load(caseId) : [];
  const scope = ctx.opts.scopeStore ? await ctx.opts.scopeStore.load(caseId) : NO_SCOPE;
  const scopedEvents = filterFalsePositiveEvents(filterEventsByScope(state.forensicTimeline, scope), markers);

  const cap = maxPromptEvents();
  const floored = applySeverityFloor([...promptCandidates(scopedEvents)], opts.minSeverity);
  const { events: rows } = collapseForPrompt(floored, groupEnvOptions());
  const batches = planBatches(rows, cap);
  const selectionHash = createHash("sha256")
    .update(JSON.stringify(rows.map((event) => event.id)))
    .digest("hex");

  // Refuse rather than quietly starting a very expensive job — and name a floor that would fit.
  const ceiling = opts.maxBatches ?? (Number(process.env.DFIR_DEEP_PASS_MAX_BATCHES) || DEFAULT_MAX_BATCHES);
  if (batches.length > ceiling) {
    const fits = floorsWithinBudget(previewFloors(scopedEvents, { cap }), ceiling);
    throw new Error(
      `deep pass needs ${batches.length} batches, above the ${ceiling} limit. ` +
        (fits.length
          ? `Raise the floor to ${fits[fits.length - 1]} or above.`
          : "Raise DFIR_DEEP_PASS_MAX_BATCHES."),
    );
  }

  const retries = ctx.opts.retries ?? 3;
  const backoffMs = ctx.opts.backoffMs ?? 500;
  const execution = await executeDeepPassBatches({
    batches,
    floor: opts.minSeverity,
    selectionHash,
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
  const { observations, batchesFailed, aborted } = execution;

  const summary: DeepPassResult = {
    aborted,
    floor: opts.minSeverity,
    events: floored.length,
    rows: rows.length,
    batches: batches.length,
    batchesFailed,
    observations: observations.length,
  };
  const runRecord = {
    id: runId,
    parentRunId: opts.analysisParentRunId,
    startedAt: runStartedAt,
    provider: provider.name,
    model: provider.model,
    eventIds: floored.map((event) => event.id),
    minSeverity: opts.minSeverity,
    maxBatches: ceiling,
    rowsPerBatch: cap,
    scope,
    batchesFailed,
    falsePositiveMarkers: markers.length,
    observePrompt: getObservePrompt(),
    synthesisPrompt: getSynthesisPrompt(),
  };
  if (aborted) {
    await recordDeepPassRun(ctx.opts.analysisRunStore, caseId, {
      ...runRecord,
      status: "failed",
      error: "cancelled before final synthesis",
      output: state,
    });
    return summary;
  }

  opts.onProgress?.(batches.length, batches.length, "synthesizing");
  await synthesize(ctx, caseId, {
    force: true,
    ...(opts.signal ? { signal: opts.signal } : {}),
    ...(opts.provider ? { provider: opts.provider } : {}),
    observationsBlock: renderObservationDigest(observations),
    analysisParentRunId: runId,
  });
  const finalState = await ctx.opts.stateStore.load(caseId);
  await recordDeepPassRun(ctx.opts.analysisRunStore, caseId, { ...runRecord, output: finalState });
  return summary;
}
