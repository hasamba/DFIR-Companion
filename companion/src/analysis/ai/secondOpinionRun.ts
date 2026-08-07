import {
  buildSecondOpinion,
  buildReconcilePrompt,
  reconcileResponseSchema,
  mergeReconcileVerdicts,
  applyAcceptedSecondOpinion,
  setDeltaStatus,
  setAllPendingStatus,
  type SecondOpinion,
} from "../secondOpinion.js";
import type { InvestigationState } from "../stateTypes.js";
import type { SynthThinkingInput } from "../synthThinking.js";
import { getReconcilePrompt } from "./prompts/index.js";
import type { AIProvider } from "../../providers/provider.js";
import { callAiJson } from "./aiContext.js";
import { synthesize, type SynthesisContext } from "./synthesis.js";

/**
 * The second-opinion QA cross-check (#418).
 *
 * Moved from AnalysisPipeline. A DIFFERENT model re-synthesizes the case independently and a
 * reconcile pass annotates every disagreement, so the analyst adjudicates model-vs-model instead of
 * taking one model's word for the case. Like ai/deepPassRun.ts it is a CONSUMER of synthesis — it
 * runs it twice, once normally and once as a non-destructive `dryRun` — which is why it lives
 * beside synthesis rather than inside it.
 *
 * Accepted deltas are durable: synthesize() re-applies them after its wholesale findings rewrite, so
 * a confirmed model-B finding survives every later re-synthesis.
 */

/** Both passes run through synthesis, plus the model B this feature exists for. */
export interface SecondOpinionContext extends SynthesisContext {
  readonly opts: SynthesisContext["opts"] & {
    secondOpinionProvider?: AIProvider;
    secondOpinionModelLabel?: string;
  };
}

export async function secondOpinion(
  ctx: SecondOpinionContext,
  caseId: string,
  opts: SynthThinkingInput = {},
): Promise<SecondOpinion> {
  const provider = ctx.opts.secondOpinionProvider;
  if (!provider) throw new Error("second-opinion model not configured (set DFIR_AI_SECOND_OPINION_MODEL)");
  if (!ctx.opts.secondOpinionStore) throw new Error("second-opinion store not configured");
  if ((await ctx.opts.stateStore.load(caseId)).forensicTimeline.length === 0) {
    throw new Error("nothing to review — import evidence and synthesize the case first");
  }
  // Deep-reasoning toggle (#121) flows into BOTH synthesis passes below, so model A's freshened
  // synthesis and model B's independent pass reason equally hard for the comparison.

  // Pass 0 — freshen the PRIMARY synthesis so model A reflects the CURRENT timeline. Without this,
  // a stale saved A vs a fresh model-B run produces deltas that are staleness artifacts (e.g. the
  // deterministic gap-silence / high-severity backfill findings) rather than real model
  // disagreements. Uses skip-if-unchanged (no `force`), so it's a NO-OP (no AI call) when A is
  // already current — it only re-synthesizes when the in-scope timeline/IOCs/scope changed.
  const a = await synthesize(ctx, caseId, {
    deepReasoning: opts.deepReasoning,
    thinkingTokens: opts.thinkingTokens,
  });

  // Pass 1 — independent synthesis with model B over the SAME current timeline/context, routed
  // through a different model and NOT persisted (dryRun). This is model B's analysis.
  const b = await synthesize(ctx, caseId, {
    dryRun: true,
    force: true,
    provider,
    deepReasoning: opts.deepReasoning,
    thinkingTokens: opts.thinkingTokens,
  });

  const modelA =
    ctx.opts.synthesisModelLabel ?? (ctx.opts.synthesisProvider ?? ctx.opts.provider)?.name ?? "model A";
  const modelB = ctx.opts.secondOpinionModelLabel ?? provider.name;
  let record = buildSecondOpinion({ a, b, modelA, modelB, now: () => new Date().toISOString() });

  record = await reconcileDeltas(ctx, caseId, provider, { a, b, record });

  await ctx.opts.secondOpinionStore.save(caseId, record);
  await recordAgreementRate(ctx, caseId, record, modelA, modelB);
  return record;
}

/**
 * Pass 2 — annotate each disagreement with a rationale and a recommendation.
 *
 * BEST-EFFORT by design: if the reconcile call fails, the deterministic deltas are kept without
 * rationales rather than failing the whole second opinion. A comparison with no explanations is
 * still useful; no comparison at all is not.
 */
async function reconcileDeltas(
  ctx: SecondOpinionContext,
  caseId: string,
  provider: AIProvider,
  input: { a: InvestigationState; b: InvestigationState; record: SecondOpinion },
): Promise<SecondOpinion> {
  const { a, b, record } = input;
  if (record.deltas.length === 0) return record;
  const userPrompt = buildReconcilePrompt(a, b, record.deltas);
  try {
    const parsed = await callAiJson(
      ctx,
      caseId,
      a,
      provider,
      "second-opinion-reconcile",
      getReconcilePrompt,
      userPrompt,
      (raw) => reconcileResponseSchema.parse(raw),
    );
    return mergeReconcileVerdicts(record, parsed);
  } catch (err) {
    ctx.log.warn(`[second-opinion] reconcile pass failed: ${(err as Error).message}`, { caseId });
    return record;
  }
}

/**
 * Per-model quality telemetry (#74): stamp the agreement rate onto synth-meta so modelA vs modelB
 * can be compared empirically across runs, not just eyeballed on this one second-opinion panel.
 */
async function recordAgreementRate(
  ctx: SecondOpinionContext,
  caseId: string,
  record: SecondOpinion,
  modelA: string,
  modelB: string,
): Promise<void> {
  const deltaCount = record.deltas.length;
  const denom = record.agreementCount + deltaCount;
  await ctx.opts.synthMetaStore?.recordSecondOpinionPerf(caseId, {
    modelA,
    modelB,
    agreementCount: record.agreementCount,
    deltaCount,
    agreementRate: denom > 0 ? record.agreementCount / denom : 0,
    at: record.generatedAt,
  });
}

export async function applySecondOpinion(
  ctx: SecondOpinionContext,
  caseId: string,
  deltaId: string,
  accept: boolean,
): Promise<{ record: SecondOpinion; state: InvestigationState }> {
  if (!ctx.opts.secondOpinionStore) throw new Error("second-opinion store not configured");
  const current = await ctx.opts.secondOpinionStore.load(caseId);
  if (!current) throw new Error("no second opinion to act on — run a second opinion first");
  if (!current.deltas.some((d) => d.id === deltaId))
    throw new Error(`unknown second-opinion delta: ${deltaId}`);
  return persistSecondOpinion(
    ctx,
    caseId,
    setDeltaStatus(current, deltaId, accept ? "accepted" : "rejected"),
  );
}

export async function applyAllSecondOpinion(
  ctx: SecondOpinionContext,
  caseId: string,
  accept: boolean,
): Promise<{ record: SecondOpinion; state: InvestigationState }> {
  if (!ctx.opts.secondOpinionStore) throw new Error("second-opinion store not configured");
  const current = await ctx.opts.secondOpinionStore.load(caseId);
  if (!current) throw new Error("no second opinion to act on — run a second opinion first");
  return persistSecondOpinion(ctx, caseId, setAllPendingStatus(current, accept ? "accepted" : "rejected"));
}

async function persistSecondOpinion(
  ctx: SecondOpinionContext,
  caseId: string,
  record: SecondOpinion,
): Promise<{ record: SecondOpinion; state: InvestigationState }> {
  await ctx.opts.secondOpinionStore!.save(caseId, record);
  const state = await ctx.opts.stateStore.load(caseId);
  const applied = applyAcceptedSecondOpinion(state, record);
  if (applied !== state) {
    await ctx.opts.stateStore.save(applied);
    ctx.opts.onState?.(applied);
  }
  return { record, state: applied };
}
