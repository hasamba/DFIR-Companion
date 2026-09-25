import {
  buildSecondOpinion,
  buildReconcilePrompt,
  reconcileResponseSchema,
  mergeReconcileVerdicts,
  applyAcceptedSecondOpinion,
  setDeltaStatus,
  setAllPendingStatus,
  followRefereeStatus,
  type ReconcileResponse,
  type SecondOpinion,
} from "../secondOpinion.js";
import { carryAcceptedDecisions, freshDeltas } from "../secondOpinionTargets.js";
import { PresidioApprovalRequired } from "../presidio.js";
import { HostMergeDecisionRequired } from "../hostDuplicateGate.js";
import type { InvestigationState } from "../stateTypes.js";
import type { SynthThinkingInput } from "../synthThinking.js";
import { getReconcilePrompt } from "./prompts/index.js";
import type { AIProvider } from "../../providers/provider.js";
import type { RefereeModel } from "./providerRoster.js";
import { callAiJson, loadScopedEvents } from "./aiContext.js";
import { StateLock } from "../stateLock.js";
import { reconcileSimulationVerdict } from "../simulationVerdict.js";
import { loadHostAliasIndex } from "../hostScopeLoad.js";
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

/** Both passes run through synthesis, plus the model B this feature exists for and its referee. */
export interface SecondOpinionContext extends SynthesisContext {
  readonly opts: SynthesisContext["opts"] & {
    secondOpinionProvider?: AIProvider;
    secondOpinionModelLabel?: string;
    referee?: RefereeModel;
  };
}

/**
 * Who judges the A-vs-B disagreements (#1466). Model B used to referee its own findings; now the
 * default is model A, and `opts.referee` (from DFIR_AI_RECONCILE_MODEL) overrides it with B or a
 * third model. Pure so the choice is testable without a run.
 */
export function pickReferee(opts: SecondOpinionContext["opts"], modelA: string): RefereeModel | undefined {
  if (opts.referee) return opts.referee;
  const provider = opts.synthesisProvider ?? opts.provider;
  return provider ? { provider, label: modelA } : undefined;
}

// Every read-modify-write of the saved record runs under this per-case lock (#1587 review): a
// referee re-run holds the AI call OUTSIDE it, then re-reads, merges and saves inside it, so an
// accept/reject or a newer full run can never land between its re-read and its save.
const recordLock = new StateLock();
// One referee re-run per case at a time; a second press answers 409 instead of racing the first.
const refereeRerunsInFlight = new Set<string>();

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
  const referee = pickReferee(ctx.opts, modelA);
  // `referee` stays "" until the verdict pass actually succeeds (reconcileDeltas stamps it), so a
  // failed or skipped pass never shows a referee that wrote nothing.
  let record = buildSecondOpinion({ a, b, modelA, modelB, now: () => new Date().toISOString() });

  if (referee) record = await reconcileDeltas(ctx, caseId, referee, { a, b, record });

  // #1590 — the new run ADDS to what the analyst already accepted; it no longer replaces it.
  const store = ctx.opts.secondOpinionStore;
  const saved = await recordLock.runExclusive(caseId, async () => {
    const merged = carryAcceptedDecisions(await store.load(caseId), record);
    await store.save(caseId, merged);
    return merged;
  });
  await recordAgreementRate(ctx, caseId, record, modelA, modelB);
  return saved;
}

/**
 * Pass 2 — annotate each disagreement with a rationale and a recommendation.
 *
 * BEST-EFFORT by design: if the reconcile call fails, the deterministic deltas are kept without
 * rationales rather than failing the whole second opinion. A comparison with no explanations is
 * still useful; no comparison at all is not. What the record must NOT do is hide the failure
 * (#1587): it keeps who was tried, why it failed, and the prompt, so the panel says so and the
 * analyst can re-run only this pass. A Presidio or merge gate is recorded the same way here — the
 * A/B work is not thrown away for it — and the referee-only re-run then raises the real gate.
 */
async function reconcileDeltas(
  ctx: SecondOpinionContext,
  caseId: string,
  referee: RefereeModel,
  input: { a: InvestigationState; b: InvestigationState; record: SecondOpinion },
): Promise<SecondOpinion> {
  const { a, b, record } = input;
  if (record.deltas.length === 0) return record;
  // The cited events the referee sees are the scoped set synthesis read — never an out-of-window
  // event or an analyst-marked false positive (#1466 review).
  const { scoped } = await loadScopedEvents(ctx, caseId, a);
  const userPrompt = buildReconcilePrompt(a, b, record.deltas, scoped);
  try {
    return foldVerdicts(record, await callReferee(ctx, caseId, a, referee, userPrompt, record), referee);
  } catch (err) {
    return withRefereeFailure(ctx, caseId, record, referee, userPrompt, err);
  }
}

const REFEREE_ERROR_MAX = 300;

/** One line, no control characters, capped — the message is persisted, logged and shown. */
function flattenRefereeError(err: unknown): string {
  const raw = err instanceof Error ? err.message : String(err);
  const flat = raw
    .replace(/[\u0000-\u001f\u007f]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  return (flat || "referee call failed").slice(0, REFEREE_ERROR_MAX);
}

/** Ask the referee. A parse that names none of the saved deltas is a failure, not an empty success. */
async function callReferee(
  ctx: SecondOpinionContext,
  caseId: string,
  loaded: InvestigationState,
  referee: RefereeModel,
  userPrompt: string,
  record: SecondOpinion,
): Promise<ReconcileResponse> {
  const parsed = await callAiJson(
    ctx,
    caseId,
    loaded,
    referee.provider,
    "second-opinion-reconcile",
    getReconcilePrompt,
    userPrompt,
    (raw) => reconcileResponseSchema.parse(raw),
  );
  const ids = new Set(record.deltas.map((d) => d.id));
  if (!parsed.verdicts.some((v) => ids.has(v.id)))
    throw new Error("referee returned no verdict for any disagreement");
  return parsed;
}

/** Success: verdicts in, referee credited, any earlier failure and its saved prompt gone. */
function foldVerdicts(
  record: SecondOpinion,
  parsed: ReconcileResponse,
  referee: RefereeModel,
): SecondOpinion {
  const { refereeError: _e, refereePrompt: _p, ...rest } = mergeReconcileVerdicts(record, parsed);
  return { ...rest, referee: referee.label };
}

function withRefereeFailure(
  ctx: SecondOpinionContext,
  caseId: string,
  record: SecondOpinion,
  referee: RefereeModel,
  userPrompt: string,
  err: unknown,
): SecondOpinion {
  const message = flattenRefereeError(err);
  ctx.log.warn(`[second-opinion] reconcile pass failed: ${message}`, { caseId });
  const refereeError = { referee: referee.label, message, at: new Date().toISOString() };
  return { ...record, refereeError, refereePrompt: userPrompt };
}

/**
 * Re-run ONLY the referee over a saved second opinion whose referee failed (#1587), replaying the
 * exact prompt the failed attempt was given. No synthesis runs. The record is re-read after the AI
 * call and only referee-owned fields are written back, so an accept/reject made while the referee
 * was thinking survives, and a newer full run is never overwritten by an older one's verdicts.
 */
export async function rerunSecondOpinionReferee(
  ctx: SecondOpinionContext,
  caseId: string,
): Promise<{ record: SecondOpinion; failed: boolean }> {
  const store = ctx.opts.secondOpinionStore;
  if (!store) throw new Error("second-opinion store not configured");
  if (refereeRerunsInFlight.has(caseId)) throw new Error("a referee re-run is already running for this case");
  refereeRerunsInFlight.add(caseId);
  try {
    return await rerunReferee(ctx, caseId, store);
  } finally {
    refereeRerunsInFlight.delete(caseId);
  }
}

async function rerunReferee(
  ctx: SecondOpinionContext,
  caseId: string,
  store: NonNullable<SecondOpinionContext["opts"]["secondOpinionStore"]>,
): Promise<{ record: SecondOpinion; failed: boolean }> {
  const before = await store.load(caseId);
  if (!before) throw new Error("no second opinion to act on — run a second opinion first");
  const prompt = before.refereePrompt;
  if (!before.refereeError || !prompt)
    throw new Error("the referee did not fail on this second opinion — nothing to re-run");
  const referee = pickReferee(ctx.opts, before.modelA);
  if (!referee) throw new Error("no referee model configured");
  const state = await ctx.opts.stateStore.load(caseId);
  let parsed: ReconcileResponse | undefined;
  let failure: unknown;
  try {
    parsed = await callReferee(ctx, caseId, state, referee, prompt, before);
  } catch (err) {
    // A gate is a question for the analyst, not a broken referee — the route shows the approval.
    if (err instanceof PresidioApprovalRequired || err instanceof HostMergeDecisionRequired) throw err;
    failure = err;
  }
  const record = await recordLock.runExclusive(caseId, async () => {
    const latest = await store.load(caseId);
    if (!latest || latest.generatedAt !== before.generatedAt)
      throw new Error(
        "this second opinion was replaced by a newer second opinion — its referee result was discarded",
      );
    const next = parsed
      ? foldVerdicts(latest, parsed, referee)
      : withRefereeFailure(ctx, caseId, latest, referee, prompt, failure);
    await store.save(caseId, next);
    return next;
  });
  if (parsed) await recordAgreementRate(ctx, caseId, record, record.modelA, record.modelB);
  return { record, failed: !parsed };
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
  const deltaCount = freshDeltas(record).length; // carried decisions are not this run's (#1590)
  const denom = record.agreementCount + deltaCount;
  await ctx.opts.synthMetaStore?.recordSecondOpinionPerf(caseId, {
    modelA,
    modelB,
    referee: record.referee,
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
  return updateSecondOpinion(ctx, caseId, (current) => {
    if (!current.deltas.some((d) => d.id === deltaId))
      throw new Error(`unknown second-opinion delta: ${deltaId}`);
    return setDeltaStatus(current, deltaId, accept ? "accepted" : "rejected");
  });
}

export async function applyAllSecondOpinion(
  ctx: SecondOpinionContext,
  caseId: string,
  accept: boolean | "referee",
): Promise<{ record: SecondOpinion; state: InvestigationState }> {
  return updateSecondOpinion(ctx, caseId, (current) =>
    accept === "referee"
      ? followRefereeStatus(current)
      : setAllPendingStatus(current, accept ? "accepted" : "rejected"),
  );
}

/** Load → decide → save under the record lock, then apply the accepted set to the case. */
async function updateSecondOpinion(
  ctx: SecondOpinionContext,
  caseId: string,
  decide: (current: SecondOpinion) => SecondOpinion,
): Promise<{ record: SecondOpinion; state: InvestigationState }> {
  const store = ctx.opts.secondOpinionStore;
  if (!store) throw new Error("second-opinion store not configured");
  const record = await recordLock.runExclusive(caseId, async () => {
    const current = await store.load(caseId);
    if (!current) throw new Error("no second opinion to act on — run a second opinion first");
    const next = decide(current);
    await store.save(caseId, next);
    return next;
  });
  // #1595: an accepted delta can add, dismiss or re-rate a finding, so the simulation verdict is
  // re-applied over the result, with the analyst's override read fresh — under the state lock, so a
  // "treat as real intrusion" saved meanwhile is not overwritten by a stale answer.
  const aliasIndex = await loadHostAliasIndex(
    {
      ...(ctx.opts.assetOverridesStore ? { assetOverrides: ctx.opts.assetOverridesStore } : {}),
      ...(ctx.opts.velociraptorClientStore ? { fleet: ctx.opts.velociraptorClientStore } : {}),
    },
    caseId,
  );
  const write = async (): Promise<{ state: InvestigationState; changed: boolean }> => {
    const state = await ctx.opts.stateStore.load(caseId);
    const applied = reconcileSimulationVerdict(applyAcceptedSecondOpinion(state, record), {
      treatAsReal: (await ctx.opts.synthMetaStore?.treatAsReal(caseId)) ?? false,
      aliasIndex,
    });
    if (applied !== state) await ctx.opts.stateStore.save(applied);
    return { state: applied, changed: applied !== state };
  };
  const { state, changed } = ctx.opts.stateLock
    ? await ctx.opts.stateLock.runExclusive(caseId, write)
    : await write();
  if (changed) ctx.opts.onState?.(state);
  return { record, state };
}
