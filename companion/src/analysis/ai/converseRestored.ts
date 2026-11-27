import { ProviderError, type AIProvider } from "../../providers/provider.js";
import {
  ToolsUnsupportedError,
  type ConverseRequest,
  type ConverseResult,
  type ToolCall,
  type ToolTurn,
} from "../../providers/toolCalling.js";
import type { AnonPair, Anonymizer } from "../anonymize.js";
import { AnonymizationChangedError, anonRevision } from "../anonRevision.js";
import type { InvestigationState } from "../stateTypes.js";
import { previewCall } from "./aiPreviewCall.js";
import { activeAiPreview } from "./aiPreviewScope.js";
import { withCallMetrics } from "./callMetrics.js";
import { maskRequest, withSendMasking, type PromptEntities } from "./maskRequest.js";
import { authoredFor, reportAnswer, reportGate } from "./presidioAuthoredText.js";
import { presidioEnabledFor } from "./presidioScan.js";
import { AiAnswerParseError, logAiUsage, parseAnswer, presidioGate, recordAiCost } from "./providerCall.js";
import type { ProviderCallContext } from "./providerCallContext.js";
import {
  assertNoSeedInClear,
  assertNothingStale,
  assertSeedKept,
  MASKING_CHANGED,
  maskDeep,
  maskTurn,
  outboundTexts,
  staleReadable,
} from "./converseMasking.js";

export { maskDeep, outboundTexts } from "./converseMasking.js";
import { captureIfSafetyStop } from "./safetyStopCapture.js";

/**
 * The AI-call gate for a multi-turn, tool-calling conversation (Watson phase 5, D6).
 *
 * The caller keeps the transcript in CLEAR text. Every send masks all of it again — the prompt through
 * `maskRequest` (the function the preview shares), then every transcript string with that same
 * anonymizer — so one send has one anonymizer. The anonymizer is seeded with the pairs the earlier
 * sends minted (`ConverseSession.pairs`), so a token keeps its meaning for the whole round and an
 * unchanged prefix is byte-identical, which keeps signed reasoning valid. Opaque provider data is
 * echoed unchanged, except a signed block whose readable text the masking now hides: the adapter
 * drops it. The Presidio gate runs on every send over every readable field the send carries.
 *
 * Revision rule: the first send masks again up to three times when the anonymization changes under
 * it (as analyzeRestored does). After it, the session holds that revision, and any change stops the
 * round with AnonymizationChangedError: nothing more is sent under a different masking.
 */

export interface GatedConverseRequest extends ConverseRequest {
  promptEntities?: PromptEntities;
  /** Runs after the send is prepared, right before it goes: a throw stops it (F4: AI off, case closed). */
  beforeSend?: () => Promise<void>;
}

export interface ConverseRestoredResult {
  /** Parsed + restored final JSON when the model answered; undefined when it called tools. */
  answer?: unknown;
  /** Restored tool calls, to append to the clear transcript. */
  calls: ToolCall[];
  /** The assistant turn to append (clear text, restored calls, opaque as the provider gave it). */
  assistant: Extract<ToolTurn, { role: "assistant" }>;
}

/** Seed for the next send; `revision` is set after the first successful send. */
export interface ConverseSession {
  readonly pairs: readonly AnonPair[];
  readonly revision?: number;
}

/** One send's result and the session the next send starts from. The input session is never changed. */
export interface ConverseRestoredSend {
  readonly result: ConverseRestoredResult;
  readonly session: ConverseSession;
}

/** A final answer that could not be parsed, after a send that happened: carries the next session. */
export class ConverseAnswerParseError extends AiAnswerParseError {
  constructor(
    parseError: AiAnswerParseError,
    readonly session: ConverseSession,
  ) {
    super(parseError.rawText, parseError.cause);
    this.name = "ConverseAnswerParseError";
  }
}

const MAX_ANON_ATTEMPTS = 3;

interface PreparedSend {
  readonly req: ConverseRequest;
  readonly anon: Anonymizer | null;
}

/** Mask the whole send, check the seed, gate it with Presidio. Writes nothing but a held approval. */
async function prepareSend(
  ctx: ProviderCallContext,
  caseId: string,
  state: InvestigationState,
  provider: AIProvider,
  gated: GatedConverseRequest,
  seed: readonly AnonPair[],
  label: string,
): Promise<PreparedSend> {
  // The per-call entities hold real values: they stop here and never reach the provider.
  // The caller's cache prefix never leaves here (#2658): only maskRequest's verified one — masked when
  // anonymization is on, the clear one only when it is off (#2675).
  const { promptEntities, withhold: _ignored, beforeSend: _check, cachePrefix: clearPrefix, ...base } = gated;
  // The prompt AND the transcript are masked under the masking-map lock: both can mint tokens (#2657).
  const { m, transcript } = await withSendMasking(ctx, caseId, async (identity) => {
    const masked = await maskRequest(ctx, caseId, state, {
      userPrompt: gated.userPrompt,
      promptEntities,
      anonSeed: seed,
      anonIdentity: identity,
      ...(clearPrefix ? { cachePrefix: clearPrefix } : {}),
    });
    const a = masked.anon;
    const turns = a ? base.transcript.map((t) => maskTurn((x) => a.apply(x), t)) : base.transcript;
    return { anon: a, result: { m: masked, transcript: turns } };
  });
  const cached = m.sentCachePrefix ? { cachePrefix: m.sentCachePrefix } : {};
  if (!m.anon || !m.known) {
    reportGate(false); // the model sees clear text: its answer may not be recorded as AI text
    return { req: { ...base, userPrompt: m.plainPrompt, ...cached }, anon: null };
  }
  const anon = m.anon;
  assertSeedKept(anon, seed);
  // Signed reasoning is never changed. The adapter drops a stale block (the controller ruling) and
  // reports the readable text it will really echo; only that text is gated.
  const withhold = staleReadable(m.policy, m.known, anon);
  const echoed = provider.echoedReadableText?.bind(provider);
  const req = { ...base, userPrompt: m.maskedPrompt, transcript, ...cached, ...(echoed ? { withhold } : {}) };
  if (!echoed) assertNothingStale(transcript, withhold);
  const texts = outboundTexts(req, echoed?.(req));
  assertNoSeedInClear(seed, texts);
  const outbound = texts.join("\n");
  const authored = await authoredFor(ctx.opts.aiAuthoredStore, ctx.log, caseId, { spans: m.spans });
  await presidioGate(ctx, caseId, label, outbound, m.known, m.control, authored);
  reportGate(Boolean(ctx.opts.presidio) && presidioEnabledFor(m.control));
  return { req, anon };
}

export async function converseRestored(
  ctx: ProviderCallContext,
  caseId: string,
  state: InvestigationState,
  provider: AIProvider,
  req: GatedConverseRequest,
  session: ConverseSession,
  label = "watson",
): Promise<ConverseRestoredSend> {
  // "Preview what the AI will see": the first request's prompt, through the same masking; no send.
  if (activeAiPreview()) {
    const { systemPrompt, userPrompt, promptEntities } = req;
    const preview = { systemPrompt, userPrompt, images: [], promptEntities };
    return previewCall(ctx, caseId, state, provider, preview, label, () => false);
  }
  const converse = provider.converse?.bind(provider);
  if (!converse) throw new ToolsUnsupportedError(`${provider.name} cannot make a tool-calling turn`);
  const fixed = session.revision;
  for (let attempt = 1; attempt <= MAX_ANON_ATTEMPTS; attempt++) {
    const revision = fixed ?? anonRevision(caseId);
    if (anonRevision(caseId) !== revision) throw new AnonymizationChangedError(MASKING_CHANGED);
    const prepared = await prepareSend(ctx, caseId, state, provider, req, session.pairs, label);
    // F4: masking and Presidio can take a while; AI off or a closed case in that time stops the send.
    await req.beforeSend?.();
    // #1840: no await between this check and the provider call.
    if (anonRevision(caseId) === revision)
      return sendPrepared(ctx, caseId, provider, converse, prepared, session, revision, label);
    if (fixed !== undefined) throw new AnonymizationChangedError(MASKING_CHANGED);
    ctx.log.warn(`[anon] anonymization changed while [${label}] was being prepared — masking again`, {
      caseId,
    });
  }
  throw new AnonymizationChangedError(
    `The anonymization settings or hidden values kept changing while this AI call was being ` +
      `prepared, so nothing was sent. Run it again.`,
  );
}

/** The send and its bookkeeping. The provider call starts before the first await. */
async function sendPrepared(
  ctx: ProviderCallContext,
  caseId: string,
  provider: AIProvider,
  converse: (req: ConverseRequest) => Promise<ConverseResult>,
  prepared: PreparedSend,
  session: ConverseSession,
  revision: number,
  label: string,
): Promise<ConverseRestoredSend> {
  const sentReq = prepared.req;
  let result: ConverseResult;
  try {
    result = await withCallMetrics(ctx, provider, label, sentReq.signal, () => converse(sentReq));
  } catch (err) {
    // Review I3: a response that was billed and then refused or cut off still counts against limits.
    const billed = err instanceof ProviderError ? err.usage : undefined;
    if (billed) {
      logAiUsage(ctx, caseId, label, provider, { usage: billed });
      await recordAiCost(ctx, caseId, label, provider, { usage: billed });
    }
    // #2083: the safety-stop capture saves the masked user prompt only.
    const req = { systemPrompt: sentReq.systemPrompt, userPrompt: sentReq.userPrompt, images: [] };
    const sent = { req, anonymized: prepared.anon !== null };
    await captureIfSafetyStop(ctx.opts.safetyStopCapture, ctx.log, caseId, provider, sent, label, err);
    throw err;
  }
  logAiUsage(ctx, caseId, label, provider, result);
  await recordAiCost(ctx, caseId, label, provider, result);
  const pairs = prepared.anon ? prepared.anon.pairs() : session.pairs;
  const next: ConverseSession = { pairs, revision };
  try {
    return { result: restoreResult(result, prepared.anon), session: next };
  } catch (err) {
    // The send happened: the next send (a finalization retry) must start from its session (review M6).
    if (err instanceof AiAnswerParseError) throw new ConverseAnswerParseError(err, next);
    throw err;
  }
}

// Each piece (call inputs, assistant text, final answer) is restored exactly once (#3001): restored
// text may hold a planted literal equal to a minted token, and a second restore would make it real.
function restoreResult(result: ConverseResult, anon: Anonymizer | null): ConverseRestoredResult {
  // Keys too (review I2): maskDeep with restore walks keys and string leaves alike.
  const calls = result.calls.map((c) => ({
    ...c,
    input: anon ? maskDeep((t) => anon.restore(t), c.input) : c.input,
  }));
  const assistant: ConverseRestoredResult["assistant"] = {
    role: "assistant",
    text: anon ? anon.restore(result.text) : result.text,
    calls,
    ...(result.opaque !== undefined ? { opaque: result.opaque } : {}),
    ...(result.opaqueText ? { opaqueText: result.opaqueText } : {}),
  };
  if (calls.length > 0) return { calls, assistant };
  return { answer: parseFinal(result.text, anon), calls, assistant };
}

/** The final text: parsed, then restored, exactly as analyzeRestored's answer. */
function parseFinal(text: string, anon: Anonymizer | null): unknown {
  if (!anon) return parseAnswer(text, (t) => t);
  const masked = parseAnswer(text, (t) => anon.restore(t));
  reportAnswer(masked); // the model's own words, placeholders kept (presidioAuthoredText.ts)
  return anon.restoreDeep(masked);
}
