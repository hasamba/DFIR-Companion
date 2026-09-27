import type { AIProvider } from "../../providers/provider.js";
import type { InvestigationState } from "../stateTypes.js";
import { deltaSchema, stripAiExtractedFrom } from "../responseSchema.js";
import { collectServedModel } from "../servedModels.js";
import { resolveSynthThinking, type SynthThinkingInput, type SynthThinkingSource } from "../synthThinking.js";
import { getSynthesisPrompt } from "./prompts/index.js";
import {
  fillOptionalSynthesisFields,
  keepFailedAnswer,
  synthesisRetryNote,
} from "./synthesisAnswerRepair.js";
import { SynthesisModelChoice, safetyRetriesFromEnv } from "./synthesisFallback.js";
import type { SynthesisContext } from "./synthesis.js";

// The synthesis model call and its answer parsing, moved out of synthesis.ts (#1734) when the
// safety-stop fallback pushed that file past its size budget. synthesis.ts is the only caller.

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
export interface SynthesisCall {
  delta: ReturnType<typeof stripAiExtractedFrom>;
  thinkingTokens: number;
  thinkingSource: SynthThinkingSource; // #1468: toggle / env / off, recorded on the run
  parseRetries: number;
  resolvedModel?: string; // #1601: the concrete model the provider reported, recorded on the run
  answeredBy: AIProvider; // #1734: the provider whose answer was accepted — the fallback after a stop
  answeredByLabel: string; // #1734: its recorded label
  fallbackFrom?: string; // #1734: the synthesis model whose safety filter stopped, when it fell back
  safetyStops: number; // #1740: how many times that model's safety filter stopped an answer
  primaryLabel: string; // #1740: the synthesis model's label, for the log line
}

export async function callSynthesisModel(
  ctx: SynthesisContext,
  caseId: string,
  state: InvestigationState,
  provider: AIProvider,
  userPrompt: string,
  // `provider` here is the CALLER's override (second-opinion model B, a replay): when set, the call
  // runs on exactly that model — it keeps its safety retries (#1740) but never falls back (#1734).
  opts: { signal?: AbortSignal; provider?: AIProvider } & SynthThinkingInput,
): Promise<SynthesisCall> {
  const { tokens: thinkingTokens, source: thinkingSource } = resolveSynthThinking(
    opts,
    Number(process.env.DFIR_AI_SYNTH_THINKING_TOKENS) || 0,
  );
  let parseRetries = 0;
  let retryNote: string | undefined; // #1602: what the last bad answer got wrong, for the next attempt
  let attempt = 0;
  // #1601: the model of the ACCEPTED attempt only. Collected per attempt (scoped to this call chain),
  // so a failed attempt's model never labels an answer that came back without one.
  let resolvedModel: string | undefined;
  // #1734/#1740: a safety-filter stop is retried on the same model, then moves THIS call to the
  // fallback — never for a caller's own provider. The retry count is read live, like the thinking budget.
  const choice = new SynthesisModelChoice(
    provider,
    ctx.opts.synthesisModelLabel ?? `${provider.name}/${provider.model}`,
    opts.provider ? undefined : ctx.opts.synthesisFallback,
    safetyRetriesFromEnv(process.env.DFIR_AI_SYNTH_SAFETY_RETRIES),
  );
  const ask = (p: AIProvider) =>
    collectServedModel(() =>
      ctx.analyzeRestored(
        caseId,
        state,
        p,
        {
          systemPrompt: getSynthesisPrompt(),
          // Appended at the END so the cached prompt prefix is unchanged on the retry.
          userPrompt: retryNote ? `${userPrompt}\n\n${retryNote}` : userPrompt,
          images: [],
          ...(thinkingTokens > 0 ? { thinkingTokens } : {}),
          rejectTruncated: true, // a cut-off synthesis is never merged; say why instead
          ...(opts.signal ? { signal: opts.signal } : {}),
        },
        "synthesis",
      ),
    );
  const delta = await ctx.withRetry(
    caseId,
    "synthesis",
    async () => {
      throwIfSuperseded(opts.signal); // #1608: a retry after a supersede calls no provider
      attempt++;
      let parsed: unknown;
      try {
        const served = await choice.ask(
          ask,
          () => throwIfSuperseded(opts.signal), // a cancelled run starts no second, expensive call
          (from, to) =>
            ctx.log.warn(
              `[synthesis] ${from}'s safety filter stopped the answer — running this synthesis on the fallback model ${to}`,
              { caseId },
            ),
          (err, stops) => {
            ctx.log.warn(
              `[synthesis] ${choice.primaryName}'s safety filter stopped the answer (${stops}) — asking it once more`,
              { caseId },
            );
            ctx.recordRetry?.(caseId, "synthesis", err); // counted like any retry (ai_retry)
          },
        );
        parsed = served.value;
        const answer = parseSynthesisAnswer(ctx, caseId, parsed);
        resolvedModel = served.resolvedModel;
        return answer;
      } catch (err) {
        throwIfSuperseded(opts.signal); // #1608: not a parse retry, and withRetry never retries it
        parseRetries++;
        retryNote = synthesisRetryNote(err) ?? retryNote; // a provider error keeps the current note
        await keepFailedAnswer(
          { log: ctx.log, store: ctx.opts.synthMetaStore },
          caseId,
          attempt,
          err,
          parsed,
        );
        throw err;
      }
    },
    ctx.opts.retries ?? 3,
    ctx.opts.backoffMs ?? 500,
  );
  return {
    delta,
    thinkingTokens,
    thinkingSource,
    parseRetries,
    ...(resolvedModel ? { resolvedModel } : {}),
    answeredBy: choice.answeredBy,
    answeredByLabel: choice.answeredByLabel,
    ...(choice.fallbackFrom ? { fallbackFrom: choice.fallbackFrom } : {}),
    safetyStops: choice.safetyStops,
    primaryLabel: choice.primaryName,
  };
}

// #1602: default the often-empty parts of a partial answer, and say which ones, so a model that
// routinely skips fields shows up in the log. findings and summary stay required.
function parseSynthesisAnswer(
  ctx: SynthesisContext,
  caseId: string,
  parsed: unknown,
): ReturnType<typeof stripAiExtractedFrom> {
  const { value, filled } = fillOptionalSynthesisFields(parsed);
  if (filled.length)
    ctx.log.warn(`[synthesis] model answer omitted ${filled.join(", ")} — filled with empty values`, {
      caseId,
    });
  return stripAiExtractedFrom(deltaSchema.parse(value));
}

/**
 * Stop here if this run has been superseded or cancelled.
 *
 * THE SIGNAL IS NOT THE PROVIDER'S ALONE. `exclusive: true` on the synthesis job means a newer kick
 * aborts this run's signal, drops its row and frees the case's single concurrency slot so the newer
 * run can start — see JobManager.dropForExclusiveRegistration. That only works if this run then
 * stops. Handing `signal` to the model call is not enough: a provider that finishes the call anyway
 * (the claude-code provider completed a six-minute call after its signal was aborted) used to carry
 * on into the fold, the PERSIST — over the newer run's work — and the run record. When this run also
 * swept for a second look, it carried a whole extra synthesis behind it too: two top-level runs held
 * the whole case state at once, state loads went from 0.6 s to 140 s, and neither reached its
 * terminal `ai_status`, which left the header pill stuck on "AI: synthesizing…" with no job to
 * explain it. Only an analyst's run-now (Re-synthesize, /dfir, replay) supersedes one now (#1608).
 *
 * Called at the stage boundaries rather than inside the steps: a step that has begun should finish
 * or throw on its own, and the boundaries are where nothing is half-written.
 *
 * Throws an `AbortError`, which is what both callers already classify a cancellation by (see
 * captureAnalysis.settleSynthesisRejection and routes/analystGate.ts) — so a superseded run reports
 * "cancelled", never "synthesis failed".
 */
export function throwIfSuperseded(signal: AbortSignal | undefined): void {
  if (!signal?.aborted) return;
  const err = new Error("synthesis superseded by a newer run");
  err.name = "AbortError";
  throw err;
}
