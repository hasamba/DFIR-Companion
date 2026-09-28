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
  UncitedAnswerError,
} from "./synthesisAnswerRepair.js";
import { needsCitationRetry, uncitedFindingIds, type CitationCounts } from "./findingCitations.js";
import { SynthesisModelChoice } from "./synthesisFallback.js";
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
  citationRetriedAfter?: CitationCounts["retriedAfter"]; // #1754: set when the citation retry ran
  citationRetries: number; // #1754: 0 or 1 — the extra model call, kept apart from parseRetries
}

// One accepted answer and the model that gave it. Snapshotted per answer: the citation retry can
// move the call to the fallback model and then keep the FIRST answer, which the primary gave.
interface Answer {
  delta: ReturnType<typeof stripAiExtractedFrom>;
  resolvedModel: string | undefined;
  answeredBy: AIProvider;
  answeredByLabel: string;
  fallbackFrom: string | undefined;
}

export async function callSynthesisModel(
  ctx: SynthesisContext,
  caseId: string,
  state: InvestigationState,
  provider: AIProvider,
  userPrompt: string,
  // `provider` here is the CALLER's override (second-opinion model B, a replay): when set, the call
  // runs on exactly that model — it keeps its safety retries (#1740) but never falls back (#1734).
  // `shownEventIds`: every event the prompt represents (#1754). When set, an answer whose findings
  // mostly cite none of them is asked for once more.
  opts: {
    signal?: AbortSignal;
    provider?: AIProvider;
    shownEventIds?: ReadonlySet<string>;
  } & SynthThinkingInput,
): Promise<SynthesisCall> {
  const { tokens: thinkingTokens, source: thinkingSource } = resolveSynthThinking(
    opts,
    Number(process.env.DFIR_AI_SYNTH_THINKING_TOKENS) || 0,
  );
  let parseRetries = 0;
  let retryNote: string | undefined; // #1602: what the last bad answer got wrong, for the next attempt
  let citationNote: string | undefined; // #1754: kept apart, so a later parse note cannot replace it
  let attempt = 0;
  // #1601: the model of the ACCEPTED attempt only. Collected per attempt (scoped to this call chain),
  // so a failed attempt's model never labels an answer that came back without one.
  let resolvedModel: string | undefined;
  // #1734/#1740: a safety-filter stop is retried on the same model, then moves THIS call to the
  // fallback — never for a caller's own provider. The retry count is fixed at startup, like the fallback.
  const choice = new SynthesisModelChoice(
    provider,
    ctx.opts.synthesisModelLabel ?? `${provider.name}/${provider.model}`,
    opts.provider ? undefined : ctx.opts.synthesisFallback,
    ctx.opts.synthesisSafetyRetries,
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
          userPrompt: [userPrompt, citationNote, retryNote].filter(Boolean).join("\n\n"),
          images: [],
          ...(thinkingTokens > 0 ? { thinkingTokens } : {}),
          rejectTruncated: true, // a cut-off synthesis is never merged; say why instead
          ...(opts.signal ? { signal: opts.signal } : {}),
        },
        "synthesis",
      ),
    );
  const answerOnce = async (): Promise<Answer> => {
    resolvedModel = undefined;
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
      resolvedModel,
      answeredBy: choice.answeredBy,
      answeredByLabel: choice.answeredByLabel,
      fallbackFrom: choice.fallbackFrom,
    };
  };
  const { answer, retriedAfter } = await answerWithCitations(ctx, caseId, {
    answerOnce,
    shown: opts.shownEventIds,
    signal: opts.signal,
    attempt: () => attempt,
    setNote: (note) => (citationNote = note),
  });
  return {
    delta: answer.delta,
    thinkingTokens,
    thinkingSource,
    parseRetries,
    ...(answer.resolvedModel ? { resolvedModel: answer.resolvedModel } : {}),
    answeredBy: answer.answeredBy,
    answeredByLabel: answer.answeredByLabel,
    ...(answer.fallbackFrom ? { fallbackFrom: answer.fallbackFrom } : {}),
    safetyStops: choice.safetyStops,
    primaryLabel: choice.primaryName,
    ...(retriedAfter ? { citationRetriedAfter: retriedAfter } : {}),
    citationRetries: retriedAfter ? 1 : 0,
  };
}

/**
 * Ask once more when most findings cite no event (#1754). On INC-2026-022 all 13 findings of an Opus
 * answer left relatedEventIds empty, and the High backfill raised 82 auto findings on rows the
 * findings had already explained. The retry is its OWN budget, outside `withRetry`: it runs even with
 * retries set to 0 and after transient failures used the budget up. The uncited answer is saved to the
 * case logs like a failed parse. Then the answer with fewer uncited findings wins (a tie takes the
 * retry); a retry that cannot be had keeps the first answer — its text is still the analysis.
 */
async function answerWithCitations(
  ctx: SynthesisContext,
  caseId: string,
  o: {
    answerOnce: () => Promise<Answer>;
    shown: ReadonlySet<string> | undefined;
    signal: AbortSignal | undefined;
    attempt: () => number;
    setNote: (note: string) => void;
  },
): Promise<{ answer: Answer; retriedAfter?: { uncited: number; total: number } }> {
  const first = await o.answerOnce();
  if (!o.shown) return { answer: first };
  const total = first.delta.findings.length;
  const uncited = uncitedFindingIds(first.delta, o.shown).length;
  if (!needsCitationRetry(uncited, total)) return { answer: first };
  const err = new UncitedAnswerError(uncited, total);
  const deps = { log: ctx.log, store: ctx.opts.synthMetaStore };
  await keepFailedAnswer(deps, caseId, o.attempt(), err, first.delta);
  ctx.log.warn(`[synthesis] ${err.message} — asking once more for event citations`, { caseId });
  ctx.recordRetry?.(caseId, "synthesis", err); // counted like any retry (ai_retry)
  o.setNote(synthesisRetryNote(err) ?? "");
  const retriedAfter = { uncited, total };
  let second: Answer;
  try {
    second = await o.answerOnce();
  } catch (retryErr) {
    throwIfSuperseded(o.signal);
    if (retryErr instanceof Error && retryErr.name === "AbortError") throw retryErr;
    ctx.log.warn(`[synthesis] the citation retry failed (${String(retryErr)}) — keeping the first answer`, {
      caseId,
    });
    return { answer: first, retriedAfter };
  }
  const again = uncitedFindingIds(second.delta, o.shown).length;
  if (needsCitationRetry(again, second.delta.findings.length))
    ctx.log.warn(
      `[synthesis] the citation retry still left ${again} of ${second.delta.findings.length} findings citing no event`,
      { caseId },
    );
  return { answer: again <= uncited ? second : first, retriedAfter };
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
