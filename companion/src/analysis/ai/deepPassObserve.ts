import type { AIProvider } from "../../providers/provider.js";
import type { InvestigationState } from "../stateTypes.js";
import { getObservePrompt } from "./prompts/index.js";
import { SynthesisModelChoice } from "./synthesisFallback.js";
import type { SynthesisContext } from "./synthesis.js";

/**
 * One deep-pass model read (a batch, or a condense group) with the synthesis safety-stop rule
 * (#2076): a stop is retried on the primary while DFIR_AI_SYNTH_SAFETY_RETRIES allows, then that
 * read runs on the fallback model (DFIR_AI_SYNTH_FALLBACK_MODEL). Each read starts on the primary
 * again — one SynthesisModelChoice per read, as synthesis has one per call. A model the analyst
 * chose for this run keeps its retries but never falls back, the same as synthesis.
 *
 * Before this, a stop cost the whole batch: the deep pass had no fallback, so a configured one sat
 * unused while two of three batches on a real case went unread.
 */

const TASK = "deep-pass";

/** How many reads the fallback model answered, and its label — for the result and run record. */
export interface DeepPassFallbackTally {
  batchesOnFallback: number;
  fallbackModel?: string;
}

export interface DeepPassObserver {
  observe: (userPrompt: string) => Promise<unknown>;
  tally: () => DeepPassFallbackTally;
  /** The configured model's label, for the run record's fallback warning. */
  primaryLabel: string;
}

function cancelledError(): Error {
  const err = new Error("deep pass cancelled");
  err.name = "AbortError";
  return err;
}

export function deepPassObserver(
  ctx: SynthesisContext,
  caseId: string,
  state: InvestigationState,
  provider: AIProvider,
  opts: { signal?: AbortSignal; analystChose: boolean },
): DeepPassObserver {
  const retries = ctx.opts.retries ?? 3;
  const backoffMs = ctx.opts.backoffMs ?? 500;
  const primaryLabel = opts.analystChose
    ? `${provider.name}/${provider.model}`
    : (ctx.opts.synthesisModelLabel ?? `${provider.name}/${provider.model}`);
  const fallback = opts.analystChose ? undefined : ctx.opts.synthesisFallback;
  let onFallback = 0;

  const read = (p: AIProvider, userPrompt: string) =>
    ctx.withRetry(
      caseId,
      "deep-pass-observe",
      () =>
        ctx.analyzeRestored(
          caseId,
          state,
          p,
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
    );

  const observe = async (userPrompt: string): Promise<unknown> => {
    const choice = new SynthesisModelChoice(
      provider,
      primaryLabel,
      fallback,
      ctx.opts.synthesisSafetyRetries,
      TASK,
    );
    const answer = await choice.ask(
      (p) => read(p, userPrompt),
      () => {
        if (opts.signal?.aborted) throw cancelledError(); // a cancelled run starts no further call
      },
      (from, to) =>
        ctx.log.warn(
          `deep pass: ${from}'s safety filter stopped this read — reading it on the fallback model ${to}`,
          { caseId },
        ),
      (err, stops) => {
        ctx.log.warn(
          `deep pass: ${primaryLabel}'s safety filter stopped this read (${stops}) — asking it once more`,
          {
            caseId,
          },
        );
        ctx.recordRetry?.(caseId, "deep-pass-observe", err);
      },
    );
    if (choice.fallbackFrom) onFallback++;
    return answer;
  };

  return {
    observe,
    primaryLabel,
    tally: () => ({
      batchesOnFallback: onFallback,
      ...(onFallback > 0 && fallback ? { fallbackModel: fallback.label } : {}),
    }),
  };
}
