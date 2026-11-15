import { ProviderError, type AIProvider, type ProviderUsage } from "../../providers/provider.js";
import { safeAiErrorKind, safeAiPhase } from "../operationalMetrics.js";
import { servedModels } from "../servedModels.js";
import { noteAiCallStarted } from "../../http/rateLimiter.js";
import type { ProviderCallContext } from "./providerCallContext.js";

/**
 * One provider call wrapped in its bookkeeping: the AI-budget note, the served-model record (#1601)
 * and the operational-metrics record for both outcomes. `analyzeRestored` (one `analyze`) and
 * `converseRestored` (one `converse` per send) share it.
 *
 * `run` is called before this function's first await, so a caller that checked the anonymization
 * revision synchronously right before calling this still starts the provider call with no gap (#1840).
 */
export async function withCallMetrics<R extends { usage?: ProviderUsage }>(
  ctx: ProviderCallContext,
  provider: AIProvider,
  label: string,
  signal: AbortSignal | undefined,
  run: () => Promise<R>,
): Promise<R> {
  const startedAt = Date.now();
  noteAiCallStarted(); // the request that caused this call keeps its AI-budget slot (#1825)
  try {
    const result = await run();
    const usage = result.usage;
    // #1601: which concrete model served this call — for the job row and the run manifest.
    servedModels.record({
      provider: provider.name,
      alias: provider.model,
      resolvedModel: usage?.resolvedModel,
      ...(signal ? { signal } : {}),
    });
    void ctx.opts.operationalMetrics?.record({
      type: "ai",
      phase: safeAiPhase(label),
      durationMs: Date.now() - startedAt,
      success: true,
      inputTokens: usage?.inputTokens ?? 0,
      outputTokens: usage?.outputTokens ?? 0,
      costUsd: usage?.costUSD ?? 0,
      errorKind: "none",
    });
    return result;
  } catch (error) {
    const billed = error instanceof ProviderError ? error.usage : undefined; // cut off or refused, still billed
    void ctx.opts.operationalMetrics?.record({
      type: "ai",
      phase: safeAiPhase(label),
      durationMs: Date.now() - startedAt,
      success: false,
      inputTokens: billed?.inputTokens ?? 0,
      outputTokens: billed?.outputTokens ?? 0,
      costUsd: billed?.costUSD ?? 0,
      errorKind: safeAiErrorKind(error instanceof ProviderError ? error.kind : "other"),
    });
    throw error;
  }
}
