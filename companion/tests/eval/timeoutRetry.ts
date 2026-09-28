import { performance } from "node:perf_hooks";
import {
  ProviderError,
  type AIProvider,
  type AnalyzeRequest,
  type AnalyzeResult,
} from "../../src/providers/provider.js";

// #1747: on a real eval run, retry a timed-out call ONCE. One hung Claude CLI call (15 minutes, no
// answer) failed a whole attestation run during #1579. The product's own retry policy
// (src/analysis/ai/retry.ts) deliberately never retries a timeout — an analyst should not wait
// three times — so this lives in the eval harness only.
//
// Scope: `ProviderError` kind "timeout", which the Claude CLI provider raises. HTTP providers raise
// "transport" on a request timeout, and the product already retries that.
//
// Wrap the MeteredProvider (not the other way round), so the meter still counts both calls and the
// failed one. The wall time lost to the timed-out attempt is kept in lostMs(), so the case's
// duration can exclude it: a retried hang must not read as a prompt that made the run slower.
export class TimeoutRetryProvider implements AIProvider {
  readonly name: string;
  readonly model: string;
  readonly supportsThinking?: boolean;
  private lost = 0;

  constructor(private readonly provider: AIProvider) {
    this.name = provider.name;
    this.model = provider.model;
    if (provider.supportsThinking !== undefined) this.supportsThinking = provider.supportsThinking;
  }

  async analyze(request: AnalyzeRequest): Promise<AnalyzeResult> {
    const started = performance.now();
    try {
      return await this.provider.analyze(request);
    } catch (error) {
      // A cancelled request also surfaces as "timeout" from the CLI runner; never re-run it.
      if (!(error instanceof ProviderError) || error.kind !== "timeout" || request.signal?.aborted)
        throw error;
      this.lost += performance.now() - started;
      console.warn(`[eval] ${this.name}/${this.model} call timed out — retrying once (#1747)`);
      return this.provider.analyze(request);
    }
  }

  lostMs(): number {
    return this.lost;
  }
}
