import { performance } from "node:perf_hooks";
import type {
  AIProvider,
  AnalyzeRequest,
  AnalyzeResult,
  ProviderUsage,
} from "../../src/providers/provider.js";
import type { EvaluationResources } from "./report.js";

function usageResources(
  usage: ProviderUsage | undefined,
): Omit<EvaluationResources, "durationMs" | "calls" | "failedCalls"> {
  return {
    inputTokens: usage?.inputTokens ?? 0,
    outputTokens: usage?.outputTokens ?? 0,
    costUsd: usage?.costUSD ?? 0,
  };
}

export class MeteredProvider implements AIProvider {
  readonly name: string;
  readonly model: string;
  private resources: EvaluationResources = {
    durationMs: 0,
    calls: 0,
    failedCalls: 0,
    inputTokens: 0,
    outputTokens: 0,
    costUsd: 0,
  };

  constructor(private readonly provider: AIProvider) {
    this.name = provider.name;
    this.model = provider.model;
  }

  async analyze(request: AnalyzeRequest): Promise<AnalyzeResult> {
    const started = performance.now();
    this.resources = { ...this.resources, calls: this.resources.calls + 1 };
    try {
      const result = await this.provider.analyze(request);
      const usage = usageResources(result.usage);
      this.resources = {
        ...this.resources,
        durationMs: this.resources.durationMs + performance.now() - started,
        inputTokens: this.resources.inputTokens + usage.inputTokens,
        outputTokens: this.resources.outputTokens + usage.outputTokens,
        costUsd: this.resources.costUsd + usage.costUsd,
      };
      return result;
    } catch (error) {
      this.resources = {
        ...this.resources,
        durationMs: this.resources.durationMs + performance.now() - started,
        failedCalls: this.resources.failedCalls + 1,
      };
      throw error;
    }
  }

  snapshot(): EvaluationResources {
    return { ...this.resources };
  }
}
