import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import type { ProviderUsage } from "../providers/provider.js";

// Per-case running total of AI API cost/tokens, bucketed by call type. Written by
// AnalysisPipeline.analyzeRestored() (the single choke point every AI call passes
// through) after every call, successful or not (a failed call still counts toward
// the call total; usage/cost are simply absent for it). Never resets — accumulates
// for the case's lifetime, same posture as findings/IOCs.

export type AiCostBucketName = "vision" | "synthesis" | "other";

// analyzeRestored's `label` param (pipeline.ts) sorts into one of three buckets:
// "extract" (per-screenshot vision) is its own bucket; the main synthesis call (whose
// label defaults to "ai") and the second-opinion reconcile pass are "synthesis"; every
// other labeled call (ask, csv, log, narrative, exec-summary, ...) is "other".
export function bucketForLabel(label: string): AiCostBucketName {
  if (label === "extract") return "vision";
  if (label === "ai" || label === "second-opinion-reconcile") return "synthesis";
  return "other";
}

const modelSchema = z.object({
  calls: z.number().catch(0),
  costUSD: z.number().catch(0),
  hasCost: z.boolean().catch(false),
  inputTokens: z.number().catch(0),
  outputTokens: z.number().catch(0),
  hasTokens: z.boolean().catch(false),
});
export type AiCostModel = z.infer<typeof modelSchema>;

const bucketSchema = z.object({
  totalCalls: z.number().catch(0),
  totalCostUSD: z.number().catch(0),
  hasCost: z.boolean().catch(false),
  totalInputTokens: z.number().catch(0),
  totalOutputTokens: z.number().catch(0),
  hasTokens: z.boolean().catch(false),
  byModel: z.record(z.string(), modelSchema).catch({}),
});
export type AiCostBucket = z.infer<typeof bucketSchema>;

export const aiCostStateSchema = z.object({
  vision: bucketSchema.catch(emptyBucket()),
  synthesis: bucketSchema.catch(emptyBucket()),
  other: bucketSchema.catch(emptyBucket()),
});
export type AiCostState = z.infer<typeof aiCostStateSchema>;

function emptyBucket(): AiCostBucket {
  return {
    totalCalls: 0, totalCostUSD: 0, hasCost: false,
    totalInputTokens: 0, totalOutputTokens: 0, hasTokens: false,
    byModel: {},
  };
}

function emptyState(): AiCostState {
  return { vision: emptyBucket(), synthesis: emptyBucket(), other: emptyBucket() };
}

function emptyModel(): AiCostModel {
  return { calls: 0, costUSD: 0, hasCost: false, inputTokens: 0, outputTokens: 0, hasTokens: false };
}

export class AiCostStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "ai-cost.json");
  }

  async load(caseId: string): Promise<AiCostState> {
    try {
      return aiCostStateSchema.parse(JSON.parse(await readFile(this.path(caseId), "utf8")));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return emptyState();
      throw err;
    }
  }

  // Record one AI call. `usage` is whatever the provider reported (possibly undefined —
  // the call count still increments; cost/tokens simply don't move for that call).
  async record(
    caseId: string,
    bucket: AiCostBucketName,
    providerName: string,
    model: string,
    usage: ProviderUsage | undefined,
  ): Promise<AiCostState> {
    const state = await this.load(caseId);
    const b = state[bucket];
    b.totalCalls += 1;
    const key = `${providerName}/${model}`;
    const m = b.byModel[key] ?? emptyModel();
    m.calls += 1;
    if (usage?.costUSD !== undefined) {
      m.costUSD += usage.costUSD;
      m.hasCost = true;
      b.totalCostUSD += usage.costUSD;
      b.hasCost = true;
    }
    if (usage?.inputTokens !== undefined || usage?.outputTokens !== undefined) {
      m.inputTokens += usage.inputTokens ?? 0;
      m.outputTokens += usage.outputTokens ?? 0;
      m.hasTokens = true;
      b.totalInputTokens += usage.inputTokens ?? 0;
      b.totalOutputTokens += usage.outputTokens ?? 0;
      b.hasTokens = true;
    }
    b.byModel[key] = m;
    await atomicWrite(this.path(caseId), JSON.stringify(state, null, 2));
    return state;
  }
}
