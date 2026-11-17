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

export type AiCostBucketName = "vision" | "synthesis" | "watson" | "other";

// analyzeRestored's `label` param (pipeline.ts) sorts into one of four buckets:
// "extract" (per-screenshot vision) is its own bucket; the main synthesis call (labeled
// "synthesis") and the second-opinion reconcile pass ("second-opinion-reconcile") are
// "synthesis"; every other labeled call (ask, csv, log, narrative, exec-summary, ...) is
// "other" — except Watson ("watson"), which has its own bucket so a round can read its own spend.
// analyzeRestored's own `label` parameter defaults to "ai", but every current
// call site in pipeline.ts passes an explicit label — that default is never actually
// reached. "ai" is still matched here defensively in case a future call site omits it.
export function bucketForLabel(label: string): AiCostBucketName {
  if (label === "extract") return "vision";
  if (label === "synthesis" || label === "ai" || label === "second-opinion-reconcile") return "synthesis";
  if (label === "watson") return "watson";
  return "other";
}

/**
 * All input the model read on one call (#2663): uncached input plus cache reads and writes. Providers
 * differ — Gemini and OpenAI-compatible counts already include the cached part (`inputIncludesCache`);
 * the Anthropic API and Claude Code report it apart.
 */
export function promptTokensOf(u: ProviderUsage): number {
  const input = u.inputTokens ?? 0;
  if (u.inputIncludesCache) return input;
  return input + (u.cacheReadTokens ?? 0) + (u.cacheCreationTokens ?? 0);
}

/** The input this call read from the provider's cache. */
export const cacheReadOf = (u: ProviderUsage): number => u.cacheReadTokens ?? 0;

/** The provider said something about its cache on this call (an explicit 0 counts). */
const reportsCache = (u: ProviderUsage): boolean =>
  u.cacheReadTokens !== undefined || u.cacheCreationTokens !== undefined;

// #2663: cache counters. A file written before them reads as zero, and they count only calls made
// since (`cacheSince`), so the panel says from when — `totalInputTokens` keeps its lifetime meaning.
const cacheFields = {
  promptTokens: z.number().catch(0),
  cacheReadTokens: z.number().catch(0),
  cacheWriteTokens: z.number().catch(0),
  hasCache: z.boolean().catch(false),
};

const modelSchema = z.object({
  calls: z.number().catch(0),
  costUSD: z.number().catch(0),
  hasCost: z.boolean().catch(false),
  inputTokens: z.number().catch(0),
  outputTokens: z.number().catch(0),
  hasTokens: z.boolean().catch(false),
  ...cacheFields,
});
export type AiCostModel = z.infer<typeof modelSchema>;

const bucketSchema = z.object({
  totalCalls: z.number().catch(0),
  totalCostUSD: z.number().catch(0),
  hasCost: z.boolean().catch(false),
  totalInputTokens: z.number().catch(0),
  totalOutputTokens: z.number().catch(0),
  hasTokens: z.boolean().catch(false),
  ...cacheFields,
  /** When this bucket first counted cache figures (ISO); absent before any. */
  cacheSince: z.string().optional().catch(undefined),
  byModel: z.record(z.string(), modelSchema).catch(() => ({})),
});
export type AiCostBucket = z.infer<typeof bucketSchema>;

export const aiCostStateSchema = z.object({
  vision: bucketSchema.catch(() => emptyBucket()),
  synthesis: bucketSchema.catch(() => emptyBucket()),
  watson: bucketSchema.catch(() => emptyBucket()),
  other: bucketSchema.catch(() => emptyBucket()),
});
export type AiCostState = z.infer<typeof aiCostStateSchema>;

function emptyBucket(): AiCostBucket {
  return {
    totalCalls: 0,
    totalCostUSD: 0,
    hasCost: false,
    totalInputTokens: 0,
    totalOutputTokens: 0,
    hasTokens: false,
    ...emptyCache(),
    byModel: {},
  };
}

function emptyCache() {
  return { promptTokens: 0, cacheReadTokens: 0, cacheWriteTokens: 0, hasCache: false };
}

/** Add one call's prompt and cache figures to a bucket or model total. */
function addCache(t: ReturnType<typeof emptyCache>, u: ProviderUsage): void {
  t.promptTokens += promptTokensOf(u);
  if (!reportsCache(u)) return;
  t.cacheReadTokens += u.cacheReadTokens ?? 0;
  t.cacheWriteTokens += u.cacheCreationTokens ?? 0;
  t.hasCache = true;
}

function emptyState(): AiCostState {
  return { vision: emptyBucket(), synthesis: emptyBucket(), watson: emptyBucket(), other: emptyBucket() };
}

function emptyModel(): AiCostModel {
  return {
    calls: 0,
    costUSD: 0,
    hasCost: false,
    inputTokens: 0,
    outputTokens: 0,
    hasTokens: false,
    ...emptyCache(),
  };
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
  // NOTE: load-mutate-write here is NOT wrapped in StateLock (unlike the higher-stakes
  // forensic-evidence writes elsewhere). Two AI calls finishing for the same case at
  // nearly the same moment could race and lose an increment. Accepted tradeoff for a
  // diagnostics-only feature — worst case is undercounted cost/tokens, not data loss.
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
      addCache(m, usage);
      addCache(b, usage);
      b.cacheSince ??= new Date().toISOString();
    }
    b.byModel[key] = m;
    await atomicWrite(this.path(caseId), JSON.stringify(state, null, 2));
    return state;
  }
}
