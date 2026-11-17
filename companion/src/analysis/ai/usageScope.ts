import { AsyncLocalStorage } from "node:async_hooks";
import type { ProviderUsage } from "../../providers/provider.js";
import { cacheReadOf, promptTokensOf } from "../aiCost.js";

// #2663: what ONE piece of work (a Watson round) read from its model calls, counted as the calls happen
// — every send, retry, tool step and hop, and a billed failure — instead of a before/after difference of
// the case's shared cost file, which loses counts when two calls finish together. recordAiCost (the one
// place every call's usage is booked) reports here too. Async-scoped, so two rounds never mix.

export interface UsageTally {
  /** All input the model read: uncached input plus cache reads and writes. */
  promptTokens: number;
  cacheReadTokens: number;
  /** At least one call reported input tokens. */
  reported: boolean;
}

const scope = new AsyncLocalStorage<UsageTally>();

export const newUsageTally = (): UsageTally => ({ promptTokens: 0, cacheReadTokens: 0, reported: false });

/** Run `fn` with `tally` collecting the usage of every model call it makes. */
export function inUsageScope<T>(tally: UsageTally, fn: () => Promise<T>): Promise<T> {
  return scope.run(tally, fn);
}

/** Book one call's usage into the active tally, if any. */
export function noteUsage(usage: ProviderUsage | undefined): void {
  const tally = scope.getStore();
  if (!tally || !usage || usage.inputTokens === undefined) return;
  tally.promptTokens += promptTokensOf(usage);
  tally.cacheReadTokens += cacheReadOf(usage);
  tally.reported = true;
}
