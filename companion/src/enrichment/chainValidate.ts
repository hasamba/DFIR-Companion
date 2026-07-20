// Validate parent→child process relationships on forensic events against behavioral
// intel (RockyRaccoon). An event whose chain has NEVER been observed in ~346M executions
// (e.g. excel.exe → powershell.exe) is a strong anomaly signal. Deduplicates by the
// (parent, child) pair so each distinct chain is queried once and the result is applied
// to every event with that chain. Throttled, capped, cached (skips events already checked).

import type { ForensicEvent, ProcessChainCheck } from "../analysis/stateTypes.js";
import type { ParentChildResult } from "./rockyraccoon.js";
import { withRateLimitRetry, type RetryPolicy } from "./provider.js";

export interface ChainValidateOptions {
  check: (parent: string, child: string) => Promise<ParentChildResult | null>;
  delayMs?: number;
  jitterMs?: number;         // ± random jitter added to the inter-call wait (default 0 = none)
  random?: () => number;     // injected jitter source (default Math.random), returns [0, 1)
  retry?: RetryPolicy;       // retry policy for a check() that throws RateLimitError (HTTP 429)
  maxChecks?: number;        // cap on distinct (parent,child) pairs queried per run
  force?: boolean;           // re-check events that already have a chainCheck
  now?: () => string;
  sleep?: (ms: number) => Promise<void>;
  onProgress?: (done: number, total: number) => void;
}

export interface ChainSummary {
  candidates: number;        // events with a parent→child to validate
  pairs: number;             // distinct (parent,child) chains
  checked: number;           // chains actually queried this run
  anomalies: number;         // chains the dataset has NOT observed
  errors: number;
}

// Cheap pre-check mirroring validateProcessChains' candidate filter: is there at least one
// parent→child pair that hasn't been checked yet? Lets a caller skip the run entirely when it
// would be a pure no-op (every event on the timeline already carries a chainCheck).
export function hasChainWork(events: readonly ForensicEvent[]): boolean {
  return events.some((e) => e.parentName && e.processName && !e.chainCheck);
}

const pairKey = (parent: string, child: string): string => `${parent.toLowerCase()} ${child.toLowerCase()}`;

export async function validateProcessChains(
  events: readonly ForensicEvent[],
  opts: ChainValidateOptions,
): Promise<{ events: ForensicEvent[]; summary: ChainSummary }> {
  const now = opts.now ?? (() => new Date().toISOString());
  const sleep = opts.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const delayMs = opts.delayMs ?? 1500;
  const jitterMs = opts.jitterMs ?? 0;
  const random = opts.random ?? Math.random;
  const maxChecks = opts.maxChecks ?? 100;

  const candidates = events.filter((e) => e.parentName && e.processName && (opts.force || !e.chainCheck));
  const summary: ChainSummary = { candidates: candidates.length, pairs: 0, checked: 0, anomalies: 0, errors: 0 };

  // Distinct chains in first-appearance order.
  const order: Array<{ parent: string; child: string; key: string }> = [];
  const seen = new Set<string>();
  for (const e of candidates) {
    const key = pairKey(e.parentName!, e.processName!);
    if (!seen.has(key)) { seen.add(key); order.push({ parent: e.parentName!, child: e.processName!, key }); }
  }
  summary.pairs = order.length;

  const results = new Map<string, ProcessChainCheck>();
  let calls = 0;
  for (const { parent, child, key } of order.slice(0, maxChecks)) {
    if (calls > 0) {
      const jitter = jitterMs > 0 ? Math.round((random() * 2 - 1) * jitterMs) : 0;
      await sleep(Math.max(0, delayMs + jitter));
    }
    calls += 1;
    try {
      const r = await withRateLimitRetry(() => opts.check(parent, child), { ...opts.retry, sleep, random });
      if (r) {
        results.set(key, { observed: r.observed, note: r.note, link: r.link, checkedAt: now() });
        if (!r.observed) summary.anomalies += 1;
      }
      summary.checked += 1;
    } catch {
      summary.errors += 1;
    }
    opts.onProgress?.(summary.checked, Math.min(order.length, maxChecks));
  }

  const out = events.map((e) => {
    if (!e.parentName || !e.processName) return e;
    const cc = results.get(pairKey(e.parentName, e.processName));
    return cc ? { ...e, chainCheck: cc } : e;
  });
  return { events: out, summary };
}
