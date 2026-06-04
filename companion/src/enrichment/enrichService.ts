// Orchestrates IOC enrichment across providers: maps each IOC to an enrichable kind,
// queries the providers that support it (throttled to respect rate limits), and attaches
// the normalized results to the IOC. Pure-ish and testable — sleep + now are injectable.

import type { IOC, IocEnrichment } from "../analysis/stateTypes.js";
import { iocKind, type EnrichmentProvider, type IocKind } from "./provider.js";

export interface EnrichOptions {
  providers: EnrichmentProvider[];
  delayMs?: number;                       // throttle between external lookups (default 1500)
  maxIocs?: number;                       // cap IOCs queried per run (default 100)
  force?: boolean;                        // re-query IOCs already enriched
  now?: () => string;                     // injected timestamp
  sleep?: (ms: number) => Promise<void>;  // injected delay (tests pass a no-op)
  onProgress?: (done: number, total: number) => void;
}

export interface EnrichSummary {
  enrichable: number;   // IOCs that have an enrichable kind
  queried: number;      // IOCs actually looked up this run
  withHits: number;     // IOCs that got ≥1 non-empty result
  skipped: number;      // already-enriched (cached) or beyond the cap
  errors: number;       // provider call failures
}

// Most-valuable kinds first so the per-run cap spends lookups where they matter.
const KIND_PRIORITY: Record<IocKind, number> = { hash: 0, ip: 1, process: 2, domain: 3, url: 4 };

export async function enrichIocs(
  iocs: readonly IOC[],
  opts: EnrichOptions,
): Promise<{ iocs: IOC[]; summary: EnrichSummary }> {
  const now = opts.now ?? (() => new Date().toISOString());
  const sleep = opts.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const delayMs = opts.delayMs ?? 1500;
  const maxIocs = opts.maxIocs ?? 100;

  // Index of IOCs that can and should be queried this run, ordered by priority.
  const candidates = iocs
    .map((ioc, idx) => ({ ioc, idx, kind: iocKind(ioc.type) }))
    .filter((c): c is { ioc: IOC; idx: number; kind: IocKind } => c.kind !== undefined)
    .filter((c) => opts.force || c.ioc.enrichments === undefined)
    .sort((a, b) => KIND_PRIORITY[a.kind] - KIND_PRIORITY[b.kind]);

  const enrichable = iocs.filter((i) => iocKind(i.type) !== undefined).length;
  const toQuery = candidates.slice(0, maxIocs);
  const summary: EnrichSummary = {
    enrichable,
    queried: 0,
    withHits: 0,
    skipped: enrichable - toQuery.length,
    errors: 0,
  };

  // Map of IOC index → new enrichments, so we can rebuild the list immutably.
  const updates = new Map<number, IocEnrichment[]>();
  let externalCalls = 0;

  for (const { ioc, idx, kind } of toQuery) {
    const providers = opts.providers.filter((p) => p.supports(kind));
    const results: IocEnrichment[] = [];
    for (const provider of providers) {
      if (externalCalls > 0) await sleep(delayMs);            // throttle between live calls
      externalCalls += 1;
      try {
        const r = await provider.lookup(kind, ioc.value);
        if (r) results.push({ ...r, fetchedAt: now() });
      } catch {
        summary.errors += 1;
      }
    }
    updates.set(idx, results);                                // empty array = "checked, no intel"
    summary.queried += 1;
    if (results.length) summary.withHits += 1;
    opts.onProgress?.(summary.queried, toQuery.length);
  }

  const out = iocs.map((ioc, idx) =>
    updates.has(idx) ? { ...ioc, enrichments: updates.get(idx)! } : ioc,
  );
  return { iocs: out, summary };
}
