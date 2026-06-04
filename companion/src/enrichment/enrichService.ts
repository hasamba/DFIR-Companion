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

  // For each enrichable IOC, work out which of the given providers still need to query it:
  // the supporting providers NOT already in `enrichedBy` (or ALL of them when force). So a
  // newly-enabled provider re-checks every IOC, while already-checked providers are skipped —
  // even ones that returned no hit (tracked via enrichedBy, not just the enrichments hits).
  const candidates = iocs
    .map((ioc, idx) => ({ ioc, idx, kind: iocKind(ioc.type) }))
    .filter((c): c is { ioc: IOC; idx: number; kind: IocKind } => c.kind !== undefined)
    .map((c) => {
      const supporting = opts.providers.filter((p) => p.supports(c.kind));
      const checked = new Set(c.ioc.enrichedBy ?? []);
      const todo = opts.force ? supporting : supporting.filter((p) => !checked.has(p.name));
      return { ...c, todo };
    })
    .filter((c) => c.todo.length > 0)
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

  // Map of IOC index → { enrichments, enrichedBy }, so we can rebuild the list immutably.
  const updates = new Map<number, { enrichments: IocEnrichment[]; enrichedBy: string[] }>();
  let externalCalls = 0;

  for (const { ioc, idx, kind, todo } of toQuery) {
    const ranNames = new Set(todo.map((p) => p.name));
    const fresh: IocEnrichment[] = [];
    for (const provider of todo) {
      if (externalCalls > 0) await sleep(delayMs);            // throttle between live calls
      externalCalls += 1;
      try {
        const r = await provider.lookup(kind, ioc.value);
        if (r) fresh.push({ ...r, fetchedAt: now() });
      } catch {
        summary.errors += 1;
      }
    }
    // Keep existing hits from providers we did NOT just run; add the fresh hits. Record
    // every provider we ran (hit or not) in enrichedBy so it isn't re-queried next time.
    const keptHits = (ioc.enrichments ?? []).filter((e) => !ranNames.has(e.source));
    const enrichedBy = [...new Set([...(ioc.enrichedBy ?? []), ...ranNames])];
    updates.set(idx, { enrichments: [...keptHits, ...fresh], enrichedBy });
    summary.queried += 1;
    if (fresh.length) summary.withHits += 1;
    opts.onProgress?.(summary.queried, toQuery.length);
  }

  const out = iocs.map((ioc, idx) => {
    const u = updates.get(idx);
    return u ? { ...ioc, enrichments: u.enrichments, enrichedBy: u.enrichedBy } : ioc;
  });
  return { iocs: out, summary };
}
