// Orchestrates IOC enrichment across providers: maps each IOC to an enrichable kind,
// queries the providers that support it (throttled to respect rate limits), and attaches
// the normalized results to the IOC. Pure-ish and testable — sleep + now are injectable.

import type { IOC, IocEnrichment } from "../analysis/stateTypes.js";
import { iocKind, type EnrichmentProvider, type IocKind } from "./provider.js";
import type { ProviderHealthCache } from "./providerHealth.js";

// Emitted once per outbound provider call so callers can log exactly which threat-intel
// API was hit, for which indicator, and how it resolved (hit / miss / error). Lets the
// server print a `[enrich]` audit line per call without the pure service touching console.
export interface EnrichLookupEvent {
  provider: string;          // provider name (e.g. "MISP", "YETI")
  kind: IocKind;             // the looked-up IOC kind
  value: string;             // the indicator value
  outcome: "hit" | "miss" | "error" | "skipped";  // "skipped" = provider was probed down, no request sent
  detail?: string;           // verdict on a hit, or the error/unreachable message
  ms: number;                // call duration in milliseconds
}

export interface EnrichOptions {
  providers: EnrichmentProvider[];
  delayMs?: number;                       // throttle between external lookups (default 1500)
  perProviderDelayMs?: Record<string, number>;  // per-provider throttle; overrides delayMs for named providers
  maxIocs?: number;                       // cap IOCs queried per run (default 100)
  force?: boolean;                        // re-query IOCs already enriched
  now?: () => string;                     // injected timestamp
  sleep?: (ms: number) => Promise<void>;  // injected delay (tests pass a no-op)
  monotonic?: () => number;               // injected ms clock for call timing (default Date.now)
  onProgress?: (done: number, total: number) => void;
  onLookup?: (event: EnrichLookupEvent) => void;   // fired per provider call (for logging)
  // Reachability gate. When provided, each provider is health-checked (cached ~60s) before we
  // send it any indicator; a provider probed DOWN is skipped — not queried, not recorded as
  // "checked" — so a dead MISP/YETI isn't hit once per IOC, and recovers retry on a later run.
  health?: ProviderHealthCache;
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

export interface EnrichSummary {
  enrichable: number;     // IOCs that have an enrichable kind
  queried: number;        // IOCs actually looked up this run (≥1 real provider call)
  withHits: number;       // IOCs that got ≥1 non-empty result
  skipped: number;        // already-enriched (cached) or beyond the cap
  errors: number;         // provider call failures
  unavailable: string[];  // providers probed DOWN and skipped this run (no requests sent)
}

// Most-valuable kinds first so the per-run cap spends lookups where they matter.
const KIND_PRIORITY: Record<IocKind, number> = { hash: 0, ip: 1, process: 2, domain: 3, url: 4 };

export async function enrichIocs(
  iocs: readonly IOC[],
  opts: EnrichOptions,
): Promise<{ iocs: IOC[]; summary: EnrichSummary }> {
  const now = opts.now ?? (() => new Date().toISOString());
  const sleep = opts.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const monotonic = opts.monotonic ?? (() => Date.now());
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
    unavailable: [],
  };

  // Map of IOC index → { enrichments, enrichedBy }, so we can rebuild the list immutably.
  const updates = new Map<number, { enrichments: IocEnrichment[]; enrichedBy: string[] }>();
  const lastCallAt = new Map<string, number>();   // provider name → monotonic timestamp of last call start
  const downReported = new Set<string>();          // providers we've already logged as unreachable this run

  for (const { ioc, idx, kind, todo } of toQuery) {
    const succeeded = new Set<string>();   // providers whose call returned (hit OR miss) — NOT errors
    const fresh: IocEnrichment[] = [];
    let queriedThisIoc = false;            // a real provider call was made for this IOC
    for (const provider of todo) {
      // Reachability gate (cached ~60s): skip a provider probed DOWN before spending a call.
      // It's NOT counted as an error and NOT added to enrichedBy, so a later run retries it
      // once the server is back. Logged once per provider per run (not once per IOC).
      if (opts.health) {
        const h = await opts.health.check(provider);
        if (!h.ok) {
          if (!downReported.has(provider.name)) {
            downReported.add(provider.name);
            summary.unavailable.push(provider.name);
            opts.onLookup?.({ provider: provider.name, kind, value: ioc.value, outcome: "skipped", detail: h.detail, ms: 0 });
          }
          continue;
        }
      }
      queriedThisIoc = true;
      const provDelay = opts.perProviderDelayMs?.[provider.name] ?? delayMs;
      const lastAt = lastCallAt.get(provider.name);
      if (lastAt !== undefined) {
        const wait = provDelay - (monotonic() - lastAt);
        if (wait > 0) await sleep(wait);
      }
      const startedAt = monotonic();
      lastCallAt.set(provider.name, startedAt);
      try {
        const r = await provider.lookup(kind, ioc.value);
        // A provider may return a single result, several (a fan-out source like Hunting.ch),
        // or null/[] for a miss. When a result's displayed `source` differs from the provider
        // (a fan-out emits sub-sources like "MalwareBazaar"), stamp the OWNING provider so
        // re-checks/dedup key on it; single-source providers keep `source` as the key.
        const list = Array.isArray(r) ? r : r ? [r] : [];
        for (const one of list) {
          const owned = one.source !== provider.name ? { provider: provider.name } : {};
          fresh.push({ ...one, ...owned, fetchedAt: now() });
        }
        succeeded.add(provider.name);
        opts.onLookup?.({
          provider: provider.name, kind, value: ioc.value,
          outcome: list.length ? "hit" : "miss",
          // verdict per result; prefix the sub-source only when a fan-out makes it differ from the provider.
          detail: list.length
            ? list.map((x) => (x.source && x.source !== provider.name ? `${x.source}:${x.verdict}` : x.verdict)).join(", ")
            : undefined,
          ms: monotonic() - startedAt,
        });
      } catch (err) {
        summary.errors += 1;
        opts.onLookup?.({
          provider: provider.name, kind, value: ioc.value,
          outcome: "error", detail: errorMessage(err), ms: monotonic() - startedAt,
        });
      }
    }
    // An IOC whose every provider was skipped (all down) was never really queried — don't
    // count it, and fall through to leave it untouched so a later run picks it up.
    if (!queriedThisIoc) continue;
    summary.queried += 1;
    opts.onProgress?.(summary.queried, toQuery.length);

    // Only record providers whose call SUCCEEDED. A provider that threw stays out of
    // `enrichedBy`, so a later run retries it — a transient outage (or a since-fixed URL)
    // never gets cached as "checked". If nothing succeeded and the IOC was never enriched,
    // leave it untouched (don't mark it "checked, no intel" when it actually errored).
    if (succeeded.size === 0 && (ioc.enrichments === undefined)) continue;
    // Keep existing hits from providers we did NOT successfully re-run (errored providers
    // retain their last-known result); successful providers are superseded by `fresh`. Match on
    // the owning `provider` (falling back to `source` for older single-source enrichments) so a
    // fan-out provider's whole set is replaced, not left to accumulate duplicates. Also drop any
    // stale hit whose `source` a fresh result now owns — so an enrichment from a retired provider
    // (e.g. the old standalone MalwareBazaar) is replaced by Hunting.ch's "MalwareBazaar" instead
    // of both showing.
    const freshSources = new Set(fresh.map((f) => f.source));
    const keptHits = (ioc.enrichments ?? []).filter(
      (e) => !succeeded.has(e.provider ?? e.source) && !freshSources.has(e.source),
    );
    const enrichedBy = [...new Set([...(ioc.enrichedBy ?? []), ...succeeded])];
    updates.set(idx, { enrichments: [...keptHits, ...fresh], enrichedBy });
    if (fresh.length) summary.withHits += 1;
  }

  const out = iocs.map((ioc, idx) => {
    const u = updates.get(idx);
    return u ? { ...ioc, enrichments: u.enrichments, enrichedBy: u.enrichedBy } : ioc;
  });
  return { iocs: out, summary };
}
