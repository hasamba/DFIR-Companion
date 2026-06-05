// Reachability gate for threat-intel providers. A self-hosted MISP / YETI instance can be
// down (server off, TLS broken, auth 405) — and a case can carry hundreds of IOCs. Without
// a gate, enrichIocs would fire one doomed request PER IOC at the dead server. This caches
// each provider's reachability for a TTL (default 60s) so a down server is probed at most
// once per window; every other IOC in that window is skipped instantly from cache.
//
// Pure-ish + testable: the only impurity is the provider's own probe() (already injectable
// via the provider's fetchFn) and the clock, which is injected.

import type { EnrichmentProvider } from "./provider.js";

export interface ProviderHealth {
  ok: boolean;          // reachable + auth OK on the last probe
  checkedAt: number;    // monotonic ms when last probed (for TTL math)
  detail?: string;      // the error message when down (for the dashboard / logs)
}

export interface HealthCacheOptions {
  ttlMs?: number;                                            // trust a probe result this long (default 60_000)
  monotonic?: () => number;                                  // injected ms clock (default Date.now)
  onProbe?: (name: string, health: ProviderHealth) => void;  // fired only when a REAL probe runs (not a cache hit)
}

export class ProviderHealthCache {
  private readonly ttlMs: number;
  private readonly monotonic: () => number;
  private readonly onProbe?: (name: string, health: ProviderHealth) => void;
  private readonly cache = new Map<string, ProviderHealth>();
  // Coalesce concurrent probes of the same provider into one in-flight request.
  private readonly inflight = new Map<string, Promise<ProviderHealth>>();

  constructor(opts: HealthCacheOptions = {}) {
    this.ttlMs = opts.ttlMs ?? 60_000;
    this.monotonic = opts.monotonic ?? (() => Date.now());
    this.onProbe = opts.onProbe;
  }

  // Reachability for a provider: cached status if still fresh, otherwise probe once and
  // cache the outcome. A provider that does NOT implement probe() is always treated as up
  // (preserves prior behavior for providers without a health endpoint, e.g. external SaaS).
  async check(provider: EnrichmentProvider): Promise<ProviderHealth> {
    if (!provider.probe) return { ok: true, checkedAt: this.monotonic() };

    const cached = this.cache.get(provider.name);
    if (cached && this.monotonic() - cached.checkedAt < this.ttlMs) return cached;

    const pending = this.inflight.get(provider.name);
    if (pending) return pending;

    const run = (async (): Promise<ProviderHealth> => {
      let health: ProviderHealth;
      try {
        await provider.probe!();
        health = { ok: true, checkedAt: this.monotonic() };
      } catch (err) {
        health = { ok: false, checkedAt: this.monotonic(), detail: err instanceof Error ? err.message : String(err) };
      }
      this.cache.set(provider.name, health);
      this.onProbe?.(provider.name, health);
      return health;
    })();

    this.inflight.set(provider.name, run);
    try {
      return await run;
    } finally {
      this.inflight.delete(provider.name);
    }
  }

  // Last-known status without probing (for the dashboard health badge). undefined = never probed.
  peek(name: string): ProviderHealth | undefined {
    return this.cache.get(name);
  }

  // Drop a cached result so the next check() re-probes (the background poller uses this to
  // force a fresh read of a server it last saw down). No name → clear all.
  invalidate(name?: string): void {
    if (name) this.cache.delete(name);
    else this.cache.clear();
  }
}
