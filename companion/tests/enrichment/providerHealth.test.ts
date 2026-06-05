import { describe, it, expect } from "vitest";
import { ProviderHealthCache, type ProviderHealth } from "../../src/enrichment/providerHealth.js";
import type { EnrichmentProvider, IocKind } from "../../src/enrichment/provider.js";

// A provider whose probe() outcome is driven by a mutable flag, counting how often it ran.
function probeProvider(name: string, state: { up: boolean; probes: number }, withProbe = true): EnrichmentProvider {
  const base: EnrichmentProvider = {
    name, scope: "local",
    supports: (_k: IocKind) => true,
    lookup: async () => null,
  };
  if (!withProbe) return base;
  return {
    ...base,
    probe: async () => {
      state.probes += 1;
      if (!state.up) throw new Error("server down");
    },
  };
}

describe("ProviderHealthCache", () => {
  it("treats a provider without probe() as always up, without probing", async () => {
    const cache = new ProviderHealthCache({ monotonic: () => 0 });
    const noProbe = probeProvider("VirusTotal", { up: true, probes: 0 }, false);
    const h = await cache.check(noProbe);
    expect(h.ok).toBe(true);
    expect(cache.peek("VirusTotal")).toBeUndefined();   // nothing cached — never probed
  });

  it("probes once and serves the cached result within the TTL", async () => {
    let t = 1000;
    const state = { up: true, probes: 0 };
    const cache = new ProviderHealthCache({ ttlMs: 60_000, monotonic: () => t });
    const p = probeProvider("MISP", state);

    expect((await cache.check(p)).ok).toBe(true);
    t = 1000 + 59_999;                                  // still inside the 60s window
    expect((await cache.check(p)).ok).toBe(true);
    expect(state.probes).toBe(1);                       // served from cache, not re-probed
  });

  it("re-probes after the TTL expires", async () => {
    let t = 0;
    const state = { up: false, probes: 0 };
    const cache = new ProviderHealthCache({ ttlMs: 60_000, monotonic: () => t });
    const p = probeProvider("YETI", state);

    expect((await cache.check(p)).ok).toBe(false);
    t = 60_001;                                          // window elapsed
    state.up = true;                                     // server recovered
    expect((await cache.check(p)).ok).toBe(true);
    expect(state.probes).toBe(2);                        // re-probed after TTL
  });

  it("caches a DOWN result with the error detail and fires onProbe only on real probes", async () => {
    let t = 0;
    const events: Array<[string, ProviderHealth]> = [];
    const state = { up: false, probes: 0 };
    const cache = new ProviderHealthCache({ ttlMs: 1000, monotonic: () => t, onProbe: (n, h) => events.push([n, h]) });
    const p = probeProvider("MISP", state);

    const h = await cache.check(p);
    expect(h.ok).toBe(false);
    expect(h.detail).toBe("server down");
    expect(cache.peek("MISP")).toMatchObject({ ok: false, detail: "server down" });

    await cache.check(p);                                // cache hit
    expect(events).toHaveLength(1);                      // onProbe fired only for the real probe
  });

  it("invalidate() forces the next check() to re-probe", async () => {
    const state = { up: false, probes: 0 };
    const cache = new ProviderHealthCache({ ttlMs: 60_000, monotonic: () => 0 });
    const p = probeProvider("YETI", state);

    expect((await cache.check(p)).ok).toBe(false);
    state.up = true;
    cache.invalidate("YETI");                            // poller saw it down, wants a fresh read
    expect((await cache.check(p)).ok).toBe(true);
    expect(state.probes).toBe(2);
  });

  it("coalesces concurrent probes of the same provider into one request", async () => {
    let resolveProbe: () => void = () => {};
    let probes = 0;
    const p: EnrichmentProvider = {
      name: "MISP", scope: "local", supports: () => true, lookup: async () => null,
      probe: () => { probes += 1; return new Promise<void>((r) => { resolveProbe = r; }); },
    };
    const cache = new ProviderHealthCache({ monotonic: () => 0 });
    const a = cache.check(p);
    const b = cache.check(p);                            // arrives while the first is in flight
    resolveProbe();
    await Promise.all([a, b]);
    expect(probes).toBe(1);                              // one shared probe, not two
  });
});
