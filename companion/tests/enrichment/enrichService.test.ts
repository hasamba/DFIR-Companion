import { describe, it, expect } from "vitest";
import { enrichIocs, hasEnrichableWork, type EnrichLookupEvent } from "../../src/enrichment/enrichService.js";
import { ProviderHealthCache } from "../../src/enrichment/providerHealth.js";
import { RateLimitError, type EnrichmentProvider, type EnrichmentResult, type IocKind } from "../../src/enrichment/provider.js";
import type { IOC } from "../../src/analysis/stateTypes.js";

function ioc(over: Partial<IOC> & { value: string; type: IOC["type"] }): IOC {
  return { id: over.value, firstSeen: "t0", ...over };
}

// A provider that records its calls and returns a canned result for a kind.
function fakeProvider(name: string, kinds: IocKind[], result: EnrichmentResult | null, calls: string[]): EnrichmentProvider {
  return {
    name,
    scope: "external",
    supports: (k) => kinds.includes(k),
    lookup: async (k, v) => { calls.push(`${name}:${k}:${v}`); return result; },
  };
}

// A provider with a probe() that's down (throws) and counts both probes and lookups.
function downProvider(name: string, kinds: IocKind[], counts: { probes: number; lookups: number }): EnrichmentProvider {
  return {
    name, scope: "local",
    supports: (k) => kinds.includes(k),
    probe: async () => { counts.probes += 1; throw new Error("ECONNREFUSED"); },
    lookup: async () => { counts.lookups += 1; return null; },
  };
}

const noSleep = async () => {};
const now = () => "2026-06-04T00:00:00Z";

describe("enrichIocs", () => {
  it("enriches enrichable IOCs (hash/ip/domain/url/process) and skips file/other", async () => {
    const calls: string[] = [];
    const vt = fakeProvider("VirusTotal", ["hash", "ip", "domain", "url"],
      { source: "VirusTotal", verdict: "malicious", score: "9/70" }, calls);
    const iocs = [
      ioc({ value: "deadbeef", type: "hash" }),
      ioc({ value: "1.2.3.4", type: "ip" }),
      ioc({ value: "C:\\evil.exe", type: "file" }),     // not enrichable
      ioc({ value: "weird", type: "other" }),           // not enrichable
    ];
    const { iocs: out, summary } = await enrichIocs(iocs, { providers: [vt], sleep: noSleep, now });
    expect(summary.enrichable).toBe(2);
    expect(summary.queried).toBe(2);
    expect(summary.withHits).toBe(2);
    expect(out[0].enrichments).toEqual([{ source: "VirusTotal", verdict: "malicious", score: "9/70", fetchedAt: now() }]);
    expect(out[2].enrichments).toBeUndefined();          // file untouched
    expect(out[3].enrichments).toBeUndefined();          // other untouched
  });

  it("re-checks an IOC only on providers that haven't checked it (a newly-enabled provider re-checks all)", async () => {
    const calls: string[] = [];
    const vt = fakeProvider("VirusTotal", ["hash"], { source: "VirusTotal", verdict: "malicious" }, calls);
    const mb = fakeProvider("MalwareBazaar", ["hash"], { source: "MalwareBazaar", verdict: "malicious" }, calls);

    const r1 = await enrichIocs([ioc({ value: "h1", type: "hash" })], { providers: [vt], sleep: noSleep, now });
    expect(calls).toEqual(["VirusTotal:hash:h1"]);
    expect(r1.iocs[0].enrichedBy).toEqual(["VirusTotal"]);

    calls.length = 0;                                       // add MalwareBazaar — only it should query
    const r2 = await enrichIocs(r1.iocs, { providers: [vt, mb], sleep: noSleep, now });
    expect(calls).toEqual(["MalwareBazaar:hash:h1"]);
    expect(new Set(r2.iocs[0].enrichedBy)).toEqual(new Set(["VirusTotal", "MalwareBazaar"]));
    expect(r2.iocs[0].enrichments!.map((e) => e.source).sort()).toEqual(["MalwareBazaar", "VirusTotal"]);

    calls.length = 0;                                       // nothing new → no calls
    const r3 = await enrichIocs(r2.iocs, { providers: [vt, mb], sleep: noSleep, now });
    expect(calls).toEqual([]);
    expect(r3.summary.queried).toBe(0);
  });

  it("records a provider that found nothing so it isn't re-queried (force overrides)", async () => {
    const calls: string[] = [];
    const misp = fakeProvider("MISP", ["hash"], null, calls);   // no hit
    const r1 = await enrichIocs([ioc({ value: "h1", type: "hash" })], { providers: [misp], sleep: noSleep, now });
    expect(r1.iocs[0].enrichments).toEqual([]);            // checked, no hit
    expect(r1.iocs[0].enrichedBy).toEqual(["MISP"]);

    calls.length = 0;
    await enrichIocs(r1.iocs, { providers: [misp], sleep: noSleep, now });
    expect(calls).toEqual([]);                              // not re-queried

    calls.length = 0;
    await enrichIocs(r1.iocs, { providers: [misp], sleep: noSleep, now, force: true });
    expect(calls).toEqual(["MISP:hash:h1"]);               // force re-queries
  });

  it("flattens a fan-out provider's array into separate enrichments, stamps the owner, and dedups on re-run", async () => {
    // A provider (like Hunting.ch) returning several sub-source results from one lookup.
    const fanout: EnrichmentProvider = {
      name: "Hunting.ch", scope: "external",
      supports: (k) => k === "hash",
      lookup: async () => [
        { source: "MalwareBazaar", verdict: "malicious", score: "known: Neshta" },
        { source: "YARAify", verdict: "malicious", score: "2 YARA rule(s)" },
      ],
    };
    const r1 = await enrichIocs([ioc({ value: "h1", type: "hash" })], { providers: [fanout], sleep: noSleep, now });
    const e1 = r1.iocs[0].enrichments!;
    expect(e1.map((e) => e.source).sort()).toEqual(["MalwareBazaar", "YARAify"]);   // two separate badges
    expect(e1.every((e) => e.provider === "Hunting.ch")).toBe(true);                // owner stamped
    expect(r1.iocs[0].enrichedBy).toEqual(["Hunting.ch"]);
    expect(r1.summary.withHits).toBe(1);

    // Re-run with force: the whole fan-out set is replaced (keyed on the owner), not duplicated.
    const r2 = await enrichIocs(r1.iocs, { providers: [fanout], sleep: noSleep, now, force: true });
    expect(r2.iocs[0].enrichments!.map((e) => e.source).sort()).toEqual(["MalwareBazaar", "YARAify"]);
  });

  it("a fresh result supersedes a stale same-source hit from a retired provider (no duplicate)", async () => {
    // IOC was enriched by the now-removed standalone MalwareBazaar provider (no `provider` field).
    const stale = ioc({
      value: "h1", type: "hash",
      enrichments: [{ source: "MalwareBazaar", verdict: "malicious", score: "old", fetchedAt: "t-1" }],
      enrichedBy: ["MalwareBazaar"],
    });
    const hunting: EnrichmentProvider = {
      name: "Hunting.ch", scope: "external",
      supports: (k) => k === "hash",
      lookup: async () => [{ source: "MalwareBazaar", verdict: "malicious", score: "new" }],
    };
    const { iocs: out } = await enrichIocs([stale], { providers: [hunting], sleep: noSleep, now });
    const mb = out[0].enrichments!.filter((e) => e.source === "MalwareBazaar");
    expect(mb).toHaveLength(1);                         // the stale one was replaced, not duplicated
    expect(mb[0]).toMatchObject({ score: "new", provider: "Hunting.ch" });
  });

  it("routes a process IOC only to providers that support 'process'", async () => {
    const calls: string[] = [];
    const vt = fakeProvider("VirusTotal", ["hash", "ip", "domain", "url"], { source: "VirusTotal", verdict: "malicious" }, calls);
    const rr = fakeProvider("RockyRaccoon", ["process"], { source: "RockyRaccoon", verdict: "suspicious", score: "LOLBIN" }, calls);
    const { iocs: out } = await enrichIocs([ioc({ value: "powershell.exe", type: "process" })], { providers: [vt, rr], sleep: noSleep, now });
    expect(calls).toEqual(["RockyRaccoon:process:powershell.exe"]);   // VT not called for a process
    expect(out[0].enrichments!.map((e) => e.source)).toEqual(["RockyRaccoon"]);
  });

  it("routes each IOC only to providers that support its kind", async () => {
    const calls: string[] = [];
    const vt = fakeProvider("VirusTotal", ["hash", "ip", "domain", "url"], { source: "VirusTotal", verdict: "harmless" }, calls);
    const mb = fakeProvider("MalwareBazaar", ["hash"], { source: "MalwareBazaar", verdict: "malicious" }, calls);
    const ab = fakeProvider("AbuseIPDB", ["ip"], { source: "AbuseIPDB", verdict: "suspicious" }, calls);
    const iocs = [ioc({ value: "h1", type: "hash" }), ioc({ value: "2.2.2.2", type: "ip" })];
    const { iocs: out } = await enrichIocs(iocs, { providers: [vt, mb, ab], sleep: noSleep, now });
    // hash → VT + MB; ip → VT + AB
    expect(calls).toEqual(expect.arrayContaining(["VirusTotal:hash:h1", "MalwareBazaar:hash:h1", "VirusTotal:ip:2.2.2.2", "AbuseIPDB:ip:2.2.2.2"]));
    expect(calls).not.toContain("MalwareBazaar:ip:2.2.2.2");
    expect(out.find((i) => i.value === "h1")!.enrichments!.map((e) => e.source)).toEqual(["VirusTotal", "MalwareBazaar"]);
  });

  it("skips already-enriched IOCs unless force is set (cache)", async () => {
    const calls: string[] = [];
    const vt = fakeProvider("VirusTotal", ["hash"], { source: "VirusTotal", verdict: "malicious" }, calls);
    const cached = ioc({ value: "h1", type: "hash", enrichedBy: ["VirusTotal"], enrichments: [{ source: "VirusTotal", verdict: "malicious", fetchedAt: "old" }] });

    const first = await enrichIocs([cached], { providers: [vt], sleep: noSleep, now });
    expect(first.summary.queried).toBe(0);               // already checked by VirusTotal → skipped
    expect(calls).toHaveLength(0);

    const forced = await enrichIocs([cached], { providers: [vt], sleep: noSleep, now, force: true });
    expect(forced.summary.queried).toBe(1);              // re-queried
  });

  it("records an empty enrichments array ('checked, no intel') when nothing is found", async () => {
    const calls: string[] = [];
    const vt = fakeProvider("VirusTotal", ["hash"], null, calls); // always not-found
    const { iocs: out, summary } = await enrichIocs([ioc({ value: "h1", type: "hash" })], { providers: [vt], sleep: noSleep, now });
    expect(out[0].enrichments).toEqual([]);
    expect(summary.withHits).toBe(0);
    expect(summary.queried).toBe(1);
  });

  it("honours the maxIocs cap (most-valuable kinds first: hash before url)", async () => {
    const calls: string[] = [];
    const vt = fakeProvider("VT", ["hash", "url"], { source: "VT", verdict: "malicious" }, calls);
    const iocs = [ioc({ value: "u1", type: "url" }), ioc({ value: "h1", type: "hash" })];
    const { iocs: out, summary } = await enrichIocs(iocs, { providers: [vt], sleep: noSleep, now, maxIocs: 1 });
    expect(summary.queried).toBe(1);
    expect(summary.skipped).toBe(1);
    expect(out.find((i) => i.value === "h1")!.enrichments).toBeDefined();  // hash prioritized
    expect(out.find((i) => i.value === "u1")!.enrichments).toBeUndefined();
  });

  it("counts provider errors without aborting the run", async () => {
    const failing: EnrichmentProvider = { name: "X", scope: "external", supports: () => true, lookup: async () => { throw new Error("boom"); } };
    const { iocs: out, summary } = await enrichIocs([ioc({ value: "h1", type: "hash" })], { providers: [failing], sleep: noSleep, now });
    expect(summary.errors).toBe(1);
    // An errored provider is NOT cached as "checked": no enrichments written, not in enrichedBy,
    // so a later run (after the outage clears / URL is fixed) retries it instead of caching the failure.
    expect(out[0].enrichments).toBeUndefined();
    expect(out[0].enrichedBy ?? []).not.toContain("X");
  });

  it("retries an errored provider on the next run (failure is not cached), and keeps a prior hit through a later error", async () => {
    const calls: string[] = [];
    let mode: "error" | "ok" = "error";
    const flaky: EnrichmentProvider = {
      name: "Flaky", scope: "local", supports: () => true,
      lookup: async (k, v) => { calls.push(`${k}:${v}`); if (mode === "error") throw new Error("temporarily down"); return { source: "Flaky", verdict: "malicious" }; },
    };
    // First run: provider errors → not recorded as checked.
    const r1 = await enrichIocs([ioc({ value: "h1", type: "hash" })], { providers: [flaky], sleep: noSleep, now });
    expect(r1.iocs[0].enrichedBy ?? []).not.toContain("Flaky");

    // Second run (no force): because it wasn't cached, it's queried again — now it succeeds.
    calls.length = 0; mode = "ok";
    const r2 = await enrichIocs(r1.iocs, { providers: [flaky], sleep: noSleep, now });
    expect(calls).toEqual(["hash:h1"]);                          // retried without force
    expect(r2.iocs[0].enrichedBy).toEqual(["Flaky"]);
    expect(r2.iocs[0].enrichments!.map((e) => e.source)).toEqual(["Flaky"]);

    // Third run with force: provider errors again → prior hit is preserved, not wiped.
    calls.length = 0; mode = "error";
    const r3 = await enrichIocs(r2.iocs, { providers: [flaky], sleep: noSleep, now, force: true });
    expect(r3.iocs[0].enrichments!.map((e) => e.source)).toEqual(["Flaky"]); // last-known hit kept
  });

  it("skips a provider probed DOWN: never sends a lookup, doesn't mark it checked, reports it unavailable", async () => {
    const counts = { probes: 0, lookups: 0 };
    const dead = downProvider("MISP", ["hash", "ip"], counts);
    const events: EnrichLookupEvent[] = [];
    const health = new ProviderHealthCache({ monotonic: () => 0 });
    const { iocs: out, summary } = await enrichIocs(
      [ioc({ value: "h1", type: "hash" }), ioc({ value: "1.2.3.4", type: "ip" })],
      { providers: [dead], sleep: noSleep, now, health, monotonic: () => 0, onLookup: (e) => events.push(e) },
    );
    expect(counts.lookups).toBe(0);                       // not a single indicator sent to the dead server
    expect(counts.probes).toBe(1);                        // probed once (cached for both IOCs)
    expect(summary.unavailable).toEqual(["MISP"]);
    expect(summary.queried).toBe(0);
    expect(out[0].enrichments).toBeUndefined();           // untouched → retried on a later run
    expect(out[0].enrichedBy ?? []).not.toContain("MISP");
    expect(events.filter((e) => e.outcome === "skipped")).toHaveLength(1);   // one line, not one-per-IOC
    expect(events[0]).toMatchObject({ provider: "MISP", outcome: "skipped", detail: "ECONNREFUSED" });
  });

  it("with a mix of up and down providers, queries the healthy one and skips the dead one", async () => {
    const calls: string[] = [];
    const counts = { probes: 0, lookups: 0 };
    const up = fakeProvider("VirusTotal", ["hash"], { source: "VirusTotal", verdict: "malicious" }, calls);   // no probe() → always up
    const down = downProvider("MISP", ["hash"], counts);
    const health = new ProviderHealthCache({ monotonic: () => 0 });
    const { iocs: out, summary } = await enrichIocs([ioc({ value: "h1", type: "hash" })], {
      providers: [up, down], sleep: noSleep, now, health,
    });
    expect(calls).toEqual(["VirusTotal:hash:h1"]);        // only the healthy provider queried
    expect(counts.lookups).toBe(0);
    expect(summary.unavailable).toEqual(["MISP"]);
    expect(summary.queried).toBe(1);
    expect(out[0].enrichedBy).toEqual(["VirusTotal"]);    // dead provider NOT recorded as checked
    expect(out[0].enrichments!.map((e) => e.source)).toEqual(["VirusTotal"]);
  });

  it("emits an onLookup event per provider call with hit / miss / error outcome", async () => {
    const calls: string[] = [];
    const hit = fakeProvider("Hitter", ["hash"], { source: "Hitter", verdict: "malicious" }, calls);
    const miss = fakeProvider("Misser", ["hash"], null, calls);
    const fail: EnrichmentProvider = {
      name: "Failer", scope: "external", supports: () => true,
      lookup: async () => { throw new Error("upstream 500"); },
    };
    const events: EnrichLookupEvent[] = [];
    await enrichIocs([ioc({ value: "h1", type: "hash" })], {
      providers: [hit, miss, fail], sleep: noSleep, now,
      monotonic: () => 0,                       // deterministic 0ms duration
      onLookup: (e) => events.push(e),
    });
    expect(events).toEqual([
      { provider: "Hitter", kind: "hash", value: "h1", outcome: "hit", detail: "malicious", ms: 0 },
      { provider: "Misser", kind: "hash", value: "h1", outcome: "miss", detail: undefined, ms: 0 },
      { provider: "Failer", kind: "hash", value: "h1", outcome: "error", detail: "upstream 500", ms: 0 },
    ]);
  });

  describe("perProviderDelayMs", () => {
    it("sleeps the provider-specific delay between calls to the same provider", async () => {
      const slept: number[] = [];
      const calls: string[] = [];
      const vt = fakeProvider("VirusTotal", ["hash"], { source: "VirusTotal", verdict: "harmless" }, calls);
      // monotonic always returns 0 → elapsed = 0 → wait = provDelay on every call after the first
      await enrichIocs(
        [ioc({ value: "h1", type: "hash" }), ioc({ value: "h2", type: "hash" })],
        { providers: [vt], now, monotonic: () => 0, sleep: async (ms) => { slept.push(ms); }, perProviderDelayMs: { VirusTotal: 500 }, delayMs: 1500 },
      );
      // First call: no sleep; second call: sleep 500 (the provider-specific delay, not 1500)
      expect(slept).toEqual([500]);
    });

    it("throttles each provider independently — a slow provider does not block a fast one", async () => {
      const slept: number[] = [];
      const slow: EnrichmentProvider = {
        name: "Slow", scope: "external", supports: (k) => k === "hash",
        lookup: async () => ({ source: "Slow", verdict: "harmless" }),
      };
      const fast: EnrichmentProvider = {
        name: "Fast", scope: "external", supports: (k) => k === "process",
        lookup: async () => ({ source: "Fast", verdict: "harmless" }),
      };
      // hashes processed before processes (KIND_PRIORITY: hash=0, process=2)
      await enrichIocs(
        [ioc({ value: "h1", type: "hash" }), ioc({ value: "p1", type: "process" }),
         ioc({ value: "h2", type: "hash" }), ioc({ value: "p2", type: "process" })],
        { providers: [slow, fast], now, monotonic: () => 0, sleep: async (ms) => { slept.push(ms); }, perProviderDelayMs: { Slow: 3000, Fast: 100 }, delayMs: 1500 },
      );
      // Each provider sleeps exactly its own delay once (second call only); they don't affect each other
      expect(slept).toHaveLength(2);
      expect(slept).toContain(3000);   // Slow: 3000ms between its two calls
      expect(slept).toContain(100);    // Fast: 100ms between its two calls
    });

    it("falls back to global delayMs for providers not in perProviderDelayMs", async () => {
      const slept: number[] = [];
      const calls: string[] = [];
      const p = fakeProvider("Unknown", ["hash"], { source: "Unknown", verdict: "harmless" }, calls);
      await enrichIocs(
        [ioc({ value: "h1", type: "hash" }), ioc({ value: "h2", type: "hash" })],
        { providers: [p], now, monotonic: () => 0, sleep: async (ms) => { slept.push(ms); }, perProviderDelayMs: { VirusTotal: 500 }, delayMs: 999 },
      );
      expect(slept).toEqual([999]);   // Unknown not in map → falls back to global 999
    });

    it("applies ± jitterMs on top of the delay when configured", async () => {
      const slept: number[] = [];
      const calls: string[] = [];
      const vt = fakeProvider("VirusTotal", ["hash"], { source: "VirusTotal", verdict: "harmless" }, calls);
      // random() → 1 picks the +jitterMs edge: 1500 + (1*2-1)*300 = 1800
      await enrichIocs(
        [ioc({ value: "h1", type: "hash" }), ioc({ value: "h2", type: "hash" })],
        { providers: [vt], now, monotonic: () => 0, sleep: async (ms) => { slept.push(ms); }, delayMs: 1500, jitterMs: 300, random: () => 1 },
      );
      expect(slept).toEqual([1800]);
    });

    it("defaults jitterMs to 0 (no jitter) when not configured", async () => {
      const slept: number[] = [];
      const calls: string[] = [];
      const vt = fakeProvider("VirusTotal", ["hash"], { source: "VirusTotal", verdict: "harmless" }, calls);
      await enrichIocs(
        [ioc({ value: "h1", type: "hash" }), ioc({ value: "h2", type: "hash" })],
        // random() would throw if ever called with jitterMs unset — proves jitter math is skipped
        { providers: [vt], now, monotonic: () => 0, sleep: async (ms) => { slept.push(ms); }, delayMs: 1500, random: () => { throw new Error("should not be called"); } },
      );
      expect(slept).toEqual([1500]);
    });

    it("skips the sleep when elapsed time already exceeds the provider delay", async () => {
      const slept: number[] = [];
      let t = 0;
      const vtFast: EnrichmentProvider = {
        name: "VirusTotal", scope: "external", supports: (k) => k === "hash",
        // each call advances the clock by 600ms (more than the 500ms provDelay)
        lookup: async () => { t += 600; return { source: "VirusTotal", verdict: "harmless" }; },
      };
      await enrichIocs(
        [ioc({ value: "h1", type: "hash" }), ioc({ value: "h2", type: "hash" })],
        { providers: [vtFast], now, monotonic: () => t, sleep: async (ms) => { slept.push(ms); }, perProviderDelayMs: { VirusTotal: 500 } },
      );
      expect(slept).toHaveLength(0);   // 600ms elapsed > 500ms delay → no sleep needed
    });
  });

  describe("429 retry", () => {
    it("retries a provider that throws RateLimitError instead of counting it as an immediate error", async () => {
      let attempts = 0;
      const flaky: EnrichmentProvider = {
        name: "Flaky", scope: "external", supports: () => true,
        lookup: async () => {
          attempts++;
          if (attempts < 3) throw new RateLimitError("rate limited");
          return { source: "Flaky", verdict: "malicious" };
        },
      };
      const { iocs: out, summary } = await enrichIocs([ioc({ value: "h1", type: "hash" })], {
        providers: [flaky], sleep: noSleep, now, retry: { retries: 3, backoffMs: 1 },
      });
      expect(attempts).toBe(3);
      expect(summary.errors).toBe(0);
      expect(out[0].enrichments!.map((e) => e.source)).toEqual(["Flaky"]);
    });

    it("counts it as an error once the retry budget is exhausted", async () => {
      let attempts = 0;
      const alwaysLimited: EnrichmentProvider = {
        name: "Limited", scope: "external", supports: () => true,
        lookup: async () => { attempts++; throw new RateLimitError("rate limited"); },
      };
      const { iocs: out, summary } = await enrichIocs([ioc({ value: "h1", type: "hash" })], {
        providers: [alwaysLimited], sleep: noSleep, now, retry: { retries: 1, backoffMs: 1 },
      });
      expect(attempts).toBe(2);          // initial + 1 retry
      expect(summary.errors).toBe(1);
      expect(out[0].enrichments).toBeUndefined();
    });

    it("honours Retry-After (via the sleep it drives) before retrying", async () => {
      let attempts = 0;
      const slept: number[] = [];
      const limited: EnrichmentProvider = {
        name: "Limited", scope: "external", supports: () => true,
        lookup: async () => { attempts++; if (attempts === 1) throw new RateLimitError("rate limited", 7000); return { source: "Limited", verdict: "harmless" }; },
      };
      await enrichIocs([ioc({ value: "h1", type: "hash" })], {
        providers: [limited], now, sleep: async (ms) => { slept.push(ms); }, random: () => 0,
      });
      expect(slept).toEqual([7000]);
    });
  });
});

describe("hasEnrichableWork", () => {
  const vt = fakeProvider("VirusTotal", ["hash", "ip"], null, []);
  const misp = fakeProvider("MISP", ["hash"], null, []);

  it("is false when every enrichable IOC has already been checked by every enabled provider", async () => {
    const iocs = [ioc({ value: "h1", type: "hash", enrichedBy: ["VirusTotal", "MISP"] })];
    expect(hasEnrichableWork(iocs, [vt, misp])).toBe(false);
  });

  it("is true when a newly-enabled provider hasn't checked an existing IOC yet", () => {
    const iocs = [ioc({ value: "h1", type: "hash", enrichedBy: ["VirusTotal"] })];
    expect(hasEnrichableWork(iocs, [vt, misp])).toBe(true);   // MISP never ran
  });

  it("is true for an IOC that's never been enriched at all", () => {
    const iocs = [ioc({ value: "1.2.3.4", type: "ip" })];
    expect(hasEnrichableWork(iocs, [vt])).toBe(true);
  });

  it("is false for a non-enrichable IOC kind (file/other) regardless of providers", () => {
    const iocs = [ioc({ value: "C:\\evil.exe", type: "file" })];
    expect(hasEnrichableWork(iocs, [vt, misp])).toBe(false);
  });

  it("is false when there are no IOCs at all", () => {
    expect(hasEnrichableWork([], [vt, misp])).toBe(false);
  });
});
