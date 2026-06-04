import { describe, it, expect } from "vitest";
import { enrichIocs } from "../../src/enrichment/enrichService.js";
import type { EnrichmentProvider, EnrichmentResult, IocKind } from "../../src/enrichment/provider.js";
import type { IOC } from "../../src/analysis/stateTypes.js";

function ioc(over: Partial<IOC> & { value: string; type: IOC["type"] }): IOC {
  return { id: over.value, firstSeen: "t0", ...over };
}

// A provider that records its calls and returns a canned result for a kind.
function fakeProvider(name: string, kinds: IocKind[], result: EnrichmentResult | null, calls: string[]): EnrichmentProvider {
  return {
    name,
    supports: (k) => kinds.includes(k),
    lookup: async (k, v) => { calls.push(`${name}:${k}:${v}`); return result; },
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
    const cached = ioc({ value: "h1", type: "hash", enrichments: [{ source: "VirusTotal", verdict: "malicious", fetchedAt: "old" }] });

    const first = await enrichIocs([cached], { providers: [vt], sleep: noSleep, now });
    expect(first.summary.queried).toBe(0);               // cached → skipped
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
    const failing: EnrichmentProvider = { name: "X", supports: () => true, lookup: async () => { throw new Error("boom"); } };
    const { iocs: out, summary } = await enrichIocs([ioc({ value: "h1", type: "hash" })], { providers: [failing], sleep: noSleep, now });
    expect(summary.errors).toBe(1);
    expect(out[0].enrichments).toEqual([]); // checked, no results (error swallowed)
  });
});
