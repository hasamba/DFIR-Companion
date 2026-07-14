import { describe, it, expect } from "vitest";
import { scoreIoc, scoreIocs, type IocRiskSignals } from "../../src/analysis/iocRiskScore.js";
import type { IOC, ForensicEvent } from "../../src/analysis/stateTypes.js";

// Minimal signal set (nothing risky) that individual tests override.
function sig(p: Partial<IocRiskSignals> = {}): IocRiskSignals {
  return {
    verdictClass: "none",
    distinctTools: 0,
    maxSeverityRank: -1,
    kevMatch: false,
    nsrlKnownGood: false,
    whitelisted: false,
    suspiciousDomain: false,
    ...p,
  };
}

describe("scoreIoc — known-good overrides", () => {
  it("whitelisted → benign regardless of other signals", () => {
    const r = scoreIoc(sig({ whitelisted: true, verdictClass: "corroborated", maxSeverityRank: 4 }));
    expect(r.score).toBe("benign");
    expect(r.factors.join(" ")).toMatch(/whitelist/i);
  });
  it("NSRL known-good hash → benign", () => {
    const r = scoreIoc(sig({ nsrlKnownGood: true, verdictClass: "corroborated" }));
    expect(r.score).toBe("benign");
    expect(r.factors.join(" ")).toMatch(/nsrl/i);
  });
});

describe("scoreIoc — conflicted verdict caps to low (northpeak guard)", () => {
  it("malicious verdict on own/internal infra never exceeds low", () => {
    const r = scoreIoc(sig({ verdictClass: "conflicted", maxSeverityRank: 4, distinctTools: 3 }));
    expect(r.score).toBe("low");
    expect(r.factors.join(" ")).toMatch(/own|internal|stale/i);
  });
});

describe("scoreIoc — composite tiers", () => {
  it("corroborated malicious verdict in a Critical event → critical", () => {
    const r = scoreIoc(sig({ verdictClass: "corroborated", maxSeverityRank: 4 }));
    expect(r.score).toBe("critical");
  });
  it("corroborated malicious verdict alone → high", () => {
    expect(scoreIoc(sig({ verdictClass: "corroborated" })).score).toBe("high");
  });
  it("single-source (lone-intel) verdict → medium", () => {
    const r = scoreIoc(sig({ verdictClass: "lone-intel" }));
    expect(r.score).toBe("medium");
    expect(r.factors.join(" ")).toMatch(/single-source|unverified/i);
  });
  it("no intel but seen by 2+ tools in a High event → medium", () => {
    expect(scoreIoc(sig({ distinctTools: 2, maxSeverityRank: 3 })).score).toBe("medium");
  });
  it("KEV match with no verdict lifts to at least high", () => {
    const r = scoreIoc(sig({ kevMatch: true, maxSeverityRank: 3 }));
    expect(["high", "critical"]).toContain(r.score);
    expect(r.factors.join(" ")).toMatch(/kev/i);
  });
  it("an unenriched IOC only in Info telemetry → low", () => {
    expect(scoreIoc(sig({ maxSeverityRank: 0 })).score).toBe("low");
    expect(scoreIoc(sig()).score).toBe("low");
  });
  it("factors list every contributing signal", () => {
    const r = scoreIoc(sig({ verdictClass: "corroborated", maxSeverityRank: 4, distinctTools: 3, kevMatch: true }));
    expect(r.factors.length).toBeGreaterThanOrEqual(3);
  });
});

describe("scoreIocs — batch orchestration over real IOCs/events", () => {
  const ev = (p: Partial<ForensicEvent> & { id: string }): ForensicEvent => ({
    timestamp: "2026-01-01T00:00:00Z", description: "x", severity: "Info", mitreTechniques: [],
    relatedFindingIds: [], sourceScreenshots: [], ...p,
  });
  const ioc = (p: Partial<IOC> & { id: string; value: string; type: IOC["type"] }): IOC => ({ firstSeen: "", ...p });

  it("scores a corroborated-malicious IP seen in a High event as high/critical", () => {
    const iocs: IOC[] = [ioc({ id: "i1", type: "ip", value: "9.9.9.9", enrichments: [
      { source: "VirusTotal", verdict: "malicious", fetchedAt: "" },
      { source: "AbuseIPDB", verdict: "malicious", fetchedAt: "" },
    ] })];
    const events: ForensicEvent[] = [ev({ id: "e1", severity: "High", description: "C2 to 9.9.9.9", srcIp: "9.9.9.9", sources: ["EDR", "Firewall"] })];
    const out = scoreIocs(iocs, events, { hostNames: new Set(), kevCveIds: new Set(), nsrlHashes: new Set(), whitelistRules: [] });
    expect(["high", "critical"]).toContain(out["i1"].score);
  });

  it("marks a whitelisted / NSRL hash benign via the real lookups", () => {
    const iocs: IOC[] = [
      ioc({ id: "i1", type: "hash", value: "a".repeat(64), enrichments: [{ source: "VT", verdict: "malicious", fetchedAt: "" }] }),
      ioc({ id: "i2", type: "domain", value: "safe.example.com" }),
    ];
    const out = scoreIocs(iocs, [], {
      hostNames: new Set(), kevCveIds: new Set(),
      nsrlHashes: new Set(["a".repeat(64)]),
      whitelistRules: [{ id: "w1", match: "exact", pattern: "safe.example.com", iocType: "domain", addedAt: "" }],
    });
    expect(out["i1"].score).toBe("benign"); // NSRL known-good beats the malicious verdict
    expect(out["i2"].score).toBe("benign"); // whitelisted
  });
});
