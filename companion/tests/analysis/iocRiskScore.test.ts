import { describe, it, expect } from "vitest";
import {
  scoreIoc,
  scoreIocs,
  iocRole,
  summarizeIocRoles,
  type IocRiskSignals,
} from "../../src/analysis/iocRiskScore.js";
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
    expect(r.factors.join(" ")).toMatch(/single-origin|unverified/i);
  });
  // #933 item 18: two named origins sit between a lone hit and local corroboration — and are never
  // called corroborated or independent. The words come from the lineage summary when given.
  it("multi-origin verdict alone → medium (+3), worded as names, not independence", () => {
    const r = scoreIoc(sig({ verdictClass: "multi-origin" }));
    expect(r.score).toBe("medium");
    expect(r.factors[0]).toMatch(/independence not established/);
    expect(r.factors[0]).not.toMatch(/corroborated/);
    expect(scoreIoc(sig({ verdictClass: "multi-origin", maxSeverityRank: 2 })).score).toBe("high"); // +1 Medium event
  });
  it("uses the lineage words when supplied", () => {
    const r = scoreIoc(
      sig({
        verdictClass: "lone-intel",
        intelFactor:
          "single intel origin (abuse.ch — 2 hits: MISP, ThreatFox), not seen in a Medium+ event in this case (unverified lead) (current reputation)",
      }),
    );
    expect(r.factors[0]).toContain("2 hits: MISP, ThreatFox");
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
    const r = scoreIoc(
      sig({ verdictClass: "corroborated", maxSeverityRank: 4, distinctTools: 3, kevMatch: true }),
    );
    expect(r.factors.length).toBeGreaterThanOrEqual(3);
  });
});

describe("scoreIocs — batch orchestration over real IOCs/events", () => {
  const ev = (p: Partial<ForensicEvent> & { id: string }): ForensicEvent => ({
    timestamp: "2026-01-01T00:00:00Z",
    description: "x",
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...p,
  });
  const ioc = (p: Partial<IOC> & { id: string; value: string; type: IOC["type"] }): IOC => ({
    firstSeen: "",
    ...p,
  });

  it("names the origins behind a two-feed verdict and folds a relayed copy (#933 item 18)", () => {
    const iocs: IOC[] = [
      ioc({
        id: "i1",
        type: "domain",
        value: "one-report.example",
        enrichments: [
          {
            source: "ThreatFox",
            provider: "Hunting.ch",
            verdict: "malicious",
            fetchedAt: "",
            originKind: "first-party",
            origins: ["abuse.ch"],
          },
          { source: "MISP", verdict: "malicious", fetchedAt: "", originKind: "relay", origins: ["abuse.ch"] },
        ],
      }),
      ioc({
        id: "i2",
        type: "domain",
        value: "two-names.example",
        enrichments: [
          {
            source: "VirusTotal",
            verdict: "malicious",
            fetchedAt: "",
            originKind: "aggregate",
            origins: ["VirusTotal"],
          },
          {
            source: "URLhaus",
            provider: "Hunting.ch",
            verdict: "malicious",
            fetchedAt: "",
            originKind: "first-party",
            origins: ["abuse.ch"],
          },
        ],
      }),
      ioc({
        id: "i3",
        type: "domain",
        value: "nobody.example",
        enrichments: [
          { source: "OpenCTI", verdict: "malicious", fetchedAt: "", originKind: "relay", origins: [] },
        ],
      }),
    ];
    const out = scoreIocs(iocs, [], { hostNames: new Set() });
    expect(out.i1.score).toBe("medium");
    expect(out.i1.factors[0]).toBe(
      "single intel origin (abuse.ch — 2 hits: ThreatFox, MISP), not seen in a Medium+ event in this case (unverified lead) (current reputation)",
    );
    expect(out.i2.score).toBe("medium");
    expect(out.i2.factors[0]).toBe(
      "intel verdict from 2 named origins (VirusTotal, abuse.ch) — independence not established (current reputation)",
    );
    expect(out.i3.score).toBe("medium");
    expect(out.i3.factors[0]).toBe(
      "1 hit with lineage not recorded (OpenCTI) — not counted as an origin; re-check with force to record the creator (current reputation)",
    );
  });

  it("scores a corroborated-malicious IP seen in a High event as high/critical", () => {
    const iocs: IOC[] = [
      ioc({
        id: "i1",
        type: "ip",
        value: "9.9.9.9",
        enrichments: [
          { source: "VirusTotal", verdict: "malicious", fetchedAt: "" },
          { source: "AbuseIPDB", verdict: "malicious", fetchedAt: "" },
        ],
      }),
    ];
    const events: ForensicEvent[] = [
      ev({
        id: "e1",
        severity: "High",
        description: "C2 to 9.9.9.9",
        srcIp: "9.9.9.9",
        sources: ["EDR", "Firewall"],
      }),
    ];
    const out = scoreIocs(iocs, events, {
      hostNames: new Set(),
      kevCveIds: new Set(),
      nsrlHashes: new Set(),
      whitelistRules: [],
    });
    expect(["high", "critical"]).toContain(out["i1"].score);
  });

  it("marks a whitelisted / NSRL hash benign via the real lookups", () => {
    const iocs: IOC[] = [
      ioc({
        id: "i1",
        type: "hash",
        value: "a".repeat(64),
        enrichments: [{ source: "VT", verdict: "malicious", fetchedAt: "" }],
      }),
      ioc({ id: "i2", type: "domain", value: "safe.example.com" }),
    ];
    const out = scoreIocs(iocs, [], {
      hostNames: new Set(),
      kevCveIds: new Set(),
      nsrlHashes: new Set(["a".repeat(64)]),
      whitelistRules: [
        { id: "w1", match: "exact", pattern: "safe.example.com", iocType: "domain", addedAt: "" },
      ],
    });
    expect(out["i1"].score).toBe("benign"); // NSRL known-good beats the malicious verdict
    expect(out["i2"].score).toBe("benign"); // whitelisted
  });
});

describe("iocRole — indicator vs observation (the 5,000-file-path problem)", () => {
  const mk = (p: Partial<IOC> & { id: string; value: string; type: IOC["type"] }): IOC => ({
    firstSeen: "",
    ...p,
  });

  it("a bare file path with no signal is an observation", () => {
    expect(iocRole(mk({ id: "f1", type: "file", value: "C:\\Windows\\notepad.exe" }), "low")).toBe(
      "observation",
    );
  });

  it("a network value (ip / domain / url) is an indicator even unenriched — a pivot point", () => {
    expect(iocRole(mk({ id: "n1", type: "ip", value: "1.2.3.4" }), "low")).toBe("indicator");
    expect(iocRole(mk({ id: "n2", type: "domain", value: "c2.example" }), "low")).toBe("indicator");
    expect(iocRole(mk({ id: "n3", type: "url", value: "http://c2.example/x" }), "low")).toBe("indicator");
  });

  it("a benign (whitelisted / NSRL known-good) value is never an indicator — even a network value or a stale verdict", () => {
    // known-good overrides everything, so the network and flagged branches must not fire.
    expect(iocRole(mk({ id: "b1", type: "domain", value: "safe.example.com" }), "benign")).toBe(
      "observation",
    );
    expect(
      iocRole(
        mk({
          id: "b2",
          type: "hash",
          value: "a".repeat(64),
          enrichments: [{ source: "old", verdict: "malicious", fetchedAt: "" }],
        }),
        "benign",
      ),
    ).toBe("observation");
  });

  it("a hash a reputation source flagged is an indicator even at low risk", () => {
    const ioc = mk({
      id: "h1",
      type: "hash",
      value: "a".repeat(64),
      enrichments: [{ source: "MalwareBazaar", verdict: "malicious", fetchedAt: "" }],
    });
    expect(iocRole(ioc, "low")).toBe("indicator");
  });

  it("any Medium+ risk tier is an indicator, whatever the type", () => {
    expect(iocRole(mk({ id: "x", type: "file", value: "x" }), "medium")).toBe("indicator");
    expect(iocRole(mk({ id: "y", type: "ip", value: "1.2.3.4" }), "high")).toBe("indicator");
  });

  it("scoreIocs stamps role, and summarizeIocRoles splits the set", () => {
    const iocs: IOC[] = [
      mk({ id: "obs1", type: "file", value: "C:\\Program Files\\app\\a.dll" }),
      mk({ id: "obs2", type: "hash", value: "b".repeat(64) }),
      mk({
        id: "ind1",
        type: "domain",
        value: "evil.test",
        enrichments: [{ source: "VT", verdict: "malicious", fetchedAt: "" }],
      }),
    ];
    const risks = scoreIocs(iocs, [], { hostNames: new Set() });
    expect(risks["obs1"].role).toBe("observation");
    expect(risks["obs2"].role).toBe("observation");
    expect(risks["ind1"].role).toBe("indicator");
    expect(summarizeIocRoles(risks)).toEqual({ indicators: 1, observations: 2 });
  });
});

describe("a verdict factor says it is current reputation and when it was measured (#933 item 19)", () => {
  it("names the latest scan date; the points are unchanged", async () => {
    const { scoreIoc, reputationMeasuredAt } = await import("../../src/analysis/iocRiskScore.js");
    const base = {
      distinctTools: 1,
      maxSeverityRank: -1,
      kevMatch: false,
      nsrlKnownGood: false,
      whitelisted: false,
      suspiciousDomain: false,
    };
    const dated = scoreIoc({
      ...base,
      verdictClass: "corroborated",
      reputationMeasuredAt: "2026-04-30T10:00:00.000Z",
    });
    const undated = scoreIoc({ ...base, verdictClass: "corroborated" });
    expect(dated.score).toBe(undated.score);
    expect(dated.factors.join(" ")).toContain("(current reputation, measured 2026-04-30)");
    expect(undated.factors.join(" ")).toContain("(current reputation)");
    expect(
      reputationMeasuredAt({
        enrichments: [
          {
            source: "VirusTotal",
            verdict: "malicious",
            fetchedAt: "2026-05-01T00:00:00.000Z",
            temporal: { verdictMeasuredAt: "2026-04-30T10:00:00.000Z" },
          },
          { source: "GeoIP", verdict: "unknown", fetchedAt: "2026-05-02T00:00:00.000Z" },
        ],
      }),
    ).toBe("2026-04-30T10:00:00.000Z");
  });
});
