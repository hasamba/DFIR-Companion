import { describe, it, expect } from "vitest";
import { buildMobileSummary, worstVerdict, mobileSummaryEnvOptions } from "../../src/analysis/mobileSummary.js";
import { emptyState, type Finding, type ForensicEvent, type IOC, type InvestigationState, type Severity, type IocEnrichment } from "../../src/analysis/stateTypes.js";

const finding = (over: Partial<Finding> & Pick<Finding, "id" | "severity">): Finding => ({
  title: "t", description: "d", relatedIocs: [], sourceScreenshots: [], mitreTechniques: [],
  firstSeen: "2026-01-01T00:00:00Z", lastUpdated: "2026-01-01T00:00:00Z", status: "open", ...over,
});

const ev = (over: Partial<ForensicEvent> & Pick<ForensicEvent, "id" | "severity">): ForensicEvent => ({
  timestamp: "2026-01-01T00:00:00Z", description: "happened", mitreTechniques: [],
  relatedFindingIds: [], sourceScreenshots: [], ...over,
});

const enrich = (verdict: IocEnrichment["verdict"]): IocEnrichment => ({
  source: "VirusTotal", verdict, fetchedAt: "2026-01-01T00:00:00Z",
});

const ioc = (over: Partial<IOC> & Pick<IOC, "id" | "type" | "value">): IOC => ({
  firstSeen: "2026-01-01T00:00:00Z", ...over,
});

function stateWith(over: Partial<InvestigationState>): InvestigationState {
  return { ...emptyState("CASE-1"), ...over };
}

describe("worstVerdict", () => {
  it("returns null when never enriched", () => {
    expect(worstVerdict({ enrichments: undefined })).toBeNull();
    expect(worstVerdict({ enrichments: [] })).toBeNull();
  });

  it("returns the most malicious verdict across engines", () => {
    expect(worstVerdict({ enrichments: [enrich("harmless"), enrich("malicious"), enrich("suspicious")] })).toBe("malicious");
    expect(worstVerdict({ enrichments: [enrich("harmless"), enrich("suspicious")] })).toBe("suspicious");
    expect(worstVerdict({ enrichments: [enrich("harmless"), enrich("unknown")] })).toBe("harmless");
    expect(worstVerdict({ enrichments: [enrich("unknown")] })).toBe("unknown");
  });
});

describe("buildMobileSummary", () => {
  it("handles an empty state without throwing", () => {
    const s = buildMobileSummary(emptyState("CASE-EMPTY"));
    expect(s.caseId).toBe("CASE-EMPTY");
    expect(s.caseName).toBe("CASE-EMPTY"); // falls back to caseId when no name
    expect(s.counts).toEqual({ findings: 0, events: 0, iocs: 0, openThreads: 0, flaggedIocs: 0, techniques: 0 });
    expect(s.severityCounts).toEqual({ Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 });
    expect(s.findings.items).toEqual([]);
    expect(s.events.items).toEqual([]);
    expect(s.iocs.items).toEqual([]);
  });

  it("counts findings by severity and open threads", () => {
    const s = buildMobileSummary(stateWith({
      findings: [
        finding({ id: "f1", severity: "Critical" }),
        finding({ id: "f2", severity: "High" }),
        finding({ id: "f3", severity: "High" }),
        finding({ id: "f4", severity: "Info" }),
      ],
      openThreads: [
        { id: "t1", description: "open one", status: "open", openedAt: "2026-01-01T00:00:00Z", closedAt: null },
        { id: "t2", description: "closed one", status: "closed", openedAt: "2026-01-01T00:00:00Z", closedAt: "2026-01-02T00:00:00Z" },
      ],
      mitreTechniques: [
        { id: "T1059", name: "Command", findingIds: ["f1"] },
        { id: "T1110", name: "Brute", findingIds: ["f2"] },
      ],
    }));
    expect(s.severityCounts).toEqual({ Critical: 1, High: 2, Medium: 0, Low: 0, Info: 1 });
    expect(s.counts.findings).toBe(4);
    expect(s.counts.openThreads).toBe(1);
    expect(s.counts.techniques).toBe(2);
  });

  it("sorts findings worst-first", () => {
    const s = buildMobileSummary(stateWith({
      findings: [
        finding({ id: "low", severity: "Low" }),
        finding({ id: "crit", severity: "Critical" }),
        finding({ id: "med", severity: "Medium" }),
        finding({ id: "high", severity: "High" }),
      ],
    }));
    expect(s.findings.items.map((f) => f.id)).toEqual(["crit", "high", "med", "low"]);
  });

  it("orders events by severity then most-recent, parking undated events at the end", () => {
    const s = buildMobileSummary(stateWith({
      forensicTimeline: [
        ev({ id: "old-high", severity: "High", timestamp: "2026-01-01T00:00:00Z" }),
        ev({ id: "new-high", severity: "High", timestamp: "2026-01-05T00:00:00Z" }),
        ev({ id: "crit", severity: "Critical", timestamp: "2026-01-02T00:00:00Z" }),
        ev({ id: "undated-crit", severity: "Critical", timestamp: "" }),
      ],
    }));
    // Critical before High; within a severity, most recent first; undated sorts after dated.
    expect(s.events.items.map((e) => e.id)).toEqual(["crit", "undated-crit", "new-high", "old-high"]);
  });

  it("orders IOCs flagged-first (malicious before suspicious) then newest, and counts flagged", () => {
    const s = buildMobileSummary(stateWith({
      iocs: [
        ioc({ id: "plain-new", type: "domain", value: "a.com", firstSeen: "2026-02-01T00:00:00Z" }),
        ioc({ id: "susp", type: "ip", value: "1.1.1.1", enrichments: [enrich("suspicious")] }),
        ioc({ id: "mal", type: "hash", value: "deadbeef", enrichments: [enrich("malicious")] }),
        ioc({ id: "plain-old", type: "domain", value: "b.com", firstSeen: "2026-01-01T00:00:00Z" }),
      ],
    }));
    expect(s.iocs.items.map((i) => i.id)).toEqual(["mal", "susp", "plain-new", "plain-old"]);
    expect(s.iocs.items.find((i) => i.id === "mal")?.verdict).toBe("malicious");
    expect(s.iocs.items.find((i) => i.id === "plain-new")?.verdict).toBeNull();
    expect(s.counts.flaggedIocs).toBe(2);
  });

  it("caps heavy lists while reporting the pre-cap total", () => {
    const events = Array.from({ length: 5 }, (_, i) =>
      ev({ id: `e${i}`, severity: "Medium", timestamp: `2026-01-0${i + 1}T00:00:00Z` }));
    const iocs = Array.from({ length: 5 }, (_, i) =>
      ioc({ id: `i${i}`, type: "ip", value: `10.0.0.${i}` }));
    const s = buildMobileSummary(stateWith({ forensicTimeline: events, iocs }), { maxEvents: 2, maxIocs: 3 });
    expect(s.events.items).toHaveLength(2);
    expect(s.events.total).toBe(5);
    expect(s.iocs.items).toHaveLength(3);
    expect(s.iocs.total).toBe(5);
  });

  it("uses the provided case name and trims the summary", () => {
    const s = buildMobileSummary(stateWith({ lastSummary: "  recap  " }), { caseName: "Acme Breach" });
    expect(s.caseName).toBe("Acme Breach");
    expect(s.summary).toBe("recap");
  });

  it("does not mutate the input state arrays", () => {
    const findings = [finding({ id: "a", severity: "Low" }), finding({ id: "b", severity: "Critical" })];
    const original = [...findings];
    buildMobileSummary(stateWith({ findings }));
    expect(findings).toEqual(original); // same order — sorting happened on a copy
  });
});

describe("mobileSummaryEnvOptions", () => {
  const KEYS = ["DFIR_MOBILE_MAX_FINDINGS", "DFIR_MOBILE_MAX_EVENTS", "DFIR_MOBILE_MAX_IOCS"] as const;
  function withEnv(values: Partial<Record<(typeof KEYS)[number], string>>, fn: () => void): void {
    const saved = KEYS.map((k) => [k, process.env[k]] as const);
    try {
      for (const k of KEYS) delete process.env[k];
      for (const [k, v] of Object.entries(values)) process.env[k] = v;
      fn();
    } finally {
      for (const [k, v] of saved) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
    }
  }

  it("defaults when unset", () => {
    withEnv({}, () => {
      expect(mobileSummaryEnvOptions()).toEqual({ maxFindings: 50, maxEvents: 50, maxIocs: 100 });
    });
  });

  it("reads overrides and ignores invalid values", () => {
    withEnv({ DFIR_MOBILE_MAX_EVENTS: "10", DFIR_MOBILE_MAX_IOCS: "nope", DFIR_MOBILE_MAX_FINDINGS: "-3" }, () => {
      const opts = mobileSummaryEnvOptions();
      expect(opts.maxEvents).toBe(10);
      expect(opts.maxIocs).toBe(100);     // invalid → default
      expect(opts.maxFindings).toBe(50);  // negative → default
    });
  });
});
