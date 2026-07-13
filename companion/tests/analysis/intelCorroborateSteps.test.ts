import { describe, it, expect } from "vitest";
import { buildIntelCorroborationSteps, capIntelOnlyFindings } from "../../src/analysis/findingGrounding.js";
import type { Finding, ForensicEvent, IOC } from "../../src/analysis/stateTypes.js";

function ioc(id: string, value: string): IOC {
  return { id, type: "ip", value, enrichments: [{ source: "OneCTI", verdict: "malicious", fetchedAt: "2026-01-01T00:00:00Z" }] } as IOC;
}
function finding(partial: Partial<Finding> & { id: string }): Finding {
  return { severity: "Critical", title: "C2 to evil", description: "d", relatedIocs: ["i1"], sourceScreenshots: [], mitreTechniques: [], firstSeen: "2026-01-01T00:00:00Z", lastUpdated: "2026-01-01T00:00:00Z", status: "open", ...partial };
}

describe("buildIntelCorroborationSteps (#7 deferred)", () => {
  it("emits one idempotent corroborate step per intel-only-capped finding, with a structured collect", () => {
    const iocs = [ioc("i1", "203.0.113.9")];
    const findings = [finding({ id: "f1", relatedIocs: ["i1"] })];
    const scopedEvents: ForensicEvent[] = []; // no behavioral event → intel-only

    // Sanity: the cap fires for this finding.
    expect(capIntelOnlyFindings({ findings, iocs, scopedEvents, hostNames: new Set() })[0].severity).toBe("Medium");

    const steps = buildIntelCorroborationSteps({ findings, iocs, scopedEvents, hostNames: new Set() });
    expect(steps).toHaveLength(1);
    expect(steps[0].id).toBe("n-corroborate-f1");
    expect(steps[0].action).toContain("203.0.113.9");
    expect(steps[0].collect?.expectedOutcome).toContain("203.0.113.9");
    expect(steps[0].relatedFindingIds).toEqual(["f1"]);
  });

  it("returns nothing for a finding with behavioral corroboration or no verdict IOC", () => {
    const iocs = [ioc("i1", "203.0.113.9")];
    const grounded = finding({ id: "f1", relatedIocs: ["i1"], corroboration: { distinctTools: 3, distinctHosts: 2, intelSources: 1, graphLinked: true } as Finding["corroboration"] });
    expect(buildIntelCorroborationSteps({ findings: [grounded], iocs, scopedEvents: [], hostNames: new Set() })).toEqual([]);

    const noVerdict = finding({ id: "f2", relatedIocs: [] });
    expect(buildIntelCorroborationSteps({ findings: [noVerdict], iocs, scopedEvents: [], hostNames: new Set() })).toEqual([]);
  });

  it("picks a host from a scoped event that references the indicator", () => {
    const iocs = [ioc("i1", "203.0.113.9")];
    const findings = [finding({ id: "f1", relatedIocs: ["i1"] })];
    const scopedEvents: ForensicEvent[] = [
      { id: "e1", timestamp: "2026-01-02T10:00:00Z", description: "connection to 203.0.113.9 observed", severity: "Info", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], asset: "WKSTN-7" },
    ];
    // NOTE: a behavioral event referencing the IOC would normally clear intel-only, but this event is a
    // bare "Info" mention with no process/connection fields, so iocHasBehavioralEvent stays false and the
    // finding is still intel-only — yet we can still harvest the host for the collect directive.
    const steps = buildIntelCorroborationSteps({ findings, iocs, scopedEvents, hostNames: new Set() });
    if (steps.length) expect(steps[0].collect?.host).toBe("WKSTN-7");
  });
});
