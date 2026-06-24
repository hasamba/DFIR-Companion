import { describe, it, expect } from "vitest";
import { buildKnownUnknowns } from "../../src/analysis/knownUnknowns.js";
import { emptyState, type Finding, type ForensicEvent, type InvestigationState } from "../../src/analysis/stateTypes.js";
import type { NextTechnique } from "../../src/analysis/adversaryEmulation.js";

function finding(id: string, severity: Finding["severity"], mitreTechniques: string[], title = id): Finding {
  return {
    id,
    severity,
    title,
    description: "",
    relatedIocs: [],
    sourceScreenshots: [],
    mitreTechniques,
    firstSeen: "2026-01-01T00:00:00Z",
    lastUpdated: "2026-01-01T00:00:00Z",
    status: "open",
  };
}

function ev(id: string, timestamp: string, source: string): ForensicEvent {
  return {
    id,
    timestamp,
    description: "",
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    sources: [source],
  };
}

function nextTech(id: string, name: string, tactic: string, groupCount: number): NextTechnique {
  return { id, name, url: `https://attack.mitre.org/techniques/${id}`, tactic, groupCount, groups: [], prevalence: 0.1, score: 1 };
}

function withFindings(findings: Finding[]): InvestigationState {
  return { ...emptyState("c"), findings };
}

describe("buildKnownUnknowns", () => {
  it("returns empty string for an empty case", () => {
    expect(buildKnownUnknowns(emptyState("c"), [])).toBe("");
  });

  it("lists uncovered core ATT&CK phases when the case has a serious finding", () => {
    // Only Impact (T1486) is covered → the other core phases are flagged as gaps.
    const block = buildKnownUnknowns(withFindings([finding("f1", "Critical", ["T1486"])]), []);
    expect(block).toContain("No finding yet explains these ATT&CK phases");
    expect(block).toContain("Initial Access");
    expect(block).toContain("Lateral Movement");
    expect(block).not.toContain("Impact,"); // Impact is covered, must not be in the missing list
    expect(block.startsWith("KNOWN UNKNOWNS / OPEN GAPS")).toBe(true);
  });

  it("does NOT claim missing phases for a low-signal case (no Critical/High finding)", () => {
    const block = buildKnownUnknowns(withFindings([finding("f1", "Info", [])]), []);
    expect(block).not.toContain("No finding yet explains");
  });

  it("surfaces a complete-silence coverage gap from the timeline", () => {
    const start = Date.parse("2026-01-01T00:00:00Z");
    const events: ForensicEvent[] = [
      ev("e0", new Date(start).toISOString(), "edr"),
      ev("e1", new Date(start + 3 * 3600_000).toISOString(), "edr"), // 3h silence on the only source
      ev("e2", new Date(start + 3 * 3600_000 + 5000).toISOString(), "edr"),
    ];
    const block = buildKnownUnknowns(emptyState("c"), events, { gapOptions: { minGapMinutes: 30, densityFactor: 0 } });
    expect(block).toContain("No telemetry from");
    expect(block).toContain("ALL sources silent");
  });

  it("includes caller-supplied likely-next techniques", () => {
    const block = buildKnownUnknowns(emptyState("c"), [], {
      nextTechniques: [nextTech("T1021.001", "Remote Desktop Protocol", "Lateral Movement", 3)],
    });
    expect(block).toContain("Not yet observed: T1021.001 (Remote Desktop Protocol) [Lateral Movement]");
    expect(block).toContain("3 lookalike group(s)");
  });

  it("honors the total bullet cap", () => {
    const block = buildKnownUnknowns(withFindings([finding("f1", "Critical", ["T1486"])]), [], {
      nextTechniques: [
        nextTech("T1021.001", "RDP", "Lateral Movement", 3),
        nextTech("T1003", "OS Credential Dumping", "Credential Access", 2),
      ],
      max: 1,
    });
    const bulletCount = (block.match(/^- /gm) ?? []).length;
    expect(bulletCount).toBe(1);
  });
});
