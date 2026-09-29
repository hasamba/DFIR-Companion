// Bug #5: the EXISTING FINDINGS echo sent id/title/detail but not the prior severity, so the model
// re-guessed every finding's severity on each re-synthesis and the grade drifted run to run.
import { describe, it, expect } from "vitest";
import {
  buildFindingsEcho,
  EXISTING_FINDINGS_HEADER,
} from "../../../src/analysis/ai/synthesisPromptBlocks.js";
import { emptyState, type Finding, type InvestigationState } from "../../../src/analysis/stateTypes.js";

function finding(id: string, severity: Finding["severity"], extra: Partial<Finding> = {}): Finding {
  return {
    id,
    severity,
    confidence: 50,
    title: `title ${id}`,
    description: `said by ${id}`,
    relatedIocs: [],
    sourceScreenshots: [],
    mitreTechniques: [],
    firstSeen: "2026-01-01T00:00:00Z",
    lastUpdated: "2026-01-01T00:00:00Z",
    status: "open",
    ...extra,
  };
}

const withFindings = (findings: Finding[]): InvestigationState => ({ ...emptyState("c"), findings });

describe("buildFindingsEcho — prior severity", () => {
  it("echoes each finding's prior severity on its head line", () => {
    const echo = buildFindingsEcho(
      withFindings([finding("f-gap-a-b", "High"), finding("f-waves", "Medium"), finding("f1", "Low")]),
    );
    expect(echo).toMatch(/^\[f-gap-a-b\] \(severity: High\) title f-gap-a-b$/m);
    expect(echo).toMatch(/^\[f-waves\] \(severity: Medium\) title f-waves$/m);
    expect(echo).toMatch(/^\[f1\] \(severity: Low\) title f1$/m);
  });

  it("echoes the severity for title-only findings past the detail cap too", () => {
    const many = Array.from({ length: 90 }, (_, i) => finding(`f${i}`, i < 85 ? "High" : "Info"));
    const echo = buildFindingsEcho(withFindings(many));
    expect(echo).toMatch(/^\[f89\] \(severity: Info\) title f89$/m);
    // f89 is past the 80-finding detail cap, so no indented detail follows it.
    expect(echo).not.toMatch(/\[f89\][^\n]*\n {4}said:/);
  });

  it("echoes the live-intrusion severity for a simulation-capped finding, not the capped one", () => {
    const capped = finding("f2", "Low", {
      simulation: { role: "simulated", originalSeverity: "Critical", appliedSeverity: "Low" },
    });
    const echo = buildFindingsEcho(withFindings([capped]));
    expect(echo).toMatch(/^\[f2\] \(severity: Critical\) title f2$/m);
  });

  it("tells the model what the severity tag means", () => {
    expect(EXISTING_FINDINGS_HEADER).toContain('"(severity: X)" is the severity a finding carried last run');
  });

  it("still reports an empty case as none", () => {
    expect(buildFindingsEcho(withFindings([]))).toBe("(none yet)");
  });
});
