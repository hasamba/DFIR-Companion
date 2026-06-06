import { describe, it, expect } from "vitest";
import { diffFindings, isEmptyDiff } from "../../src/analysis/findingsDiff.js";
import type { Finding, Severity } from "../../src/analysis/stateTypes.js";

function f(title: string, severity: Severity, id = title): Finding {
  return {
    id,
    severity,
    title,
    description: "",
    relatedIocs: [],
    sourceScreenshots: [],
    mitreTechniques: [],
    firstSeen: "2026-01-01T00:00:00Z",
    lastUpdated: "2026-01-01T00:00:00Z",
    status: "open",
  };
}

describe("diffFindings", () => {
  it("detects added findings (by title, ignoring new ids)", () => {
    const before = [f("Mimikatz execution", "High", "f1")];
    const after = [f("Mimikatz execution", "High", "f-NEW-id"), f("Ransomware deployment", "Critical", "f2")];
    const d = diffFindings(before, after);
    expect(d.added).toEqual(["Ransomware deployment"]);
    expect(d.removed).toEqual([]);
    expect(d.severityChanged).toEqual([]);
  });

  it("detects removed findings", () => {
    const before = [f("A", "High"), f("B", "Medium")];
    const after = [f("A", "High")];
    expect(diffFindings(before, after).removed).toEqual(["B"]);
  });

  it("detects severity changes on a finding that keeps its title", () => {
    const before = [f("Suspicious logon", "Medium")];
    const after = [f("Suspicious logon", "Critical")];
    const d = diffFindings(before, after);
    expect(d.added).toEqual([]);
    expect(d.removed).toEqual([]);
    expect(d.severityChanged).toEqual([{ title: "Suspicious logon", from: "Medium", to: "Critical" }]);
  });

  it("matches titles case-insensitively and ignores whitespace differences", () => {
    const before = [f("Mimikatz  Execution", "High")];
    const after = [f("mimikatz execution", "High")];
    expect(isEmptyDiff(diffFindings(before, after))).toBe(true);
  });

  it("returns an empty diff for identical finding sets", () => {
    const set = [f("A", "High"), f("B", "Low")];
    expect(isEmptyDiff(diffFindings(set, set))).toBe(true);
  });
});
