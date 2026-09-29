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

  it("matches a retitled finding by id — a same-id rewrite is not removed + added (bug #5)", () => {
    const before = [f("Timeline coverage gap: 6h of complete silence", "High", "f-gap-a-b")];
    const after = [f("Suspected log clearing on DC01", "High", "f-gap-a-b")];
    expect(isEmptyDiff(diffFindings(before, after))).toBe(true);
  });

  it("reports a severity change on a retitled same-id finding under its new title", () => {
    const before = [f("Activity in 3 waves", "High", "f-waves")];
    const after = [f("Returning operator across 3 visits", "Medium", "f-waves")];
    const d = diffFindings(before, after);
    expect(d.added).toEqual([]);
    expect(d.removed).toEqual([]);
    expect(d.severityChanged).toEqual([
      { title: "Returning operator across 3 visits", from: "High", to: "Medium" },
    ]);
  });

  it("falls back to the title when the ids differ", () => {
    const before = [f("Mimikatz execution", "Medium", "f1")];
    const after = [f("Mimikatz execution", "High", "f9")];
    const d = diffFindings(before, after);
    expect(d.added).toEqual([]);
    expect(d.removed).toEqual([]);
    expect(d.severityChanged).toEqual([{ title: "Mimikatz execution", from: "Medium", to: "High" }]);
  });

  it("falls back to the title when a side has no id", () => {
    const before = [f("Mimikatz execution", "High", "")];
    const after = [f("Mimikatz execution", "High", "f9")];
    expect(isEmptyDiff(diffFindings(before, after))).toBe(true);
  });

  it("does not pair one old finding twice — an id match takes it out of the title fallback", () => {
    // f1 kept its id but was retitled; a NEW finding reuses f1's old title. The old f1 pairs by id,
    // so the new one is genuinely added.
    const before = [f("Lateral movement", "High", "f1")];
    const after = [f("Lateral movement via PsExec", "High", "f1"), f("Lateral movement", "Low", "f2")];
    const d = diffFindings(before, after);
    expect(d.added).toEqual(["Lateral movement"]);
    expect(d.removed).toEqual([]);
    expect(d.severityChanged).toEqual([]);
  });

  it("returns an empty diff for identical finding sets", () => {
    const set = [f("A", "High"), f("B", "Low")];
    expect(isEmptyDiff(diffFindings(set, set))).toBe(true);
  });
});
