import { describe, it, expect } from "vitest";
import { renderMarkdownReport } from "../../src/reports/markdown.js";
import { emptyState, type Finding } from "../../src/analysis/stateTypes.js";

const HOSTILE = "Dana\n## Forged heading\n| a | b |";

function stateWith(f: Partial<Finding>) {
  const state = emptyState("c1");
  state.findings.push({
    id: "f-watson-1a2b3c4d",
    severity: "High",
    title: "Staged archive\n## Forged title",
    description: "An archive was written.\n## Forged body",
    relatedIocs: [],
    relatedHosts: [],
    mitreTechniques: [],
    sourceScreenshots: [],
    status: "open",
    firstSeen: "2026-01-01T00:00:00Z",
    lastUpdated: "2026-01-01T00:00:00Z",
    ...f,
  } as Finding);
  return state;
}

describe("a Watson-written finding in the Markdown report", () => {
  it("carries the approval line", () => {
    const md = renderMarkdownReport(stateWith({ author: "watson", approvedBy: "Dana" }));
    expect(md).toContain("- Added by Watson, approved by Dana");
  });

  it("says an analyst approved it when the name was not recorded", () => {
    const md = renderMarkdownReport(stateWith({ author: "watson" }));
    expect(md).toContain("- Added by Watson, approved by an analyst");
  });

  it("adds no line to a finding Watson did not write", () => {
    const md = renderMarkdownReport(stateWith({ approvedBy: "Dana" }));
    expect(md).not.toContain("Added by Watson");
  });

  it("forges no heading from the approver, title or description", () => {
    const md = renderMarkdownReport(stateWith({ author: "watson", approvedBy: HOSTILE }));
    const lines = md.split("\n");
    expect(lines.some((l) => /^#{1,6}\s+Forged/.test(l))).toBe(false);
    expect(lines.some((l) => /^\| a \| b \|/.test(l))).toBe(false);
    expect(md).toContain("- Added by Watson, approved by Dana");
  });
});
