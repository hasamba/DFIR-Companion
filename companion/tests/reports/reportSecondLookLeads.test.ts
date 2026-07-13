import { describe, it, expect } from "vitest";
import { renderMarkdownReport } from "../../src/reports/markdown.js";
import { emptyState, type InvestigationState } from "../../src/analysis/stateTypes.js";

// #11 deferred: the exported report surfaces the second-look collection leads (raw re-query requests
// that matched nothing) in §4.6.2 Evidence gaps.

function stateWith(): InvestigationState {
  const s = emptyState("c1");
  s.forensicTimeline.push({ id: "e1", timestamp: "2026-05-20T09:00:00Z", description: "x", severity: "High", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [] });
  return s;
}

describe("renderMarkdownReport second-look leads (#11 deferred)", () => {
  it("renders unresolved second-look leads in the Evidence gaps section", () => {
    const md = renderMarkdownReport(stateWith(), undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, [
      "confirm the staging/exfil hypothesis with archive-write rows",
      "every raw mention of the connective indicator 203.0.113.9",
    ]);
    expect(md).toContain("Evidence gaps");
    expect(md).toContain("Unresolved lead");
    expect(md).toContain("confirm the staging/exfil hypothesis");
    expect(md).toContain("203.0.113.9");
  });

  it("omits the leads (and the whole gaps section) when there are none", () => {
    const md = renderMarkdownReport(stateWith(), undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, []);
    expect(md).not.toContain("Unresolved lead");
  });
});
