import { describe, it, expect } from "vitest";
import { renderHtmlReport } from "../../src/reports/html.js";
import { emptyState, type Finding } from "../../src/analysis/stateTypes.js";

// #1898: a finding description is attacker-influenced text. No setext underline in it — of any
// length, at any indent, inside a list or a blockquote — may turn its line into a report heading.
function stateWith(description: string) {
  const s = emptyState("c1");
  const finding: Finding = {
    id: "f1",
    severity: "High",
    title: "Beacon on WS01",
    description,
    relatedIocs: [],
    mitreTechniques: [],
    sourceScreenshots: [],
    firstSeen: "2026-05-28T10:00:00.000Z",
    lastUpdated: "2026-05-28T10:00:00.000Z",
    status: "open",
  };
  s.findings.push(finding);
  return s;
}

describe("a finding description cannot forge a report heading in the HTML export (#1898)", () => {
  const forged = [
    "99 Attacker Appendix\n-",
    "99 Attacker Appendix\n- ",
    "99 Attacker Appendix\n   -",
    "99 Attacker Appendix\n=",
    "99 Attacker Appendix\n--",
    "- 99 Attacker Appendix\n  -",
    "10. 99 Attacker Appendix\n    -",
    "> 99 Attacker Appendix\n> -",
    "> ## 99 Attacker Appendix",
    "- # 99 Attacker Appendix",
    "1. ## 99 Attacker Appendix",
  ];
  it.each(forged)("%j renders no heading", (description) => {
    const html = renderHtmlReport(stateWith(description));
    expect(html).toContain("99 Attacker Appendix");
    expect(html).not.toMatch(/<h[1-6][^>]*>\s*99 Attacker Appendix/);
  });
});
