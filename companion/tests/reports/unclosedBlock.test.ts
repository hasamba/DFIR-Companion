import { describe, it, expect } from "vitest";
import { renderHtmlReport } from "../../src/reports/html.js";
import { renderMarkdownReport } from "../../src/reports/markdown.js";
import { emptyState, type Finding, type InvestigationState } from "../../src/analysis/stateTypes.js";

// #1918: an unclosed fence or raw-HTML block in a finding description must not swallow the rest of
// the report. The next finding's heading still renders as a heading after it.
function finding(id: string, title: string, description: string): Finding {
  return {
    id,
    severity: "High",
    title,
    description,
    relatedIocs: [],
    mitreTechniques: [],
    sourceScreenshots: [],
    firstSeen: "2026-05-28T10:00:00.000Z",
    lastUpdated: "2026-05-28T10:00:00.000Z",
    status: "open",
  };
}

function stateWith(description: string): InvestigationState {
  const s = emptyState("c1");
  s.findings.push(finding("f1", "Beacon on WS01", description), finding("f2", "Second Finding", "benign"));
  return s;
}

describe("finding text cannot hide the report after it (#1918)", () => {
  const openers = [
    "intro\n```\nhidden",
    "intro\n~~~\nhidden",
    "```powershell\nhidden",
    "- ```\nhidden",
    "> ~~~\nhidden",
    "intro\n<pre>\nhidden",
    "intro\n<script>\nhidden",
    "intro\n<!--\nhidden",
  ];
  it.each(openers)("%j: the HTML export keeps the next heading", (description) => {
    const html = renderHtmlReport(stateWith(description));
    expect(html).toMatch(/<h[1-6][^>]*>[^<]*Second Finding/);
  });

  it.each(openers)("%j: the Markdown export keeps the next heading outside any fence", (description) => {
    const md = renderMarkdownReport(stateWith(description));
    const before = md.slice(0, md.indexOf("Second Finding"));
    expect(before).not.toMatch(/^ {0,3}(?:[-*+] |> )*(?:```|~~~)/m);
    expect(md).toMatch(/^#{1,6} .*Second Finding/m);
  });
});
