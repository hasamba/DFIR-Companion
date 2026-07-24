import { describe, it, expect } from "vitest";
import { renderInteractiveHtmlReport } from "../../src/reports/interactiveHtml.js";
import { emptyReportMeta } from "../../src/reports/reportMeta.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import type { CaseMeta } from "../../src/types.js";

function ev(id: string, severity: "Critical" | "High" | "Medium" | "Low" | "Info", asset?: string, sources?: string[]) {
  return {
    id, timestamp: `2026-05-0${id.slice(1)}T00:00:00Z`, description: `event ${id}`,
    severity, mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [],
    asset, sources,
  };
}

function finding(id: string, severity: "Critical" | "High" | "Medium" | "Low" | "Info", confidence: number, title = "Finding") {
  return {
    id, severity, confidence, title,
    description: `description for ${id}`,
    relatedIocs: [], mitreTechniques: [], sourceScreenshots: [],
    firstSeen: "2026-05-01T00:00:00Z", lastUpdated: "2026-05-02T00:00:00Z", status: "open" as const,
  };
}

const caseMeta: CaseMeta = {
  caseId: "c1", name: "Phishing Case", investigator: "Alice",
  createdAt: "2026-05-01T00:00:00Z", aiProvider: null,
};

describe("renderInteractiveHtmlReport", () => {
  it("produces a standalone HTML document with inline CSS and JS (no external deps)", () => {
    const state = emptyState("c1");
    state.forensicTimeline.push(ev("e1", "High", "WIN-01"));
    const html = renderInteractiveHtmlReport(state, caseMeta, emptyReportMeta());
    expect(html.startsWith("<!doctype html>")).toBe(true);
    expect(html).toContain("<title>Interactive Report — c1</title>");
    expect(html).toContain("<style>");
    expect(html).toContain("<script>");
    expect(html).not.toContain('src="http');
    expect(html).not.toContain('href="http');
    expect(html.trim().endsWith("</html>")).toBe(true);
  });

  it("embeds the case data as a JSON blob in a script tag and escapes </script>", () => {
    const state = emptyState("c1");
    state.forensicTimeline.push({
      id: "e1", timestamp: "2026-05-01T00:00:00Z", description: "attack </script><script>alert(1)",
      severity: "High", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [],
    });
    const html = renderInteractiveHtmlReport(state, caseMeta, emptyReportMeta());
    expect(html).toContain("window.__DFIR_CASE__");
    expect(html).not.toContain("</script><script>alert(1)");
    expect(html).toContain("<\\/script>");
  });

  it("stamps a warning banner and keeps only Critical/High events when over the size limit", () => {
    const state = emptyState("c1");
    for (let i = 0; i < 1500; i++) state.forensicTimeline.push(ev(`e${i}`, "Medium", "WIN-01"));
    for (let i = 1500; i < 2100; i++) state.forensicTimeline.push(ev(`e${i}`, "Low", "WIN-01"));
    state.forensicTimeline.push(ev("c1", "Critical", "WIN-01"));
    state.forensicTimeline.push(ev("c2", "High", "WIN-01"));
    const html = renderInteractiveHtmlReport(state, caseMeta, emptyReportMeta());
    const data = (html.match(/window\.__DFIR_CASE__ = (\{.*?\});<\/script>/s) as RegExpMatchArray)![1]
      .replace(/<\\\/script>/g, "</script>");
    const parsed = JSON.parse(data);
    expect(parsed.truncated).toBe(true);
    expect(parsed.totalEvents).toBe(2102);
    expect(parsed.state.forensicTimeline.length).toBe(2);
    expect(parsed.state.forensicTimeline.every((e: { severity: string }) => e.severity === "Critical" || e.severity === "High")).toBe(true);
    expect(html).toContain('id="size-banner"');
  });

  it("does not truncate or show a banner when events are within the limit", () => {
    const state = emptyState("c1");
    state.forensicTimeline.push(ev("e1", "Low", "WIN-01"));
    const html = renderInteractiveHtmlReport(state, caseMeta, emptyReportMeta());
    const data = (html.match(/window\.__DFIR_CASE__ = (\{.*?\});<\/script>/s) as RegExpMatchArray)![1]
      .replace(/<\\\/script>/g, "</script>");
    const parsed = JSON.parse(data);
    expect(parsed.truncated).toBe(false);
    expect(parsed.state.forensicTimeline.length).toBe(1);
  });

  it("embeds finding-card rendering logic with severity badges and confidence bars", () => {
    const state = emptyState("c1");
    state.findings.push(finding("f1", "Critical", 90, "Beaconing"));
    state.findings.push(finding("f2", "Low", 10, "Benign"));
    const html = renderInteractiveHtmlReport(state, caseMeta, emptyReportMeta());
    expect(html).toContain('"finding-card"');
    expect(html).toContain("Beaconing");
    expect(html).toContain('function sevClass');
    expect(html).toContain('"severity":"Critical"');
    expect(html).toContain('"severity":"Low"');
    expect(html).toContain('id="conf-slider"');
    expect(html).toContain('"confidence":90');
    expect(html).toContain('"confidence":10');
  });

  it("renders the timeline filter controls (severity / source / host / search)", () => {
    const state = emptyState("c1");
    state.forensicTimeline.push({
      id: "e1", timestamp: "2026-05-01T00:00:00Z", description: "powershell",
      severity: "High", mitreTechniques: ["T1059"], relatedFindingIds: [], sourceScreenshots: [],
      asset: "WIN-01", sources: ["Velociraptor"],
    });
    const html = renderInteractiveHtmlReport(state, caseMeta, emptyReportMeta());
    expect(html).toContain('id="sev-filter"');
    expect(html).toContain('id="src-filter"');
    expect(html).toContain('id="host-filter"');
    expect(html).toContain('id="search"');
    expect(html).toContain('id="timeline-body"');
    expect(html).toContain("T1059");
  });

  it("uses the incident id in the title and metadata when set", () => {
    const meta = emptyReportMeta();
    meta.incidentId = "INC-42";
    meta.companyName = "Acme DFIR";
    const html = renderInteractiveHtmlReport(emptyState("c1"), caseMeta, meta);
    expect(html).toContain("<title>Interactive Report — INC-42</title>");
    expect(html).toContain("Acme DFIR");
  });
});