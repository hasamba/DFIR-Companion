import { describe, it, expect } from "vitest";
import { renderInteractiveHtmlReport } from "../../src/reports/interactiveHtml.js";
import { emptyReportMeta } from "../../src/reports/reportMeta.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import { CSP_NONCE_PLACEHOLDER } from "../../src/http/securityHeaders.js";
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

// The raw JSON source as it sits in the document, before any parsing. Assertions about escaping
// have to run against this, not the parsed value: JSON.parse turns the escapes back into `<`.
function blobSource(html: string): string {
  const m = html.match(/window\.__DFIR_CASE__ = (\{.*?\});<\/script>/s);
  if (!m) throw new Error("no embedded case blob found");
  return m[1];
}

function parseBlob(html: string) {
  return JSON.parse(blobSource(html));
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
    // Inline script blocks carry the CSP nonce placeholder; the route swaps in the real value.
    expect(html).toContain(`<script nonce="${CSP_NONCE_PLACEHOLDER}">`);
    expect(html).not.toContain('src="http');
    expect(html).not.toContain('href="http');
    expect(html.trim().endsWith("</html>")).toBe(true);
  });

  it("embeds the case data as a JSON blob in a script tag", () => {
    const state = emptyState("c1");
    state.forensicTimeline.push({
      id: "e1", timestamp: "2026-05-01T00:00:00Z", description: "attack </script><script>alert(1)",
      severity: "High", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [],
    });
    const html = renderInteractiveHtmlReport(state, caseMeta, emptyReportMeta());
    expect(html).toContain("window.__DFIR_CASE__");
    expect(html).not.toContain("</script><script>alert(1)");
    // Every `<` from case data is escaped, so no end-tag spelling can survive in the blob.
    expect(blobSource(html)).not.toContain("<");
  });

  // Escaping only the literal `</script>` is not enough: the HTML script-data tokenizer also ends
  // the element on `</script ` and `</script/`, and `<!--` + `<script` flips it into
  // script-data-double-escaped state where the real closing tag is swallowed. Each payload below
  // broke out of the data script before every `<` was escaped.
  it.each([
    ["space-terminated end tag", "</script ><img src=x onerror=alert(1)>"],
    ["solidus-terminated end tag", "</script/><img src=x onerror=alert(1)>"],
    ["end tag with attribute text", "</script foo=bar><img src=x onerror=alert(1)>"],
    ["uppercase end tag", "</SCRIPT ><img src=x onerror=alert(1)>"],
    ["comment double-escape", "<!--<script>"],
  ])("neutralizes a %s breakout in untrusted event text", (_name, payload) => {
    const state = emptyState("c1");
    state.forensicTimeline.push({
      id: "e1", timestamp: "2026-05-01T00:00:00Z", description: payload,
      severity: "High", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [],
    });
    const html = renderInteractiveHtmlReport(state, caseMeta, emptyReportMeta());

    // The payload must not appear as live markup anywhere in the document.
    expect(html).not.toContain(payload);
    expect(html).not.toContain("<img src=x");
    // The blob carries no raw `<` at all, so no tokenizer transition can fire inside it.
    expect(blobSource(html)).not.toContain("<");
    // Exactly the two intended <script> elements, and the payload survives intact after parsing.
    expect(html.match(/<script\b/gi) ?? []).toHaveLength(2);
    expect(parseBlob(html).state.forensicTimeline[0].description).toBe(payload);
  });

  it("stamps a warning banner and keeps only Critical/High events when over the size limit", () => {
    const state = emptyState("c1");
    for (let i = 0; i < 1500; i++) state.forensicTimeline.push(ev(`e${i}`, "Medium", "WIN-01"));
    for (let i = 1500; i < 2100; i++) state.forensicTimeline.push(ev(`e${i}`, "Low", "WIN-01"));
    state.forensicTimeline.push(ev("c1", "Critical", "WIN-01"));
    state.forensicTimeline.push(ev("c2", "High", "WIN-01"));
    const html = renderInteractiveHtmlReport(state, caseMeta, emptyReportMeta());
    const parsed = parseBlob(html);
    expect(parsed.truncated).toBe(true);
    expect(parsed.totalEvents).toBe(2102);
    expect(parsed.state.forensicTimeline.length).toBe(2);
    expect(parsed.state.forensicTimeline.every((e: { severity: string }) => e.severity === "Critical" || e.severity === "High")).toBe(true);
    expect(html).toContain('id="size-banner"');
  });

  it("does not truncate or show a banner when events are within the limit", () => {
    const state = emptyState("c1");
    state.forensicTimeline.push(ev("e1", "Low", "WIN-01"));
    const parsed = parseBlob(renderInteractiveHtmlReport(state, caseMeta, emptyReportMeta()));
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