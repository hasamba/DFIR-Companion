import { describe, it, expect } from "vitest";
import { renderHtmlReport, injectPrintTrigger } from "../../src/reports/html.js";
import { emptyReportMeta } from "../../src/reports/reportMeta.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import { CSP_NONCE_PLACEHOLDER } from "../../src/http/securityHeaders.js";

describe("renderHtmlReport", () => {
  it("produces a standalone HTML document from the markdown report", () => {
    const state = emptyState("c1");
    state.lastSummary = "Host compromised via phishing.";
    state.iocs.push({ id: "i1", type: "ip", value: "10.0.0.5", firstSeen: "2026-05-20T09:00:00Z" });

    const html = renderHtmlReport(state);
    expect(html.startsWith("<!doctype html>")).toBe(true);
    expect(html).toContain("<title>Incident Report — c1</title>");
    expect(html).toContain("<h1>Incident Investigation Report</h1>");
    expect(html).toContain("Host compromised via phishing.");
    expect(html).toContain("<table>"); // the IOC markdown table is converted to HTML
    expect(html).toContain("10[.]0[.]0[.]5"); // defanged for the reader, per #883
    expect(html).toContain(`<style nonce="${CSP_NONCE_PLACEHOLDER}">`);
    expect(html).not.toMatch(/\sstyle\s*=/i);
    expect(html.trim().endsWith("</html>")).toBe(true);
  });

  it("uses the incident id in the document title when set", () => {
    const meta = emptyReportMeta();
    meta.incidentId = "INC-42";
    const html = renderHtmlReport(emptyState("c1"), meta);
    expect(html).toContain("<title>Incident Report — INC-42</title>");
  });

  it("embeds the company logo as an <img> with the data URI preserved", () => {
    const logo =
      "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";
    const meta = emptyReportMeta();
    meta.companyName = "Acme DFIR";
    meta.companyLogo = logo;
    const html = renderHtmlReport(emptyState("c1"), meta);
    expect(html).toContain(`<img src="${logo}"`);
    expect(html).toContain('alt="Acme DFIR logo"');
  });

  it("escapes raw HTML from untrusted investigation text so it can't become live markup", () => {
    const state = emptyState("c1");
    state.findings.push({
      id: "f1",
      severity: "High",
      title: "XSS attempt",
      description: "<script>alert(document.cookie)</script>",
      relatedIocs: [],
      mitreTechniques: [],
      sourceScreenshots: [],
      firstSeen: "",
      lastUpdated: "",
      status: "open",
    });
    const html = renderHtmlReport(state);
    expect(html).not.toContain("<script>"); // the document contains no real <script> tag
    expect(html).toContain("&lt;script&gt;"); // the attacker-controlled text is rendered inert
  });

  it("does not render unsafe markdown links from untrusted investigation text", () => {
    const state = emptyState("c1");
    state.findings.push({
      id: "f1",
      severity: "High",
      title: "Unsafe markdown",
      description: "[open](javascript:alert(1)) ![pixel](javascript:alert(2))",
      relatedIocs: [],
      mitreTechniques: [],
      sourceScreenshots: [],
      firstSeen: "",
      lastUpdated: "",
      status: "open",
    });
    const html = renderHtmlReport(state);
    expect(html).not.toContain("javascript:");
    expect(html).toContain("[open]");
    expect(html).toContain("![pixel]");
  });

  it("does not auto-print the base report (the saved/downloaded HTML stays clean)", () => {
    const html = renderHtmlReport(emptyState("c1"));
    expect(html).not.toContain("window.print()");
    expect(html).not.toContain("print-hint");
  });

  it("embeds the asset–IoC graph SVG when the state has host assets", () => {
    const state = emptyState("c1");
    state.iocs.push({ id: "i1", type: "ip", value: "10.0.0.5", firstSeen: "" });
    state.findings.push({
      id: "f1",
      severity: "High",
      title: "Beacon",
      description: "beacon",
      relatedIocs: ["i1"],
      mitreTechniques: [],
      sourceScreenshots: [],
      firstSeen: "",
      lastUpdated: "",
      status: "open",
    });
    state.forensicTimeline.push({
      id: "e1",
      timestamp: "2026-05-01T00:00:00Z",
      description: "bad.exe on WIN-01",
      severity: "High",
      mitreTechniques: [],
      relatedFindingIds: ["f1"],
      sourceScreenshots: [],
      asset: "WIN-01",
    });
    const html = renderHtmlReport(state);
    expect(html).toContain('class="asset-graph"');
    expect(html).toContain("<svg ");
    expect(html).toContain("Assets (1)");
  });

  it("omits the graph section when the state has no host or account assets", () => {
    const html = renderHtmlReport(emptyState("c1"));
    expect(html).not.toContain('class="asset-graph"');
    expect(html).not.toContain("<svg ");
  });
});

describe("injectPrintTrigger", () => {
  it("inserts a print trigger + Save-as-PDF hint before </body>", () => {
    const out = injectPrintTrigger(renderHtmlReport(emptyState("c1")));
    expect(out).toContain("window.print()");
    expect(out).toContain("print-hint");
    expect(out).toContain("Save as PDF");
    expect(out).toContain(`<script nonce="${CSP_NONCE_PLACEHOLDER}">`);
    expect(out).not.toMatch(/\son[a-z]+\s*=/i);
    // The trigger lives inside the document body, not after it.
    expect(out.indexOf("window.print()")).toBeLessThan(out.indexOf("</body>"));
    // Screen-only chrome: the banner is hidden when actually printing so the saved PDF is clean.
    expect(out).toContain(".print-hint { display: none !important; }");
    expect(out.trim().endsWith("</html>")).toBe(true);
  });

  it("appends the trigger when the document has no </body>", () => {
    expect(injectPrintTrigger("<p>hi</p>")).toContain("window.print()");
  });
});

// The incident report travels furthest of any artifact and is read by people who click things.
// Live anchors to attacker infrastructure are one mis-click away from reaching out from the
// reader's machine, which in a live incident can burn the investigation. #883.
describe("renderHtmlReport indicator defanging (#883)", () => {
  it("emits no live anchor for an attacker URL or address", () => {
    const state = emptyState("c1");
    state.lastSummary = "Payload fetched from http://evil.example/stage1.sh by root@evil.example.";
    state.iocs.push({ id: "i1", type: "ip", value: "203.0.113.10", firstSeen: "2026-05-20T09:00:00Z" });

    const html = renderHtmlReport(state);

    expect(html).not.toMatch(/<a\s+href="https?:/i);
    expect(html).not.toMatch(/href="mailto:/i);
    expect(html).toContain("hxxp://evil[.]example/stage1.sh");
    expect(html).toContain("root[@]evil[.]example");
    expect(html).toContain("203[.]0[.]113[.]10");
  });

  it("emits no live anchor for a bare domain indicator", () => {
    const state = emptyState("c1");
    state.lastSummary = "Callback to www.evil.com observed.";
    state.iocs.push({ id: "i1", type: "domain", value: "evil.example", firstSeen: "2026-05-20T09:00:00Z" });

    const html = renderHtmlReport(state);

    // GFM autolinks a bare www. host into http://www.evil.com even with no scheme in the source.
    expect(html).not.toMatch(/<a\s+href="https?:/i);
    expect(html).toContain("www[.]evil[.]com");
    expect(html).toContain("evil[.]example");
  });
});

// The asset graph and the swimlane are built from state directly, so they never passed through the
// defang applied to the markdown. The graph's right-hand column IS the case's IOC values — every
// URL, domain and address, live, inside the artifact that travels furthest. #892.
describe("renderHtmlReport SVG indicator defanging (#892)", () => {
  function stateWithIndicators() {
    const state = emptyState("c1");
    state.iocs.push(
      {
        id: "i001",
        type: "url",
        value: "http://evil.example/stage1.sh",
        firstSeen: "2026-05-28T09:00:00Z",
      },
      { id: "i002", type: "ip", value: "203.0.113.10", firstSeen: "2026-05-28T09:00:00Z" },
    );
    state.findings.push({
      id: "f1",
      severity: "High",
      title: "Payload staged",
      description: "Downloaded from the C2",
      relatedIocs: ["i001", "i002"],
      mitreTechniques: [],
      sourceScreenshots: [],
      firstSeen: "2026-05-28T09:00:00Z",
      lastUpdated: "2026-05-28T09:00:00Z",
      status: "open",
    });
    state.forensicTimeline.push({
      id: "e1",
      timestamp: "2026-05-28T09:00:00Z",
      description: "beacon",
      severity: "High",
      mitreTechniques: [],
      relatedFindingIds: ["f1"],
      sourceScreenshots: [],
      asset: "WIN-01",
    });
    return state;
  }

  /** Just the SVG sections, so an assertion cannot be satisfied by the defanged markdown body. */
  function svgSections(html: string): string {
    return [...html.matchAll(/<div class="asset-graph">([\s\S]*?)<\/div>/g)].map((m) => m[1]).join("\n");
  }

  it("renders the graph's IOC values inert", () => {
    const svg = svgSections(renderHtmlReport(stateWithIndicators()));

    expect(svg, "the graph section must actually be present").toContain("<svg");
    // Labels are truncated for layout, so assert on the defanged head of each value.
    expect(svg).toContain("hxxp://evil[.]example");
    expect(svg).toContain("203[.]0[.]113[.]10");
    expect(svg).not.toContain("http://evil.example");
    expect(svg).not.toContain("203.0.113.10");
  });

  it("leaves no live scheme or dotted quad anywhere in the rendered report", () => {
    const html = renderHtmlReport(stateWithIndicators());

    // Ignore the document's own markup URLs (xmlns, CSS) — only evidence text is at issue.
    const evidence = html.replace(/xmlns="[^"]*"/g, "");
    expect(evidence).not.toContain("http://evil.example");
    expect(evidence).not.toContain("203.0.113.10");
  });
});
