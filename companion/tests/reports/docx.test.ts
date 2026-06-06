import { describe, it, expect } from "vitest";
import JSZip from "jszip";
import { renderDocxReport, tokensToDocxChildren } from "../../src/reports/docx.js";
import { emptyReportMeta } from "../../src/reports/reportMeta.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import { Marked } from "marked";

async function unzipDocumentXml(buf: Buffer): Promise<string> {
  const zip = await JSZip.loadAsync(buf);
  const entry = zip.file("word/document.xml");
  if (!entry) throw new Error("word/document.xml missing from .docx");
  return entry.async("text");
}

// External hyperlinks are stored in the relationship file, not document.xml.
async function unzipDocumentRels(buf: Buffer): Promise<string> {
  const zip = await JSZip.loadAsync(buf);
  const entry = zip.file("word/_rels/document.xml.rels");
  if (!entry) return "";
  return entry.async("text");
}

describe("renderDocxReport", () => {
  it("produces a valid .docx with the report's headings, tables, IOCs and summary", async () => {
    const state = emptyState("c1");
    state.lastSummary = "Host compromised via phishing.";
    state.iocs.push({ id: "i1", type: "ip", value: "10.0.0.5", firstSeen: "2026-05-20T09:00:00Z" });
    state.findings.push({
      id: "f1", severity: "High", title: "Beacon callout",
      description: "Attacker C2 callback observed.",
      relatedIocs: ["i1"], mitreTechniques: [], sourceScreenshots: [],
      firstSeen: "2026-05-20T09:00:00Z", lastUpdated: "2026-05-20T09:00:00Z", status: "open",
    });

    const buf = await renderDocxReport(state);
    expect(Buffer.isBuffer(buf)).toBe(true);
    expect(buf.length).toBeGreaterThan(1024); // a real docx is at least a few KB

    const xml = await unzipDocumentXml(buf);
    // H1 report title flowed through the heading mapper.
    expect(xml).toContain("Incident Investigation Report");
    // Executive summary text from state.lastSummary survives the pipeline.
    expect(xml).toContain("Host compromised via phishing.");
    // IOC table cell value is present (proves GFM tables map to <w:tbl>).
    expect(xml).toContain("10.0.0.5");
    expect(xml).toContain("<w:tbl");
    // Finding heading + description are present.
    expect(xml).toContain("Beacon callout");
    expect(xml).toContain("Attacker C2 callback observed.");
    // Standard Word heading style is applied at least once.
    expect(xml).toMatch(/w:pStyle w:val="Heading[12]"/);
  });

  it("uses the incident id in the report title when set", async () => {
    const meta = emptyReportMeta();
    meta.incidentId = "INC-42";
    const buf = await renderDocxReport(emptyState("c1"), meta);
    const xml = await unzipDocumentXml(buf);
    expect(xml).toContain("INC-42");
  });

  it("treats untrusted text as plain runs (no markup injection)", async () => {
    // DFIR data is untrusted; the docx model has no HTML pass-through, but we still want a
    // regression test that confirms angle-bracket payloads land as text, not as elements.
    const state = emptyState("c1");
    state.findings.push({
      id: "f1", severity: "High", title: "XSS attempt",
      description: "<script>alert(1)</script>",
      relatedIocs: [], mitreTechniques: [], sourceScreenshots: [],
      firstSeen: "", lastUpdated: "", status: "open",
    });
    const buf = await renderDocxReport(state);
    const xml = await unzipDocumentXml(buf);
    // The angle brackets get XML-escaped inside the text run; the literal payload is present
    // as escaped characters and never as a docx structural element.
    expect(xml).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
    expect(xml).not.toContain("<script>alert(1)</script>");
  });
});

describe("tokensToDocxChildren", () => {
  it("maps every Markdown token type the report emits", async () => {
    // Single focused fixture exercising every token type the renderer produces. We pack a
    // minimal Document around the mapper output and assert against the resulting XML, which
    // is the only stable contract docx exposes.
    const md = [
      "# H1 Title",
      "",
      "## H2 Section",
      "",
      "### H3 Subsection",
      "",
      "#### H4 Subblock",
      "",
      "A paragraph with **bold**, *italic*, `code`, and a [link](https://example.com).",
      "",
      "- bullet one",
      "- bullet two",
      "  - nested bullet",
      "",
      "1. first",
      "2. second",
      "",
      "| A | B |",
      "| --- | --- |",
      "| a1 | b1 |",
      "| a2 | b2 |",
      "",
      "> a blockquote line",
      "",
      "```",
      "code block line",
      "```",
      "",
      "---",
      "",
      "trailing paragraph",
      "",
    ].join("\n");

    const lexer = new Marked({ gfm: true });
    const tokens = lexer.lexer(md);
    const children = tokensToDocxChildren(tokens);
    expect(children.length).toBeGreaterThan(0);

    // Pack a minimal document and inspect document.xml.
    const { Document, Packer } = await import("docx");
    const doc = new Document({ sections: [{ children }] });
    const buf = await Packer.toBuffer(doc);
    const xml = await unzipDocumentXml(buf);
    // ExternalHyperlink URLs are stored in the rels file, not document.xml.
    const rels = await unzipDocumentRels(buf);

    // Headings 1..4 each present.
    expect(xml).toContain("H1 Title");
    expect(xml).toContain("H2 Section");
    expect(xml).toContain("H3 Subsection");
    expect(xml).toContain("H4 Subblock");
    expect(xml).toMatch(/w:pStyle w:val="Heading1"/);
    expect(xml).toMatch(/w:pStyle w:val="Heading4"/);

    // Inline runs: bold + italic + code all present in document.xml;
    // link target is in the relationship file.
    expect(xml).toContain("bold");
    expect(xml).toContain("italic");
    expect(xml).toContain("code");
    expect(rels).toContain("https://example.com");

    // Lists: each item text present.
    expect(xml).toContain("bullet one");
    expect(xml).toContain("nested bullet");
    expect(xml).toContain("first");
    expect(xml).toContain("second");

    // GFM table with header + cells.
    expect(xml).toContain("<w:tbl");
    expect(xml).toContain("a1");
    expect(xml).toContain("b2");

    // Blockquote text + code-block text + trailing paragraph all present.
    expect(xml).toContain("a blockquote line");
    expect(xml).toContain("code block line");
    expect(xml).toContain("trailing paragraph");
  });
});
