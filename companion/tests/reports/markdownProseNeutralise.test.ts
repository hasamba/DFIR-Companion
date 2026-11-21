import { describe, expect, it } from "vitest";
import JSZip from "jszip";
import { Marked } from "marked";
import { blockMd, cellMd, oneLineMd } from "../../src/reports/mdText.js";
import { renderMarkdownReport } from "../../src/reports/markdown.js";
import { renderHtmlReport } from "../../src/reports/html.js";
import { renderDocxReport } from "../../src/reports/docx.js";
import { emptyState } from "../../src/analysis/stateTypes.js";

// Case text in the Markdown report's body paragraphs gets the same HTML neutralisation headings and
// cells already had, and Markdown link or image syntax from case data never produces a live link in
// a heading, a cell or a paragraph. Judged by rendering through marked (a CommonMark reader), not by
// string shape alone.

const IMG = "<img src=x onerror=alert(1)>";
const LINK = "[click](javascript:alert(3))";
const DANGEROUS = /(?:href|src)\s*=\s*"?\s*(?:javascript|data|vbscript):/i;

function html(md: string): string {
  return new Marked({ gfm: true }).parse(md, { async: false });
}

function assertInert(md: string): void {
  const out = html(md);
  expect(out).not.toMatch(/<img/i);
  expect(out).not.toMatch(/<a\s/i);
  expect(out).not.toMatch(DANGEROUS);
}

describe("blockMd neutralises inline HTML and links in body text", () => {
  it("escapes a mid-line tag like the heading and cell helpers do", () => {
    expect(blockMd(`event 0 ${IMG} end`)).toBe("event 0 \\<img src=x onerror=alert(1)\\> end");
    assertInert(blockMd(`event 0 ${IMG} end`));
  });

  it.each([
    LINK,
    "![x](javascript:alert(1))",
    "[x](JaVaScRiPt:alert(1))",
    "[x]( javascript:alert(1) )",
    "[x](<javascript:alert(1)>)",
    "[x](javascript&#58;alert(1))",
    "[x](java\\script:alert(1))",
    "[x](data:text/html;base64,PHNjcmlwdD4=)",
    "[x](vbscript:msgbox(1))",
    "<javascript:alert(1)>",
    "see [x]\n\n[x]: javascript:alert(1)",
    "see [x]\n\n- [x]: javascript:alert(1)",
    "see [x][r]\n\n> [r]: javascript:alert(1)",
    "`a\nb` [x](javascript:alert(1)) `c`",
    "`a\n- b`  `[x](javascript:alert(1))`",
    "\\`[x](javascript:alert(1))`",
    "``` <img src=x onerror=alert(1)> ```",
    "```` [x](javascript:alert(1)) ````",
    "- ``` <img src=x onerror=alert(1)> ```",
    "> ```` [x](javascript:alert(1)) ````",
  ])("%j renders with no live link", (input) => {
    assertInert(blockMd(input));
  });

  it("leaves a literal absolute web or mailto link live, as the HTML and DOCX link policy does", () => {
    expect(blockMd("[m](mailto:soc@example.invalid) [w](https://example.invalid/x)")).toBe(
      "[m](mailto:soc@example.invalid) [w](https://example.invalid/x)",
    );
    expect(blockMd("[w](https\\://x)")).toBe("[w]\\(https\\://x)");
  });

  it("keeps code spans literal", () => {
    expect(blockMd("ran `<b>&</b> [a](b)` then ``a`b``")).toBe("ran `<b>&</b> [a](b)` then ``a`b``");
    expect(html(blockMd("ran `<b>&</b>`"))).toContain("<code>&lt;b&gt;&amp;&lt;/b&gt;</code>");
  });

  it("keeps blockquotes, lists and task boxes", () => {
    expect(blockMd("> quoted <x>")).toBe("> quoted \\<x\\>");
    expect(blockMd("- [ ] todo")).toBe("- [ ] todo");
  });

  it("renders the text once: no stray backslash", () => {
    const out = html(blockMd(`a ${IMG} ${LINK} R&D [::1]:445`));
    expect(out).toContain("&lt;img src=x onerror=alert(1)&gt;");
    expect(out).toContain("[click](javascript:alert(3))");
    expect(out).toContain("R&amp;D [::1]:445");
    expect(out).not.toContain("\\");
  });
});

describe("heading and cell helpers break link syntax", () => {
  for (const [name, fn] of [
    ["oneLineMd", oneLineMd],
    ["cellMd", cellMd],
  ] as const) {
    it(`${name}: no live javascript: link, text shown once`, () => {
      const out = new Marked({ gfm: true }).parseInline(fn(`${LINK} ![i](data:x)`), { async: false });
      expect(out).not.toMatch(/<a\s|<img/i);
      expect(out).toContain("[click](javascript:alert(3)) ![i](data:x)");
    });
  }
});

function hostileState() {
  const state = emptyState("case-x");
  state.findings.push({
    id: "f1",
    severity: "High",
    title: `title ${LINK}`,
    description: `event 0 ${IMG} ${LINK} end`,
    relatedIocs: [],
    mitreTechniques: [],
    sourceScreenshots: [],
    firstSeen: "2026-05-28T10:00:00.000Z",
    lastUpdated: "2026-05-28T10:00:00.000Z",
    status: "open",
    relatedEventIds: [],
  });
  state.forensicTimeline.push({
    id: "e1",
    timestamp: "2026-05-28T10:00:00.000Z",
    description: `${IMG} ${LINK}`,
    severity: "High",
    asset: "WS01",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
  });
  return state;
}

describe("the report and its exports", () => {
  it("report.md has no live HTML or link from case data", () => {
    const md = renderMarkdownReport(hostileState());
    expect(md).not.toMatch(/(^|[^\\])<img src=x/m);
    expect(md).not.toMatch(/\]\(javascript:/);
    assertInert(md);
  });

  it("the HTML export shows the payload once", () => {
    const out = renderHtmlReport(hostileState());
    expect(out).toContain("event 0 &lt;img src=x onerror=alert(1)&gt; [click](javascript:alert(3)) end");
    expect(out).not.toContain("\\&lt;");
    expect(out).not.toContain("]\\(");
    expect(out).not.toMatch(DANGEROUS);
  });

  it("the DOCX export shows the payload once", async () => {
    const zip = await JSZip.loadAsync(await renderDocxReport(hostileState()));
    const xml = (await zip.file("word/document.xml")?.async("text")) ?? "";
    const text = [...xml.matchAll(/<w:t[^>]*>([^<]*)<\/w:t>/g)].map((m) => m[1]).join("");
    expect(text).toContain("event 0 &lt;img src=x onerror=alert(1)&gt; [click](javascript:alert(3)) end");
    expect(text).not.toContain("\\");
  });
});
