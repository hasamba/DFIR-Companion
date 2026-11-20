import { describe, expect, it } from "vitest";
import { Marked } from "marked";
import { cellMd, codeSpanMd, eventCellMd, flatLineMd, oneLineMd } from "../../src/reports/mdText.js";
import { evidenceCellMd } from "../../src/reports/aiAgentReportExport.js";
import { renderMarkdownReport } from "../../src/reports/markdown.js";
import { renderHtmlReport } from "../../src/reports/html.js";
import { emptyState } from "../../src/analysis/stateTypes.js";

// Case text written into a heading or a table cell of the Markdown report must not become live
// HTML in a Markdown viewer that renders raw HTML. The HTML export escapes on its own; the .md file
// is a deliverable too. A backslash escape renders the literal character in every CommonMark
// reader, and marked hands DOCX an "escape" token whose text is the plain character.

const SCRIPT = "<script>alert(1)</script>";
const IMG = "<img src=x onerror=alert(2)>";
const AMP = "R&D share &lt;b&gt;";

/** Text a CommonMark reader shows for one inline fragment, with any raw HTML kept as `RAW[…]`. */
function rendered(fragment: string): string {
  const marked = new Marked({ gfm: true });
  marked.use({ renderer: { html: (t) => `RAW[${typeof t === "string" ? t : t.text}]` } });
  return marked.parseInline(fragment, { async: false });
}

describe("inline and cell helpers neutralise HTML-significant characters", () => {
  for (const [name, fn] of [
    ["oneLineMd", oneLineMd],
    ["cellMd", cellMd],
  ] as const) {
    it(`${name}: a script tag is never raw HTML`, () => {
      const out = fn(SCRIPT);
      expect(out).not.toMatch(/(^|[^\\])<script/);
      expect(rendered(out)).not.toContain("RAW[");
      expect(rendered(out)).toBe("&lt;script&gt;alert(1)&lt;/script&gt;");
    });

    it(`${name}: an img onerror tag is never raw HTML`, () => {
      const out = fn(IMG);
      expect(rendered(out)).not.toContain("RAW[");
      expect(rendered(out)).toBe("&lt;img src=x onerror=alert(2)&gt;");
    });

    it(`${name}: an ampersand stays a literal ampersand, never an entity`, () => {
      // "&lt;" in case data is the four characters the attacker typed, not a less-than sign.
      expect(rendered(fn(AMP))).toBe("R&amp;D share &amp;lt;b&amp;gt;");
    });

    it(`${name}: a backslash already before a tag does not cancel the escape`, () => {
      for (const v of ["\\<script>", "\\\\<script>", "\\\\\\&lt;"]) {
        const html = rendered(fn(v));
        expect(html).not.toContain("RAW[");
        expect(html).not.toMatch(/<script|<b>/);
      }
      expect(rendered(fn("\\<script>"))).toBe("\\&lt;script&gt;");
      expect(rendered(fn("\\\\<b>"))).toBe("\\\\&lt;b&gt;");
    });

    it(`${name}: a Windows path keeps its backslashes as written`, () => {
      expect(fn("C:\\Windows\\Temp\\a.ps1")).toBe("C:\\Windows\\Temp\\a.ps1");
    });
  }

  it("eventCellMd escapes the event text", () => {
    expect(rendered(eventCellMd({ description: IMG }))).not.toContain("RAW[");
  });

  it("cellMd still escapes the pipe and keeps one row", () => {
    expect(cellMd("a|<b>")).toBe("a\\|\\<b\\>");
  });
});

describe("code spans stay literal", () => {
  it("codeSpanMd does not add backslashes inside the span", () => {
    expect(codeSpanMd(`${SCRIPT} & x`)).toBe(`\` ${SCRIPT} & x \``);
  });

  it("an evidence table cell (a code span) shows the raw text once", () => {
    const md = `| a |\n| --- |\n| ${evidenceCellMd(`${IMG} & |`)} |\n`;
    const html = new Marked({ gfm: true }).parse(md, { async: false });
    expect(html).toContain("<code>&lt;img src=x onerror=alert(2)&gt; &amp; |</code>");
  });

  it("flatLineMd flattens without escaping, for text placed inside backticks", () => {
    expect(flatLineMd(` ${SCRIPT}\n& `)).toBe(`${SCRIPT} &`);
  });
});

function hostileState() {
  const state = emptyState("case-x");
  state.findings.push({
    id: "f1",
    severity: "High",
    title: `${SCRIPT} ${IMG} ${AMP}`,
    description: "Observed.",
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
    description: `${IMG} ${SCRIPT} ${AMP}`,
    severity: "High",
    asset: "<b>WS01</b>",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
  });
  return state;
}

describe("the Markdown report escapes case HTML in headings and table cells", () => {
  const md = renderMarkdownReport(hostileState());

  it("writes no raw tag from case data", () => {
    expect(md).not.toMatch(/(^|[^\\])<script>alert/m);
    expect(md).not.toMatch(/(^|[^\\])<img src=x/m);
  });

  it("escapes the finding heading", () => {
    const heading = md.split("\n").find((l) => /^#{2,6} .*script/.test(l));
    expect(heading).toBeDefined();
    expect(heading).toContain("\\<script\\>");
    expect(heading).toContain("\\<img src=x onerror=alert(2)\\>");
    expect(heading).toContain("R\\&D share \\&lt;b\\&gt;");
  });

  it("escapes the timeline table cell", () => {
    const row = md.split("\n").find((l) => l.startsWith("|") && l.includes("onerror"));
    expect(row).toBeDefined();
    expect(row).toContain("\\<img src=x onerror=alert(2)\\>");
    expect(row).toContain("\\<script\\>alert(1)\\</script\\>");
    expect(row).toContain("R\\&D share \\&lt;b\\&gt;");
    expect(row).toContain("\\<b\\>WS01\\</b\\>");
  });

  it("the HTML export shows each character once, not double-escaped", () => {
    const html = renderHtmlReport(hostileState());
    expect(html).toContain("&lt;img src=x onerror=alert(2)&gt;");
    expect(html).toContain("R&amp;D share &amp;lt;b&amp;gt;");
    expect(html).not.toContain("\\&lt;");
    expect(html).not.toContain("&amp;amp;");
    expect(html).not.toMatch(/<img src=x/);
  });
});
