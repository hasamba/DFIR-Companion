// F3: report text Watson writes is model text, and report.md renders the report fields raw. The
// proposal neutralises it when it is built, so a forged heading, an unclosed code fence or an HTML
// comment can never hide or forge a later report section. Analyst-typed text keeps today's raw path.
import { describe, expect, it } from "vitest";
import { buildWriteProposals } from "../../src/analysis/ai/watson/writeProposals.js";
import type { WatsonWriteInputs } from "../../src/analysis/ai/watson/roundWrites.js";
import type { WatsonWrites } from "../../src/analysis/ai/watson/writesSchema.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import { pasteLineEvent } from "../../src/analysis/ai/watson/writers/pasteLineEvents.js";
import type { WatsonPaste, WatsonReportTextProposal } from "../../src/analysis/ai/watson/types.js";
import { renderHtmlReport } from "../../src/reports/html.js";
import { renderMarkdownReport } from "../../src/reports/markdown.js";
import { blockMd } from "../../src/reports/mdText.js";
import { emptyReportMeta } from "../../src/reports/reportMeta.js";

const HOSTILE = "Lateral movement was confirmed.\n## Forged section\n```\n<!-- hide the rest\nstill text";

const inputs = (over: Partial<WatsonWriteInputs> = {}): WatsonWriteInputs => ({
  findings: new Map(),
  pastes: new Map(),
  lines: new Map(),
  report: { conclusions: "", investigationLimitations: "" },
  reportBlockText: blockMd,
  ...over,
});
const writes: WatsonWrites = {
  findings: [],
  nextSteps: [],
  report: [
    { field: "investigationLimitations", text: HOSTILE },
    { field: "conclusions", text: HOSTILE },
  ],
};
let n = 0;
const newId = (prefix: string) => `${prefix}-${++n}`;

function proposals(over: Partial<WatsonWriteInputs> = {}): WatsonReportTextProposal[] {
  return buildWriteProposals(writes, inputs(over), "t1", newId) as WatsonReportTextProposal[];
}

describe("Watson report text is neutralised when the proposal is built", () => {
  it("stores text with no heading, fence or comment opener at a line start", () => {
    const [limits, concl] = proposals();
    for (const p of [limits, concl]) {
      expect(p.kind).toBe("report_text");
      expect(p.after).toContain("Lateral movement was confirmed.");
      expect(p.after.split("\n").some((l) => /^#{1,6}\s/.test(l))).toBe(false);
      expect(p.after.split("\n").some((l) => /^(```|<!--)/.test(l))).toBe(false);
    }
  });

  it("the exported Markdown keeps every later section and has no forged heading", () => {
    const [limits, concl] = proposals();
    const meta = { ...emptyReportMeta(), investigationLimitations: limits.after, conclusions: concl.after };
    const md = renderMarkdownReport(emptyState("c1"), meta);
    const lines = md.split("\n");
    expect(lines.some((l) => /^#{1,6}\s+Forged/.test(l))).toBe(false);
    expect(lines.some((l) => /^```/.test(l))).toBe(false);
    expect(lines.some((l) => /^<!--/.test(l))).toBe(false);
    // Sections after 2.2 (limitations) and after 5 (conclusions) are still headings.
    expect(lines.some((l) => l.startsWith("## 2.3"))).toBe(true);
    const conclAt = lines.findIndex((l) => /^## 5\b/.test(l));
    expect(conclAt).toBeGreaterThan(-1);
    expect(lines.slice(conclAt + 1).some((l) => l.startsWith("### Recommendations"))).toBe(true);
    expect(lines.slice(conclAt + 1).some((l) => l.startsWith("## Attacker Sessions"))).toBe(true);
  });

  it("does not re-propose text the report already holds once neutralised", () => {
    const [, concl] = proposals();
    const again = proposals({ report: { conclusions: concl.after, investigationLimitations: "" } });
    expect(again.map((p) => p.field)).toEqual(["investigationLimitations"]);
  });

  it("proposes no report text without the neutraliser", () => {
    expect(proposals({ reportBlockText: undefined })).toEqual([]);
  });
});

// F16: a hostile pasted line a Watson finding cites becomes a forensic event; its row in the report's
// event table stays one row, with the pipe escaped, no forged heading, and no live markup in HTML.
describe("a hostile pasted line cited as an event", () => {
  const paste: WatsonPaste = {
    id: "wf-1",
    storedName: "0001_p.txt",
    filename: "gateway.log",
    bytes: 80,
    lines: 1,
    at: "2026-03-01T09:00:00Z",
  };
  const LINE = "2026-03-01T08:00:00Z <img src=x onerror=alert(1)> a | b\n## Forged heading";
  const event = pasteLineEvent(paste, 1, LINE, "High", "f-watson-1a2b3c4d", "2026-03-01T09:00:00Z");
  const state = { ...emptyState("c1"), forensicTimeline: [event] };

  it("renders as one table row in the Markdown report", () => {
    const lines = renderMarkdownReport(state).split("\n");
    expect(lines.some((l) => /^#{1,6}\s+Forged/.test(l))).toBe(false);
    const rows = lines.filter((l) => l.includes("Pasted gateway.log line 1"));
    expect(rows).toHaveLength(1);
    expect(rows[0]).toContain("a \\| b");
    expect(rows[0]).toContain("## Forged heading"); // kept as text, inside the cell
    const header = lines.find((l) => l.startsWith("| Time |")) ?? "";
    const cells = (l: string) => l.replace(/\\\|/g, "").split("|").length;
    expect(cells(rows[0])).toBe(cells(header));
  });

  it("carries no live markup into the HTML report", () => {
    const html = renderHtmlReport(state);
    expect(html).not.toMatch(/<img[^>]*onerror/i);
    expect(html).not.toMatch(/<h\d[^>]*>\s*Forged heading/i);
  });
});
