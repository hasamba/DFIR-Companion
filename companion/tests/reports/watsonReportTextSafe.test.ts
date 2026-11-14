// F3: report text Watson writes is model text, and report.md renders the report fields raw. The
// proposal neutralises it when it is built, so a forged heading, an unclosed code fence or an HTML
// comment can never hide or forge a later report section. Analyst-typed text keeps today's raw path.
import { describe, expect, it } from "vitest";
import { buildWriteProposals } from "../../src/analysis/ai/watson/writeProposals.js";
import type { WatsonWriteInputs } from "../../src/analysis/ai/watson/roundWrites.js";
import type { WatsonReportTextProposal } from "../../src/analysis/ai/watson/types.js";
import type { WatsonWrites } from "../../src/analysis/ai/watson/writesSchema.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
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
