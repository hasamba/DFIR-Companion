import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { buildHandoffBrief } from "../../src/analysis/handoffBrief.js";
import { emptyState, type InvestigationQuestion } from "../../src/analysis/stateTypes.js";
import { renderHandoffMarkdown } from "../../src/reports/handoffMarkdown.js";
import { buildNotes } from "../../src/integrations/iris/irisMap.js";
import { renderMarkdownReport } from "../../src/reports/markdown.js";
import { emptyReportMeta } from "../../src/reports/reportMeta.js";
import { SYSTEM_CHECK_LABEL } from "../../src/reports/mdText.js";

// #2681: the system-made burst-gap question is marked wherever Key Questions are shown, so it never
// reads as a finding or as an analyst's question, and it is not an investigation goal.

const gapQuestion: InvestigationQuestion = {
  id: "sys-burst-5e100",
  question: "A grouped burst of 20 events from winupd.exe on WS-07 hid 7 distinct command lines | =cmd",
  status: "unknown",
  answer: "",
  pointer: "Read these forensic-timeline events by id: 5e113, 5e114",
  pinned: true,
  coverageGap: {
    kind: "burst-hidden-lines",
    representativeId: "5e100",
    memberCount: 20,
    hiddenCount: 7,
    hiddenEventIds: ["5e113", "5e114"],
  },
};
const analystQuestion: InvestigationQuestion = {
  id: "q1",
  question: "How did they get in?",
  status: "unknown",
  answer: "",
  pointer: "",
};

const state = () => ({ ...emptyState("c1"), keyQuestions: [analystQuestion, gapQuestion] });

describe("burst-gap question in the reports (#2681)", () => {
  const md = renderMarkdownReport(state());

  it("marks the question as a system check in the Key Questions table, escaped", () => {
    const row = md.split("\n").find((l) => l.includes("winupd.exe") && l.startsWith("|"));
    expect(row).toBeDefined();
    expect(row).toContain("System coverage check");
    expect(row).toContain("\\| =cmd");
    const analystRow = md.split("\n").find((l) => l.includes("How did they get in?") && l.startsWith("|"));
    expect(analystRow).not.toContain("System coverage check");
  });

  it("leaves it out of the investigation goals", () => {
    const goals = md.slice(md.indexOf("## 2.3"), md.indexOf("## 2.4"));
    expect(goals).toContain("How did they get in?");
    expect(goals).not.toContain("winupd.exe");
  });

  it("marks it in the IRIS notes export", () => {
    const note = buildNotes(state(), emptyReportMeta()).find(
      (n) => n.title === "Key Investigative Questions",
    );
    expect(note?.content).toContain(`### ${SYSTEM_CHECK_LABEL} A grouped burst`);
    expect(note?.content).toContain("### How did they get in?");
  });

  it("marks it in the shift hand-off", () => {
    const text = renderHandoffMarkdown(buildHandoffBrief(state(), {}));
    const line = text.split("\n").find((l) => l.includes("winupd.exe"));
    expect(line).toContain(SYSTEM_CHECK_LABEL);
    expect(text.split("\n").find((l) => l.includes("How did they get in?"))).not.toContain(
      SYSTEM_CHECK_LABEL,
    );
  });
});

describe("burst-gap question in the dashboard (#2681)", () => {
  const read = (f: string) => readFileSync(new URL(`../../../public/js/${f}`, import.meta.url), "utf8");

  it("the Key Questions panel and Watson's board both badge it as a system check", () => {
    for (const f of ["dashboard-render.js", "dashboard-watson-view.js"]) {
      const src = read(f);
      expect(src, f).toMatch(/q\.coverageGap\s*\?\s*` <span class="q-system"[^`]*>System check<\/span>`/);
    }
  });

  it("is not saved into a case template", () => {
    expect(read("dashboard-save-template.js")).toMatch(/\.filter\(\(q\) => !q\.coverageGap\)/);
  });
});
