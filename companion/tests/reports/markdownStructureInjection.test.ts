import { describe, expect, it } from "vitest";
import { renderMarkdownReport } from "../../src/reports/markdown.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import { hypothesisSchema, type Hypothesis } from "../../src/analysis/hypothesis.js";
import type { NotebookEntry } from "../../src/analysis/notebookStore.js";

// Report-structure integrity. Finding titles, finding descriptions and hypothesis titles are
// written by the AI from evidence the attacker chose — filenames, command lines, registry values.
// reports/html.ts already refuses to turn that text into live markup; this suite covers the other
// half, which no escape guarded: text that keeps the report's OWN Markdown structure honest. A
// title carrying a newline plus "## 99 Attacker Appendix" forges a section inside a forensic
// deliverable, and reports/docx.ts classifies headings by their TEXT, so it reaches the DOCX
// outline too.

const FORGED = "## 99 Attacker Appendix";
const forgedHeading = /^ {0,3}#{1,6}\s+99 Attacker Appendix/m;

function findingWith(fields: { title?: string; description?: string }) {
  return {
    id: "f1",
    severity: "High" as const,
    title: fields.title ?? "Beacon on WS01",
    description: fields.description ?? "Observed periodic beaconing.",
    relatedIocs: [],
    mitreTechniques: [],
    sourceScreenshots: [],
    firstSeen: "2026-05-28T10:00:00.000Z",
    lastUpdated: "2026-05-28T10:00:00.000Z",
    status: "open" as const,
    relatedEventIds: [],
  };
}

function hypothesisWith(fields: Record<string, unknown>): Hypothesis {
  return hypothesisSchema.parse({
    createdAt: "2026-05-28T10:00:00.000Z",
    updatedAt: "2026-05-28T10:00:00.000Z",
    ...fields,
  });
}

function renderWithHypotheses(hypotheses: Hypothesis[]): string {
  return renderMarkdownReport(
    emptyState("c1"),
    undefined,
    undefined,
    undefined,
    undefined,
    undefined,
    undefined,
    undefined,
    hypotheses,
  );
}

describe("report structure cannot be forged through finding text", () => {
  it("keeps a newline-bearing finding title inside its own heading", () => {
    const state = emptyState("c1");
    state.findings.push(
      findingWith({ title: `Beacon on WS01\n\n${FORGED}\n\nNo compromise was identified.` }),
    );

    const md = renderMarkdownReport(state);

    expect(md).not.toMatch(forgedHeading);
    // The text is not dropped — it stays on the finding's own heading line, where a reader sees it
    // attributed to the finding rather than presented as a section of the report.
    const headingLine = md.split("\n").find((l) => l.startsWith("#### [High]"));
    expect(headingLine).toContain("No compromise was identified.");
  });

  it("neutralises a heading a finding description tries to open", () => {
    const state = emptyState("c1");
    state.findings.push(
      findingWith({
        description: `Observed periodic beaconing.\n\n${FORGED}\n\nNo compromise was identified.`,
      }),
    );

    const md = renderMarkdownReport(state);

    expect(md).not.toMatch(forgedHeading);
    expect(md).toContain("99 Attacker Appendix");
  });

  it("neutralises a setext underline a finding description tries to open", () => {
    const state = emptyState("c1");
    state.findings.push(
      findingWith({ description: "Observed periodic beaconing.\n\n99 Attacker Appendix\n===" }),
    );

    const md = renderMarkdownReport(state);

    expect(md.split("\n").some((l) => l.trim() === "===")).toBe(false);
  });

  it("keeps a newline-bearing hypothesis title inside its own heading", () => {
    const md = renderWithHypotheses([
      hypothesisWith({
        id: "h1",
        title: `Phishing was the initial access\n\n${FORGED}\n\nNo compromise was identified.`,
      }),
    ]);

    expect(md).not.toMatch(forgedHeading);
    expect(md).toContain("No compromise was identified.");
  });

  it("keeps a refuted hypothesis's title and reason on one list line", () => {
    const md = renderWithHypotheses([
      hypothesisWith({
        id: "h1",
        title: "Insider access",
        status: "refuted",
        notes: `ruled out\n\n${FORGED}\n\nNo compromise was identified.`,
      }),
    ]);

    expect(md).not.toMatch(forgedHeading);
    const listLine = md.split("\n").find((l) => l.startsWith("- **[Refuted]**"));
    expect(listLine).toContain("No compromise was identified.");
  });

  it("neutralises a heading a notebook entry tries to open", () => {
    // Analysts paste raw log lines into the notebook constantly, so its prose carries evidence text
    // just as directly as an AI-written description does.
    const entries: NotebookEntry[] = [
      {
        id: "n1",
        timestamp: "2026-05-28T10:00:00.000Z",
        type: "note",
        text: `Pasted from the host:\n\n${FORGED}\n\nNo compromise was identified.`,
      },
    ];

    const md = renderMarkdownReport(emptyState("c1"), undefined, undefined, undefined, entries);

    expect(md).not.toMatch(forgedHeading);
    expect(md).toContain("99 Attacker Appendix");
  });
});
