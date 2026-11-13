import { describe, it, expect } from "vitest";
import { renderMarkdownReport } from "../../src/reports/markdown.js";
import { emptyState } from "../../src/analysis/stateTypes.js";

const HOSTILE = "Was it staged?\n## Forged section\n| a | b |\n=cmd|' /C calc'!A0";

describe("Watson-authored key questions in the Markdown report", () => {
  const state = emptyState("c1");
  state.keyQuestions.push({
    id: "q-watson-1",
    question: HOSTILE,
    status: "answered",
    answer: HOSTILE,
    pointer: HOSTILE,
    pinned: true,
    author: "watson",
  } as never);
  const md = renderMarkdownReport(state);

  it("adds no heading line from question, answer or pointer text", () => {
    expect(md.split("\n").some((l) => /^#{1,6}\s+Forged section/.test(l))).toBe(false);
  });

  it("keeps the questions table intact (one row, no spill lines)", () => {
    const lines = md.split("\n");
    const start = lines.findIndex((l) => l.startsWith("| | Question | Answer"));
    expect(start).toBeGreaterThan(-1);
    const rows: string[] = [];
    for (let i = start + 2; i < lines.length && lines[i].startsWith("|"); i++) rows.push(lines[i]);
    expect(rows).toHaveLength(1);
    expect(lines[start + 2 + 1] ?? "").not.toMatch(/^\|\s*a\s*\|/);
  });

  it("flattens the goals list entry onto one line", () => {
    const goals = md.slice(md.indexOf("## 2.3"), md.indexOf("## 2.4"));
    expect(goals).toContain("Derived from the investigation's key questions");
    expect(goals).not.toMatch(/^## Forged/m);
    expect(goals).not.toMatch(/^=cmd/m);
    expect(goals).not.toMatch(/^\| a \| b \|/m);
  });
});
