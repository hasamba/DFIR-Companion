import { describe, expect, it } from "vitest";
import { questionStatusSchema } from "../../../src/analysis/responseSchema.js";
import { renderMarkdownReport } from "../../../src/reports/markdown.js";
import { emptyState } from "../../../src/analysis/stateTypes.js";

describe("key question status: unanswerable", () => {
  it("parses unanswerable and falls back to unknown for junk", () => {
    expect(questionStatusSchema.parse("unanswerable")).toBe("unanswerable");
    expect(questionStatusSchema.parse("nope")).toBe("unknown");
  });

  it("renders unanswerable in the markdown report", () => {
    const state = emptyState("c1");
    state.keyQuestions = [
      { id: "q1", question: "How?", status: "unanswerable", answer: "No proxy logs exist", pointer: "" },
    ];
    const md = renderMarkdownReport(state);
    expect(md).toContain("Not answerable with available data");
    expect(md).toContain("No proxy logs exist");
  });
});
