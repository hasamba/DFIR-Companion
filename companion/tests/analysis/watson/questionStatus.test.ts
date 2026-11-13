import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { openCollectTargets } from "../../../src/analysis/collectSatisfaction.js";
import { askSchema, deltaSchema, questionStatusSchema } from "../../../src/analysis/responseSchema.js";
import { keepWatsonAnswers } from "../../../src/analysis/timeline/watsonQuestions.js";
import { renderMarkdownReport } from "../../../src/reports/markdown.js";
import { emptyState, type InvestigationQuestion } from "../../../src/analysis/stateTypes.js";

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

describe("only Watson sets unanswerable (synthesis and Ask read it as unknown)", () => {
  it("a synthesis delta saying unanswerable parses as unknown", () => {
    const delta = deltaSchema.parse({
      findings: [],
      iocs: [],
      mitreTechniques: [],
      forensicEvents: [],
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: "",
      summary: "",
      keyQuestions: [
        { id: "q1", question: "How did they get in?", status: "unanswerable", answer: "no logs" },
      ],
    });
    expect(delta.keyQuestions?.[0]?.status).toBe("unknown");
  });

  it("an Ask answer saying unanswerable parses as unknown", () => {
    expect(
      askSchema.parse({ answer: "a", status: "unanswerable", pointer: "", relatedEventIds: [] }).status,
    ).toBe("unknown");
  });

  it("Watson's applied unanswerable is kept, and synthesis's unknown raises no disagreement", () => {
    const w: InvestigationQuestion = {
      id: "q1",
      question: "How did they get in?",
      status: "unanswerable",
      answer: "No proxy logs exist",
      pointer: "",
      pinned: true,
      author: "watson",
    };
    const out = keepWatsonAnswers([{ ...w, status: "unknown", answer: "", author: undefined }], [w], [w]);
    expect(out[0]).toMatchObject({ status: "unanswerable", answer: "No proxy logs exist" });
    expect(out[0]?.synthesisDisagrees).toBeUndefined();
  });

  it("no collect target or Deploy button for an unanswerable question", () => {
    const state = emptyState("c1");
    state.keyQuestions = [
      {
        id: "q1",
        question: "How?",
        status: "unanswerable",
        answer: "",
        pointer: "",
        collect: { host: "DC01", logSource: "Security.evtx" },
      },
    ];
    expect(openCollectTargets(state)).toEqual([]);
    const render = readFileSync(
      new URL("../../../../public/js/dashboard-render.js", import.meta.url),
      "utf8",
    );
    expect(render).toContain(
      'q.status !== "answered" && q.status !== "unanswerable" ? collectDirectiveHtml(q.collect)',
    );
  });
});
