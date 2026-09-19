import { describe, it, expect } from "vitest";
import {
  ASK_HISTORY_MAX,
  ASK_HISTORY_FIELD_MAX,
  parseAskHistory,
  parseAskRequest,
} from "../../src/analysis/askHistory.js";

// The panel sends its last few Q&A pairs back with each question (#1411). This is untrusted
// request input: bounded, trimmed, never throws.

describe("parseAskHistory", () => {
  it("returns [] for anything that is not an array", () => {
    expect(parseAskHistory(undefined)).toEqual([]);
    expect(parseAskHistory(null)).toEqual([]);
    expect(parseAskHistory("q")).toEqual([]);
    expect(parseAskHistory({ question: "q", answer: "a" })).toEqual([]);
  });

  it("drops malformed entries and trims the good ones", () => {
    expect(
      parseAskHistory([
        { question: "  q1 ", answer: " a1 " },
        { question: "", answer: "a" },
        { question: "q", answer: 3 },
        "nope",
        null,
      ]),
    ).toEqual([{ question: "q1", answer: "a1" }]);
  });

  it("keeps only the LAST ASK_HISTORY_MAX turns", () => {
    const turns = Array.from({ length: ASK_HISTORY_MAX + 3 }, (_, i) => ({
      question: `q${i}`,
      answer: `a${i}`,
    }));
    const out = parseAskHistory(turns);
    expect(out.length).toBe(ASK_HISTORY_MAX);
    expect(out[out.length - 1]?.question).toBe(`q${ASK_HISTORY_MAX + 2}`);
  });

  it("caps each field at ASK_HISTORY_FIELD_MAX characters", () => {
    const long = "x".repeat(ASK_HISTORY_FIELD_MAX + 50);
    const [t] = parseAskHistory([{ question: long, answer: long }]);
    expect(t?.question.length).toBe(ASK_HISTORY_FIELD_MAX);
    expect(t?.answer.length).toBe(ASK_HISTORY_FIELD_MAX);
  });

  it("allows an empty answer (the model returned nothing) but not an empty question", () => {
    expect(parseAskHistory([{ question: "q", answer: "" }])).toEqual([{ question: "q", answer: "" }]);
  });
});

describe("parseAskRequest", () => {
  it("returns the trimmed question and the parsed history", () => {
    expect(parseAskRequest({ question: " was it? ", history: [{ question: "q", answer: "a" }] })).toEqual({
      question: "was it?",
      history: [{ question: "q", answer: "a" }],
    });
  });

  it("returns an empty question for a missing or non-string body field", () => {
    expect(parseAskRequest(undefined).question).toBe("");
    expect(parseAskRequest({ question: 7 }).question).toBe("");
    expect(parseAskRequest({}).history).toEqual([]);
  });
});
