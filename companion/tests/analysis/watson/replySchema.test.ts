import { describe, expect, it } from "vitest";
import { sanitizeWatsonReply, watsonReplySchema } from "../../../src/analysis/ai/watson/replySchema.js";
import { WATSON_TURN_TEXT_MAX } from "../../../src/analysis/ai/watson/chatStore.js";

const parse = (v: unknown) => watsonReplySchema.parse(v);
const qs = new Set(["q1"]);
const ps = new Set(["p1"]);

describe("watsonReplySchema", () => {
  it("parses {} into empty defaults", () => {
    expect(parse({})).toEqual({
      message: "",
      workingOn: "",
      learned: "",
      questionUpdates: [],
      newQuestions: [],
      request: null,
      search: null,
      memory: "",
      answer: null,
      writes: { findings: [], nextSteps: [], report: [] },
    });
  });
  it("falls back per field on junk", () => {
    const r = parse({ message: 5, questionUpdates: "x", request: 7, search: [] });
    expect(r.message).toBe("");
    expect(r.questionUpdates).toEqual([]);
    expect(r.request).toBeNull();
    expect(r.search).toBeNull();
  });
  it("maps a bad status to unknown", () => {
    const r = parse({ questionUpdates: [{ questionId: "q1", status: "bogus" }] });
    expect(r.questionUpdates[0].status).toBe("unknown");
  });
});

describe("per-element leniency", () => {
  it("keeps valid elements next to junk", () => {
    const r = parse({
      questionUpdates: ["x", null, 3, { questionId: "q1", status: "answered" }],
      newQuestions: [null, { question: "real?", why: "w" }, "s"],
      search: { pasteId: "p1", terms: ["a", 5, null, "b"] },
    });
    expect(r.questionUpdates.map((u) => u.questionId)).toEqual(["q1"]);
    expect(r.newQuestions.map((q) => q.question)).toEqual(["real?"]);
    expect(r.search?.terms).toEqual(["a", "b"]);
  });
});

describe("sanitizeWatsonReply", () => {
  it("drops blank questions and terms before capping", () => {
    const r = parse({
      newQuestions: [
        { question: "  ", why: "" },
        { question: "", why: "" },
        { question: "a", why: "" },
        { question: "b", why: "" },
        { question: "c", why: "" },
      ],
      search: { pasteId: "p1", terms: ["", "  ", "t"] },
    });
    const out = sanitizeWatsonReply(r, qs, ps, new Set());
    expect(out.newQuestions.map((q) => q.question)).toEqual(["a", "b", "c"]);
    expect(out.search?.terms).toEqual(["t"]);
  });
  it("passes an import request through", () => {
    const r = parse({ request: { kind: "import", what: "event logs", why: "w" } });
    expect(sanitizeWatsonReply(r, qs, ps, new Set()).request).toEqual({
      kind: "import",
      what: "event logs",
      why: "w",
    });
  });
  it("drops updates with unknown questionId", () => {
    const r = parse({
      questionUpdates: [
        { questionId: "q1", status: "answered", answer: "a", pointer: "" },
        { questionId: "zz", status: "answered", answer: "a", pointer: "" },
      ],
    });
    const out = sanitizeWatsonReply(r, qs, ps, new Set());
    expect(out.questionUpdates.map((u) => u.questionId)).toEqual(["q1"]);
  });
  it("drops search with unknown pasteId and caps terms", () => {
    const terms = Array.from({ length: 12 }, () => "x".repeat(300));
    const ok = sanitizeWatsonReply(parse({ search: { pasteId: "p1", terms } }), qs, ps, new Set());
    expect(ok.search?.terms).toHaveLength(8);
    expect(ok.search?.terms[0]).toHaveLength(200);
    expect(
      sanitizeWatsonReply(parse({ search: { pasteId: "nope", terms } }), qs, ps, new Set()).search,
    ).toBeNull();
  });
  it("caps newQuestions, message, memory, query", () => {
    const r = parse({
      message: "m".repeat(WATSON_TURN_TEXT_MAX + 50),
      memory: "m".repeat(5000),
      newQuestions: Array.from({ length: 5 }, (_, i) => ({ question: `q${i}`, why: "w" })),
      request: { kind: "query", language: "vql", query: "q".repeat(30000), why: "w" },
    });
    const out = sanitizeWatsonReply(r, qs, ps, new Set());
    expect(out.message).toHaveLength(WATSON_TURN_TEXT_MAX);
    expect(out.memory).toHaveLength(4000);
    expect(out.newQuestions).toHaveLength(3);
    expect(out.request?.kind === "query" && out.request.query.length).toBe(20000);
  });
  it("normalizes request language", () => {
    const mk = (language: string) =>
      sanitizeWatsonReply(
        parse({ request: { kind: "query", language, query: "q", why: "w" } }),
        qs,
        ps,
        new Set(),
      ).request;
    expect(mk(" KQL ")).toMatchObject({ language: "kql" });
    expect(mk("Esql")).toMatchObject({ language: "esql" });
    expect(mk("powershell")).toMatchObject({ language: "other" });
  });
  it("does not mutate its input", () => {
    const r = parse({ questionUpdates: [{ questionId: "zz" }] });
    sanitizeWatsonReply(r, qs, ps, new Set());
    expect(r.questionUpdates).toHaveLength(1);
  });
});
