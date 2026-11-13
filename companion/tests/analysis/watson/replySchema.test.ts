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

describe("sanitizeWatsonReply", () => {
  it("drops updates with unknown questionId", () => {
    const r = parse({
      questionUpdates: [
        { questionId: "q1", status: "answered", answer: "a", pointer: "" },
        { questionId: "zz", status: "answered", answer: "a", pointer: "" },
      ],
    });
    const out = sanitizeWatsonReply(r, qs, ps);
    expect(out.questionUpdates.map((u) => u.questionId)).toEqual(["q1"]);
  });
  it("drops search with unknown pasteId and caps terms", () => {
    const terms = Array.from({ length: 12 }, () => "x".repeat(300));
    const ok = sanitizeWatsonReply(parse({ search: { pasteId: "p1", terms } }), qs, ps);
    expect(ok.search?.terms).toHaveLength(8);
    expect(ok.search?.terms[0]).toHaveLength(200);
    expect(sanitizeWatsonReply(parse({ search: { pasteId: "nope", terms } }), qs, ps).search).toBeNull();
  });
  it("caps newQuestions, message, memory, query", () => {
    const r = parse({
      message: "m".repeat(WATSON_TURN_TEXT_MAX + 50),
      memory: "m".repeat(5000),
      newQuestions: Array.from({ length: 5 }, (_, i) => ({ question: `q${i}`, why: "w" })),
      request: { kind: "query", language: "vql", query: "q".repeat(30000), why: "w" },
    });
    const out = sanitizeWatsonReply(r, qs, ps);
    expect(out.message).toHaveLength(WATSON_TURN_TEXT_MAX);
    expect(out.memory).toHaveLength(4000);
    expect(out.newQuestions).toHaveLength(3);
    expect(out.request?.kind === "query" && out.request.query.length).toBe(20000);
  });
  it("normalizes request language", () => {
    const mk = (language: string) =>
      sanitizeWatsonReply(parse({ request: { kind: "query", language, query: "q", why: "w" } }), qs, ps)
        .request;
    expect(mk(" KQL ")).toMatchObject({ language: "kql" });
    expect(mk("Esql")).toMatchObject({ language: "esql" });
    expect(mk("powershell")).toMatchObject({ language: "other" });
  });
  it("does not mutate its input", () => {
    const r = parse({ questionUpdates: [{ questionId: "zz" }] });
    sanitizeWatsonReply(r, qs, ps);
    expect(r.questionUpdates).toHaveLength(1);
  });
});
