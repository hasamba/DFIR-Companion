import { describe, it, expect } from "vitest";
import { deltaSchema } from "../../src/analysis/responseSchema.js";
import {
  fillOptionalSynthesisFields,
  synthesisRetryNote,
} from "../../src/analysis/ai/synthesisAnswerRepair.js";
import { AiAnswerParseError } from "../../src/analysis/ai/providerCall.js";

function zodErrorFor(value: unknown): unknown {
  const r = deltaSchema.safeParse(value);
  if (r.success) throw new Error("expected a schema failure");
  return r.error;
}

describe("fillOptionalSynthesisFields (#1602)", () => {
  it("fills the four lists and timelineNote when they are missing, and names each one", () => {
    const input = { findings: [], summary: "s" };
    const { value, filled } = fillOptionalSynthesisFields(input);
    expect(value).toEqual({
      findings: [],
      summary: "s",
      iocs: [],
      mitreTechniques: [],
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: "",
    });
    expect(filled).toEqual(["iocs", "mitreTechniques", "threadsOpened", "threadsClosed", "timelineNote"]);
    expect(input).toEqual({ findings: [], summary: "s" }); // not mutated
    expect(deltaSchema.safeParse(value).success).toBe(true);
  });

  it("fills a field the model set to null", () => {
    const { value, filled } = fillOptionalSynthesisFields({
      findings: [],
      summary: "s",
      iocs: null,
      mitreTechniques: [],
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: "t",
    });
    expect(filled).toEqual(["iocs"]);
    expect((value as { iocs: unknown }).iocs).toEqual([]);
  });

  it("never fills findings or summary, and leaves a wrong non-null type alone", () => {
    const { value, filled } = fillOptionalSynthesisFields({ iocs: "x" });
    expect(filled).not.toContain("findings");
    expect(filled).not.toContain("summary");
    expect(filled).not.toContain("iocs");
    expect((value as { iocs: unknown }).iocs).toBe("x");
    expect(deltaSchema.safeParse(value).success).toBe(false);
  });

  it("passes a non-object answer through untouched", () => {
    expect(fillOptionalSynthesisFields([1])).toEqual({ value: [1], filled: [] });
    expect(fillOptionalSynthesisFields("x")).toEqual({ value: "x", filled: [] });
  });
});

describe("synthesisRetryNote (#1602)", () => {
  it("names every omitted top-level field", () => {
    const note = synthesisRetryNote(zodErrorFor({ findings: [] }));
    expect(note).toContain("Your previous answer omitted: ");
    expect(note).toContain("summary");
    expect(note).toContain("iocs");
    expect(note).toContain("timelineNote");
    expect(note).toContain("Return the complete JSON object with every field.");
  });

  it("names invalid field paths, deduplicated and capped at ten", () => {
    const badFindings = Array.from({ length: 12 }, () => ({ id: "" }));
    const note = synthesisRetryNote(
      zodErrorFor({
        findings: badFindings,
        summary: "s",
        iocs: [],
        mitreTechniques: [],
        threadsOpened: [],
        threadsClosed: [],
        timelineNote: "",
      }),
    );
    expect(note).toContain("had invalid fields: ");
    const list = note!.split("had invalid fields: ")[1].split(". Return")[0];
    const paths = list.split(", ");
    expect(paths.length).toBeLessThanOrEqual(10);
    expect(new Set(paths).size).toBe(paths.length);
  });

  it("names the root when the answer is not an object", () => {
    expect(synthesisRetryNote(zodErrorFor([1]))).toContain("<root>");
  });

  it("says the answer was not valid JSON after a parse failure", () => {
    const note = synthesisRetryNote(new AiAnswerParseError("{oops", new SyntaxError("bad")));
    expect(note).toContain("was not valid JSON");
  });

  it("returns undefined for any other error, so the caller keeps its current note", () => {
    expect(synthesisRetryNote(new Error("socket hang up"))).toBeUndefined();
  });
});

describe("AiAnswerParseError", () => {
  it("keeps the raw text and the original error as its cause", () => {
    const cause = new SyntaxError("Expected property name");
    const err = new AiAnswerParseError("{x", cause);
    expect(err.rawText).toBe("{x");
    expect(err.cause).toBe(cause);
    expect(err.message).toBe("Expected property name");
    expect(err).toBeInstanceOf(Error);
  });
});
