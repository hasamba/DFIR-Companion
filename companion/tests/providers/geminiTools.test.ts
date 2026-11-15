import { describe, it, expect } from "vitest";
import { ProviderError } from "../../src/providers/provider.js";
import { assistantTurn, fc, gem, geminiWith, req, toolTurn, turnOf } from "./toolAdapterHelpers.js";

const FINAL = gem([{ text: '{"answer":"done"}' }]);
const SKIP = "skip_thought_signature_validator";

describe("GeminiProvider.converse — request shape", () => {
  it("declares tool support and a secret-free endpoint", () => {
    const { provider } = geminiWith([FINAL]);
    expect(provider.supportsTools).toBe(true);
    expect(provider.endpoint).toBe("https://generativelanguage.googleapis.com/v1beta");
  });

  it("functionDeclarations, NO responseMimeType when tools are sent, functionResponse turns", async () => {
    const { provider, bodies, urls } = geminiWith([FINAL]);
    await provider.converse(req({ transcript: [assistantTurn("g1"), toolTurn("g1")] }));
    const b = bodies[0];
    expect(urls[0]).toBe(
      "https://generativelanguage.googleapis.com/v1beta/models/gemini-3-pro:generateContent",
    );
    expect(b.tools[0].functionDeclarations[0]).toMatchObject({
      name: "forensic_lookup",
      description: expect.any(String),
      parameters: expect.any(Object),
    });
    expect(b.generationConfig?.responseMimeType).toBeUndefined();
    expect(b.toolConfig).toEqual({ functionCallingConfig: { mode: "AUTO" } });
    // The system prompt is folded into the first user text, as analyze does.
    expect(b.contents[0]).toEqual({
      role: "user",
      parts: [{ text: "You are Watson.\n\nWhat ran on ANON_HOST_1?" }],
    });
    expect(b.contents[1].role).toBe("model");
    expect(b.contents[1].parts[0].functionCall).toMatchObject({
      name: "forensic_lookup",
      args: { text: "x" },
    });
    expect(b.contents.at(-1).role).toBe("user");
    expect(b.contents.at(-1).parts[0].functionResponse).toMatchObject({
      name: "forensic_lookup",
      response: { output: "rows for g1" },
    });
  });

  it("toolChoice none → toolConfig.functionCallingConfig.mode NONE", async () => {
    const { provider, bodies } = geminiWith([FINAL]);
    await provider.converse(req({ toolChoice: "none" }));
    expect(bodies[0].toolConfig.functionCallingConfig.mode).toBe("NONE");
  });

  it("an error result goes back as response.error", async () => {
    const { provider, bodies } = geminiWith([FINAL]);
    const bad = {
      role: "tool" as const,
      results: [{ id: "g1", name: "forensic_lookup", content: "bad", isError: true }],
    };
    await provider.converse(req({ transcript: [assistantTurn("g1"), bad] }));
    expect(bodies[0].contents.at(-1).parts[0].functionResponse.response).toEqual({ error: "bad" });
  });
});

describe("GeminiProvider.converse — tool schema filter", () => {
  it("sends only Gemini Schema keywords, recursively; everything else is dropped", async () => {
    const parameters = {
      $schema: "http://json-schema.org/draft-07/schema#",
      type: "object",
      additionalProperties: false,
      properties: {
        text: { type: "string", minLength: 1, maxLength: 200, pattern: "^\\S", description: "d", const: "x" },
        kind: { type: "string", enum: ["a", "b"], default: "a" },
        tags: {
          type: "array",
          maxItems: 5,
          items: {
            type: "object",
            additionalProperties: false,
            properties: { n: { type: ["integer", "null"], minimum: 0 } },
          },
        },
        either: { anyOf: [{ type: "string", $ref: "#/x" }, { type: "number" }], oneOf: [{ type: "string" }] },
      },
      required: ["text"],
      $defs: { x: { type: "string" } },
    };
    const { provider, bodies } = geminiWith([FINAL]);
    await provider.converse(req({ tools: [{ name: "forensic_lookup", description: "d", parameters }] }));
    expect(bodies[0].tools[0].functionDeclarations[0].parameters).toEqual({
      type: "object",
      properties: {
        text: { type: "string", minLength: 1, maxLength: 200, pattern: "^\\S", description: "d" },
        kind: { type: "string", enum: ["a", "b"], default: "a" },
        tags: {
          type: "array",
          maxItems: 5,
          items: { type: "object", properties: { n: { type: "integer", nullable: true, minimum: 0 } } },
        },
        either: { anyOf: [{ type: "string" }, { type: "number" }] },
      },
      required: ["text"],
    });
  });
});

describe("GeminiProvider.converse — call ids", () => {
  it("vendor ids are kept and sent back as functionResponse ids; same-name parallel calls stay distinct", async () => {
    const reply = gem([fc("v-a", { text: "a" }, "SIG"), fc("v-b", { text: "b" })]);
    const { provider, bodies } = geminiWith([reply, FINAL]);
    const r1 = await provider.converse(req());
    expect(r1.calls.map((c) => c.id)).toEqual(["v-a", "v-b"]);
    // Results come back out of order; they are matched by id, never by name + order.
    await provider.converse(req({ transcript: [turnOf(r1), toolTurn("v-b", "v-a")] }));
    const fr = bodies[1].contents.at(-1).parts.map((p: { functionResponse: unknown }) => p.functionResponse);
    expect(fr).toEqual([
      { id: "v-a", name: "forensic_lookup", response: { output: "rows for v-a" } },
      { id: "v-b", name: "forensic_lookup", response: { output: "rows for v-b" } },
    ]);
  });

  it("a response without ids gets synthetic g<index> ids, which never go on the wire", async () => {
    const reply = gem([fc(undefined, { text: "a" }, "SIG"), fc(undefined, { text: "b" })]);
    const { provider, bodies } = geminiWith([reply, FINAL]);
    const r1 = await provider.converse(req());
    expect(r1.calls.map((c) => c.id)).toEqual(["g0", "g1"]);
    await provider.converse(req({ transcript: [turnOf(r1), toolTurn("g0", "g1")] }));
    expect(bodies[1].contents[1].parts).toEqual(reply.candidates[0].content.parts);
    const fr = bodies[1].contents
      .at(-1)
      .parts.map((p: { functionResponse: { id?: string } }) => p.functionResponse);
    expect(fr.map((f: { id?: string }) => f.id)).toEqual([undefined, undefined]);
    expect(fr.map((f: { response: { output: string } }) => f.response.output)).toEqual([
      "rows for g0",
      "rows for g1",
    ]);
  });

  it("adapter contract: a duplicate vendor id gets a wire-safe synthetic id (review M2); the wire keeps the vendor id", async () => {
    const reply = gem([fc("d", { text: "a" }), fc("d", { text: "b" })]);
    const { provider, bodies } = geminiWith([reply, FINAL]);
    const r1 = await provider.converse(req());
    expect(r1.calls.map((c) => c.id)).toEqual(["d", "g1"]);
    await provider.converse(req({ transcript: [turnOf(r1), toolTurn("d", "g1")] }));
    const fr = bodies[1].contents
      .at(-1)
      .parts.map((p: { functionResponse: { id?: string } }) => p.functionResponse.id);
    expect(fr).toEqual(["d", "d"]);
  });
});

describe("GeminiProvider.converse — thought signatures", () => {
  it("a thoughtSignature on a functionCall part is echoed on the same part", async () => {
    const reply = gem([fc("v1", { text: "a" }, "SIG-1")]);
    const { provider, bodies } = geminiWith([reply, FINAL]);
    const r1 = await provider.converse(req());
    await provider.converse(req({ transcript: [turnOf(r1), toolTurn("v1")] }));
    expect(bodies[1].contents[1].parts).toEqual([fc("v1", { text: "a" }, "SIG-1")]);
  });

  it("signatures on TEXT parts and several signed parts survive, in the original part order, over two continuations", async () => {
    const parts1 = [
      { text: "Let me ", thoughtSignature: "T1" },
      { text: "look." },
      fc("v1", { text: "a" }, "S1"),
      fc("v2", { text: "b" }),
    ];
    const parts2 = [{ text: "Next.", thoughtSignature: "T2" }, fc("v3", { text: "c" }, "S2")];
    const { provider, bodies } = geminiWith([gem(parts1), gem(parts2), FINAL]);
    const r1 = await provider.converse(req());
    expect(r1.text).toBe("Let me look.");
    const t1 = [turnOf(r1), toolTurn("v1", "v2")];
    const r2 = await provider.converse(req({ transcript: t1 }));
    await provider.converse(req({ transcript: [...t1, turnOf(r2), toolTurn("v3")] }));
    expect(bodies[2].contents[1].parts).toEqual(parts1);
    expect(bodies[2].contents[3].parts).toEqual(parts2);
  });

  it("re-masked args never carry the real signature: the documented skip signature replaces it", async () => {
    const reply = gem([{ text: "Look.", thoughtSignature: "T1" }, fc("v1", { text: "a" }, "S1")]);
    const { provider, bodies } = geminiWith([reply, FINAL]);
    const r1 = await provider.converse(req());
    const masked = [{ id: "v1", name: "forensic_lookup", input: { text: "ANON_HOST_9" } }];
    await provider.converse(
      req({ transcript: [turnOf(r1, { text: "Look again.", calls: masked }), toolTurn("v1")] }),
    );
    expect(bodies[1].contents[1].parts).toEqual([
      { text: "Look again." },
      {
        functionCall: { id: "v1", name: "forensic_lookup", args: { text: "ANON_HOST_9" } },
        thoughtSignature: SKIP,
      },
    ]);
  });

  it("a turn with no opaque value (or from another model) puts the skip signature on its first call", async () => {
    const { provider, bodies } = geminiWith([FINAL]);
    await provider.converse(req({ transcript: [assistantTurn("g1"), toolTurn("g1")] }));
    expect(bodies[0].contents[1].parts[0].thoughtSignature).toBe(SKIP);
  });

  it("our own call ids never go on the wire: a plain turn sends no functionCall or functionResponse id", async () => {
    const { provider, bodies } = geminiWith([FINAL]);
    await provider.converse(req({ transcript: [assistantTurn("g0"), toolTurn("g0")] }));
    expect(bodies[0].contents[1].parts[0].functionCall.id).toBeUndefined();
    expect(bodies[0].contents[2].parts[0].functionResponse.id).toBeUndefined();
  });

  it("thought-summary parts are kept out of text and returned as opaqueText", async () => {
    const reply = gem([{ text: "I will search.", thought: true }, { text: '{"answer":"ok"}' }]);
    const { provider } = geminiWith([reply]);
    const r = await provider.converse(req());
    expect(r.text).toBe('{"answer":"ok"}');
    expect(r.opaqueText).toEqual(["I will search."]);
    expect(r.usage).toEqual({ inputTokens: 10, outputTokens: 5 });
  });
});

describe("GeminiProvider.converse — stops", () => {
  it("safety, max tokens, malformed call and an empty reply are errors", async () => {
    for (const [reply, kind] of [
      [gem([], "SAFETY"), "safety_stop"],
      [{ promptFeedback: { blockReason: "SAFETY" } }, "safety_stop"],
      [gem([fc("v1", { te: 1 })], "MAX_TOKENS"), "output_limit"],
      [gem([], "MALFORMED_FUNCTION_CALL"), "other"],
      [gem([], "STOP"), "other"],
    ] as const) {
      const { provider } = geminiWith([reply]);
      const err = await provider.converse(req()).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(ProviderError);
      expect((err as ProviderError).kind).toBe(kind);
    }
  });
});
