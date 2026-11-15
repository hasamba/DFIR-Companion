// Guards around the Anthropic tool turn: repaired ids, model changes, foreign opaque values, a safe
// endpoint, and the thinking-block rejection a loop must not resend.
import { describe, it, expect } from "vitest";
import { jsonResponse } from "../helpers/fetchMock.js";
import { AnthropicProvider } from "../../src/providers/anthropic.js";
import { ProviderError } from "../../src/providers/provider.js";
import {
  isThinkingRejection,
  ThinkingBindingError,
  ToolsUnsupportedError,
  type ToolTurn,
} from "../../src/providers/toolCalling.js";
import { isRetryableError } from "../../src/analysis/ai/retry.js";
import {
  anthropicWith,
  req,
  response,
  text,
  thinking,
  toolTurn,
  toolUse,
  turnOf,
} from "./anthropicToolsHelpers.js";

const FINAL = response([text("{}")], "end_turn");

describe("Anthropic tool turn guards", () => {
  it("I1: thinking after a repaired tool_use id is never stored or echoed; thinking before it is", async () => {
    const content = [
      thinking("s1", "first"),
      toolUse("dup", { a: 1 }),
      toolUse("dup", { a: 2 }),
      thinking("s2", "after the repair"),
      toolUse("tuC", { a: 3 }),
    ];
    const { provider, bodies } = anthropicWith([response(content), FINAL]);
    const r1 = await provider.converse(req());
    expect(r1.opaqueText).toEqual(["first"]);
    await provider.converse(req({ transcript: [turnOf(r1), toolTurn(...r1.calls.map((c) => c.id))] }));
    const sent = bodies[1].messages[1].content;
    expect(sent[0]).toEqual(thinking("s1", "first"));
    expect(JSON.stringify(sent)).not.toContain("s2");
    expect(sent.filter((b: { type: string }) => b.type === "tool_use")).toHaveLength(3);
  });

  it("I1: thinking after a malformed (filtered) block is dropped", async () => {
    const content = [thinking("s1"), { nope: true }, thinking("s2"), toolUse("tuA", {})];
    const { provider, bodies } = anthropicWith([response(content), FINAL]);
    const r1 = await provider.converse(req());
    await provider.converse(req({ transcript: [turnOf(r1), toolTurn("tuA")] }));
    expect(bodies[1].messages[1].content).toEqual([thinking("s1"), toolUse("tuA", {})]);
  });

  it("M1: a transcript carried to another model drops the old model's thinking", async () => {
    const a = anthropicWith([response([thinking("s1"), toolUse("tuA", {})])], "claude-opus-5-5");
    const r1 = await a.provider.converse(req());
    const b = anthropicWith([FINAL], "claude-sonnet-5-5");
    await b.provider.converse(req({ transcript: [turnOf(r1), toolTurn("tuA")] }));
    expect(b.bodies[0].messages[1].content).toEqual([toolUse("tuA", {})]);
    const same = anthropicWith([FINAL], "claude-opus-5-5");
    await same.provider.converse(req({ transcript: [turnOf(r1), toolTurn("tuA")] }));
    expect(same.bodies[0].messages[1].content).toEqual([thinking("s1"), toolUse("tuA", {})]);
  });

  it("M2: an opaque value from another provider is ignored: only text and tool calls go", async () => {
    const { provider, bodies } = anthropicWith([FINAL]);
    const foreign: ToolTurn = {
      role: "assistant",
      text: "Looking.",
      calls: [{ id: "c1", name: "forensic_lookup", input: {} }],
      opaque: { v: 1, prefixHash: "x", blocks: [{ type: "function_call", id: "c1" }, thinking("s9")] },
    };
    await provider.converse(req({ transcript: [foreign, toolTurn("c1")] }));
    expect(bodies[0].messages[1].content).toEqual([text("Looking."), toolUse("c1", {})]);
  });

  it("M3: endpoint never carries credentials, a query string or a fragment", () => {
    const p = new AnthropicProvider({
      apiKey: "k",
      model: "m",
      baseUrl: "https://user:secret@proxy.example/v1?key=abc#x", // trufflehog:ignore
    });
    expect(p.endpoint).toBe("https://proxy.example/v1");
    expect(new AnthropicProvider({ apiKey: "k", model: "m" }).endpoint).toBe("https://api.anthropic.com/v1");
  });
});

// Recorded shapes of Anthropic 400 bodies (from the vendor docs and API error format). No network.
const FINAL_TURN_400 = JSON.stringify({
  type: "error",
  error: {
    type: "invalid_request_error",
    message:
      "messages.1.content.0.type: Expected `thinking` or `redacted_thinking`, but found `text`. When `thinking` is enabled, a final `assistant` message must start with a thinking block (preceeding the lastmost set of `tool_use` and `tool_result` blocks).",
  },
});
const BOUND_400 = JSON.stringify({
  type: "error",
  error: {
    type: "invalid_request_error",
    message:
      "messages.5.content.0: Invalid `signature` in `thinking` block. The block is bound to a different conversation.",
  },
});
const MODIFIED_400 = JSON.stringify({
  type: "error",
  error: {
    type: "invalid_request_error",
    message:
      "messages.3.content.1: `thinking` or `redacted_thinking` blocks in the latest assistant message cannot be modified.",
  },
});

describe("V1: thinking-block rejection", () => {
  it("isThinkingRejection matches the recorded thinking 400s and nothing else", () => {
    for (const body of [FINAL_TURN_400, BOUND_400, MODIFIED_400])
      expect(isThinkingRejection(400, body)).toBe(true);
    expect(isThinkingRejection(500, BOUND_400)).toBe(false);
    expect(isThinkingRejection(400, "prompt is too long: maximum context length is 200000 tokens")).toBe(
      false,
    );
    expect(
      isThinkingRejection(
        400,
        '{"error":{"message":"max_tokens: must be greater than thinking.budget_tokens"}}',
      ),
    ).toBe(false);
  });

  it("converse raises ThinkingBindingError, kind other, never retried", async () => {
    const { provider, fetchFn } = anthropicWith([new Response(FINAL_TURN_400, { status: 400 })]);
    const err = await provider.converse(req()).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ThinkingBindingError);
    expect(err).toBeInstanceOf(ProviderError);
    expect(err).not.toBeInstanceOf(ToolsUnsupportedError);
    expect((err as ProviderError).kind).toBe("other");
    expect(isRetryableError(err)).toBe(false);
    expect(fetchFn).toHaveBeenCalledTimes(1);
  });

  it("analyze keeps its plain HTTP error for the same body", async () => {
    const { provider } = anthropicWith([jsonResponse(JSON.parse(BOUND_400), 400)]);
    const err = await provider
      .analyze({ systemPrompt: "s", userPrompt: "u", images: [] })
      .catch((e: unknown) => e);
    expect(err).not.toBeInstanceOf(ThinkingBindingError);
  });
});
