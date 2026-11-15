import { describe, it, expect } from "vitest";
import { jsonResponse } from "../helpers/fetchMock.js";
import { ProviderError } from "../../src/providers/provider.js";
import { isToolsRejection, ToolsUnsupportedError } from "../../src/providers/toolCalling.js";
import { isRetryableError } from "../../src/analysis/ai/retry.js";
import {
  anthropicWith,
  assistantTurn,
  redacted,
  req,
  response,
  text,
  thinking,
  toolTurn,
  toolUse,
  toolUseResponse,
  turnOf,
} from "./anthropicToolsHelpers.js";

describe("AnthropicProvider.converse — request shape", () => {
  it("declares tool support and its endpoint", () => {
    const { provider } = anthropicWith([]);
    expect(provider.supportsTools).toBe(true);
    expect(provider.endpoint).toBe("https://api.anthropic.com/v1");
  });

  it("sends tools, tool_choice and the transcript as Messages API blocks", async () => {
    const { provider, bodies } = anthropicWith([toolUseResponse("tu1", "forensic_lookup", { text: "x" })]);
    await provider.converse(req({ transcript: [assistantTurn, toolTurn("tu0")], toolChoice: "auto" }));
    const b = bodies[0];
    expect(b.tools[0]).toEqual({
      name: "forensic_lookup",
      description: expect.any(String),
      input_schema: expect.any(Object),
    });
    expect(b.tool_choice).toEqual({ type: "auto" });
    expect(b.messages.map((m: { role: string }) => m.role)).toEqual(["user", "assistant", "user"]);
    expect(b.messages[0].content).toEqual([{ type: "text", text: "What ran on ANON_HOST_1?" }]);
    expect(b.messages[1].content).toEqual([text("Looking."), toolUse("tu0", { text: "a" })]);
    expect(b.messages[2].content[0]).toMatchObject({ type: "tool_result", tool_use_id: "tu0" });
    expect(b.system[0].cache_control).toEqual({ type: "ephemeral" });
  });

  it("uses the same max_tokens and thinking rules as analyze", async () => {
    const current = anthropicWith([response([text("{}")], "end_turn")]);
    await current.provider.converse(req());
    expect(current.bodies[0].max_tokens).toBe(16000 + 16000);
    expect(current.bodies[0].thinking).toBeUndefined();
    const legacy = anthropicWith([response([text("{}")], "end_turn")], "claude-haiku-4-5-20251001");
    await legacy.provider.converse(req());
    expect(legacy.bodies[0].max_tokens).toBe(16000);
  });

  it("maps toolChoice none to {type:'none'} and keeps the tools array identical", async () => {
    const { provider, bodies } = anthropicWith([
      toolUseResponse("tu1", "forensic_lookup", { text: "x" }),
      response([text('{"answer":"done"}')], "end_turn"),
    ]);
    const r1 = await provider.converse(req());
    await provider.converse(req({ transcript: [turnOf(r1), toolTurn("tu1")], toolChoice: "none" }));
    expect(bodies[1].tool_choice).toEqual({ type: "none" });
    expect(bodies[1].tools).toEqual(bodies[0].tools);
    expect(bodies[1].system).toEqual(bodies[0].system);
  });

  it("an isError result is sent as tool_result is_error: true; a good result has no is_error", async () => {
    const { provider, bodies } = anthropicWith([response([text("{}")], "end_turn")]);
    const tool = {
      role: "tool" as const,
      results: [
        { id: "tu0", name: "forensic_lookup", content: "bad input", isError: true },
        { id: "tu9", name: "forensic_lookup", content: "ok" },
      ],
    };
    const two = {
      ...assistantTurn,
      calls: [...assistantTurn.calls, { id: "tu9", name: "forensic_lookup", input: {} }],
    };
    await provider.converse(req({ transcript: [two, tool] }));
    expect(bodies[0].messages[2].content).toEqual([
      { type: "tool_result", tool_use_id: "tu0", content: "bad input", is_error: true },
      { type: "tool_result", tool_use_id: "tu9", content: "ok" },
    ]);
  });
});

describe("AnthropicProvider.converse — reply parsing", () => {
  it("returns tool calls and keeps thinking blocks as opaque, echoed unchanged next time", async () => {
    const content = [
      thinking("s1"),
      text("Checking two hosts."),
      thinking("s2", "Next I search the first host."),
      toolUse("tuA", { text: "ANON_HOST_1" }),
      text("And the second."),
      redacted("enc"),
      toolUse("tuB", { text: "ANON_HOST_2" }),
    ];
    const { provider, bodies } = anthropicWith([response(content), response([text("{}")], "end_turn")]);
    const r1 = await provider.converse(req());
    expect(r1.calls).toEqual([
      { id: "tuA", name: "forensic_lookup", input: { text: "ANON_HOST_1" } },
      { id: "tuB", name: "forensic_lookup", input: { text: "ANON_HOST_2" } },
    ]);
    expect(r1.text).toBe("Checking two hosts.\n\nAnd the second.");
    expect(r1.opaque).toBeDefined();
    expect(r1.usage).toMatchObject({ inputTokens: 10, outputTokens: 5, cacheReadTokens: 3 });
    await provider.converse(req({ transcript: [turnOf(r1), toolTurn("tuA", "tuB")] }));
    expect(bodies[1].messages[1].content).toEqual(content);
  });

  it("thinking text is returned in opaqueText; redacted_thinking and empty thinking are not", async () => {
    const { provider } = anthropicWith([
      response([thinking("s1", "I look at ANON_HOST_1."), thinking("s2"), redacted("enc"), toolUse("t", {})]),
    ]);
    const r = await provider.converse(req());
    expect(r.opaqueText).toEqual(["I look at ANON_HOST_1."]);
  });

  it("a missing or duplicate tool_use id is made present and unique, and the echo uses the same ids", async () => {
    const { provider, bodies } = anthropicWith([
      response([
        thinking("s1"),
        toolUse("dup", { a: 1 }),
        toolUse("dup", { a: 2 }),
        { type: "tool_use", name: "forensic_lookup", input: {} },
      ]),
      response([text("{}")], "end_turn"),
    ]);
    const r1 = await provider.converse(req());
    const ids = r1.calls.map((c) => c.id);
    expect(ids.every((id) => typeof id === "string" && id.length > 0)).toBe(true);
    expect(new Set(ids).size).toBe(3);
    await provider.converse(req({ transcript: [turnOf(r1), toolTurn(...ids)] }));
    const echoed = bodies[1].messages[1].content.filter((b: { type: string }) => b.type === "tool_use");
    expect(echoed.map((b: { id: string }) => b.id)).toEqual(ids);
    expect(bodies[1].messages[1].content[0]).toEqual(thinking("s1"));
  });

  it("returns final text with no calls and no opaque on stop_reason end_turn", async () => {
    const { provider } = anthropicWith([response([text('{"answer":"x"}')], "end_turn")]);
    const r = await provider.converse(req());
    expect(r).toMatchObject({ text: '{"answer":"x"}', calls: [] });
    expect(r.opaque).toBeUndefined();
  });

  it("refusal and max_tokens raise the same errors analyze raises", async () => {
    const refusal = anthropicWith([
      { content: [], stop_reason: "refusal", stop_details: { category: "cyber" } },
    ]);
    await expect(refusal.provider.converse(req())).rejects.toMatchObject({ kind: "safety_stop" });
    const cut = anthropicWith([{ content: [text("{")], stop_reason: "max_tokens" }]);
    await expect(cut.provider.converse(req())).rejects.toMatchObject({ kind: "output_limit" });
  });
});

describe("tool rejection", () => {
  it("isToolsRejection: true for 404 'No endpoints found that support tool use' and 400 'does not support tools'; false for a context-length 400", () => {
    expect(isToolsRejection(404, '{"error":{"message":"No endpoints found that support tool use."}}')).toBe(
      true,
    );
    expect(isToolsRejection(400, '{"error":"model llama3 does not support tools"}')).toBe(true);
    expect(isToolsRejection(400, "prompt is too long: maximum context length is 200000 tokens")).toBe(false);
    expect(isToolsRejection(401, "does not support tools")).toBe(false);
  });

  it("a tool rejection becomes ToolsUnsupportedError, kind other, never retried", async () => {
    const { provider } = anthropicWith([jsonResponse({ error: "this model does not support tools" }, 400)]);
    const err = await provider.converse(req()).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ToolsUnsupportedError);
    expect(err).toBeInstanceOf(ProviderError);
    expect((err as ProviderError).kind).toBe("other");
    expect(isRetryableError(err)).toBe(false);
  });

  it("analyze keeps its plain HTTP error for the same body", async () => {
    const { provider } = anthropicWith([jsonResponse({ error: "this model does not support tools" }, 400)]);
    const err = await provider
      .analyze({ systemPrompt: "s", userPrompt: "u", images: [] })
      .catch((e: unknown) => e);
    expect(err).not.toBeInstanceOf(ToolsUnsupportedError);
  });
});
