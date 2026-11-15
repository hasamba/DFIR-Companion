import { describe, it, expect } from "vitest";
import { httpErrorKind, ProviderError } from "../../src/providers/provider.js";
import { ToolsUnsupportedError } from "../../src/providers/toolCalling.js";
import { LiteLlmProvider } from "../../src/providers/litellm.js";
import { assistantTurn, chat, openAiWith, req, toolTurn, turnOf, wireCall } from "./toolAdapterHelpers.js";

const FINAL = chat({ content: '{"answer":"done"}' }, "stop");

describe("OpenAIProvider.converse — request shape", () => {
  it("declares tool support and a secret-free endpoint", () => {
    const { provider } = openAiWith("openai", [FINAL], { baseUrl: "https://user:pw@gw.example.com/v1?x=1" });
    expect(provider.supportsTools).toBe(true);
    expect(provider.endpoint).toBe("https://gw.example.com/v1");
  });

  it("sends function tools, keeps response_format json_object, maps tool turns to role 'tool'", async () => {
    const { provider, bodies } = openAiWith("openai", [FINAL]);
    await provider.converse(req({ transcript: [assistantTurn("c1"), toolTurn("c1")] }));
    const b = bodies[0];
    expect(b.tools[0]).toMatchObject({
      type: "function",
      function: { name: "forensic_lookup", parameters: expect.any(Object) },
    });
    expect(b.response_format).toEqual({ type: "json_object" });
    expect(b.tool_choice).toBe("auto");
    expect(b.messages[0]).toEqual({ role: "system", content: "You are Watson." });
    expect(b.messages[1]).toEqual({ role: "user", content: "What ran on ANON_HOST_1?" });
    expect(b.messages.at(-2)).toMatchObject({
      role: "assistant",
      tool_calls: [{ id: "c1", type: "function" }],
    });
    expect(JSON.parse(b.messages.at(-2).tool_calls[0].function.arguments)).toEqual({ text: "x" });
    expect(b.messages.at(-1)).toEqual({ role: "tool", tool_call_id: "c1", content: "rows for c1" });
  });

  it("toolChoice none → tool_choice 'none', tools still sent", async () => {
    const { provider, bodies } = openAiWith("openai", [FINAL]);
    await provider.converse(req({ toolChoice: "none" }));
    expect(bodies[0].tool_choice).toBe("none");
    expect(bodies[0].tools).toHaveLength(1);
  });

  it("ollama keeps its reasoning_effort hook; openrouter asks for usage cost", async () => {
    const o = openAiWith("ollama", [FINAL]);
    await o.provider.converse(req());
    expect(o.bodies[0].reasoning_effort).toBe("low");
    const r = openAiWith("openrouter", [FINAL]);
    await r.provider.converse(req());
    expect(r.bodies[0].usage).toEqual({ include: true });
  });

  it("the context guard counts the transcript, not only the prompts", async () => {
    const big = {
      role: "tool" as const,
      results: [{ id: "c1", name: "forensic_lookup", content: "x".repeat(60_000) }],
    };
    const { provider } = openAiWith("openai", [FINAL], { contextTokens: 12_000 });
    const err = await provider
      .converse(req({ transcript: [assistantTurn("c1"), big] }))
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ProviderError);
    expect((err as ProviderError).kind).toBe("context");
  });
});

describe("OpenAIProvider.converse — reply parsing", () => {
  it("parses tool_calls (arguments JSON string) into ToolCall input; bad JSON → input {}", async () => {
    const reply = chat({ tool_calls: [wireCall("c1", '{"text":"a"}'), wireCall("c2", "{not json")] });
    const { provider } = openAiWith("openai", [reply]);
    const r = await provider.converse(req());
    expect(r.calls).toEqual([
      { id: "c1", name: "forensic_lookup", input: { text: "a" } },
      { id: "c2", name: "forensic_lookup", input: {} },
    ]);
    expect(r.text).toBe("");
    expect(r.usage).toEqual({ inputTokens: 10, outputTokens: 5 });
  });

  it("a final answer returns text and no calls", async () => {
    const { provider } = openAiWith("openai", [FINAL]);
    const r = await provider.converse(req());
    expect(r).toMatchObject({ text: '{"answer":"done"}', calls: [] });
  });

  it("adapter contract: a missing call id is synthesized, a duplicate id gets a wire-safe synthetic id (review M2)", async () => {
    const reply = chat({
      tool_calls: [wireCall(undefined, "{}"), wireCall("d", "{}"), wireCall("d", "{}"), wireCall("", "{}")],
    });
    const { provider } = openAiWith("openai", [reply]);
    const ids = (await provider.converse(req())).calls.map((c) => c.id);
    expect(ids[1]).toBe("d");
    expect(ids[2]).toBe("call_dfir_2");
    expect(ids[0]).toBeTruthy();
    expect(ids[3]).toBeTruthy();
    expect(new Set(ids).size).toBe(4);
  });

  it("content_filter is a safety stop; length is an output-limit error; empty is no content", async () => {
    for (const [reply, kind] of [
      [chat({ content: "" }, "content_filter"), "safety_stop"],
      [chat({ tool_calls: [wireCall("c1", '{"te')] }, "length"), "output_limit"],
      [chat({ content: "" }, "stop"), "other"],
    ] as const) {
      const { provider } = openAiWith("openai", [reply]);
      const err = await provider.converse(req()).catch((e: unknown) => e);
      expect((err as ProviderError).kind).toBe(kind);
    }
  });
});

type OpenAiKind = "openai" | "openrouter" | "ollama";

describe("OpenRouter reasoning_details", () => {
  const details = [
    {
      type: "reasoning.text",
      text: "I should search ANON_HOST_1.",
      signature: "sig-1",
      format: "anthropic-claude-v1",
      index: 0,
    },
    { type: "reasoning.summary", summary: "Searching first.", format: "openai-responses-v1", index: 1 },
    { type: "reasoning.encrypted", data: "ENCRYPTED==", format: "openai-responses-v1", index: 2 },
  ];
  const reply = chat({ reasoning_details: details, tool_calls: [wireCall("c1", '{"text": "a"}')] });

  it("rides in opaque and is echoed unmodified, with the original argument string", async () => {
    const { provider, bodies } = openAiWith("openrouter", [reply, FINAL]);
    const r1 = await provider.converse(req());
    await provider.converse(req({ transcript: [turnOf(r1), toolTurn("c1")] }));
    const assistant = bodies[1].messages[2];
    expect(assistant.reasoning_details).toEqual(details);
    expect(assistant.tool_calls[0].function.arguments).toBe('{"text": "a"}');
  });

  it("readable text/summary is returned in opaqueText; encrypted entries are not", async () => {
    const { provider } = openAiWith("openrouter", [reply]);
    const r = await provider.converse(req());
    expect(r.opaqueText).toEqual(["I should search ANON_HOST_1.", "Searching first."]);
  });

  it("a changed (re-masked) call or another model drops reasoning_details", async () => {
    const { provider, bodies } = openAiWith("openrouter", [reply, FINAL, FINAL]);
    const r1 = await provider.converse(req());
    const masked = [{ id: "c1", name: "forensic_lookup", input: { text: "ANON_HOST_2" } }];
    await provider.converse(req({ transcript: [turnOf(r1, { calls: masked }), toolTurn("c1")] }));
    expect(bodies[1].messages[2].reasoning_details).toBeUndefined();
    expect(JSON.parse(bodies[1].messages[2].tool_calls[0].function.arguments)).toEqual({
      text: "ANON_HOST_2",
    });
    const other = openAiWith("openrouter", [FINAL], { model: "m-2" });
    await other.provider.converse(req({ transcript: [turnOf(r1), toolTurn("c1")] }));
    expect(other.bodies[0].messages[2].reasoning_details).toBeUndefined();
  });

  it("unreadable arguments never echo raw next to reasoning_details", async () => {
    const bad = chat({ reasoning_details: details, tool_calls: [wireCall("c1", "{not json")] });
    const { provider } = openAiWith("openrouter", [bad]);
    expect((await provider.converse(req())).opaque).toBeUndefined();
  });

  it("an empty reasoning_details array still exposes a plain reasoning string", async () => {
    const r1 = chat({ reasoning_details: [], reasoning: "Thinking.", content: '{"a":1}' }, "stop");
    const { provider } = openAiWith("ollama", [r1]);
    expect((await provider.converse(req())).opaqueText).toEqual(["Thinking."]);
  });

  it("another provider's opaque value is ignored", async () => {
    const { provider, bodies } = openAiWith("openai", [FINAL]);
    const turn = { ...assistantTurn("c1"), opaque: { p: "anthropic", v: 1, blocks: [] } };
    await provider.converse(req({ transcript: [turn, toolTurn("c1")] }));
    expect(bodies[0].messages[2].reasoning_details).toBeUndefined();
  });
});

describe("tool rejection → ToolsUnsupportedError (recorded shapes)", () => {
  it("openrouter: 404 'No endpoints found that support tool use' → ToolsUnsupportedError", async () => {
    const body = {
      error: {
        message:
          "No endpoints found that support tool use. To learn more about provider routing, visit: https://openrouter.ai/docs/provider-routing",
        code: 404,
      },
    };
    const { provider } = openAiWith("openrouter", [new Response(JSON.stringify(body), { status: 404 })]);
    await expect(provider.converse(req())).rejects.toBeInstanceOf(ToolsUnsupportedError);
  });

  it("ollama: 400 'does not support tools' → ToolsUnsupportedError", async () => {
    const body = {
      error: {
        message: "registry.ollama.ai/library/gemma2:latest does not support tools",
        type: "invalid_request_error",
        param: null,
        code: null,
      },
    };
    const { provider } = openAiWith("ollama", [new Response(JSON.stringify(body), { status: 400 })]);
    await expect(provider.converse(req())).rejects.toBeInstanceOf(ToolsUnsupportedError);
  });

  it("auth, context-length, unknown-model and 'does not support thinking' keep their existing kinds", async () => {
    const cases: [OpenAiKind, number, unknown, string][] = [
      ["openrouter", 401, { error: { message: "No auth credentials found", code: 401 } }, "auth"],
      [
        "openrouter",
        400,
        { error: { message: "This endpoint's maximum context length is 8192 tokens.", code: 400 } },
        "other",
      ],
      [
        "openrouter",
        404,
        { error: { message: "No endpoints found for the requested model.", code: 404 } },
        "other",
      ],
      [
        "ollama",
        404,
        { error: { message: 'model "nope" not found, try pulling it first', type: "not_found_error" } },
        "other",
      ],
      [
        "ollama",
        400,
        { error: { message: '"qwen" does not support thinking', type: "invalid_request_error" } },
        "other",
      ],
    ];
    for (const [kind, status, body, expected] of cases) {
      const { provider } = openAiWith(kind, [new Response(JSON.stringify(body), { status })]);
      const err = await provider.converse(req()).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(ProviderError);
      expect(err).not.toBeInstanceOf(ToolsUnsupportedError);
      expect((err as ProviderError).kind).toBe(expected);
      expect((err as ProviderError).kind).toBe(httpErrorKind(status));
    }
  });

  it("analyze never raises ToolsUnsupportedError", async () => {
    const body = { error: { message: "does not support tools" } };
    const { provider } = openAiWith("ollama", [new Response(JSON.stringify(body), { status: 400 })]);
    const err = await provider
      .analyze({ systemPrompt: "s", userPrompt: "u", images: [] })
      .catch((e: unknown) => e);
    expect(err).not.toBeInstanceOf(ToolsUnsupportedError);
  });
});

describe("LiteLLM", () => {
  it("supportsTools is false (stays on the one-step lookup)", () => {
    expect(new LiteLlmProvider({ apiKey: "k", model: "m" }).supportsTools).toBe(false);
  });
});
