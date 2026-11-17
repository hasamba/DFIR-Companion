import { describe, expect, it, vi } from "vitest";
import { cachedUserContent, API_CACHE, CLI_CACHE } from "../../src/providers/cachedUserContent.js";
import { ClaudeCodeProvider } from "../../src/providers/claudeCode.js";
import { AnthropicProvider } from "../../src/providers/anthropic.js";
import type { ClaudeRunOptions, ClaudeRunResult } from "../../src/providers/claudeRunner.js";
import { fetchMock, jsonResponse } from "../helpers/fetchMock.js";

// #2658: a masked cache prefix becomes its own content block with a cache breakpoint; without one the
// prompt is one block, exactly as before.

const PREFIX = "RULE\n\n<<<TIMELINE>>>\nrows\n<<<END TIMELINE>>>\n\n";
const PROMPT = `${PREFIX}CASE CONTEXT\nquestion`;

describe("cachedUserContent (#2658)", () => {
  it("splits at the prefix and marks it", () => {
    expect(cachedUserContent(PROMPT, PREFIX, API_CACHE)).toEqual([
      { type: "text", text: PREFIX, cache_control: { type: "ephemeral" } },
      { type: "text", text: "CASE CONTEXT\nquestion" },
    ]);
  });

  it("one block when there is no prefix, a prefix the prompt does not start with, or nothing after it", () => {
    for (const prefix of [undefined, "", "OTHER", PROMPT])
      expect(cachedUserContent(PROMPT, prefix, API_CACHE)).toEqual([{ type: "text", text: PROMPT }]);
  });
});

describe("providers send the cached block (#2658)", () => {
  it("Claude Code marks the prefix block with a one-hour breakpoint", async () => {
    let captured: ClaudeRunOptions | undefined;
    const runner = vi.fn(async (o: ClaudeRunOptions): Promise<ClaudeRunResult> => {
      captured = o;
      return {
        code: 0,
        stdout: JSON.stringify({ type: "result", subtype: "success", is_error: false, result: "{}" }),
        stderr: "",
      };
    });
    await new ClaudeCodeProvider({ model: "sonnet", runner }).analyze({
      systemPrompt: "S",
      userPrompt: PROMPT,
      cachePrefix: PREFIX,
      images: [],
    });
    const content = JSON.parse(captured!.stdin.trim()).message.content;
    expect(content[0]).toEqual({ type: "text", text: PREFIX, cache_control: CLI_CACHE });
    expect(content[1]).toEqual({ type: "text", text: "CASE CONTEXT\nquestion" });
  });

  it("the Anthropic API marks the prefix block with the default breakpoint", async () => {
    const fetchFn = fetchMock(async () =>
      jsonResponse({ content: [{ type: "text", text: "{}" }], usage: { input_tokens: 1, output_tokens: 1 } }),
    );
    await new AnthropicProvider({ apiKey: "k", model: "claude-sonnet-4-6", fetchFn }).analyze({
      systemPrompt: "S",
      userPrompt: PROMPT,
      cachePrefix: PREFIX,
      images: [],
    });
    const body = JSON.parse((fetchFn.mock.calls[0][1] as RequestInit).body as string);
    expect(body.messages[0].content[0]).toEqual({
      type: "text",
      text: PREFIX,
      cache_control: { type: "ephemeral" },
    });
    expect(body.messages[0].content[1]).toEqual({ type: "text", text: "CASE CONTEXT\nquestion" });
  });
});
