import { describe, it, expect, vi } from "vitest";
import { ClaudeCodeProvider } from "../../src/providers/claudeCode.js";
import type { ClaudeRunOptions, ClaudeRunResult } from "../../src/providers/claudeRunner.js";

// Build a fake runner that captures the invocation and returns canned stdout lines.
function fakeRunner(result: Partial<ClaudeRunResult>, capture?: (o: ClaudeRunOptions) => void) {
  return vi.fn(async (opts: ClaudeRunOptions): Promise<ClaudeRunResult> => {
    capture?.(opts);
    return { code: 0, stdout: "", stderr: "", ...result };
  });
}

const resultLine = (obj: Record<string, unknown>) => JSON.stringify({ type: "result", subtype: "success", is_error: false, ...obj });

describe("ClaudeCodeProvider", () => {
  it("builds the isolated stream-json invocation and encodes text + image blocks", async () => {
    let captured: ClaudeRunOptions | undefined;
    const runner = fakeRunner({ stdout: resultLine({ result: '{"summary":"ok"}' }) }, (o) => { captured = o; });
    const p = new ClaudeCodeProvider({ model: "haiku", runner });
    const out = await p.analyze({
      systemPrompt: "SYS",
      userPrompt: "USER",
      images: [{ base64: "AAA", mimeType: "image/webp" }],
    });
    expect(out.rawText).toBe('{"summary":"ok"}');
    expect(p.name).toBe("claude-code");
    // args
    const a = captured!.args;
    expect(a).toContain("-p");
    expect(a).toEqual(expect.arrayContaining(["--input-format", "stream-json", "--output-format", "stream-json", "--verbose"]));
    expect(a).toEqual(expect.arrayContaining(["--model", "haiku"]));
    expect(a).toEqual(expect.arrayContaining(["--system-prompt", "SYS"]));
    expect(a).toEqual(expect.arrayContaining(["--strict-mcp-config", "--setting-sources", "", "--allowed-tools", ""]));
    // stdin message
    const msg = JSON.parse(captured!.stdin.trim());
    expect(msg.type).toBe("user");
    expect(msg.message.content[0]).toEqual({ type: "text", text: "USER" });
    expect(msg.message.content[1]).toEqual({ type: "image", source: { type: "base64", media_type: "image/webp", data: "AAA" } });
  });

  it("omits --model when the model is empty", async () => {
    let captured: ClaudeRunOptions | undefined;
    const runner = fakeRunner({ stdout: resultLine({ result: "x" }) }, (o) => { captured = o; });
    await new ClaudeCodeProvider({ model: "", runner }).analyze({ systemPrompt: "s", userPrompt: "u", images: [] });
    expect(captured!.args).not.toContain("--model");
  });

  it("maps usage and total_cost_usd from the result event", async () => {
    const runner = fakeRunner({ stdout: resultLine({
      result: "hi",
      total_cost_usd: 0.042,
      usage: { input_tokens: 10, output_tokens: 20, cache_creation_input_tokens: 30, cache_read_input_tokens: 40 },
    }) });
    const out = await new ClaudeCodeProvider({ model: "haiku", runner }).analyze({ systemPrompt: "s", userPrompt: "u", images: [] });
    expect(out.usage).toEqual({ inputTokens: 10, outputTokens: 20, cacheCreationTokens: 30, cacheReadTokens: 40, costUSD: 0.042 });
  });

  it("resolves the model that actually produced the output, not just the first modelUsage key", async () => {
    // Captured live: a --model claude-sonnet-5 call reports modelUsage for BOTH the primary
    // generation AND a small internal Haiku sub-call, with claude-haiku-4-5-20251001 listed FIRST
    // despite claude-sonnet-5 being the one that wrote the actual response (5 output tokens vs 13
    // — small counts either way, but the ordering is what previously fooled Object.keys()[0]).
    const runner = fakeRunner({ stdout: resultLine({
      result: "hi",
      modelUsage: {
        "claude-haiku-4-5-20251001": { inputTokens: 343, outputTokens: 13, cacheReadInputTokens: 0, cacheCreationInputTokens: 0 },
        "claude-sonnet-5": { inputTokens: 2, outputTokens: 30874, cacheReadInputTokens: 12635, cacheCreationInputTokens: 7154 },
      },
    }) });
    const out = await new ClaudeCodeProvider({ model: "claude-sonnet-5", runner }).analyze({ systemPrompt: "s", userPrompt: "u", images: [] });
    expect(out.usage?.resolvedModel).toBe("claude-sonnet-5");
  });

  it("throws an actionable error when the CLI binary is missing", async () => {
    const runner = fakeRunner({ code: null, spawnError: Object.assign(new Error("nope"), { code: "ENOENT" }) });
    const p = new ClaudeCodeProvider({ model: "haiku", runner });
    await expect(p.analyze({ systemPrompt: "s", userPrompt: "u", images: [] })).rejects.toThrow(/not found.*claude auth login/i);
  });

  it("maps a rejected rate_limit_event to a rate_limit error", async () => {
    const stdout = [
      JSON.stringify({ type: "rate_limit_event", rate_limit_info: { status: "rejected" } }),
      resultLine({ is_error: true, subtype: "error", result: "usage limit reached" }),
    ].join("\n");
    const runner = fakeRunner({ stdout });
    const p = new ClaudeCodeProvider({ model: "haiku", runner });
    await expect(p.analyze({ systemPrompt: "s", userPrompt: "u", images: [] }))
      .rejects.toMatchObject({ kind: "rate_limit" });
  });

  it("maps a timeout to a timeout error", async () => {
    const runner = fakeRunner({ code: null, timedOut: true });
    const p = new ClaudeCodeProvider({ model: "haiku", timeoutMs: 5, runner });
    await expect(p.analyze({ systemPrompt: "s", userPrompt: "u", images: [] }))
      .rejects.toMatchObject({ kind: "timeout" });
  });

  it("errors as transport when no result event is produced", async () => {
    const runner = fakeRunner({ code: 1, stdout: "", stderr: "boom" });
    const p = new ClaudeCodeProvider({ model: "haiku", runner });
    await expect(p.analyze({ systemPrompt: "s", userPrompt: "u", images: [] }))
      .rejects.toMatchObject({ kind: "transport" });
    await expect(p.analyze({ systemPrompt: "s", userPrompt: "u", images: [] }))
      .rejects.toThrow("boom");
  });
});
