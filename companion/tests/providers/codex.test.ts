import { describe, it, expect, vi } from "vitest";
import { CodexProvider } from "../../src/providers/codex.js";
import type { CodexRunOptions, CodexRunResult } from "../../src/providers/codexRunner.js";
import { ProviderError } from "../../src/providers/provider.js";

function fakeRunner(result: Partial<CodexRunResult>, capture?: (o: CodexRunOptions) => void) {
  return vi.fn(async (opts: CodexRunOptions): Promise<CodexRunResult> => {
    capture?.(opts);
    return { code: 0, stdout: "", stderr: "", ...result };
  });
}

describe("CodexProvider", () => {
  it("rejects vision requests — codex is text-only", async () => {
    const runner = fakeRunner({ stdout: "" });
    const p = new CodexProvider({ model: "gpt-5-codex", runner });
    await expect(
      p.analyze({ systemPrompt: "s", userPrompt: "u", images: [{ base64: "AAA", mimeType: "image/png" }] }),
    ).rejects.toMatchObject({ kind: "other" });
    await expect(
      p.analyze({ systemPrompt: "s", userPrompt: "u", images: [{ base64: "AAA", mimeType: "image/png" }] }),
    ).rejects.toThrow(/text-only|screenshots/i);
    expect(runner).not.toHaveBeenCalled();
  });

  it("builds the codex exec invocation with the prompt sent over stdin", async () => {
    let captured: CodexRunOptions | undefined;
    const runner = fakeRunner({ stdout: JSON.stringify({ type: "agent_message", text: "ok" }) }, (o) => { captured = o; });
    const p = new CodexProvider({ model: "gpt-5-codex", runner });
    const out = await p.analyze({ systemPrompt: "SYS", userPrompt: "USER", images: [] });
    expect(out.rawText).toBe("ok");
    expect(p.name).toBe("codex");
    const a = captured!.args;
    expect(a[0]).toBe("exec");
    expect(a).toEqual(expect.arrayContaining(["--json", "--skip-git-repo-check", "--sandbox", "read-only"]));
    expect(a).toEqual(expect.arrayContaining(["-m", "gpt-5-codex"]));
    // no PROMPT argument — it's sent over stdin (Windows argv length limit; see codexRunner.ts)
    expect(a).not.toContain("SYS\n\nUSER");
    expect(captured!.stdin).toBe("SYS\n\nUSER");
  });

  it("omits -m when the model is empty", async () => {
    let captured: CodexRunOptions | undefined;
    const runner = fakeRunner({ stdout: JSON.stringify({ type: "agent_message", text: "x" }) }, (o) => { captured = o; });
    await new CodexProvider({ model: "", runner }).analyze({ systemPrompt: "s", userPrompt: "u", images: [] });
    expect(captured!.args).not.toContain("-m");
  });

  it("parses the final message and token usage from NDJSON events", async () => {
    const stdout = [
      JSON.stringify({ type: "task_started" }),
      JSON.stringify({ type: "agent_message", text: "not final" }),
      JSON.stringify({ type: "agent_message", text: "the answer" }),
      JSON.stringify({ type: "token_count", usage: { input_tokens: 12, output_tokens: 7 } }),
    ].join("\n");
    const out = await new CodexProvider({ model: "m", runner: fakeRunner({ stdout }) })
      .analyze({ systemPrompt: "s", userPrompt: "u", images: [] });
    expect(out.rawText).toBe("the answer");
    expect(out.usage).toEqual({ inputTokens: 12, outputTokens: 7 });
  });

  // Captured verbatim from a real `codex exec --json` run (codex-cli 0.39.0). Every event is
  // wrapped in an { id, msg } envelope — the shape the original parser missed, which made a
  // SUCCESSFUL run surface as "synthesis failed" with stderr noise as the message.
  it("parses the real codex-cli 0.39 envelope: msg.message + msg.info.total_token_usage", async () => {
    const stdout = [
      '{"provider":"openai","workdir":"C:\\\\tmp","approval":"never","model":"gpt-5-codex","sandbox":"read-only"}',
      '{"prompt":"Reply with exactly: PONG"}',
      '{"id":"0","msg":{"type":"task_started","model_context_window":null}}',
      '{"id":"0","msg":{"type":"agent_message","message":"PONG"}}',
      '{"id":"0","msg":{"type":"token_count","info":{"total_token_usage":{"input_tokens":6717,"cached_input_tokens":0,"output_tokens":4,"total_tokens":6721}}}}',
    ].join("\n");
    const out = await new CodexProvider({ model: "m", runner: fakeRunner({ stdout, stderr: "Reading prompt from stdin...\n" }) })
      .analyze({ systemPrompt: "s", userPrompt: "u", images: [] });
    expect(out.rawText).toBe("PONG");
    expect(out.usage).toEqual({ inputTokens: 6717, outputTokens: 4 });
  });

  // codex logs MCP-client startup failures as `error` events on runs that otherwise SUCCEED.
  it("ignores error events when a real answer is present", async () => {
    const stdout = [
      '{"id":"","msg":{"type":"error","message":"MCP client for `n8n` failed to start: program not found"}}',
      '{"id":"0","msg":{"type":"agent_message","message":"the answer"}}',
    ].join("\n");
    const out = await new CodexProvider({ model: "m", runner: fakeRunner({ stdout }) })
      .analyze({ systemPrompt: "s", userPrompt: "u", images: [] });
    expect(out.rawText).toBe("the answer");
  });

  // stderr is non-empty on EVERY successful run ("Reading prompt from stdin..."), so it must not
  // be treated as a failure signal on its own — and when there IS no answer, codex's own error
  // events are the useful message, not the stderr noise.
  it("surfaces codex error events, not stderr noise, when no answer came back", async () => {
    const stdout = '{"id":"0","msg":{"type":"error","message":"stream error: connection refused"}}';
    const runner = fakeRunner({ code: 0, stdout, stderr: "Reading prompt from stdin...\nERROR MCP client blah\n" });
    await expect(
      new CodexProvider({ model: "m", runner }).analyze({ systemPrompt: "s", userPrompt: "u", images: [] }),
    ).rejects.toThrow(/stream error: connection refused/);
  });

  // Regression: captured verbatim from a real failing run (exit code 0, no agent_message, only
  // `stream_error` events). `stream_error` carries a human-readable `message`, so a parser that
  // only skips type === "error" returns the ERROR TEXT as the synthesis result — a hard failure
  // reported as a confident finding. Must reject instead.
  it("never returns a stream_error as the answer (exit 0, retries exhausted)", async () => {
    const stdout = [
      '{"id":"0","msg":{"type":"task_started","model_context_window":null}}',
      '{"id":"0","msg":{"type":"stream_error","message":"stream error: unexpected status 404 Not Found: {\\"error\\":{\\"message\\":\\"model \'gpt-5-codex\' not found\\"}}; retrying 5/5 in 3.263s…"}}',
    ].join("\n");
    const runner = fakeRunner({ code: 0, stdout, stderr: "Reading prompt from stdin...\n" });
    const call = new CodexProvider({ model: "m", runner }).analyze({ systemPrompt: "s", userPrompt: "u", images: [] });
    await expect(call).rejects.toBeInstanceOf(ProviderError);
    await expect(call).rejects.toThrow(/model 'gpt-5-codex' not found/);
  });

  // The real cause must lead the message: MCP-client startup failures come from the user's own
  // ~/.codex/config.toml, are emitted even on successful runs, and would otherwise push the
  // actionable error past the 300-char truncation in the dashboard.
  it("leads with the real error, not MCP-client startup noise", async () => {
    const stdout = [
      '{"id":"","msg":{"type":"error","message":"MCP client for `n8n` failed to start: program not found"}}',
      '{"id":"","msg":{"type":"error","message":"MCP client for `playwright` failed to start: program not found"}}',
      '{"id":"0","msg":{"type":"stream_error","message":"stream error: unexpected status 404 Not Found: model \'gpt-5\' not found"}}',
    ].join("\n");
    const runner = fakeRunner({ code: 0, stdout, stderr: "Reading prompt from stdin...\n" });
    await expect(
      new CodexProvider({ model: "m", runner }).analyze({ systemPrompt: "s", userPrompt: "u", images: [] }),
    ).rejects.toThrow(/^Codex: stream error: unexpected status 404/);
  });

  it("does not fail a successful run just because stderr has content", async () => {
    const stdout = '{"id":"0","msg":{"type":"agent_message","message":"fine"}}';
    const out = await new CodexProvider({ model: "m", runner: fakeRunner({ code: 0, stdout, stderr: "Reading prompt from stdin...\n" }) })
      .analyze({ systemPrompt: "s", userPrompt: "u", images: [] });
    expect(out.rawText).toBe("fine");
  });

  it("falls back to raw stdout when there is no JSON message event", async () => {
    const out = await new CodexProvider({ model: "m", runner: fakeRunner({ stdout: "plain text answer\n" }) })
      .analyze({ systemPrompt: "s", userPrompt: "u", images: [] });
    expect(out.rawText).toBe("plain text answer");
  });

  it("throws an actionable error when the CLI binary is missing", async () => {
    const runner = fakeRunner({ code: null, spawnError: Object.assign(new Error("nope"), { code: "ENOENT" }) });
    await expect(
      new CodexProvider({ model: "m", runner }).analyze({ systemPrompt: "s", userPrompt: "u", images: [] }),
    ).rejects.toThrow(/codex login|@openai\/codex|not found/i);
  });

  it("maps an auth failure (stderr) to an auth error", async () => {
    const runner = fakeRunner({ code: 1, stdout: "", stderr: "Error: not logged in. Run codex login." });
    await expect(
      new CodexProvider({ model: "m", runner }).analyze({ systemPrompt: "s", userPrompt: "u", images: [] }),
    ).rejects.toMatchObject({ kind: "auth" });
  });

  it("maps a timeout to a timeout error", async () => {
    const runner = fakeRunner({ code: null, timedOut: true });
    await expect(
      new CodexProvider({ model: "m", timeoutMs: 5, runner }).analyze({ systemPrompt: "s", userPrompt: "u", images: [] }),
    ).rejects.toMatchObject({ kind: "timeout" });
  });

  it("errors when there is no content at all", async () => {
    const runner = fakeRunner({ code: 1, stdout: "", stderr: "" });
    await expect(
      new CodexProvider({ model: "m", runner }).analyze({ systemPrompt: "s", userPrompt: "u", images: [] }),
    ).rejects.toBeInstanceOf(ProviderError);
  });
});
