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

  it("builds the codex exec invocation with the prompt as one arg", async () => {
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
    // prompt is the final argument and combines system + user
    expect(a[a.length - 1]).toBe("SYS\n\nUSER");
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
