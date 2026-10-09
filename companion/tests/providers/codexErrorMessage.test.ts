import { describe, it, expect, vi } from "vitest";
import { CodexProvider } from "../../src/providers/codex.js";
import type { CodexRunResult } from "../../src/providers/codexRunner.js";
import { ProviderError } from "../../src/providers/provider.js";
import { withRetry } from "../../src/analysis/ai/retry.js";

// #2042: the real events codex-cli 0.154.0 printed for a model the ChatGPT account cannot use.
// Two warning-only `error` items come first; the API's 400 arrives last as a JSON string.
const UNSUPPORTED_MODEL_STDOUT = [
  '{"type":"thread.started","thread_id":"t"}',
  '{"type":"item.completed","item":{"id":"item_0","type":"error","message":"Configured service tier `priority` is not advertised as supported for model `gpt-6-sol` and will be omitted from requests."}}',
  '{"type":"item.completed","item":{"id":"item_1","type":"error","message":"Model metadata for `gpt-6-sol` not found. Defaulting to fallback metadata; this can degrade performance and cause issues."}}',
  '{"type":"turn.started"}',
  '{"type":"error","message":"{\\"type\\":\\"error\\",\\"status\\":400,\\"error\\":{\\"type\\":\\"invalid_request_error\\",\\"message\\":\\"The \'gpt-6-sol\' model is not supported when using Codex with a ChatGPT account.\\"}}"}',
  '{"type":"turn.failed","error":{"message":"{\\"type\\":\\"error\\",\\"status\\":400,\\"error\\":{\\"type\\":\\"invalid_request_error\\",\\"message\\":\\"The \'gpt-6-sol\' model is not supported when using Codex with a ChatGPT account.\\"}}"}}',
].join("\n");

const runWith = (stdout: string, code = 1) =>
  vi.fn(async (): Promise<CodexRunResult> => ({ code, stdout, stderr: "Reading prompt from stdin...\n" }));

const analyze = (stdout: string, code?: number) =>
  new CodexProvider({ model: "gpt-6-sol", runner: runWith(stdout, code) }).analyze({
    systemPrompt: "s",
    userPrompt: "u",
    images: [],
  });

async function caught(p: Promise<unknown>): Promise<ProviderError> {
  try {
    await p;
  } catch (e) {
    if (e instanceof ProviderError) return e;
    throw e;
  }
  throw new Error("expected a ProviderError");
}

describe("Codex error message (#2042)", () => {
  it("leads with the API's own message, unwrapped from its JSON envelope", async () => {
    const err = await caught(analyze(UNSUPPORTED_MODEL_STDOUT));
    expect(err.message).toMatch(
      /^Codex: 400 invalid_request_error — The 'gpt-6-sol' model is not supported when using Codex with a ChatGPT account\./,
    );
  });

  it("drops the service-tier and model-metadata warnings", async () => {
    const err = await caught(analyze(UNSUPPORTED_MODEL_STDOUT));
    expect(err.message).not.toMatch(/service tier/i);
    expect(err.message).not.toMatch(/fallback metadata/i);
  });

  it("names the setting to change for an unsupported model", async () => {
    const err = await caught(analyze(UNSUPPORTED_MODEL_STDOUT));
    expect(err.message).toMatch(/Settings/);
  });

  it("classifies an unsupported model as a model error that is not retried", async () => {
    const err = await caught(analyze(UNSUPPORTED_MODEL_STDOUT));
    expect(err.kind).toBe("model");
    const fn = vi.fn(async () => {
      throw err;
    });
    await expect(withRetry(fn, 3, 0)).rejects.toBe(err);
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it("still shows a warning when it is the only error Codex reported", async () => {
    const onlyWarning = UNSUPPORTED_MODEL_STDOUT.split("\n").slice(0, 3).join("\n");
    const err = await caught(analyze(onlyWarning));
    expect(err.message).toMatch(/service tier/);
  });

  it("keeps a plain-text error message as it is", async () => {
    const stdout = '{"type":"error","message":"stream error: connection reset"}';
    const err = await caught(analyze(stdout));
    expect(err.message).toBe("Codex: stream error: connection reset");
  });
});

// #2051: kind "model" stops every retry and blames the model setting, so it needs the API's own
// 4xx refusal, not just a sentence that mentions a model and "not found".
const envelope = (status: number, type: string, message: string) =>
  JSON.stringify({
    type: "error",
    message: JSON.stringify({ type: "error", status, error: { type, message } }),
  });

describe("Codex model-error classification (#2051)", () => {
  it("does not treat a reworded model-metadata warning as a model error", async () => {
    const stdout = '{"type":"error","message":"model metadata not found for gpt-5.1"}';
    const err = await caught(analyze(stdout));
    expect(err.kind).not.toBe("model");
    expect(err.message).not.toMatch(/Settings/);
  });

  it("retries a server error that mentions a model and 'not found'", async () => {
    const stdout = envelope(500, "server_error", "The model produced invalid output, request id not found.");
    const err = await caught(analyze(stdout));
    expect(err.kind).not.toBe("model");
    expect(err.message).not.toMatch(/Settings/);
    const fn = vi.fn(async () => {
      throw err;
    });
    await expect(withRetry(fn, 3, 0)).rejects.toBe(err);
    expect(fn.mock.calls.length).toBeGreaterThan(1);
  });

  it("still classifies a 404 'model does not exist' refusal as a model error", async () => {
    const stdout = envelope(404, "invalid_request_error", "The model `gpt-9` does not exist.");
    const err = await caught(analyze(stdout));
    expect(err.kind).toBe("model");
    expect(err.message).toMatch(/Settings/);
  });
});
