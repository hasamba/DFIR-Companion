import { describe, expect, it } from "vitest";
import { writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fetchMock, jsonResponse } from "../helpers/fetchMock.js";
import { listProviderModels } from "../../src/providers/modelCatalog.js";
import type { CodexRunner } from "../../src/providers/codexRunner.js";

describe("AI provider model catalog", () => {
  it("lists and sorts OpenAI-compatible model IDs without exposing non-generation models", async () => {
    const fetchFn = fetchMock(async () =>
      jsonResponse({
        data: [
          { id: "gpt-4o-mini" },
          { id: "text-embedding-3-small" },
          { id: "gpt-4o" },
          { id: "gpt-4o" },
          { id: 42 },
        ],
      }),
    );

    const result = await listProviderModels({
      provider: "openai",
      apiKey: "secret",
      fetchFn,
    });

    expect(result.models).toEqual(["gpt-4o", "gpt-4o-mini"]);
    expect(fetchFn.mock.calls[0][0]).toBe("https://api.openai.com/v1/models");
    expect((fetchFn.mock.calls[0][1]?.headers as Record<string, string>).authorization).toBe("Bearer secret");
  });

  it("uses OpenRouter capability metadata to keep image-capable models in the vision picker", async () => {
    const fetchFn = fetchMock(async () =>
      jsonResponse({
        data: [
          { id: "vendor/text-only", architecture: { input_modalities: ["text"] } },
          { id: "vendor/vision", architecture: { input_modalities: ["text", "image"] } },
          { id: "vendor/legacy-without-metadata" },
        ],
      }),
    );

    const result = await listProviderModels({
      provider: "openrouter",
      apiKey: "secret",
      role: "vision",
      fetchFn,
    });

    expect(result.models).toEqual(["vendor/legacy-without-metadata", "vendor/vision"]);
  });

  it("lists only Gemini models that support generateContent and keeps the usable model ID", async () => {
    const fetchFn = fetchMock(async () =>
      jsonResponse({
        models: [
          { name: "models/gemini-2.5-flash", supportedGenerationMethods: ["generateContent"] },
          { name: "models/gemini-embedding-001", supportedGenerationMethods: ["embedContent"] },
        ],
      }),
    );

    const result = await listProviderModels({
      provider: "gemini",
      apiKey: "google-secret",
      fetchFn,
    });

    expect(result.models).toEqual(["gemini-2.5-flash"]);
    expect(fetchFn.mock.calls[0][0]).toBe(
      "https://generativelanguage.googleapis.com/v1beta/models?pageSize=1000",
    );
    const headers = fetchFn.mock.calls[0][1]?.headers as Record<string, string>;
    expect(headers["x-goog-api-key"]).toBe("google-secret");
    expect(fetchFn.mock.calls[0][0]).not.toContain("google-secret");
  });

  it("uses Anthropic's model endpoint and required headers", async () => {
    const fetchFn = fetchMock(async () =>
      jsonResponse({ data: [{ id: "claude-haiku-4-5-20251001" }, { id: "claude-sonnet-4-6" }] }),
    );

    const result = await listProviderModels({
      provider: "anthropic",
      apiKey: "anthropic-secret",
      fetchFn,
    });

    expect(result.models).toEqual(["claude-haiku-4-5-20251001", "claude-sonnet-4-6"]);
    expect(fetchFn.mock.calls[0][0]).toBe("https://api.anthropic.com/v1/models?limit=1000");
    expect(fetchFn.mock.calls[0][1]?.headers).toMatchObject({
      "x-api-key": "anthropic-secret",
      "anthropic-version": "2023-06-01",
    });
  });

  it("offers stable aliases for Claude Code and preserves manual entry", async () => {
    const fetchFn = fetchMock(async () => jsonResponse({}));

    const result = await listProviderModels({ provider: "claude-code", fetchFn });

    expect(result.models).toEqual(["haiku", "opus", "sonnet"]);
    expect(result.manualEntry).toBe(true);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it("asks the installed Codex CLI for the models available to its account", async () => {
    let invocation: { args: string[]; stdin: string } | undefined;
    const codexRunner: CodexRunner = async (opts) => {
      invocation = { args: opts.args, stdin: opts.stdin };
      return {
        code: 0,
        stderr: "",
        stdout: [
          JSON.stringify({ id: "initialize", result: { userAgent: "codex-cli" } }),
          JSON.stringify({
            id: "models",
            result: {
              data: [
                { id: "gpt-5.6-luna", model: "gpt-5.6-luna" },
                { id: "gpt-5.6-sol", model: "gpt-5.6-sol" },
              ],
              nextCursor: null,
            },
          }),
        ].join("\n"),
      };
    };

    const result = await listProviderModels({ provider: "codex", codexRunner });

    expect(result.models).toEqual(["gpt-5.6-luna", "gpt-5.6-sol"]);
    expect(result.note).toContain("Codex CLI");
    expect(invocation?.args).toEqual(["app-server", "--stdio"]);
    expect(invocation?.stdin).toContain('"method":"initialize"');
    expect(invocation?.stdin).toContain('"method":"initialized"');
    expect(invocation?.stdin).toContain('"method":"model/list"');
  });

  it("uses the installed Codex model cache and hides models excluded from its picker", async () => {
    const cachePath = join(tmpdir(), `dfir-codex-model-cache-${process.pid}-${Date.now()}.json`);
    await writeFile(
      cachePath,
      JSON.stringify({
        models: [
          { slug: "gpt-5.6-sol", visibility: "list" },
          { slug: "gpt-5.6-luna", visibility: "list" },
          { slug: "codex-auto-review", visibility: "hide" },
        ],
      }),
      "utf8",
    );
    let runnerCalled = false;
    const codexRunner: CodexRunner = async () => {
      runnerCalled = true;
      return { code: 0, stdout: "", stderr: "" };
    };

    const result = await listProviderModels({ provider: "codex", codexCachePath: cachePath, codexRunner });

    expect(result.models).toEqual(["gpt-5.6-luna", "gpt-5.6-sol"]);
    expect(runnerCalled).toBe(false);
  });

  it("rejects unsafe custom base URLs before making a request", async () => {
    const fetchFn = fetchMock(async () => jsonResponse({ data: [] }));

    await expect(
      listProviderModels({
        provider: "openai",
        baseUrl: "http://models.example.com/v1",
        fetchFn,
      }),
    ).rejects.toThrow("cleartext");
    expect(fetchFn).not.toHaveBeenCalled();
  });
});
