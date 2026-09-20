import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import type { AIProvider } from "../../src/providers/provider.js";

// The 🧠 deep-reasoning box (#1468). Only a provider that ACTS on `thinkingTokens` earns the box:
// /health has to say which, or the dashboard offers a toggle that silently does nothing on Ollama,
// OpenAI, Gemini and the rest. `deepReasoningSupported` is true when the TEXT provider (synthesis,
// else vision) or the second-opinion provider reports `supportsThinking`; `aiProvider` names the
// text provider so the disabled tooltip can say who does not support it.

function stubProvider(name: string, supportsThinking?: boolean): AIProvider {
  return {
    name,
    model: `${name}-model`,
    ...(supportsThinking === undefined ? {} : { supportsThinking }),
    analyze: async () => ({ rawText: "{}" }),
  };
}

async function healthWith(opts: {
  provider?: AIProvider;
  synthesisProvider?: AIProvider;
  secondOpinionThinking?: boolean;
}) {
  const store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-health-deep-")));
  const pipeline = opts.provider
    ? new AnalysisPipeline({
        provider: opts.provider,
        synthesisProvider: opts.synthesisProvider,
        stateStore: new StateStore(store),
        imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
      })
    : undefined;
  const res = await request(
    createApp(store, { pipeline, secondOpinionThinking: opts.secondOpinionThinking }),
  ).get("/health");
  expect(res.status).toBe(200);
  return res.body as { deepReasoningSupported: boolean; aiProvider: string | null };
}

describe("GET /health deepReasoningSupported (#1468)", () => {
  it("is true when the configured provider acts on thinkingTokens", async () => {
    const body = await healthWith({ provider: stubProvider("anthropic", true) });
    expect(body.deepReasoningSupported).toBe(true);
    expect(body.aiProvider).toBe("anthropic");
  });

  it("is false for a provider that never declared support", async () => {
    const body = await healthWith({ provider: stubProvider("ollama") });
    expect(body.deepReasoningSupported).toBe(false);
    expect(body.aiProvider).toBe("ollama");
  });

  it("reads the SYNTHESIS provider, not the vision one — deep reasoning runs on synthesis", async () => {
    const body = await healthWith({
      provider: stubProvider("openai"),
      synthesisProvider: stubProvider("openrouter", true),
    });
    expect(body.deepReasoningSupported).toBe(true);
    expect(body.aiProvider).toBe("openrouter");
  });

  it("is true when only the second-opinion model supports thinking", async () => {
    const body = await healthWith({ provider: stubProvider("ollama"), secondOpinionThinking: true });
    expect(body.deepReasoningSupported).toBe(true);
  });

  it("is false, with no provider name, when no AI is configured at all", async () => {
    const body = await healthWith({});
    expect(body.deepReasoningSupported).toBe(false);
    expect(body.aiProvider).toBeNull();
  });
});
