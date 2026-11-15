import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { AiControlStore } from "../../../src/analysis/aiControl.js";
import { AiCostStore } from "../../../src/analysis/aiCost.js";
import { WatsonChatStore } from "../../../src/analysis/ai/watson/chatStore.js";
import { AnalysisPipeline } from "../../../src/analysis/pipeline.js";
import { StateLock } from "../../../src/analysis/stateLock.js";
import { StateStore } from "../../../src/analysis/stateStore.js";
import { emptyState } from "../../../src/analysis/stateTypes.js";
import type { AIProvider, AnalyzeRequest, AnalyzeResult } from "../../../src/providers/provider.js";
import { createApp } from "../../../src/server.js";
import { CaseStore } from "../../../src/storage/caseStore.js";

// U2: Watson may run on another provider than synthesis. Its AI preview and its cost bucket must then
// name the Watson provider and model, never the synthesis ones.

const CASE = "c1";
const REPLY = JSON.stringify({
  message: "ok",
  workingOn: "",
  learned: "",
  questionUpdates: [],
  newQuestions: [],
  request: null,
  search: null,
  memory: "m",
});

class Fake implements AIProvider {
  readonly sent: AnalyzeRequest[] = [];
  constructor(
    readonly name: string,
    readonly model: string,
  ) {}
  async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
    this.sent.push(req);
    return { rawText: REPLY, usage: { costUSD: 0.01, inputTokens: 5, outputTokens: 2 } };
  }
}

async function harness(withSynthesis = true, withWatson = true) {
  const root = await mkdtemp(join(tmpdir(), "dfir-watson-provider-"));
  const store = new CaseStore(root);
  await store.createCase({ caseId: CASE, name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(store);
  await stateStore.save(emptyState(CASE));
  await new AiControlStore(store).save(CASE, { enabled: true, lastAnalyzedSeq: 0 });
  const synth = new Fake("claude-code", "opus");
  const watson = new Fake("anthropic", "claude-sonnet-5");
  const aiCostStore = new AiCostStore(store);
  const pipeline = new AnalysisPipeline({
    ...(withSynthesis ? { provider: synth, synthesisProvider: synth } : {}),
    stateStore,
    stateLock: new StateLock(),
    aiCostStore,
    retries: 0,
    imageLoader: async () => ({ base64: "", mimeType: "image/webp" }),
  });
  const app = createApp(store, {
    stateStore,
    pipeline,
    watsonChatStore: new WatsonChatStore(store),
    ...(withWatson ? { watsonProvider: () => watson } : {}),
  });
  return { app, synth, watson, aiCostStore };
}

describe("Watson on its own provider", () => {
  it("Watson's preview capture and cost bucket name the Watson provider, not the synthesis one", async () => {
    const h = await harness();
    const preview = await request(h.app)
      .post(`/cases/${CASE}/ai-preview`)
      .send({ action: "watson", params: { text: "what ran?" } });
    expect(preview.status).toBe(200);
    expect([preview.body.call.provider, preview.body.call.model]).toEqual(["anthropic", "claude-sonnet-5"]);

    const real = await request(h.app).post(`/cases/${CASE}/watson/message`).send({ text: "what ran?" });
    expect(real.status).toBe(200);
    expect(h.watson.sent).toHaveLength(1);
    expect(h.synth.sent).toHaveLength(0);
    const cost = await h.aiCostStore.load(CASE);
    expect(Object.keys(cost.watson.byModel)).toEqual(["anthropic/claude-sonnet-5"]);
    expect(cost.synthesis.totalCalls).toBe(0);
  });
});

describe("Watson preview when only Watson has a provider", () => {
  it("answers 200 and captures the Watson request, not 501", async () => {
    const h = await harness(false);
    const preview = await request(h.app)
      .post(`/cases/${CASE}/ai-preview`)
      .send({ action: "watson", params: { text: "what ran?" } });
    expect(preview.status).toBe(200);
    expect(preview.body.call.provider).toBe("anthropic");
  });

  it("still answers 501 when neither has a provider", async () => {
    const h = await harness(false, false);
    const res = await request(h.app)
      .post(`/cases/${CASE}/ai-preview`)
      .send({ action: "watson", params: { text: "x" } });
    expect(res.status).toBe(501);
  });
});
