import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ActivityLogStore } from "../../src/analysis/activityLog.js";
import { CustomEntitiesStore } from "../../src/analysis/anonEntities.js";
import { AnonControlStore } from "../../src/analysis/anonControl.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import { AiControlStore } from "../../src/analysis/aiControl.js";
import { AiCostStore } from "../../src/analysis/aiCost.js";
import { StateLock } from "../../src/analysis/stateLock.js";
import { WatsonChatStore } from "../../src/analysis/ai/watson/chatStore.js";
import { resolveRequestPolicy } from "../../src/auth/policy.js";
import { createApp } from "../../src/server.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import type { AIProvider, AnalyzeRequest, AnalyzeResult } from "../../src/providers/provider.js";

// #2491 — POST /cases/:id/ai-preview: the first request an action would send, clear and masked,
// with nothing sent, nothing spent and nothing recorded.

const HOST = "ACME-FS02";

class Recording implements AIProvider {
  readonly name = "rec";
  readonly model = "m";
  readonly sent: AnalyzeRequest[] = [];
  async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
    this.sent.push(req);
    return { rawText: "{}" };
  }
}

async function harness(withProvider = true) {
  const root = await mkdtemp(join(tmpdir(), "dfir-ai-preview-route-"));
  const store = new CaseStore(root);
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(store);
  const state = emptyState("c1");
  state.forensicTimeline = [
    {
      id: "e1",
      timestamp: "2026-01-01T00:00:00Z",
      description: `whoami on ${HOST}`,
      severity: "High",
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
      asset: HOST,
    },
  ];
  await stateStore.save(state);
  const customEntitiesStore = new CustomEntitiesStore(store);
  await customEntitiesStore.save("c1", [{ value: HOST, category: "HOST" }]);
  const provider = new Recording();
  const pipeline = new AnalysisPipeline({
    provider: withProvider ? provider : undefined,
    synthesisProvider: withProvider ? provider : undefined,
    stateStore,
    stateLock: new StateLock(),
    aiCostStore: new AiCostStore(store),
    anonStore: new AnonControlStore(store),
    customEntitiesStore,
    retries: 0,
    imageLoader: async () => ({ base64: "", mimeType: "image/webp" }),
  });
  const activityLogStore = new ActivityLogStore(store);
  const aiControlStore = new AiControlStore(store);
  await aiControlStore.save("c1", { enabled: true, lastAnalyzedSeq: 0 });
  const app = createApp(store, {
    stateStore,
    pipeline,
    activityLogStore,
    watsonChatStore: new WatsonChatStore(store),
    watsonProvider: () => (withProvider ? provider : undefined),
  });
  return { app, provider, activityLogStore };
}

describe("POST /cases/:id/ai-preview", () => {
  it("returns the first request, clear and masked, and sends nothing", async () => {
    const { app, provider, activityLogStore } = await harness();
    const res = await request(app)
      .post("/cases/c1/ai-preview")
      .send({ action: "watson", params: { text: `what ran on ${HOST}?` } });
    expect(res.status).toBe(200);
    expect(res.headers["cache-control"]).toBe("no-store");
    expect(res.body).toMatchObject({ action: "watson", outcome: "captured" });
    expect(res.body.call.kind).toBe("watson");
    expect(res.body.call.clearPrompt).toContain(HOST);
    expect(res.body.call.maskedPrompt).not.toContain(HOST);
    expect(typeof res.body.call.systemPrompt).toBe("string");
    expect(provider.sent).toHaveLength(0);
    expect(await activityLogStore.load("c1")).toEqual([]); // no activity entry, no clear text kept
  });

  it("names the multi-request limit for an action that asks more than once", async () => {
    const { app } = await harness();
    const res = await request(app).post("/cases/c1/ai-preview").send({ action: "deep-pass" });
    expect(res.status).toBe(200);
    expect(res.body.multiRequest).toMatch(/first batch/);
  });

  it("400 for an unknown action or a missing parameter; 404 for an unknown case", async () => {
    const { app } = await harness();
    expect((await request(app).post("/cases/c1/ai-preview").send({ action: "nope" })).status).toBe(400);
    expect((await request(app).post("/cases/c1/ai-preview").send({ action: "__proto__" })).status).toBe(400);
    const missing = await request(app).post("/cases/c1/ai-preview").send({ action: "explain-event" });
    expect(missing.status).toBe(400);
    expect(missing.body.error).toMatch(/eventId/);
    const noDraft = await request(app).post("/cases/c1/ai-preview").send({ action: "watson", params: {} });
    expect(noDraft.status).toBe(400);
    expect(noDraft.body.error).toMatch(/text is required/);
    expect(
      (
        await request(app)
          .post("/cases/zz/ai-preview")
          .send({ action: "watson", params: { text: "q" } })
      ).status,
    ).toBe(404);
  });

  it("501 without an AI provider", async () => {
    const { app } = await harness(false);
    expect((await request(app).post("/cases/c1/ai-preview").send({ action: "synthesis" })).status).toBe(501);
  });

  it("needs the same team permission as running the action (case write)", () => {
    expect(resolveRequestPolicy("POST", "/cases/c1/ai-preview")).toEqual(
      resolveRequestPolicy("POST", "/cases/c1/synthesize"),
    );
    expect(resolveRequestPolicy("POST", "/cases/c1/ai-preview")).toMatchObject({ permission: "write" });
  });
});
