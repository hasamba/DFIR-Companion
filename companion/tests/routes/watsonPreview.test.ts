import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { AiControlStore } from "../../src/analysis/aiControl.js";
import { AiCostStore } from "../../src/analysis/aiCost.js";
import { CustomEntitiesStore } from "../../src/analysis/anonEntities.js";
import { AnonControlStore } from "../../src/analysis/anonControl.js";
import { WatsonChatStore } from "../../src/analysis/ai/watson/chatStore.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { StateLock } from "../../src/analysis/stateLock.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import type { AIProvider, AnalyzeRequest, AnalyzeResult } from "../../src/providers/provider.js";
import { createApp } from "../../src/server.js";
import { CaseStore } from "../../src/storage/caseStore.js";

// "Preview what the AI will see" for a Watson message goes through the real interception seam: the
// masked request it shows is the one a real round sends for the same draft, and it saves nothing.

const CASE = "c1";
const HOST = "ACME-FS02";
const PASTE_HOST = "files01.corp.local";

class Recording implements AIProvider {
  readonly name = "rec";
  readonly model = "m";
  readonly sent: AnalyzeRequest[] = [];
  async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
    this.sent.push(req);
    const rawText = JSON.stringify({
      message: "ok",
      workingOn: "",
      learned: "",
      questionUpdates: [],
      newQuestions: [],
      request: null,
      search: null,
      memory: "m",
    });
    return { rawText, usage: { costUSD: 0.01 } };
  }
}

async function harness(aiOn = true) {
  const root = await mkdtemp(join(tmpdir(), "dfir-watson-preview-"));
  const store = new CaseStore(root);
  await store.createCase({ caseId: CASE, name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(store);
  await stateStore.save({
    ...emptyState(CASE),
    forensicTimeline: [
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
    ],
  });
  const customEntitiesStore = new CustomEntitiesStore(store);
  await customEntitiesStore.save(CASE, [{ value: HOST, category: "HOST" }]);
  const aiControlStore = new AiControlStore(store);
  await aiControlStore.save(CASE, { enabled: aiOn, lastAnalyzedSeq: 0 });
  const provider = new Recording();
  const pipeline = new AnalysisPipeline({
    provider,
    synthesisProvider: provider,
    stateStore,
    stateLock: new StateLock(),
    aiCostStore: new AiCostStore(store),
    anonStore: new AnonControlStore(store),
    customEntitiesStore,
    retries: 0,
    imageLoader: async () => ({ base64: "", mimeType: "image/webp" }),
  });
  const chatStore = new WatsonChatStore(store);
  const app = createApp(store, {
    stateStore,
    pipeline,
    watsonChatStore: chatStore,
    watsonProvider: () => provider,
  });
  return { app, store, provider, chatStore, stateStore };
}

/** A paste no round has read yet: the next round (and its preview) attaches its head on its own. */
async function addUnreadPaste(h: Awaited<ReturnType<typeof harness>>): Promise<void> {
  const storedName = "0001_notes.txt";
  const text = `copied \\\\${PASTE_HOST}\\share\\loot.zip\nsecond line\n`;
  await h.store.saveImport(CASE, storedName, text, { source: "watson-chat", trigger: "watson-paste" });
  const paste = {
    id: "wf-1",
    storedName,
    filename: "notes.txt",
    bytes: text.length,
    lines: 2,
    at: "2026-01-02T00:00:00Z",
  };
  await h.chatStore.update(CASE, (c) => ({ ...c, pastes: [paste], unreadPasteIds: [paste.id] }));
}

const chatFile = (h: Awaited<ReturnType<typeof harness>>) =>
  readFile(join(h.store.caseDir(CASE), "state", "watson-chat.json"), "utf8");

describe("AI preview of a Watson message", () => {
  it("shows the masked request a real round then sends for the same draft, and saves nothing", async () => {
    const h = await harness();
    await addUnreadPaste(h);
    const before = await chatFile(h);
    const draft = `what ran on ${HOST}? marker-quokka`;

    const preview = await request(h.app)
      .post(`/cases/${CASE}/ai-preview`)
      .send({ action: "watson", params: { text: draft } });
    expect(preview.status).toBe(200);
    expect(preview.body.outcome).toBe("captured");
    const call = preview.body.call;
    expect(call.kind).toBe("watson");
    expect(call.anonymized).toBe(true);
    expect(call.clearPrompt).toContain(HOST);
    // The draft is the ANALYST block, inside its fence.
    const analyst = call.clearPrompt.slice(
      call.clearPrompt.indexOf("<<<ANALYST>>>"),
      call.clearPrompt.indexOf("<<<END ANALYST>>>"),
    );
    expect(analyst).toContain("marker-quokka");
    expect(call.clearPrompt.split("marker-quokka")).toHaveLength(2); // nowhere else
    expect(call.clearPrompt).toContain(PASTE_HOST); // the unread paste's head is attached
    expect(call.maskedPrompt).not.toContain(HOST);
    expect(call.maskedPrompt).not.toContain(PASTE_HOST);
    expect(call.clearPrompt).toContain("wq-std-what"); // the standard questions a first round seeds
    expect(h.provider.sent).toHaveLength(0);
    // Nothing saved: no chat turn, the paste still unread, no standard questions seeded.
    expect(await chatFile(h)).toBe(before);
    expect((await h.stateStore.load(CASE)).keyQuestions).toEqual([]);

    const real = await request(h.app).post(`/cases/${CASE}/watson/message`).send({ text: draft });
    expect(real.status).toBe(200);
    expect(h.provider.sent).toHaveLength(1);
    expect(h.provider.sent[0].userPrompt).toBe(call.maskedPrompt);
    expect(h.provider.sent[0].systemPrompt).toBe(call.systemPrompt);
  });

  it("stops where the real press would: the case's AI switch is off", async () => {
    const h = await harness(false);
    const res = await request(h.app)
      .post(`/cases/${CASE}/ai-preview`)
      .send({ action: "watson", params: { text: "anything?" } });
    expect(res.status).toBe(409);
    expect(res.body.error).toMatch(/AI is off for this case/);
    expect(h.provider.sent).toHaveLength(0);
  });
});
