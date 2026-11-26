// #2930: a Watson paste's settle sweeps rows an EARLIER paste left marked "held" (its held tagger
// failed). Those rows belong to the earlier paste: they are offered through the held-proposal outbox
// (#2918) under that paste's name — never in the new paste's own turn as the new paste's. Real stores
// and the real app.
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { WatsonChatStore } from "../../src/analysis/ai/watson/chatStore.js";
import { heldOfferIdle } from "../../src/analysis/ai/watson/heldOffer.js";
import { readHeldQueue } from "../../src/analysis/ai/watson/heldQueue.js";
import type { WatsonChat, WatsonEventPromoteProposal } from "../../src/analysis/ai/watson/types.js";
import { AiControlStore } from "../../src/analysis/aiControl.js";
import { AiCostStore } from "../../src/analysis/aiCost.js";
import { AnonControlStore } from "../../src/analysis/anonControl.js";
import { ForensicGateControlStore } from "../../src/analysis/forensicGateControl.js";
import { forensicGradePendingIds } from "../../src/analysis/gradeMark.js";
import { ImportLock } from "../../src/analysis/importLock.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { StateLock } from "../../src/analysis/stateLock.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { SynthMetaStore } from "../../src/analysis/synthMeta.js";
import { TaggerStore } from "../../src/analysis/taggerStore.js";
import { TagsStore } from "../../src/analysis/tags.js";
import { getServerLogger } from "../../src/logging/serverLogger.js";
import type { AIProvider, AnalyzeResult } from "../../src/providers/provider.js";
import { resetSweepBackoff } from "../../src/routes/importRegrade.js";
import { createApp } from "../../src/server.js";
import { CaseStore } from "../../src/storage/caseStore.js";

const CASE = "c1";

// SIEM rows logged at Information level land as Info; the bundled rule pack grades `ntdsutil` High.
const siemRow = (host: string, message: string) => ({
  "@timestamp": "2026-07-01T11:00:00.000Z",
  log_name: "Application",
  computer_name: host,
  event_id: 1000,
  level: "Information",
  message,
});
const FIRST = JSON.stringify([
  siemRow("vault.example.com", "ntdsutil ifm create full c:\\staging ran on the controller"),
  siemRow("desk.example.com", "The Windows Update service entered the running state."),
]);
const SECOND = JSON.stringify([
  siemRow("desk2.example.com", "The Print Spooler service entered the running state."),
  siemRow("desk3.example.com", "The Time service entered the running state."),
]);

class Fake implements AIProvider {
  readonly name = "fake";
  readonly model = "fake-model";
  async analyze(): Promise<AnalyzeResult> {
    const reply = { message: "ok", workingOn: "", learned: "", questionUpdates: [], newQuestions: [] };
    return {
      rawText: JSON.stringify({ ...reply, request: null, search: null, memory: "" }),
      usage: { costUSD: 0 },
    };
  }
}

let root: string;
let app: ReturnType<typeof createApp>;
let store: CaseStore;
let stateStore: StateStore;
let chatStore: WatsonChatStore;

beforeEach(async () => {
  resetSweepBackoff();
  vi.spyOn(getServerLogger(), "warn").mockImplementation(() => {});
  vi.spyOn(getServerLogger(), "info").mockImplementation(() => {});
  root = await mkdtemp(join(tmpdir(), "dfir-held-leftover-"));
  store = new CaseStore(root);
  await store.createCase({ caseId: CASE, name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(store);
  await stateStore.save(emptyState(CASE));
  await new AiControlStore(store).save(CASE, { enabled: true, lastAnalyzedSeq: 0 });
  chatStore = new WatsonChatStore(store);
  const stateLock = new StateLock();
  const fake = new Fake();
  const aiCostStore = new AiCostStore(store);
  const pipeline = new AnalysisPipeline({
    provider: fake,
    synthesisProvider: fake,
    stateStore,
    stateLock,
    aiCostStore,
    anonStore: new AnonControlStore(store),
    retries: 0,
    imageLoader: async () => ({ base64: "", mimeType: "image/webp" }),
  });
  app = createApp(store, {
    importLock: new ImportLock(),
    stateStore,
    stateLock,
    pipeline,
    aiCostStore,
    synthMetaStore: new SynthMetaStore(store),
    watsonProvider: () => fake,
    superTimelineStore: new SuperTimelineStore(store),
    tagsStore: new TagsStore(store),
    taggerStore: new TaggerStore(join(root, "user-tags.yaml")),
    forensicGateControlStore: new ForensicGateControlStore(store),
    watsonChatStore: chatStore,
  });
});

afterEach(async () => {
  vi.restoreAllMocks();
  await heldOfferIdle(CASE);
  await rm(root, { recursive: true, force: true });
});

async function paste(text: string, filename: string, brokenTagger = false) {
  const load = brokenTagger
    ? vi.spyOn(TaggerStore.prototype, "load").mockRejectedValueOnce(new Error("broken ruleset"))
    : undefined;
  const res = await request(app).post(`/cases/${CASE}/watson/paste`).send({ text, filename });
  load?.mockRestore();
  expect(res.status, JSON.stringify(res.body)).toBe(200);
  expect(res.text).not.toContain("gradePending"); // the chat it returns carries no grade mark (#2930)
}

const cardsOf = (chat: WatsonChat) =>
  chat.proposals.filter((p): p is WatsonEventPromoteProposal => p.kind === "event_promote");
const pasteNamed = (chat: WatsonChat, filename: string) => chat.pastes.find((p) => p.filename === filename)!;

describe("#2930 — rows an earlier paste left held are offered under that paste", () => {
  it("the second paste's sweep queues the first paste's raise; its own turn does not carry it", async () => {
    await paste(FIRST, "first.json", true);
    expect((await forensicGradePendingIds(stateStore, CASE)).length).toBe(2); // held, no card yet
    expect(cardsOf(await chatStore.load(CASE))).toHaveLength(0);

    await paste(SECOND, "second.json");
    await heldOfferIdle(CASE);

    expect(await forensicGradePendingIds(stateStore, CASE)).toEqual([]); // the sweep graded them
    const chat = await new WatsonChatStore(new CaseStore(root)).load(CASE); // as saved on disk
    const first = pasteNamed(chat, "first.json");
    const second = pasteNamed(chat, "second.json");
    const cards = cardsOf(chat);
    expect(cards).toHaveLength(1);
    expect(cards[0].pasteId).toBe(first.id);
    expect(cards[0].status).toBe("pending");
    expect(cards[0].events.map((e) => e.description)).toEqual([expect.stringContaining("ntdsutil")]);
    const outboxTurn = chat.turns.find((t) => t.proposalIds?.includes(cards[0].id));
    expect(outboxTurn?.role).toBe("system");
    expect(outboxTurn?.pasteId).toBe(first.id);
    expect(outboxTurn?.text).toContain("first.json");
    // The second paste's own turn is there, holds no card, and names only its own rows.
    const ownTurn = chat.turns.find((t) => t.role === "system" && t.pasteId === second.id);
    expect(ownTurn).toBeDefined();
    expect(ownTurn?.proposalIds ?? []).toEqual([]);
    expect(ownTurn?.text).not.toContain("ntdsutil");
    expect(await readHeldQueue(store.stateDir(CASE))).toEqual([]);
  });

  it("a row of the first paste already on a card is not offered again", async () => {
    await paste(FIRST, "first.json"); // its own turn offers the raise
    const before = cardsOf(await chatStore.load(CASE));
    expect(before).toHaveLength(1);
    await paste(SECOND, "second.json");
    await heldOfferIdle(CASE);
    const after = cardsOf(await chatStore.load(CASE));
    expect(after.map((c) => c.id)).toEqual(before.map((c) => c.id));
  });
});
