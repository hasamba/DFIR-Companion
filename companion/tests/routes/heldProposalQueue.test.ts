// #2918: held Watson promotions a RE-GRADE finds are not lost. Real stores and the real app.
//   1. a paste whose held tagger failed leaves its rows marked "held"; after a restart the start-up
//      re-grade offers the raise as a held-rows card in the Watson chat (Apply/Reject, recorded the
//      same way as a paste's own card), once;
//   2. a queue a stop left (no marked rows any more) is offered at the next start-up;
//   3. a decided, duplicate or stale row is dropped; an offer acknowledges only what it read;
//   4. a raise that cannot be queued keeps its row marked, so a later re-grade tries again;
//   5. a streamed import's settle (here: the push webhook) grades a held row it meets and queues it.
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { afterEach, describe, expect, it, vi } from "vitest";
import { WatsonChatStore } from "../../src/analysis/ai/watson/chatStore.js";
import { heldOfferIdle, offerQueuedHeld } from "../../src/analysis/ai/watson/heldOffer.js";
import {
  ackHeld,
  enqueueHeld,
  HELD_QUEUE_FILE,
  readHeldQueue,
} from "../../src/analysis/ai/watson/heldQueue.js";
import { emptyWatsonChat, type WatsonEventPromoteProposal } from "../../src/analysis/ai/watson/types.js";
import { ActivityLogStore } from "../../src/analysis/activityLog.js";
import { AiControlStore } from "../../src/analysis/aiControl.js";
import { AiCostStore } from "../../src/analysis/aiCost.js";
import { AnonControlStore } from "../../src/analysis/anonControl.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { SynthMetaStore } from "../../src/analysis/synthMeta.js";
import type { AIProvider, AnalyzeResult } from "../../src/providers/provider.js";
import { ForensicGateControlStore } from "../../src/analysis/forensicGateControl.js";
import { forensicGradePendingIds } from "../../src/analysis/gradeMark.js";
import { ImportLock } from "../../src/analysis/importLock.js";
import { StateLock } from "../../src/analysis/stateLock.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { TaggerStore } from "../../src/analysis/taggerStore.js";
import { TagsStore } from "../../src/analysis/tags.js";
import { WATSON_MARKER } from "../../src/analysis/timeline/watsonItems.js";
import { getServerLogger } from "../../src/logging/serverLogger.js";
import { createApp } from "../../src/server.js";
import { CaseStore } from "../../src/storage/caseStore.js";

const CASE = "c1";
const PUSH_KEY = "push-key-for-tests";

// SIEM rows logged at Information level land as Info; the bundled rule pack grades `ntdsutil` High.
const siemRow = (host: string, message: string) => ({
  "@timestamp": "2026-07-01T11:00:00.000Z",
  log_name: "Application",
  computer_name: host,
  event_id: 1000,
  level: "Information",
  message,
});
const SIEM = JSON.stringify([
  siemRow("vault.example.com", "ntdsutil ifm create full c:\\staging ran on the controller"),
  siemRow("desk.example.com", "The Windows Update service entered the running state."),
]);
const OTHER_SIEM = JSON.stringify([
  siemRow("desk2.example.com", "The Print Spooler service entered the running state."),
  siemRow("desk3.example.com", "The Time service entered the running state."),
]);

/** Watson's model: answers every round with an empty reply. */
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

let root: string | undefined;
afterEach(async () => {
  vi.restoreAllMocks();
  await heldOfferIdle(CASE);
  if (root) await rm(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  root = undefined;
});

/** One app over the case folder — a second call over the same folder is a restart. */
function boot(dir: string) {
  const store = new CaseStore(dir);
  const stateStore = new StateStore(store);
  const chatStore = new WatsonChatStore(store);
  const onWatson = vi.fn();
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
  const app = createApp(store, {
    importLock: new ImportLock(),
    stateStore,
    stateLock,
    pipeline,
    aiCostStore,
    synthMetaStore: new SynthMetaStore(store),
    watsonProvider: () => fake,
    superTimelineStore: new SuperTimelineStore(store),
    tagsStore: new TagsStore(store),
    taggerStore: new TaggerStore(join(dir, "user-tags.yaml")),
    forensicGateControlStore: new ForensicGateControlStore(store),
    activityLogStore: new ActivityLogStore(store),
    watsonChatStore: chatStore,
    onWatson,
    pushToken: PUSH_KEY,
  });
  const regrade = app.locals.regradeUngraded as () => Promise<void>;
  return { app, store, stateStore, chatStore, onWatson, regrade };
}

async function harness() {
  vi.spyOn(getServerLogger(), "warn").mockImplementation(() => {});
  vi.spyOn(getServerLogger(), "info").mockImplementation(() => {});
  root = await mkdtemp(join(tmpdir(), "dfir-held-queue-"));
  const store = new CaseStore(root);
  await store.createCase({ caseId: CASE, name: "n", investigator: "i", aiProvider: null });
  await new StateStore(store).save(emptyState(CASE));
  await new AiControlStore(store).save(CASE, { enabled: true, lastAnalyzedSeq: 0 });
  return { dir: root, ...boot(root) };
}

/** A paste whose held tagger fails (a broken ruleset read): its rows stay marked "held". */
async function pasteWithBrokenTagger(h: Awaited<ReturnType<typeof harness>>) {
  const load = vi.spyOn(TaggerStore.prototype, "load").mockRejectedValueOnce(new Error("broken ruleset"));
  const res = await request(h.app)
    .post(`/cases/${CASE}/watson/paste`)
    .send({ text: SIEM, filename: "events.json" });
  load.mockRestore();
  expect(res.status, JSON.stringify(res.body)).toBe(200);
  return res;
}

const heldCards = async (chatStore: WatsonChatStore) =>
  (await chatStore.load(CASE)).proposals.filter(
    (p): p is WatsonEventPromoteProposal => p.kind === "event_promote",
  );

const mentions = (events: readonly ForensicEvent[], text: string) =>
  events.filter((e) => e.description.includes(text));

describe("#2918 — held promotions a re-grade finds are offered, once", () => {
  it("after a restart, the start-up re-grade offers the paste's raise as a held-rows card", async () => {
    const h = await harness();
    await pasteWithBrokenTagger(h);
    expect((await forensicGradePendingIds(h.stateStore, CASE)).length).toBe(2); // held, not demoted
    expect(await heldCards(h.chatStore)).toHaveLength(0); // the paste's own turn had nothing to offer

    const after = boot(h.dir); // restart: fresh stores over the same case folder
    await after.regrade();
    await heldOfferIdle(CASE);

    expect(await forensicGradePendingIds(after.stateStore, CASE)).toEqual([]);
    const fresh = new WatsonChatStore(new CaseStore(h.dir)); // the chat as saved on disk
    const chat = await fresh.load(CASE);
    const cards = await heldCards(fresh);
    expect(cards).toHaveLength(1);
    expect(cards[0].status).toBe("pending");
    expect(cards[0].pasteId).toBe(chat.pastes[0].id);
    expect(cards[0].events.map((e) => e.severity)).toEqual(["High"]);
    expect(cards[0].events[0].provenance).toContain(WATSON_MARKER);
    expect(cards[0].events[0]).not.toHaveProperty("gradePending");
    const turn = chat.turns.find((t) => t.proposalIds?.includes(cards[0].id));
    expect(turn?.role).toBe("system");
    expect(turn?.pasteId).toBe(chat.pastes[0].id);
    expect(turn?.text).toContain("from events.json after an interruption");
    expect(turn?.text).not.toContain("ntdsutil"); // a count and a file name, never a row's content
    expect(after.onWatson).toHaveBeenCalledWith(CASE);
    expect(await readHeldQueue(after.store.stateDir(CASE))).toEqual([]);
    // Not in the forensic timeline until the analyst applies it.
    expect(mentions((await after.stateStore.load(CASE)).forensicTimeline, "ntdsutil")).toHaveLength(0);

    // Apply goes through the same promotion path as a paste's own card: Watson's, named by its paste.
    const applied = await request(after.app).post(`/cases/${CASE}/watson/proposals/${cards[0].id}/apply`);
    expect(applied.status).toBe(200);
    const landed = mentions((await after.stateStore.load(CASE)).forensicTimeline, "ntdsutil");
    expect(landed).toHaveLength(1);
    expect(landed[0].severity).toBe("High");
    expect(landed[0].promotedAt).toBeTruthy();
    expect(landed[0].provenance).toContain(WATSON_MARKER);

    // Offered once: another start-up and another offer add nothing.
    await boot(h.dir).regrade();
    await heldOfferIdle(CASE);
    expect(await heldCards(fresh)).toHaveLength(1);
  });

  it("a queue a stop left with no marked rows is offered at the next start-up", async () => {
    const h = await harness();
    const raised: ForensicEvent = {
      id: "q-1",
      timestamp: "2026-07-01T11:00:00.000Z",
      description: "a raised copy",
      severity: "High",
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: ["0001_events.json"],
      sources: ["SIEM"],
      provenance: [WATSON_MARKER],
    };
    await enqueueHeld(h.store.stateDir(CASE), [raised]);
    const after = boot(h.dir);
    await after.regrade();
    const cards = await heldCards(new WatsonChatStore(new CaseStore(h.dir)));
    expect(cards.map((c) => c.events.map((e) => e.id))).toEqual([["q-1"]]);
    expect(cards[0].pasteId).toBeUndefined(); // no paste in the chat: the stored file names it
    const turn = (await after.chatStore.load(CASE)).turns.at(-1);
    expect(turn?.text).toContain("from 0001_events.json");
    expect(await readHeldQueue(after.store.stateDir(CASE))).toEqual([]);
  });

  it("drops a decided, duplicate or stale row, and acknowledges only the copy it read", async () => {
    const h = await harness();
    const dir = h.store.stateDir(CASE);
    const row = (id: string): ForensicEvent => ({
      id,
      timestamp: "2026-07-01T11:00:00.000Z",
      description: `raised ${id}`,
      severity: "High",
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: ["0001_events.json"],
      sources: ["SIEM"],
    });
    // A rejected card for "decided"; "stale" is back in the forensic timeline above Info.
    await h.chatStore.update(CASE, () => ({
      ...emptyWatsonChat(),
      turns: [{ id: "t0", at: "", role: "system", text: "earlier", proposalIds: ["p0"] }],
      proposals: [
        {
          id: "p0",
          turnId: "t0",
          kind: "event_promote",
          targetId: "decided",
          events: [row("decided")],
          status: "rejected",
        },
      ],
    }));
    await h.stateStore.save({ ...emptyState(CASE), forensicTimeline: [row("stale")] });
    await enqueueHeld(dir, [row("decided"), row("stale"), row("fresh")]);
    const deps = {
      stateDir: () => dir,
      stateStore: h.stateStore,
      chatStore: h.chatStore,
    };
    expect(await offerQueuedHeld(deps, CASE)).toBe(1);
    const ids = (await heldCards(h.chatStore)).flatMap((c) => c.events.map((e) => e.id));
    expect(ids.sort()).toEqual(["decided", "fresh"]); // "decided" only on its old, rejected card
    expect(await readHeldQueue(dir)).toEqual([]);
    expect(await offerQueuedHeld(deps, CASE)).toBe(0);

    // A newer copy queued after an offer read the old one survives that offer's acknowledgement.
    await enqueueHeld(dir, [row("later")]);
    const read = await readHeldQueue(dir);
    await enqueueHeld(dir, [{ ...row("later"), description: "newer copy" }]);
    await ackHeld(dir, read);
    expect((await readHeldQueue(dir)).map((q) => q.event.description)).toEqual(["newer copy"]);
  });

  it("a raise that cannot be queued keeps its row marked held for a later re-grade", async () => {
    const h = await harness();
    await pasteWithBrokenTagger(h);
    const queuePath = join(h.store.stateDir(CASE), HELD_QUEUE_FILE);
    await mkdir(queuePath); // the queue file cannot be written
    const after = boot(h.dir);
    await after.regrade();
    await heldOfferIdle(CASE);
    const still = await forensicGradePendingIds(after.stateStore, CASE);
    expect(still).toHaveLength(1); // the row the tagger raises; the Info row was graded and demoted
    expect(mentions((await after.stateStore.load(CASE)).forensicTimeline, "ntdsutil")).toHaveLength(1);

    await rm(queuePath, { recursive: true });
    await writeFile(queuePath, "{ not json"); // a corrupt queue is kept aside and read as empty
    await boot(h.dir).regrade();
    await heldOfferIdle(CASE);
    expect(await forensicGradePendingIds(after.stateStore, CASE)).toEqual([]);
    expect(await heldCards(new WatsonChatStore(new CaseStore(h.dir)))).toHaveLength(1);
  });

  it("a streamed import's settle grades a held row it meets and queues its raise", async () => {
    const h = await harness();
    await pasteWithBrokenTagger(h);
    expect((await forensicGradePendingIds(h.stateStore, CASE)).length).toBe(2);
    const res = await request(h.app)
      .post(`/cases/${CASE}/push`)
      .set("X-DFIR-Key", PUSH_KEY)
      .send({ filename: "more.json", text: OTHER_SIEM });
    expect(res.status, JSON.stringify(res.body)).toBe(202);
    await vi.waitFor(
      async () => {
        expect(await forensicGradePendingIds(h.stateStore, CASE)).toEqual([]);
        expect(await heldCards(h.chatStore)).toHaveLength(1);
      },
      { timeout: 15_000, interval: 100 },
    );
    const cards = await heldCards(h.chatStore);
    expect(cards[0].events.map((e) => e.severity)).toEqual(["High"]);
  });
});
