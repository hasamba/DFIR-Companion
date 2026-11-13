import { mkdtemp, readdir, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AiControlStore } from "../../src/analysis/aiControl.js";
import { AiCostStore } from "../../src/analysis/aiCost.js";
import { ActivityLogStore } from "../../src/analysis/activityLog.js";
import { AnonControlStore } from "../../src/analysis/anonControl.js";
import { WatsonChatStore } from "../../src/analysis/ai/watson/chatStore.js";
import { WATSON_PASTE_MAX_BYTES } from "../../src/analysis/ai/watson/pasteSearch.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { StateLock } from "../../src/analysis/stateLock.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SynthMetaStore } from "../../src/analysis/synthMeta.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import { resolveRequestPolicy } from "../../src/auth/policy.js";
import type { AIProvider, AnalyzeRequest, AnalyzeResult } from "../../src/providers/provider.js";
import { createApp } from "../../src/server.js";
import { CaseStore } from "../../src/storage/caseStore.js";

// Watson routes: status codes, the paste path (stored, never synthesized), shared rate budget,
// frozen-case refusal, team policy, proposals, and case-event notes on the shared chat store.

// A fresh case id per harness: the AI rate limiter is process-wide and keyed by case id, so one test
// spending the budget must not starve the next.
let CASE = "c1";
let caseCounter = 0;

class Fake implements AIProvider {
  readonly name = "fake";
  readonly model = "fake-model";
  readonly sent: AnalyzeRequest[] = [];
  constructor(private readonly usage: AnalyzeResult["usage"] = { costUSD: 0.1 }) {}
  async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
    this.sent.push(req);
    return { rawText: reply(), usage: this.usage };
  }
}

const reply = (over: Record<string, unknown> = {}): string =>
  JSON.stringify({
    message: "I looked at the case.",
    workingOn: "initial access",
    learned: "",
    questionUpdates: [],
    newQuestions: [
      { question: "How did they get in?", status: "unknown", answer: "", why: "entry point unknown" },
    ],
    request: null,
    search: null,
    memory: "memory v1",
    ...over,
  });

const savedEnv = { ...process.env };
afterEach(() => {
  process.env = { ...savedEnv };
});

async function harness(
  opts: { aiOn?: boolean; provider?: AIProvider | null; broadcasts?: string[]; stateChanges?: string[] } = {},
) {
  CASE = `c${++caseCounter}`;
  const root = await mkdtemp(join(tmpdir(), "dfir-watson-route-"));
  const store = new CaseStore(root);
  await store.createCase({ caseId: CASE, name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(store);
  await stateStore.save(emptyState(CASE));
  const aiControlStore = new AiControlStore(store);
  await aiControlStore.save(CASE, { enabled: opts.aiOn ?? true, lastAnalyzedSeq: 0 });
  const aiCostStore = new AiCostStore(store);
  const stateLock = new StateLock();
  const fake = new Fake();
  const provider = opts.provider === undefined ? fake : (opts.provider ?? undefined);
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
  const chatStore = new WatsonChatStore(store);
  const synthMetaStore = new SynthMetaStore(store);
  const broadcasts = opts.broadcasts ?? [];
  const app = createApp(store, {
    stateStore,
    stateLock,
    pipeline,
    aiCostStore,
    synthMetaStore,
    activityLogStore: new ActivityLogStore(store),
    watsonChatStore: chatStore,
    watsonProvider: () => provider,
    onWatson: (id: string) => broadcasts.push(id),
    onStateChanged: (id: string) => opts.stateChanges?.push(id),
  });
  return { app, store, fake, pipeline, chatStore, synthMetaStore, broadcasts, stateStore };
}

describe("Watson routes", () => {
  it("GET returns an empty chat for a new case", async () => {
    const { app } = await harness();
    const res = await request(app).get(`/cases/${CASE}/watson`);
    expect(res.status).toBe(200);
    expect(res.body.turns).toEqual([]);
  });

  it("GET on an unknown case is 404", async () => {
    const { app } = await harness();
    expect((await request(app).get("/cases/nope/watson")).status).toBe(404);
  });

  it("POST message runs a round and broadcasts watson_changed", async () => {
    const { app, fake, broadcasts } = await harness();
    const res = await request(app).post(`/cases/${CASE}/watson/message`).send({ text: "hello Watson" });
    expect(res.status).toBe(200);
    expect(res.body.turns.map((t: { role: string }) => t.role)).toEqual(["analyst", "watson"]);
    expect(res.body.proposals).toHaveLength(1);
    expect(fake.sent.length).toBeGreaterThan(0);
    expect(broadcasts).toContain(CASE);
  });

  it("rejects an empty message with 400", async () => {
    const { app } = await harness();
    const res = await request(app).post(`/cases/${CASE}/watson/message`).send({ text: "   " });
    expect(res.status).toBe(400);
  });

  it("answers 501 when no Watson provider is configured", async () => {
    const { app } = await harness({ provider: null });
    const res = await request(app).post(`/cases/${CASE}/watson/message`).send({ text: "hi" });
    expect(res.status).toBe(501);
  });

  it("answers 409 when AI is off for the case, and saves nothing", async () => {
    const { app, chatStore, fake } = await harness({ aiOn: false });
    const res = await request(app).post(`/cases/${CASE}/watson/message`).send({ text: "hi" });
    expect(res.status).toBe(409);
    expect(fake.sent).toHaveLength(0);
    expect((await chatStore.load(CASE)).turns).toEqual([]);
  });

  it("answers 409 once the per-case cost limit is reached", async () => {
    process.env.DFIR_AI_WATSON_COST_LIMIT_USD = "0.05";
    const { app } = await harness();
    const first = await request(app).post(`/cases/${CASE}/watson/message`).send({ text: "one" });
    expect(first.status).toBe(200);
    const second = await request(app).post(`/cases/${CASE}/watson/message`).send({ text: "two" });
    expect(second.status).toBe(409);
    expect(second.body.error).toMatch(/limit/i);
  });

  it("ignores a non-finite or non-positive cost limit", async () => {
    process.env.DFIR_AI_WATSON_COST_LIMIT_USD = "-3";
    process.env.DFIR_AI_WATSON_TOKEN_LIMIT = "abc";
    const { app } = await harness();
    for (const t of ["a", "b", "c"]) {
      expect((await request(app).post(`/cases/${CASE}/watson/message`).send({ text: t })).status).toBe(200);
    }
  });

  it("POST paste stores the text, attaches it, and never starts a synthesis", async () => {
    const { app, store, chatStore, synthMetaStore, fake, pipeline } = await harness();
    const synth = vi.spyOn(pipeline, "synthesize");
    const text = "line one\nline two\nline three\n";
    const res = await request(app)
      .post(`/cases/${CASE}/watson/paste`)
      .send({ text, filename: "../evil name.txt" });
    expect(res.status).toBe(200);
    expect(res.body.pastes).toHaveLength(1);
    const paste = res.body.pastes[0];
    expect(paste.lines).toBe(3);
    expect(paste.bytes).toBe(Buffer.byteLength(text));
    expect(paste.storedName).not.toMatch(/[\\/]/);
    const files = await readdir(store.importsDir(CASE));
    expect(files).toEqual([paste.storedName]);
    expect(await readFile(join(store.importsDir(CASE), paste.storedName), "utf8")).toBe(text);
    const turn = res.body.turns.find((t: { pasteId?: string }) => t.pasteId);
    expect(turn.pasteId).toBe(paste.id);
    expect((await chatStore.load(CASE)).pastes).toHaveLength(1);
    // Marked out of date, not re-synthesized: the fake provider saw only Watson's own call(s).
    expect((await synthMetaStore.load(CASE)).outOfDate?.reason).toBe("Watson paste stored");
    expect(synth).not.toHaveBeenCalled();
    expect(fake.sent.length).toBeGreaterThan(0); // Watson's own round ran
  });

  it("GET says whether a Watson provider is configured, and still returns the chat without one", async () => {
    const on = await harness();
    expect((await request(on.app).get(`/cases/${CASE}/watson`)).body.providerConfigured).toBe(true);
    const off = await harness({ provider: null });
    const res = await request(off.app).get(`/cases/${CASE}/watson`);
    expect(res.status).toBe(200);
    expect(res.body.providerConfigured).toBe(false);
    expect(res.body.turns).toEqual([]);
  });

  it("the first round's question seed refreshes the board (state changed)", async () => {
    const stateChanges: string[] = [];
    const { app } = await harness({ stateChanges });
    await request(app).post(`/cases/${CASE}/watson/message`).send({ text: "hi" });
    expect(stateChanges).toContain(CASE);
  });

  it("a stored paste is marked on the response, and read once a round answers", async () => {
    const { app } = await harness();
    const res = await request(app)
      .post(`/cases/${CASE}/watson/paste`)
      .send({ text: "abc", filename: "two\r\nlines.txt" });
    expect(res.status).toBe(200);
    expect(res.headers["x-watson-paste-stored"]).toBe("1");
    expect(res.body.pastes[0].filename).toBe("two lines.txt");
    expect(res.body.unreadPasteIds).toEqual([]);
  });

  it("a paste stored before a refused round stays unread and says it was stored", async () => {
    process.env.DFIR_AI_WATSON_COST_LIMIT_USD = "0.05";
    const { app, chatStore } = await harness();
    await request(app).post(`/cases/${CASE}/watson/message`).send({ text: "spend" });
    const res = await request(app).post(`/cases/${CASE}/watson/paste`).send({ text: "abc" });
    expect(res.status).toBe(409);
    expect(res.headers["x-watson-paste-stored"]).toBe("1");
    const chat = await chatStore.load(CASE);
    expect(chat.unreadPasteIds).toEqual([chat.pastes[0].id]);
  });

  it("refuses a paste above WATSON_PASTE_MAX_BYTES with 413", async () => {
    const { app } = await harness();
    const res = await request(app)
      .post(`/cases/${CASE}/watson/paste`)
      .send({ text: "x".repeat(WATSON_PASTE_MAX_BYTES + 1) });
    expect(res.status).toBe(413);
  }, 30_000);

  it("answers 501 on a paste with no provider, storing nothing", async () => {
    const { app, chatStore } = await harness({ provider: null });
    const res = await request(app).post(`/cases/${CASE}/watson/paste`).send({ text: "abc" });
    expect(res.status).toBe(501);
    expect((await chatStore.load(CASE)).pastes).toEqual([]);
  });

  it("answers 409 on a paste when AI is off, storing nothing", async () => {
    const { app, chatStore } = await harness({ aiOn: false });
    const res = await request(app).post(`/cases/${CASE}/watson/paste`).send({ text: "abc" });
    expect(res.status).toBe(409);
    expect(res.headers["x-watson-paste-stored"]).toBeUndefined();
    expect((await chatStore.load(CASE)).pastes).toEqual([]);
  });

  it("shares one rate budget between message and paste", async () => {
    const { app } = await harness();
    let limited = 0;
    for (let i = 0; i < 24; i++) {
      const url = i % 2 ? "paste" : "message";
      const body = i % 2 ? { text: `p${i}` } : { text: `m${i}` };
      const res = await request(app).post(`/cases/${CASE}/watson/${url}`).send(body);
      if (res.status === 429) limited++;
    }
    expect(limited).toBeGreaterThan(0);
  }, 60_000);

  it("applies, undoes and rejects a proposal; state carries only keyQuestions", async () => {
    const { app, stateStore } = await harness();
    const chat = (await request(app).post(`/cases/${CASE}/watson/message`).send({ text: "go" })).body;
    const pid = chat.proposals[0].id as string;
    const applied = await request(app).post(`/cases/${CASE}/watson/proposals/${pid}/apply`);
    expect(applied.status).toBe(200);
    expect(Object.keys(applied.body.state)).toEqual(["keyQuestions"]);
    expect(applied.body.chat.proposals[0].status).toBe("applied");
    expect(
      (await stateStore.loadOverview(CASE)).keyQuestions.some((q) => q.id === chat.proposals[0].questionId),
    ).toBe(true);
    expect((await request(app).post(`/cases/${CASE}/watson/proposals/${pid}/apply`)).status).toBe(409);
    expect((await request(app).post(`/cases/${CASE}/watson/proposals/${pid}/undo`)).status).toBe(200);
    expect((await request(app).post(`/cases/${CASE}/watson/proposals/${pid}/reject`)).status).toBe(409);
    expect((await request(app).post(`/cases/${CASE}/watson/proposals/nope/apply`)).status).toBe(404);
    expect((await request(app).post(`/cases/${CASE}/watson/proposals/${pid}/explode`)).status).toBe(400);
  });

  it("refuses Watson POSTs on a frozen case", async () => {
    const { app, store } = await harness();
    await store.updateCaseMeta(CASE, { status: "closed" });
    const res = await request(app).post(`/cases/${CASE}/watson/message`).send({ text: "hi" });
    expect(res.status).toBe(423);
  });

  it("adds a free-form answer to the open questions, once, and starts a new thread", async () => {
    const answer = {
      question: "Which host ran it?",
      status: "answered" as const,
      answer: "HOST-A",
      pointer: "the PowerShell log",
      relatedEventIds: [],
    };
    const { app, chatStore, stateStore } = await harness();
    await chatStore.update(CASE, (c) => ({
      ...c,
      turns: [{ id: "wt-1", at: "2026-01-01T00:00:00Z", role: "watson", text: "HOST-A.", answer }],
    }));
    const res = await request(app).post(`/cases/${CASE}/watson/turns/wt-1/add-question`);
    expect(res.status).toBe(200);
    expect(
      res.body.state.keyQuestions.some((q: { question: string }) => q.question === answer.question),
    ).toBe(true);
    expect(res.body.chat.proposals[0].status).toBe("applied");
    expect((await stateStore.loadOverview(CASE)).keyQuestions.some((q) => q.author === "watson")).toBe(true);
    expect((await request(app).post(`/cases/${CASE}/watson/turns/wt-1/add-question`)).status).toBe(409);
    expect((await request(app).post(`/cases/${CASE}/watson/turns/nope/add-question`)).status).toBe(404);
    const thread = await request(app).post(`/cases/${CASE}/watson/new-thread`);
    expect(thread.status).toBe(200);
    expect(typeof thread.body.threadStartAt).toBe("string");
    expect(thread.body.turns.at(-1).role).toBe("system");
    expect((await request(app).post("/cases/nope/watson/new-thread")).status).toBe(404);
  });

  it("refuses add-question and new-thread on a closed case", async () => {
    const { app, store } = await harness();
    await store.updateCaseMeta(CASE, { status: "closed" });
    expect((await request(app).post(`/cases/${CASE}/watson/turns/t/add-question`)).status).toBe(423);
    expect((await request(app).post(`/cases/${CASE}/watson/new-thread`)).status).toBe(423);
  });

  it("gives Watson POSTs the case write policy and GET the read policy", () => {
    expect(resolveRequestPolicy("POST", `/cases/${CASE}/watson/message`)).toMatchObject({
      permission: "write",
    });
    expect(resolveRequestPolicy("POST", `/cases/${CASE}/watson/paste`)).toMatchObject({
      permission: "write",
    });
    expect(resolveRequestPolicy("POST", `/cases/${CASE}/watson/proposals/p/apply`)).toMatchObject({
      permission: "write",
    });
    expect(resolveRequestPolicy("POST", `/cases/${CASE}/watson/new-thread`)).toMatchObject({
      permission: "write",
    });
    expect(resolveRequestPolicy("POST", `/cases/${CASE}/watson/turns/t/add-question`)).toMatchObject({
      permission: "write",
    });
    expect(resolveRequestPolicy("GET", `/cases/${CASE}/watson`)).toMatchObject({ permission: "read" });
  });
});
