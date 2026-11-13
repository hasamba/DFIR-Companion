import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { ActivityLogStore } from "../../../src/analysis/activityLog.js";
import { AiCostStore } from "../../../src/analysis/aiCost.js";
import { AnonControlStore } from "../../../src/analysis/anonControl.js";
import { analyzeRestored } from "../../../src/analysis/ai/providerCall.js";
import type { AiCallContext } from "../../../src/analysis/ai/aiContext.js";
import { addAnswerAsQuestion } from "../../../src/analysis/ai/watson/addQuestion.js";
import { WatsonChatStore } from "../../../src/analysis/ai/watson/chatStore.js";
import { buildWatsonUserPrompt } from "../../../src/analysis/ai/watson/promptBuilder.js";
import {
  WatsonProposalNotFoundError,
  WatsonProposalStateError,
  applyWatsonProposal,
} from "../../../src/analysis/ai/watson/proposals.js";
import { runWatsonRound, type WatsonRoundContext } from "../../../src/analysis/ai/watson/round.js";
import { startNewThread } from "../../../src/analysis/ai/watson/thread.js";
import { emptyWatsonChat, type WatsonTurn } from "../../../src/analysis/ai/watson/types.js";
import { StateLock } from "../../../src/analysis/stateLock.js";
import { StateStore } from "../../../src/analysis/stateStore.js";
import { emptyState, type ForensicEvent } from "../../../src/analysis/stateTypes.js";
import type { Logger } from "../../../src/logging/logger.js";
import type { AIProvider, AnalyzeRequest, AnalyzeResult } from "../../../src/providers/provider.js";
import { CaseStore } from "../../../src/storage/caseStore.js";

const CASE = "c1";
const log: Logger = {
  debug: () => undefined,
  info: () => undefined,
  warn: () => undefined,
  error: () => undefined,
  getLevel: () => "debug",
  setLevel: () => undefined,
  close: async () => undefined,
};

class FakeProvider implements AIProvider {
  readonly name = "fake";
  readonly model = "fake-model";
  readonly sent: AnalyzeRequest[] = [];
  constructor(private readonly replies: string[]) {}
  async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
    this.sent.push(req);
    return { rawText: this.replies.shift() ?? "{}", usage: { costUSD: 0.1 } };
  }
}

const reply = (over: Record<string, unknown> = {}): string =>
  JSON.stringify({
    message: "Here is what the case shows.",
    workingOn: "",
    learned: "",
    questionUpdates: [],
    newQuestions: [],
    request: null,
    search: null,
    memory: "memory v1",
    answer: null,
    ...over,
  });

const ev = (id: string): ForensicEvent => ({
  id,
  timestamp: "2026-01-01T10:00:00Z",
  description: "powershell.exe -enc AAA on HOST-A",
  severity: "High",
  sources: ["Hayabusa"],
  asset: "HOST-A",
  mitreTechniques: ["T1059.001"],
  relatedFindingIds: [],
  sourceScreenshots: [],
});

async function harness(replies: string[]) {
  const root = await mkdtemp(join(tmpdir(), "dfir-watson-free-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: CASE, name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(cases);
  await stateStore.save({ ...emptyState(CASE), forensicTimeline: [ev("e1"), ev("e2")] });
  const anonStore = new AnonControlStore(cases);
  await anonStore.save(CASE, { ...(await anonStore.load(CASE)), enabled: false });
  const costStore = new AiCostStore(cases);
  const provider = new FakeProvider(replies);
  const gateCtx = { log, opts: { anonStore, aiCostStore: costStore } };
  const chatStore = new WatsonChatStore(cases);
  const stateLock = new StateLock();
  const ctx: WatsonRoundContext = {
    opts: { stateStore, retries: 0, backoffMs: 0 },
    log,
    requireProvider: () => provider,
    getKevCatalog: async () => undefined,
    withRetry: (_c, _l, fn) => fn(),
    analyzeRestored: (caseId, state, p, req, label, skip) =>
      analyzeRestored(
        gateCtx,
        caseId,
        state,
        p,
        req as Parameters<AiCallContext["analyzeRestored"]>[3],
        label,
        skip,
      ),
    chatStore,
    stateStore,
    stateLock,
    cases,
    costStore,
    provider,
    isAiEnabled: async () => true,
  };
  const activity = new ActivityLogStore(cases);
  return { ctx, provider, chatStore, stateStore, deps: { stateStore, stateLock, chatStore, activity } };
}

const answerReply = (over: Record<string, unknown> = {}) =>
  reply({
    answer: {
      question: "Which host ran the encoded command?",
      status: "answered",
      answer: "HOST-A ran powershell with an encoded command.",
      pointer: "Check the PowerShell operational log on HOST-A",
      relatedEventIds: ["e1", "ev-invented"],
      ...over,
    },
  });

describe("a free-form answer", () => {
  it("is kept on the Watson turn with only the real event ids", async () => {
    const h = await harness([answerReply()]);
    const chat = await runWatsonRound(h.ctx, CASE, { text: "Which host ran the encoded command?" });
    const turn = chat.turns.find((t) => t.role === "watson") as WatsonTurn;
    expect(turn.answer).toMatchObject({
      question: "Which host ran the encoded command?",
      status: "answered",
      pointer: "Check the PowerShell operational log on HOST-A",
      relatedEventIds: ["e1"],
    });
  });

  it("turns unanswerable into unknown: only an approved Watson proposal may set it", async () => {
    const h = await harness([answerReply({ status: "unanswerable" })]);
    const chat = await runWatsonRound(h.ctx, CASE, { text: "q" });
    expect(chat.turns.at(-1)?.answer?.status).toBe("unknown");
  });

  it("is absent when the model gave none, and the turn needs no workingOn or request", async () => {
    const h = await harness([reply()]);
    const chat = await runWatsonRound(h.ctx, CASE, { text: "hello" });
    const turn = chat.turns.at(-1) as WatsonTurn;
    expect(turn.answer).toBeUndefined();
    expect(turn.workingOn).toBeUndefined();
    expect(turn.request).toBeUndefined();
  });
});

describe("addAnswerAsQuestion", () => {
  async function withAnswer() {
    const h = await harness([answerReply()]);
    const chat = await runWatsonRound(h.ctx, CASE, { text: "Which host ran the encoded command?" });
    return { h, turnId: chat.turns.at(-1)!.id };
  }

  it("adds one applied proposal and one pinned Watson question; a second call is refused; undo removes it", async () => {
    const { h, turnId } = await withAnswer();
    const out = await addAnswerAsQuestion(h.deps, CASE, turnId, "ana");
    const added = out.chat.proposals.filter((p) => p.turnId === turnId);
    expect(added).toHaveLength(1);
    expect(added[0]).toMatchObject({ kind: "question_new", status: "applied" });
    expect(added[0].questionId).toMatch(/^wq-[0-9a-f]{8}$/);
    const q = out.state.keyQuestions.find((x) => x.id === added[0].questionId);
    expect(q).toMatchObject({
      question: "Which host ran the encoded command?",
      status: "answered",
      pinned: true,
      author: "watson",
      pointer: "Check the PowerShell operational log on HOST-A",
    });
    expect((await h.stateStore.loadOverview(CASE)).keyQuestions.some((x) => x.id === q?.id)).toBe(true);
    await expect(addAnswerAsQuestion(h.deps, CASE, turnId, "ana")).rejects.toBeInstanceOf(
      WatsonProposalStateError,
    );
    await applyWatsonProposal(h.deps, CASE, added[0].id, "undo", "ana");
    expect((await h.stateStore.loadOverview(CASE)).keyQuestions.some((x) => x.id === q?.id)).toBe(false);
  });

  it("coerces a stored unanswerable status to unknown", async () => {
    const { h, turnId } = await withAnswer();
    await h.chatStore.update(CASE, (c) => ({
      ...c,
      turns: c.turns.map((t) =>
        t.id === turnId && t.answer ? { ...t, answer: { ...t.answer, status: "unanswerable" as const } } : t,
      ),
    }));
    const out = await addAnswerAsQuestion(h.deps, CASE, turnId);
    expect(out.state.keyQuestions.find((x) => x.author === "watson" && x.id.startsWith("wq-"))?.status).toBe(
      "unknown",
    );
  });

  it("throws not-found for a turn with no answer or no such turn", async () => {
    const h = await harness([reply()]);
    const chat = await runWatsonRound(h.ctx, CASE, { text: "hello" });
    await expect(addAnswerAsQuestion(h.deps, CASE, chat.turns.at(-1)!.id)).rejects.toBeInstanceOf(
      WatsonProposalNotFoundError,
    );
    await expect(addAnswerAsQuestion(h.deps, CASE, "nope")).rejects.toBeInstanceOf(
      WatsonProposalNotFoundError,
    );
  });
});

describe("new thread", () => {
  const turn = (id: string, at: string, text: string): WatsonTurn => ({
    id,
    at,
    role: "analyst",
    text,
  });
  const build = (chat: ReturnType<typeof emptyWatsonChat>) =>
    buildWatsonUserPrompt({
      state: emptyState(CASE),
      chat,
      analystText: "next question",
      caseContext: "CTX",
      mainLanguages: [],
    });

  it("keeps turns before the boundary out of RECENT CHAT and keeps Watson's memory", async () => {
    const h = await harness([]);
    await h.chatStore.update(CASE, (c) => ({
      ...c,
      memory: "MEMORY-KEPT",
      turns: [turn("t1", "2026-01-01T00:00:00.000Z", "OLD-THREAD-TEXT")],
    }));
    const after = await startNewThread(h.chatStore, CASE);
    expect(after.threadStartAt).toBeTruthy();
    expect(after.turns.at(-1)).toMatchObject({ role: "system" });
    expect(after.turns.at(-1)?.text).toContain("New thread");
    expect(after.turns).toHaveLength(2); // the old turn stays in the history
    const prompt = build({
      ...after,
      turns: [...after.turns, turn("t3", new Date(Date.now() + 1000).toISOString(), "NEW-THREAD-TEXT")],
    });
    expect(prompt).not.toContain("OLD-THREAD-TEXT");
    expect(prompt).toContain("NEW-THREAD-TEXT");
    expect(prompt).toContain("MEMORY-KEPT");
  });

  it("without a boundary the whole recent chat is used", () => {
    const prompt = build({ ...emptyWatsonChat(), turns: [turn("t1", "2026-01-01T00:00:00Z", "SOME-TEXT")] });
    expect(prompt).toContain("SOME-TEXT");
  });
});
