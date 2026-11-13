import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { AiCostStore } from "../../../src/analysis/aiCost.js";
import { AnonControlStore } from "../../../src/analysis/anonControl.js";
import type { Logger } from "../../../src/logging/logger.js";
import { analyzeRestored } from "../../../src/analysis/ai/providerCall.js";
import type { AiCallContext } from "../../../src/analysis/ai/aiContext.js";
import { WatsonChatStore } from "../../../src/analysis/ai/watson/chatStore.js";
import {
  runWatsonRound,
  WatsonAiOff,
  WatsonCostLimitReached,
  type WatsonRoundContext,
} from "../../../src/analysis/ai/watson/round.js";
import type { WatsonPaste } from "../../../src/analysis/ai/watson/types.js";
import { PresidioApprovalRequired } from "../../../src/analysis/presidio.js";
import { StateLock } from "../../../src/analysis/stateLock.js";
import { StateStore } from "../../../src/analysis/stateStore.js";
import { emptyState, type ForensicEvent } from "../../../src/analysis/stateTypes.js";
import type { AIProvider, AnalyzeRequest, AnalyzeResult } from "../../../src/providers/provider.js";
import { CaseStore } from "../../../src/storage/caseStore.js";

const CASE = "c1";
const UNSEEN_HOST = "ws-pay-07.example.com";

const log: Logger = {
  debug: () => undefined,
  info: () => undefined,
  warn: () => undefined,
  error: () => undefined,
  getLevel: () => "debug",
  setLevel: () => undefined,
  close: async () => undefined,
};

// Replies in order; records every request the provider actually received.
class FakeProvider implements AIProvider {
  readonly name = "fake";
  readonly model = "fake-model";
  readonly sent: AnalyzeRequest[] = [];
  constructor(
    private readonly replies: string[],
    private readonly costPerCall = 0.1,
  ) {}
  async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
    this.sent.push(req);
    const rawText = this.replies.shift() ?? "{}";
    return { rawText, usage: { costUSD: this.costPerCall } };
  }
}

const reply = (over: Record<string, unknown> = {}): string =>
  JSON.stringify({
    message: "I looked at the case.",
    workingOn: "initial access",
    learned: "",
    questionUpdates: [],
    newQuestions: [],
    request: null,
    search: null,
    memory: "memory v1",
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

interface Harness {
  ctx: WatsonRoundContext;
  provider: FakeProvider;
  chatStore: WatsonChatStore;
  stateStore: StateStore;
  cases: CaseStore;
  costStore: AiCostStore;
  analyzeSpy: ReturnType<typeof vi.fn>;
}

async function harness(
  replies: string[],
  opts: { aiOn?: boolean; anonymize?: boolean; costLimitUSD?: number; cost?: number } = {},
): Promise<Harness> {
  const root = await mkdtemp(join(tmpdir(), "dfir-watson-round-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: CASE, name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(cases);
  await stateStore.save({ ...emptyState(CASE), forensicTimeline: [ev("e1")] });
  const anonStore = new AnonControlStore(cases);
  await anonStore.save(CASE, { ...(await anonStore.load(CASE)), enabled: opts.anonymize ?? false });
  const costStore = new AiCostStore(cases);
  const provider = new FakeProvider(replies, opts.cost ?? 0.1);
  const gateCtx = { log, opts: { anonStore, aiCostStore: costStore } };
  // Bound with the same six arguments as pipeline.ts, so a value that only a seventh positional
  // argument carried would be dropped here exactly as it would be in production.
  const analyzeSpy = vi.fn(
    (
      caseId: string,
      state: Parameters<AiCallContext["analyzeRestored"]>[1],
      p: AIProvider,
      req: Parameters<AiCallContext["analyzeRestored"]>[3],
      label?: string,
      skip?: Parameters<AiCallContext["analyzeRestored"]>[5],
    ) => analyzeRestored(gateCtx, caseId, state, p, req, label, skip),
  );
  const chatStore = new WatsonChatStore(cases);
  const ctx: WatsonRoundContext = {
    opts: { stateStore, retries: 0, backoffMs: 0 },
    log,
    requireProvider: () => provider,
    getKevCatalog: async () => undefined,
    withRetry: (_c, _l, fn) => fn(),
    analyzeRestored: analyzeSpy,
    chatStore,
    stateStore,
    stateLock: new StateLock(),
    cases,
    costStore,
    provider,
    isAiEnabled: async () => opts.aiOn ?? true,
    ...(opts.costLimitUSD !== undefined ? { costLimitUSD: opts.costLimitUSD } : {}),
  };
  return { ctx, provider, chatStore, stateStore, cases, costStore, analyzeSpy };
}

async function addPaste(h: Harness, id: string, text: string): Promise<WatsonPaste> {
  const storedName = `watson-paste-${id}.txt`;
  await writeFile(join(h.cases.importsDir(CASE), storedName), text, { flag: "w" }).catch(async () => {
    const { mkdir } = await import("node:fs/promises");
    await mkdir(h.cases.importsDir(CASE), { recursive: true });
    await writeFile(join(h.cases.importsDir(CASE), storedName), text);
  });
  const paste: WatsonPaste = {
    id,
    storedName,
    filename: "netstat.txt",
    bytes: text.length,
    lines: text.split("\n").length,
    at: "2026-01-01T00:00:00Z",
  };
  await h.chatStore.update(CASE, (c) => ({ ...c, pastes: [...c.pastes, paste] }));
  return paste;
}

describe("runWatsonRound", () => {
  it("happy path: saves the analyst turn, the Watson turn, one pending proposal, and new memory", async () => {
    const h = await harness([
      reply({
        questionUpdates: [
          { questionId: "wq-std-what", status: "partial", answer: "Encoded PowerShell ran", pointer: "e1" },
        ],
      }),
    ]);
    const chat = await runWatsonRound(h.ctx, CASE, { text: "What do we know?", actor: "ana" });

    expect(chat.turns.map((t) => t.role)).toEqual(["analyst", "watson"]);
    expect(chat.turns[0]).toMatchObject({ text: "What do we know?", actor: "ana" });
    expect(chat.turns[1]).toMatchObject({ text: "I looked at the case.", workingOn: "initial access" });
    expect(chat.proposals).toHaveLength(1);
    const p = chat.proposals[0];
    expect(p).toMatchObject({ kind: "question_update", questionId: "wq-std-what", status: "pending" });
    expect(p.before).toMatchObject({ id: "wq-std-what", status: "unknown" });
    expect(p.after).toMatchObject({
      status: "partial",
      answer: "Encoded PowerShell ran",
      pinned: true,
      author: "watson",
    });
    expect(chat.turns[1].proposalIds).toEqual([p.id]);
    expect(chat.memory).toBe("memory v1");
    expect(chat.calls).toBe(1);
    expect(chat.costUSD).toBeCloseTo(0.1);
    expect(chat.turns[1].costUSD).toBeCloseTo(0.1);
    expect(await h.chatStore.load(CASE)).toEqual(chat);
  });

  it("seeds the standard questions once, and new questions get a wq-<8 hex> id", async () => {
    const h = await harness([
      reply({ newQuestions: [{ question: "Was data staged?", why: "rar.exe ran" }] }),
    ]);
    const chat = await runWatsonRound(h.ctx, CASE, { text: "go" });
    const state = await h.stateStore.loadOverview(CASE);
    expect(state.keyQuestions.filter((q) => q.id.startsWith("wq-std-"))).toHaveLength(6);
    expect(h.provider.sent[0].userPrompt).toContain("wq-std-what");
    const p = chat.proposals[0];
    expect(p.kind).toBe("question_new");
    expect(p.questionId).toMatch(/^wq-[0-9a-f]{8}$/);
    expect(p.before).toBeUndefined();
    expect(p.after).toMatchObject({
      question: "Was data staged?",
      status: "unknown",
      pinned: true,
      author: "watson",
    });
  });

  it("search hop: the second call receives the excerpt, and a further search request is ignored", async () => {
    const h = await harness([
      reply({ search: { pasteId: "p1", terms: ["4444"] } }),
      reply({ message: "Found it.", search: { pasteId: "p1", terms: ["again"] } }),
      reply({ message: "should never be asked" }),
    ]);
    const lines = Array.from({ length: 3000 }, (_, i) => `line ${i} tcp 10.0.0.1:${i === 2500 ? 4444 : 80}`);
    await addPaste(h, "p1", lines.join("\n"));
    const chat = await runWatsonRound(h.ctx, CASE, { text: "check the paste", pasteId: "p1" });

    expect(h.provider.sent).toHaveLength(2);
    expect(h.provider.sent[0].userPrompt).toContain("line 0 tcp"); // the head of a new paste
    expect(h.provider.sent[1].userPrompt).toContain("2501: line 2500 tcp 10.0.0.1:4444");
    expect(chat.turns.at(-1)?.text).toBe("Found it.");
    expect(chat.turns[0].pasteId).toBe("p1");
    expect(chat.calls).toBe(2);
    expect(chat.costUSD).toBeCloseTo(0.2);
  });

  it("broken JSON: the analyst turn stays, an error turn is appended, no proposals, the call is charged", async () => {
    const h = await harness(["this is not json {{{"]);
    const chat = await runWatsonRound(h.ctx, CASE, { text: "hello" });
    expect(chat.turns.map((t) => t.role)).toEqual(["analyst", "system"]);
    expect(chat.turns[1].error).toBe(true);
    expect(chat.turns[1].text).toMatch(/Watson/);
    expect(chat.proposals).toHaveLength(0);
    expect(chat.costUSD).toBeCloseTo(0.1);
    expect(chat.calls).toBe(1);
  });

  it("saves the analyst turn before the model is called", async () => {
    const h = await harness([reply()]);
    let seen: string[] = [];
    const inner = h.ctx.analyzeRestored;
    h.ctx = {
      ...h.ctx,
      analyzeRestored: async (...args) => {
        seen = (await h.chatStore.load(CASE)).turns.map((t) => t.text);
        return inner(...args);
      },
    };
    await runWatsonRound(h.ctx, CASE, { text: "first words" });
    expect(seen).toEqual(["first words"]);
  });

  it("cost limit reached: throws WatsonCostLimitReached and never calls the model", async () => {
    const h = await harness([reply()], { costLimitUSD: 5 });
    await h.chatStore.update(CASE, (c) => ({ ...c, costUSD: 5 }));
    await expect(runWatsonRound(h.ctx, CASE, { text: "hi" })).rejects.toBeInstanceOf(WatsonCostLimitReached);
    expect(h.provider.sent).toHaveLength(0);
    expect((await h.chatStore.load(CASE)).turns).toHaveLength(0);
  });

  it("skips the search hop when the first call reached the cost limit, and says so", async () => {
    const h = await harness([reply({ search: { pasteId: "p1", terms: ["x"] } })], { costLimitUSD: 0.05 });
    await addPaste(h, "p1", "x\ny");
    const chat = await runWatsonRound(h.ctx, CASE, { text: "search" });
    expect(h.provider.sent).toHaveLength(1);
    expect(chat.turns.at(-1)?.text).toMatch(/cost limit/i);
  });

  it("AI off: throws WatsonAiOff and never calls the model", async () => {
    const h = await harness([reply()], { aiOn: false });
    await expect(runWatsonRound(h.ctx, CASE, { text: "hi" })).rejects.toBeInstanceOf(WatsonAiOff);
    expect(h.provider.sent).toHaveLength(0);
  });

  it("concurrency: the second round's prompt contains the first round's Watson turn", async () => {
    const h = await harness([reply({ message: "FIRST ANSWER" }), reply({ message: "second" })]);
    const [a, b] = await Promise.all([
      runWatsonRound(h.ctx, CASE, { text: "one" }),
      runWatsonRound(h.ctx, CASE, { text: "two" }),
    ]);
    expect(a.turns).toHaveLength(2);
    expect(b.turns.map((t) => t.text)).toEqual(["one", "FIRST ANSWER", "two", "second"]);
    expect(h.provider.sent[1].userPrompt).toContain("FIRST ANSWER");
  });

  it("removes only the pending case events its prompt showed", async () => {
    const h = await harness([reply()]);
    await h.chatStore.update(CASE, (c) => ({ ...c, pendingCaseEvents: ["import finished: evtx"] }));
    const inner = h.ctx.analyzeRestored;
    h.ctx = {
      ...h.ctx,
      analyzeRestored: async (...args) => {
        await h.chatStore.update(CASE, (c) => ({
          ...c,
          pendingCaseEvents: [...c.pendingCaseEvents, "late event"],
        }));
        return inner(...args);
      },
    };
    const chat = await runWatsonRound(h.ctx, CASE, { text: "x" });
    expect(h.provider.sent[0].userPrompt).toContain("import finished: evtx");
    expect(chat.pendingCaseEvents).toEqual(["late event"]);
  });

  it("reaches the provider only through ctx.analyzeRestored", async () => {
    const h = await harness([reply({ search: { pasteId: "p1", terms: ["a"] } }), reply()]);
    await addPaste(h, "p1", "a\nb");
    await runWatsonRound(h.ctx, CASE, { text: "x" });
    expect(h.analyzeSpy).toHaveBeenCalledTimes(2);
    expect(h.provider.sent).toHaveLength(2);
    for (const call of h.analyzeSpy.mock.calls) expect(call[4]).toBe("watson");
    expect((await h.costStore.load(CASE)).watson.totalCalls).toBe(2);
  });

  it("rethrows PresidioApprovalRequired after saving an error turn", async () => {
    const h = await harness([reply()]);
    h.ctx = {
      ...h.ctx,
      analyzeRestored: async () => {
        throw new PresidioApprovalRequired([{ value: "Jane Roe", category: "PERSON" }]);
      },
    };
    await expect(runWatsonRound(h.ctx, CASE, { text: "x" })).rejects.toBeInstanceOf(PresidioApprovalRequired);
    const chat = await h.chatStore.load(CASE);
    expect(chat.turns.map((t) => t.role)).toEqual(["analyst", "system"]);
    expect(chat.turns[1].error).toBe(true);
  });

  it("masks a hostname the case has never seen when it arrives in a paste, on both hops", async () => {
    const h = await harness(
      [reply({ search: { pasteId: "p1", terms: ["ws-pay"] } }), reply({ message: `Seen ${UNSEEN_HOST}` })],
      { anonymize: true },
    );
    await addPaste(
      h,
      "p1",
      `TCP 10.1.2.3:445 ${UNSEEN_HOST} ESTABLISHED\nSMB ${UNSEEN_HOST.toUpperCase()}\nmail jane.roe@${UNSEEN_HOST}\nother line`,
    );
    const chat = await runWatsonRound(h.ctx, CASE, { text: "what is in the paste?", pasteId: "p1" });
    expect(h.provider.sent).toHaveLength(2);
    for (const req of h.provider.sent) {
      expect(req.userPrompt.toLowerCase()).not.toContain(UNSEEN_HOST);
      expect(req.userPrompt).not.toContain("jane.roe");
      expect(req.userPrompt).not.toContain("10.1.2.3");
      expect(req.userPrompt).toMatch(/ANON_HOST_\d+/);
      expect(req).not.toHaveProperty("promptEntities");
    }
    // The answer comes back with the real value restored.
    expect(chat.turns.at(-1)?.text).toBe(`Seen ${UNSEEN_HOST}`);
  });

  it("keeps masking a paste hostname that Watson repeated, in a later round with no paste", async () => {
    const h = await harness([reply({ message: `The host ${UNSEEN_HOST} talks out.` }), reply()], {
      anonymize: true,
    });
    await addPaste(h, "p1", `${UNSEEN_HOST} 443`);
    await runWatsonRound(h.ctx, CASE, { text: "look", pasteId: "p1" });
    await runWatsonRound(h.ctx, CASE, { text: "and now?" });
    expect(h.provider.sent[1].userPrompt).not.toContain(UNSEEN_HOST);
  });

  it("attaches a new paste's head again when the round that carried it failed", async () => {
    const h = await harness(["not json {{", reply()]);
    await addPaste(h, "p1", "first paste line\nsecond");
    await runWatsonRound(h.ctx, CASE, { text: "look", pasteId: "p1" });
    await runWatsonRound(h.ctx, CASE, { text: "look again", pasteId: "p1" });
    expect(h.provider.sent[1].userPrompt).toContain("first paste line");
  });

  it("refuses a stored paste name that is not a bare file name", async () => {
    const h = await harness([reply()]);
    await h.chatStore.update(CASE, (c) => ({
      ...c,
      pastes: [{ id: "p9", storedName: "../../etc/passwd", filename: "x", bytes: 1, lines: 1, at: "t" }],
    }));
    const chat = await runWatsonRound(h.ctx, CASE, { text: "x", pasteId: "p9" });
    expect(h.provider.sent).toHaveLength(0);
    expect(chat.turns.at(-1)).toMatchObject({ role: "system", error: true });
  });
});
