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
import { withRetry } from "../../../src/analysis/ai/retry.js";
import { StateLock } from "../../../src/analysis/stateLock.js";
import { StateStore } from "../../../src/analysis/stateStore.js";
import { emptyState, type ForensicEvent } from "../../../src/analysis/stateTypes.js";
import {
  ProviderError,
  type AIProvider,
  type AnalyzeRequest,
  type AnalyzeResult,
} from "../../../src/providers/provider.js";
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
    private readonly usage: AnalyzeResult["usage"] = { costUSD: 0.1 },
  ) {}
  async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
    this.sent.push(req);
    const rawText = this.replies.shift() ?? "{}";
    return { rawText, usage: this.usage };
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
  opts: {
    aiOn?: boolean;
    anonymize?: boolean;
    costLimitUSD?: number;
    tokenLimit?: number;
    usage?: AnalyzeResult["usage"];
    /** The real retry loop with this many retries (the default harness never retries). */
    retries?: number;
  } = {},
): Promise<Harness> {
  const root = await mkdtemp(join(tmpdir(), "dfir-watson-round-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: CASE, name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(cases);
  await stateStore.save({ ...emptyState(CASE), forensicTimeline: [ev("e1")] });
  const anonStore = new AnonControlStore(cases);
  await anonStore.save(CASE, { ...(await anonStore.load(CASE)), enabled: opts.anonymize ?? false });
  const costStore = new AiCostStore(cases);
  const provider = new FakeProvider(replies, opts.usage ?? { costUSD: 0.1 });
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
    opts: { stateStore, retries: opts.retries ?? 0, backoffMs: 0 },
    log,
    requireProvider: () => provider,
    getKevCatalog: async () => undefined,
    withRetry:
      opts.retries === undefined
        ? (_c, _l, fn) => fn()
        : (_c, _l, fn, retries, backoff) => withRetry(fn, retries, backoff),
    analyzeRestored: analyzeSpy,
    chatStore,
    stateStore,
    stateLock: new StateLock(),
    cases,
    costStore,
    provider,
    isAiEnabled: async () => opts.aiOn ?? true,
    ...(opts.costLimitUSD !== undefined ? { costLimitUSD: opts.costLimitUSD } : {}),
    ...(opts.tokenLimit !== undefined ? { tokenLimit: opts.tokenLimit } : {}),
  };
  return { ctx, provider, chatStore, stateStore, cases, costStore, analyzeSpy };
}

async function addPaste(h: Harness, id: string, text: string, unread = false): Promise<WatsonPaste> {
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
  await h.chatStore.update(CASE, (c) => ({
    ...c,
    pastes: [...c.pastes, paste],
    unreadPasteIds: unread ? [...c.unreadPasteIds, id] : c.unreadPasteIds,
  }));
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

  it("cost limit: a malformed first reply that reaches the limit gets no retry", async () => {
    const h = await harness(["not json {{", reply()], { costLimitUSD: 0.1, retries: 3 });
    const chat = await runWatsonRound(h.ctx, CASE, { text: "hi" });
    expect(h.provider.sent).toHaveLength(1);
    expect(chat.calls).toBe(1);
    expect(chat.turns.at(-1)).toMatchObject({ role: "system", error: true });
    expect(chat.turns.at(-1)?.text).toMatch(/cost limit/i);
  });

  it("counts provider attempts, not rounds: a retried malformed reply is two calls", async () => {
    const h = await harness(["not json {{", reply({ message: "second try" })], { retries: 3 });
    const chat = await runWatsonRound(h.ctx, CASE, { text: "hi" });
    expect(h.provider.sent).toHaveLength(2);
    expect(chat.calls).toBe(2);
    expect(chat.turns.at(-1)?.text).toBe("second try");
  });

  it("does not retry a Presidio hold", async () => {
    const h = await harness([reply()], { retries: 3 });
    let attempts = 0;
    h.ctx = {
      ...h.ctx,
      analyzeRestored: async () => {
        attempts++;
        throw new PresidioApprovalRequired([{ value: "Jane Roe", category: "PERSON" }]);
      },
    };
    await expect(runWatsonRound(h.ctx, CASE, { text: "x" })).rejects.toBeInstanceOf(PresidioApprovalRequired);
    expect(attempts).toBe(1);
  });

  it("tells the dashboard the state changed when it seeds the questions, even if the call then fails", async () => {
    const h = await harness(["not json {{"]);
    const changed: string[] = [];
    h.ctx = { ...h.ctx, onStateChanged: (id) => changed.push(id) };
    await runWatsonRound(h.ctx, CASE, { text: "go" });
    expect(changed).toEqual([CASE]);
    await runWatsonRound(h.ctx, CASE, { text: "again" });
    expect(changed).toEqual([CASE]); // seeded once, announced once
  });

  it("re-attaches an unread paste on the next message after a held round, and clears it once read", async () => {
    const h = await harness([reply(), reply()]);
    await addPaste(h, "p1", "first paste line\nsecond", true);
    const inner = h.ctx.analyzeRestored;
    h.ctx = {
      ...h.ctx,
      analyzeRestored: async () => {
        throw new PresidioApprovalRequired([{ value: "Jane Roe", category: "PERSON" }]);
      },
    };
    await expect(runWatsonRound(h.ctx, CASE, { text: "Pasted", pasteId: "p1" })).rejects.toBeInstanceOf(
      PresidioApprovalRequired,
    );
    expect((await h.chatStore.load(CASE)).unreadPasteIds).toEqual(["p1"]);
    h.ctx = { ...h.ctx, analyzeRestored: inner };
    const chat = await runWatsonRound(h.ctx, CASE, { text: "approved, go on" });
    expect(h.provider.sent[0].userPrompt).toContain("first paste line");
    expect(chat.unreadPasteIds).toEqual([]);
    await runWatsonRound(h.ctx, CASE, { text: "next" });
    expect(h.provider.sent[1].userPrompt).not.toContain("1: first paste line");
    expect(h.provider.sent[1].userPrompt).toContain("[p1] netstat.txt (2 lines)");
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

  // Internal-suffix fixtures are assembled at runtime so the CI secret scan never sees them literally.
  const dotted = (...labels: string[]): string => labels.join(".");

  it("masks an internal host found only in an event description, and still masks the known host", async () => {
    const corpHost = dotted("ws-pay-07", "corp");
    const h = await harness([reply()], { anonymize: true });
    await h.stateStore.save({
      ...emptyState(CASE),
      forensicTimeline: [ev("e1"), { ...ev("e2"), description: `SMB session from ${corpHost} to HOST-A` }],
    });
    await runWatsonRound(h.ctx, CASE, { text: "what happened?" });
    const sent = h.provider.sent[0].userPrompt;
    expect(sent).toContain("SMB session from");
    expect(sent.toLowerCase()).not.toContain(corpHost);
    expect(sent).not.toContain("HOST-A");
    expect(new Set(sent.match(/ANON_HOST_\d+/g) ?? []).size).toBeGreaterThanOrEqual(2);
  });

  it("masking the whole prompt keeps one token per known host, file and registry names readable", async () => {
    const fqdn = "WS-PAY-08.CORP.EXAMPLE.COM";
    const h = await harness([reply({ message: `${fqdn} is the host` })], { anonymize: true });
    await h.stateStore.save({
      ...emptyState(CASE),
      forensicTimeline: [
        { ...ev("e1"), asset: fqdn, description: `logon on ${fqdn}` },
        {
          ...ev("e2"),
          description: "reg add HKLM\\Software\\Run ran update.sh and install.ps1; beacon to c2.example.net",
        },
      ],
    });
    const chat = await runWatsonRound(h.ctx, CASE, { text: "what happened?" });
    const sent = h.provider.sent[0].userPrompt;
    expect(sent.toLowerCase()).not.toContain(fqdn.toLowerCase());
    const hostToken = /logon on (ANON_HOST_\d+)/.exec(sent)?.[1];
    expect(hostToken).toBeDefined();
    expect(sent).toContain("HKLM\\Software\\Run ran update.sh and install.ps1");
    expect(sent).not.toContain("c2.example.net"); // the accepted cost: an adversary domain is a token too
    expect(chat.turns.at(-1)?.text).toBe(`${fqdn} is the host`); // restored in the case's spelling
  });

  it("masks internal-suffix hosts, short host names and machine accounts from a paste", async () => {
    const intranet = dotted("srv1", "intranet");
    const priv = dotted("nas", "private");
    const arpa = dotted("printer", "home", "arpa");
    const h = await harness([reply()], { anonymize: true });
    await addPaste(
      h,
      "p1",
      [
        `${UNSEEN_HOST} 445`,
        `share on ${intranet} and ${priv}`,
        `print to ${arpa}`,
        "logon from WS-PAY-07 as WS-PAY-07$",
        "login failed on login.microsoftonline.com",
      ].join("\n"),
    );
    await runWatsonRound(h.ctx, CASE, { text: "read it", pasteId: "p1" });
    const sent = h.provider.sent[0].userPrompt;
    for (const leak of [intranet, priv, arpa, "WS-PAY-07", "ws-pay-07", "WS-PAY-07$"]) {
      expect(sent).not.toContain(leak);
    }
    expect(sent).toContain("login failed"); // a generic first label never becomes a short-name token
  });

  it("token limit reached: throws WatsonCostLimitReached and never calls the model", async () => {
    const h = await harness([reply()], { tokenLimit: 1000, usage: { inputTokens: 10, outputTokens: 5 } });
    await h.chatStore.update(CASE, (c) => ({ ...c, tokens: 1000 }));
    await expect(runWatsonRound(h.ctx, CASE, { text: "hi" })).rejects.toBeInstanceOf(WatsonCostLimitReached);
    expect(h.provider.sent).toHaveLength(0);
    expect((await h.chatStore.load(CASE)).turns).toHaveLength(0);
  });

  it("counts tokens per round when the provider reports no dollar cost", async () => {
    const h = await harness([reply()], { usage: { inputTokens: 300, outputTokens: 40 } });
    const chat = await runWatsonRound(h.ctx, CASE, { text: "hi" });
    expect(chat.tokens).toBe(340);
    expect(chat.costUSD).toBe(0);
  });

  it("skips the search hop when the first call reached the token limit, and says so", async () => {
    const h = await harness([reply({ search: { pasteId: "p1", terms: ["x"] } })], {
      tokenLimit: 100,
      usage: { inputTokens: 90, outputTokens: 20 },
    });
    await addPaste(h, "p1", "x\ny");
    const chat = await runWatsonRound(h.ctx, CASE, { text: "search" });
    expect(h.provider.sent).toHaveLength(1);
    expect(chat.turns.at(-1)?.text).toMatch(/token limit/i);
    expect(chat.tokens).toBe(110);
  });

  it("takes the state lock only on the round that seeds the standard questions", async () => {
    const h = await harness([reply(), reply()]);
    const lock = vi.spyOn(h.ctx.stateLock, "runExclusive");
    await runWatsonRound(h.ctx, CASE, { text: "one" });
    expect(lock).toHaveBeenCalledTimes(1);
    await runWatsonRound(h.ctx, CASE, { text: "two" });
    expect(lock).toHaveBeenCalledTimes(1);
  });

  it("leaves an error turn when the spend cannot be read before the call", async () => {
    const h = await harness([reply()]);
    vi.spyOn(h.costStore, "load").mockRejectedValue(new Error("cost file unreadable"));
    const chat = await runWatsonRound(h.ctx, CASE, { text: "x" });
    expect(chat.turns.map((t) => t.role)).toEqual(["analyst", "system"]);
    expect(chat.turns[1].error).toBe(true);
  });

  it("keeps a good first reply when the spend read before the search hop fails", async () => {
    const h = await harness([reply({ message: "FIRST", search: { pasteId: "p1", terms: ["a"] } }), reply()]);
    await addPaste(h, "p1", "a\nb");
    const real = h.costStore.load.bind(h.costStore);
    // record() reads the file too; keep it out of the count so call 2 is the hop's own check.
    vi.spyOn(h.costStore, "record").mockImplementation(async (id) => real(id));
    let n = 0;
    vi.spyOn(h.costStore, "load").mockImplementation(async (id) => {
      n++;
      if (n === 2) throw new Error("cost file busy");
      return real(id);
    });
    const chat = await runWatsonRound(h.ctx, CASE, { text: "x" });
    expect(h.provider.sent).toHaveLength(1);
    expect(chat.turns.at(-1)).toMatchObject({ role: "watson" });
    expect(chat.turns.at(-1)?.text).toMatch(/^FIRST/);
  });

  it("refuses a stored paste name that is not a bare file name", async () => {
    const h = await harness([reply()]);
    await h.chatStore.update(CASE, (c) => ({
      ...c,
      pastes: [{ id: "p9", storedName: "../../etc/passwd", filename: "x", bytes: 1, lines: 1, at: "t" }],
    }));
    const chat = await runWatsonRound(h.ctx, CASE, { text: "x", pasteId: "p9" });
    // The file is never read; Watson answers without it and says so once.
    expect(h.provider.sent).toHaveLength(1);
    expect(h.provider.sent[0].userPrompt).not.toContain("<<<PASTE");
    expect(chat.turns.map((t) => t.role)).toEqual(["analyst", "watson", "system"]);
    expect(chat.turns.at(-1)?.text).toBe(
      "Watson could not read x. It stays stored as evidence — ask Watson to search it.",
    );
  });

  it("a missing stored paste file does not fail the round: Watson answers with the note", async () => {
    const h = await harness([reply({ message: "answered anyway" })]);
    await h.chatStore.update(CASE, (c) => ({
      ...c,
      pastes: [{ id: "p8", storedName: "0001_gone.txt", filename: "gone.txt", bytes: 1, lines: 1, at: "t" }],
      unreadPasteIds: ["p8"],
    }));
    const chat = await runWatsonRound(h.ctx, CASE, { text: "go on" });
    expect(chat.turns.map((t) => t.text)).toEqual([
      "go on",
      "answered anyway",
      "Watson could not read gone.txt. It stays stored as evidence — ask Watson to search it.",
    ]);
    expect(chat.unreadPasteIds).toEqual([]);
    expect(h.provider.sent[0].userPrompt).toContain("[p8] gone.txt (1 lines");
  });

  it("an auto-attached head that fails (safety stop) is tried once; the next message runs without it", async () => {
    const h = await harness([reply({ message: "second message works" })]);
    await addPaste(h, "p1", "Invoke-Mimikatz script text\nmore", true);
    const inner = h.ctx.analyzeRestored;
    let failNext = true;
    h.ctx = {
      ...h.ctx,
      analyzeRestored: async (...args) => {
        if (failNext) {
          failNext = false;
          throw new ProviderError("the model's safety filter stopped the answer", "safety_stop");
        }
        return inner(...args);
      },
    };
    const failed = await runWatsonRound(h.ctx, CASE, { text: "look" });
    expect(failed.unreadPasteIds).toEqual([]);
    expect(failed.turns.at(-1)?.text).toBe(
      "Watson could not read netstat.txt. It stays stored as evidence — ask Watson to search it.",
    );
    const chat = await runWatsonRound(h.ctx, CASE, { text: "next" });
    expect(h.provider.sent).toHaveLength(1);
    expect(h.provider.sent[0].userPrompt).not.toContain("Invoke-Mimikatz");
    expect(h.provider.sent[0].userPrompt).toContain("[p1] netstat.txt (2 lines)");
    expect(chat.turns.at(-1)?.text).toBe("second message works");
  });

  it("a Presidio hold on the auto-attached round keeps the paste unread, with no note", async () => {
    const h = await harness([reply({ message: "read it" })]);
    await addPaste(h, "p1", "held paste head line\nmore", true);
    const inner = h.ctx.analyzeRestored;
    h.ctx = {
      ...h.ctx,
      analyzeRestored: async () => {
        throw new PresidioApprovalRequired([{ value: "Jane Roe", category: "PERSON" }]);
      },
    };
    await expect(runWatsonRound(h.ctx, CASE, { text: "look" })).rejects.toBeInstanceOf(
      PresidioApprovalRequired,
    );
    const held = await h.chatStore.load(CASE);
    expect(held.unreadPasteIds).toEqual(["p1"]);
    expect(held.turns.some((t) => t.text.startsWith("Watson could not read"))).toBe(false);
    h.ctx = { ...h.ctx, analyzeRestored: inner };
    const chat = await runWatsonRound(h.ctx, CASE, { text: "approved" });
    expect(h.provider.sent[0].userPrompt).toContain("1: held paste head line");
    expect(chat.unreadPasteIds).toEqual([]);
  });

  it("a paste read through a successful search counts as read", async () => {
    const h = await harness([
      reply({ search: { pasteId: "p2", terms: ["needle"] } }),
      reply({ message: "found" }),
    ]);
    await addPaste(h, "p1", "head of the newer paste", true);
    await addPaste(h, "p2", "a\nneedle here", true);
    await h.chatStore.update(CASE, (c) => ({ ...c, unreadPasteIds: ["p2", "p1"] }));
    const chat = await runWatsonRound(h.ctx, CASE, { text: "search the older one" });
    expect(chat.turns.at(-1)?.text).toBe("found");
    expect(chat.unreadPasteIds).toEqual([]);
  });

  it("prints a key question id as it is, so an update to Q1.2 is kept", async () => {
    const h = await harness([
      reply({
        questionUpdates: [{ questionId: "Q1.2", status: "partial", answer: "RDP from VPN", pointer: "e1" }],
      }),
    ]);
    await h.stateStore.save({
      ...emptyState(CASE),
      forensicTimeline: [ev("e1")],
      keyQuestions: [
        { id: "wq-std-what", question: "What happened?", status: "unknown", answer: "", pointer: "" },
        { id: "Q1.2", question: "How did they get in?", status: "unknown", answer: "", pointer: "" },
      ],
    });
    const chat = await runWatsonRound(h.ctx, CASE, { text: "go" });
    expect(h.provider.sent[0].userPrompt).toContain("- [Q1.2] (unknown) How did they get in?");
    expect(chat.proposals.map((p) => p.questionId)).toEqual(["Q1.2"]);
  });
});
