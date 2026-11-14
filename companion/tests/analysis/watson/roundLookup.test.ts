import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { AiCostStore } from "../../../src/analysis/aiCost.js";
import { AnonControlStore } from "../../../src/analysis/anonControl.js";
import type { Logger } from "../../../src/logging/logger.js";
import { analyzeRestored } from "../../../src/analysis/ai/providerCall.js";
import { WatsonChatStore } from "../../../src/analysis/ai/watson/chatStore.js";
import { runWatsonRound, type WatsonRoundContext } from "../../../src/analysis/ai/watson/round.js";
import { StateLock } from "../../../src/analysis/stateLock.js";
import { StateStore } from "../../../src/analysis/stateStore.js";
import { emptyState, type Finding, type ForensicEvent } from "../../../src/analysis/stateTypes.js";
import type { AIProvider, AnalyzeRequest, AnalyzeResult } from "../../../src/providers/provider.js";
import { CaseStore } from "../../../src/storage/caseStore.js";

// Task 11: one lookup hop per round over the FORENSIC timeline, the same hop a paste search uses.

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
  constructor(private readonly replies: (string | Error)[]) {}
  async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
    this.sent.push(req);
    const next = this.replies.shift() ?? "{}";
    if (next instanceof Error) throw next;
    return { rawText: next, usage: { costUSD: 0.1 } };
  }
}

const reply = (over: Record<string, unknown> = {}): string =>
  JSON.stringify({
    message: "I looked at the case.",
    workingOn: "",
    learned: "",
    questionUpdates: [],
    newQuestions: [],
    request: null,
    search: null,
    memory: "memory v1",
    ...over,
  });

const ev = (id: string, minute: number, over: Partial<ForensicEvent> = {}): ForensicEvent => ({
  id,
  timestamp: `2026-01-01T15:${String(minute).padStart(2, "0")}:00Z`,
  description: `quiet event ${id}`,
  severity: "Low",
  sources: ["Hayabusa"],
  asset: "HOST-A",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
  ...over,
});

async function harness(
  replies: (string | Error)[],
  opts: { events?: ForensicEvent[]; findings?: Finding[]; costLimitUSD?: number; anonymize?: boolean } = {},
) {
  const root = await mkdtemp(join(tmpdir(), "dfir-watson-lookup-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: CASE, name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(cases);
  await stateStore.save({
    ...emptyState(CASE),
    forensicTimeline: opts.events ?? [ev("e1", 0)],
    findings: opts.findings ?? [],
  });
  const anonStore = new AnonControlStore(cases);
  await anonStore.save(CASE, { ...(await anonStore.load(CASE)), enabled: opts.anonymize ?? false });
  const costStore = new AiCostStore(cases);
  const provider = new FakeProvider(replies);
  const gateCtx = { log, opts: { anonStore, aiCostStore: costStore } };
  const chatStore = new WatsonChatStore(cases);
  const ctx: WatsonRoundContext = {
    opts: { stateStore, retries: 0, backoffMs: 0 },
    log,
    requireProvider: () => provider,
    getKevCatalog: async () => undefined,
    withRetry: (_c, _l, fn) => fn(),
    analyzeRestored: (caseId, state, p, req, label, skip) =>
      analyzeRestored(gateCtx, caseId, state, p, req, label, skip),
    chatStore,
    stateStore,
    stateLock: new StateLock(),
    cases,
    costStore,
    provider,
    isAiEnabled: async () => true,
    ...(opts.costLimitUSD !== undefined ? { costLimitUSD: opts.costLimitUSD } : {}),
  };
  return { ctx, provider, chatStore };
}

const finding = (id: string, relatedEventIds: string[]): Finding =>
  ({
    id,
    title: `finding ${id}`,
    description: "d",
    severity: "High",
    relatedIocs: [],
    sourceScreenshots: [],
    mitreTechniques: [],
    relatedEventIds,
    firstSeen: "2026-01-01T00:00:00Z",
    lastUpdated: "2026-01-01T00:00:00Z",
    status: "open",
  }) as unknown as Finding;

describe("Watson's timeline lookup hop", () => {
  it("runs once: the second call gets the looked-up rows, and a further lookup is ignored", async () => {
    const h = await harness(
      [
        reply({ lookup: { findingIds: ["f6"] } }),
        reply({ message: "Now I see them.", lookup: { host: "HOST-A" } }),
        reply({ message: "should never be asked" }),
      ],
      {
        events: [ev("e1", 0), ev("e2", 56, { description: "rar.exe a loot.rar" })],
        findings: [finding("f6", ["e2"])],
      },
    );
    const chat = await runWatsonRound(h.ctx, CASE, { text: "what happened at 15:56?" });
    expect(h.provider.sent).toHaveLength(2);
    const second = h.provider.sent[1].userPrompt;
    expect(second).toContain("<<<LOOKUP>>>");
    expect(second).toMatch(/\[e2\] 2026-01-01T15:56:00Z \[Low\] rar\.exe a loot\.rar/);
    const turn = chat.turns.at(-1)!;
    expect(turn.text).toBe("Now I see them.");
    expect(turn.lookedUp).toMatchObject({ shown: 1, matched: 1 });
    expect(turn.lookedUp?.what).toContain("f6");
    expect(chat.calls).toBe(2);
    // The disclosure survives a reload of the chat file.
    expect((await h.chatStore.load(CASE)).turns.at(-1)?.lookedUp).toEqual(turn.lookedUp);
  });

  it("a looked-up event may be cited in the answer and in a finding", async () => {
    const h = await harness(
      [
        reply({ lookup: { eventIds: ["e2"] } }),
        reply({
          answer: {
            question: "q?",
            status: "answered",
            answer: "a",
            pointer: "p",
            relatedEventIds: ["e2", "nope"],
          },
          writes: {
            findings: [
              {
                severity: "High",
                title: "Staging",
                description: "rar",
                mitreTechniques: [],
                eventIds: ["e2"],
                pasteLines: [],
              },
            ],
          },
        }),
      ],
      { events: [ev("e1", 0), ev("e2", 56)] },
    );
    const chat = await runWatsonRound(h.ctx, CASE, { text: "q?" });
    expect(chat.turns.at(-1)?.answer?.relatedEventIds).toEqual(["e2"]);
    expect(chat.proposals.some((p) => p.kind === "finding_new")).toBe(true);
  });

  it("an empty lookup still answers, and says nothing matched", async () => {
    const h = await harness([reply({ lookup: { text: "never-there" } }), reply({ message: "none" })]);
    const chat = await runWatsonRound(h.ctx, CASE, { text: "x" });
    expect(h.provider.sent[1].userPrompt).toContain("(no event matched the lookup)");
    expect(chat.turns.at(-1)?.lookedUp).toMatchObject({ shown: 0, matched: 0 });
  });

  it("skips the lookup when the first call reached the cost limit, and says so", async () => {
    const h = await harness([reply({ lookup: { host: "HOST-A" } })], { costLimitUSD: 0.05 });
    const chat = await runWatsonRound(h.ctx, CASE, { text: "x" });
    expect(h.provider.sent).toHaveLength(1);
    expect(chat.turns.at(-1)?.text).toMatch(/look up.*cost limit/is);
    expect(chat.turns.at(-1)?.lookedUp).toBeUndefined();
  });

  it("a failed second call keeps the first reply and adds a note", async () => {
    const h = await harness([reply({ message: "FIRST", lookup: { host: "HOST-A" } }), new Error("boom")]);
    const chat = await runWatsonRound(h.ctx, CASE, { text: "x" });
    const turn = chat.turns.at(-1)!;
    expect(turn.role).toBe("watson");
    expect(turn.text).toContain("FIRST");
    expect(turn.text).toMatch(/lookup.*failed.*boom/is);
    expect(turn.lookedUp).toBeUndefined();
  });

  it("an invalid lookup is dropped with a note and no second call", async () => {
    const h = await harness([reply({ message: "FIRST", lookup: { from: "2026-01-01T00:00:00Z" } })]);
    const chat = await runWatsonRound(h.ctx, CASE, { text: "x" });
    expect(h.provider.sent).toHaveLength(1);
    expect(chat.turns.at(-1)?.text).toMatch(/FIRST[\s\S]*lookup[\s\S]*not valid/i);
  });

  it("matches the analyst's real host after masking, and the second prompt never shows it", async () => {
    const host = "ws-pay-07.example.com";
    const h = await harness([reply({ lookup: { host: "PLACEHOLDER" } }), reply({ message: "ok" })], {
      anonymize: true,
      events: [
        ev("e1", 0, { asset: host, description: `logon on ${host}` }),
        ev("e2", 1, { asset: "OTHER" }),
      ],
    });
    // Watson can only name the host by the token it was shown; ask with that token.
    const inner = h.provider.analyze.bind(h.provider);
    let first = true;
    h.provider.analyze = async (req) => {
      if (first) {
        first = false;
        const token = req.userPrompt.match(/ANON_HOST_\d+/)?.[0] ?? "missing";
        const out = await inner(req);
        return { ...out, rawText: out.rawText.replace("PLACEHOLDER", token) };
      }
      return inner(req);
    };
    const chat = await runWatsonRound(h.ctx, CASE, { text: "x" });
    expect(chat.turns.at(-1)?.lookedUp).toMatchObject({ shown: 1, matched: 1 });
    expect(h.provider.sent[1].userPrompt.toLowerCase()).not.toContain(host);
    expect(h.provider.sent[1].userPrompt).toContain("[e1]");
  });
});
