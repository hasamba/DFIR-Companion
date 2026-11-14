import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { AiControlStore } from "../../../src/analysis/aiControl.js";
import { AiCostStore } from "../../../src/analysis/aiCost.js";
import { CommentsStore } from "../../../src/analysis/comments.js";
import { DwellWindowStore } from "../../../src/analysis/dwellWindowStore.js";
import { HostScopeStore } from "../../../src/analysis/hostScopeStore.js";
import { HuntOutcomeStore } from "../../../src/analysis/huntOutcomeStore.js";
import { HypothesisStore } from "../../../src/analysis/hypothesisStore.js";
import { NotebookStore } from "../../../src/analysis/notebookStore.js";
import { StateLock } from "../../../src/analysis/stateLock.js";
import { StateStore } from "../../../src/analysis/stateStore.js";
import { emptyState, type ForensicEvent } from "../../../src/analysis/stateTypes.js";
import { TagsStore } from "../../../src/analysis/tags.js";
import { WatsonChatStore } from "../../../src/analysis/ai/watson/chatStore.js";
import { graphMaxEdges } from "../../../src/analysis/ai/analystContext.js";
import { WATSON_CASE_CONTEXT_PROMPT_MAX } from "../../../src/analysis/ai/watson/promptBuilder.js";
import { runWatsonRound, type WatsonRoundContext } from "../../../src/analysis/ai/watson/round.js";
import type { AIProvider, AnalyzeRequest, AnalyzeResult } from "../../../src/providers/provider.js";
import { CaseStore } from "../../../src/storage/caseStore.js";

const CASE = "c1";

class FakeProvider implements AIProvider {
  readonly name = "fake";
  readonly model = "fake-model";
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

const ev = (id: string, over: Partial<ForensicEvent> = {}): ForensicEvent => ({
  id,
  timestamp: "2026-01-01T10:00:00Z",
  description: `event ${id}`,
  severity: "High",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
  ...over,
});

async function make(timeline: ForensicEvent[]) {
  const root = await mkdtemp(join(tmpdir(), "dfir-watson-parity-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: CASE, name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(cases);
  await stateStore.save({ ...emptyState(CASE), forensicTimeline: timeline });
  const stores = {
    hypothesisStore: new HypothesisStore(cases),
    hostScopeStore: new HostScopeStore(cases),
    dwellWindowStore: new DwellWindowStore(cases),
    huntOutcomeStore: new HuntOutcomeStore(cases),
    tagsStore: new TagsStore(cases),
    commentsStore: new CommentsStore(cases),
    notebookStore: new NotebookStore(cases),
    aiControlStore: new AiControlStore(cases),
  };
  const provider = new FakeProvider();
  const costStore = new AiCostStore(cases);
  const ctx: WatsonRoundContext = {
    opts: { stateStore, retries: 0, backoffMs: 0, ...stores },
    requireProvider: () => provider,
    getKevCatalog: async () => undefined,
    withRetry: (_c, _l, fn) => fn(),
    analyzeRestored: async (_caseId, _state, p, req) => p.analyze(req),
    chatStore: new WatsonChatStore(cases),
    stateStore,
    stateLock: new StateLock(),
    cases,
    costStore,
    provider,
    isAiEnabled: async () => true,
  };
  return { ctx, provider, stores, stateStore };
}

describe("Watson reads the case context Ask did", () => {
  it("carries every analyst decision block and the graph, and the notebook only when opted in", async () => {
    const { ctx, provider, stores } = await make([
      ev("e1", { asset: "WS01", parentName: "excel.exe", processName: "powershell.exe" }),
      ev("e2", { asset: "WS01", dstIp: "203.0.113.9", port: 443 }),
    ]);
    await stores.hypothesisStore.add(CASE, {
      title: "Data left via OneDrive",
      expectedOutcome: "egress to onedrive.example.com",
    });
    await stores.hostScopeStore.append(CASE, {
      host: "FS01",
      from: "unknown",
      to: "cleared",
      reason: "full triage, nothing",
      analyst: "carol",
      at: "2026-01-03T00:00:00Z",
      basis: { sources: [], windowCovered: true, tacticsCovered: [], evidenceFingerprint: "" },
    });
    await stores.dwellWindowStore.add(CASE, {
      label: "Session 1",
      start: "2026-01-01T10:00:00Z",
      end: "2026-01-01T12:00:00Z",
    });
    await stores.huntOutcomeStore.save(CASE, [
      {
        id: "h1",
        source: "fleet",
        title: "Sweep for the staging archive",
        vqlFingerprint: "abc",
        vqlPreview: "SELECT * FROM glob(...)",
        mitreTechniques: ["T1074"],
        deployedAt: "2026-01-02T00:00:00Z",
        status: "collected",
        foundEvidence: false,
        resultSummary: "no results",
      },
    ]);
    await stores.tagsStore.add(CASE, {
      targetType: "event",
      targetId: "e1",
      author: "alice",
      label: "starred",
    });
    await stores.commentsStore.add(CASE, {
      targetType: "event",
      targetId: "e1",
      author: "bob",
      text: "the staging archive",
    });
    await stores.aiControlStore.save(CASE, { enabled: true, lastAnalyzedSeq: 0, includeNotebook: false });
    await stores.notebookStore.add(CASE, { text: "check the proxy logs for 198.51.100.7", type: "note" });

    await runWatsonRound(ctx, CASE, { text: "Where did it go?" });
    const first = provider.sent[0].userPrompt;
    expect(first).toContain("- [open] Data left via OneDrive — decided by: egress to onedrive.example.com");
    expect(first).toContain("- FS01: cleared — full triage, nothing (carol, 2026-01-03)");
    expect(first).toContain("- Session 1: 2026-01-01T10:00:00.000Z → 2026-01-01T12:00:00.000Z");
    expect(first).toContain('[collected] "Sweep for the staging archive" — no results');
    expect(first).toContain('- [event e1] tags: starred · "the staging archive" (bob)');
    expect(first).toContain("excel.exe → powershell.exe on WS01");
    expect(first).toContain("203.0.113.9:443");
    expect(first).not.toContain("check the proxy logs");
    const order = ["ATTACK GRAPH", "ATTACKER PATH:", "FINDINGS:", "ANALYST HYPOTHESES", "FORENSIC TIMELINE"];
    const at = order.map((h) => first.indexOf(h));
    expect(at.every((p) => p >= 0)).toBe(true);
    expect([...at].sort((a, b) => a - b)).toEqual(at);

    await stores.aiControlStore.save(CASE, { enabled: true, lastAnalyzedSeq: 0, includeNotebook: true });
    await runWatsonRound(ctx, CASE, { text: "And now?" });
    expect(provider.sent[1].userPrompt).toContain("[NOTE] check the proxy logs for 198.51.100.7");
  });

  it("stores coverage on the Watson turn when the timeline was trimmed, and not otherwise", async () => {
    const many = Array.from({ length: 2000 }, (_, i) =>
      ev(`e${i}`, { description: `process created with a long command line number ${i} `.repeat(4) }),
    );
    const big = await make(many);
    const chat = await runWatsonRound(big.ctx, CASE, { text: "Summarise" });
    const turn = chat.turns.find((t) => t.role === "watson");
    expect(turn?.coverage?.eventCount).toBe(2000);
    expect(turn?.coverage?.usedEvents).toBeLessThan(2000);
    // Task 11: the packet tells Watson it is partial and how to read the rest.
    const used = turn?.coverage?.usedEvents ?? -1;
    expect(big.provider.sent[0].userPrompt).toContain(
      `(showing ${used} of 2000 in-scope events — ask for a 'lookup' to read others)`,
    );

    const small = await make([ev("e1")]);
    const chat2 = await runWatsonRound(small.ctx, CASE, { text: "Summarise" });
    expect(chat2.turns.find((t) => t.role === "watson")?.coverage).toBeUndefined();
    expect(small.provider.sent[0].userPrompt).not.toContain("ask for a 'lookup'");
  });
});

// Ported from Ask's own tests (askAnalystDecisions, askGraphRag) when Watson retired Ask: the shared
// renderers are exercised through Watson's prompt now.
describe("Watson's case context, as Ask's tests pinned it", () => {
  const DECISION_HEADERS = [
    "ANALYST HYPOTHESES",
    "ANALYST HOST-SCOPE DECISIONS",
    "ANALYST DWELL WINDOWS",
    "PRIOR HUNTS",
    "ANALYST MARKS",
    "ANALYST NOTEBOOK",
  ];

  it("emits no decision block and no ATTACK GRAPH on a fresh case with no causal edges", async () => {
    const { ctx, provider } = await make([ev("e1", { description: "a lone observation", severity: "Low" })]);
    await runWatsonRound(ctx, CASE, { text: "Anything?" });
    const prompt = provider.sent[0].userPrompt;
    for (const h of DECISION_HEADERS) expect(prompt).not.toContain(h);
    expect(prompt).not.toContain("ATTACK GRAPH");
  });

  it("serializes the evidence-chain graph with its relationship headings and citable event ids (#98)", async () => {
    const { ctx, provider } = await make([
      ev("e1", { asset: "WEB01", parentName: "excel.exe", processName: "powershell.exe" }),
      ev("e2", { asset: "WEB01", dstIp: "203.0.113.4", port: 443 }),
    ]);
    await runWatsonRound(ctx, CASE, { text: "Trace the path from the document to the C2 server" });
    const prompt = provider.sent[0].userPrompt;
    expect(prompt).toContain("Process spawns (parent → child):");
    expect(prompt).toContain("excel.exe → powershell.exe on WEB01");
    expect(prompt).toContain("[e1]");
    expect(prompt).toContain("Network connections (source → destination):");
    expect(prompt).toContain("203.0.113.4:443");
  });

  it("names the surviving event for a mark made on a folded-away one (#1715)", async () => {
    const { ctx, provider, stores, stateStore } = await make([ev("e9")]);
    await stateStore.save({ ...(await stateStore.load(CASE)), eventAliases: { e1: "e9" } });
    await stores.tagsStore.add(CASE, {
      targetType: "event",
      targetId: "e1",
      label: "starred",
      author: "bob",
    });
    await runWatsonRound(ctx, CASE, { text: "Anything?" });
    const prompt = provider.sent[0].userPrompt;
    expect(prompt).toContain("- [event e9] tags: starred");
    expect(prompt).not.toContain("[event e1]");
  });
});

describe("Watson bounds the analyst-decision context", () => {
  it("keeps the case context inside its cap, keeps timeline rows, and discloses the trim on the turn", async () => {
    const { ctx, provider, stores } = await make([ev("e1"), ev("e2"), ev("e3")]);
    await stores.aiControlStore.save(CASE, { enabled: true, lastAnalyzedSeq: 0, includeNotebook: true });
    for (let i = 0; i < 400; i++) {
      await stores.notebookStore.add(CASE, { text: `note ${i} ${"lorem ipsum ".repeat(60)}`, type: "note" });
      await stores.commentsStore.add(CASE, {
        targetType: "event",
        targetId: "e1",
        author: "bob",
        text: `comment ${i} ${"dolor sit ".repeat(60)}`,
      });
    }
    const chat = await runWatsonRound(ctx, CASE, { text: "Summarise" });
    const prompt = provider.sent[0].userPrompt;
    const body = prompt.slice(prompt.indexOf("<<<CONTEXT>>>") + 13, prompt.indexOf("<<<END CONTEXT>>>"));
    expect(body.length).toBeLessThanOrEqual(WATSON_CASE_CONTEXT_PROMPT_MAX + 2);
    expect(body).toContain("analyst decisions trimmed to fit the prompt");
    expect(body).toContain("[e1]");
    expect(body).toContain("FORENSIC TIMELINE");
    const turn = chat.turns.find((t) => t.role === "watson");
    expect(turn?.coverage).toMatchObject({ decisionsTrimmed: true, usedEvents: 3, eventCount: 3 });
  });
});

describe("graphMaxEdges", () => {
  it("prefers the Watson name, falls back to the Ask name, then the default", () => {
    expect(graphMaxEdges({ DFIR_AI_WATSON_GRAPH_MAX_EDGES: "7", DFIR_ASK_GRAPH_MAX_EDGES: "9" })).toBe(7);
    expect(graphMaxEdges({ DFIR_ASK_GRAPH_MAX_EDGES: "9" })).toBe(9);
    expect(graphMaxEdges({})).toBe(120);
  });
});
