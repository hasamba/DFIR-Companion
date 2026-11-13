import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { buildCollectionInventory } from "../../../src/analysis/collectionInventory.js";
import { AnalysisPipeline } from "../../../src/analysis/pipeline.js";
import { StateStore as CaseStateStore } from "../../../src/analysis/stateStore.js";
import type { AnalyzeRequest, AnalyzeResult } from "../../../src/providers/provider.js";
import { CaseStore } from "../../../src/storage/caseStore.js";
import { buildCurrentKeyQuestionsBlock } from "../../../src/analysis/ai/currentKeyQuestionsBlock.js";
import { foldSynthesisDelta, type DeltaFoldContext } from "../../../src/analysis/ai/synthesisMerge.js";
import { persistSynthesis } from "../../../src/analysis/ai/synthesisPersist.js";
import { deltaSchema } from "../../../src/analysis/responseSchema.js";
import { StateLock } from "../../../src/analysis/stateLock.js";
import { mergeDelta } from "../../../src/analysis/stateMerge.js";
import type { StateStore } from "../../../src/analysis/stateStore.js";
import {
  emptyState,
  type ForensicEvent,
  type InvestigationQuestion,
  type InvestigationState,
} from "../../../src/analysis/stateTypes.js";

// Watson answers the analyst applied survive a synthesis: the whole fold (pinned merge, the
// key-question corrections, the coverage backstop) and the locked persist. Synthesis may still say
// it disagrees, in synthesisDisagrees, but it never overwrites the applied answer.

const watsonQ: InvestigationQuestion = {
  id: "q-access",
  question: "What was the initial access vector?",
  status: "answered",
  answer: "A phishing mail from mailer.example.com",
  pointer: "row 12 of the pasted mail log",
  pinned: true,
  author: "watson",
};

const analystPinned: InvestigationQuestion = {
  id: "q-pinned",
  question: "Was the backup server touched?",
  status: "unknown",
  answer: "",
  pointer: "",
  pinned: true,
};

const delta = (keyQuestions: unknown[]) =>
  deltaSchema.parse({
    findings: [],
    iocs: [],
    mitreTechniques: [],
    threadsOpened: [],
    threadsClosed: [],
    timelineNote: "n",
    summary: "s",
    keyQuestions,
  });

function context(stored: () => InvestigationState): DeltaFoldContext {
  return {
    opts: { stateStore: { load: async () => stored() } } as unknown as DeltaFoldContext["opts"],
    mergeWithAliases: async (base, d, ctx) => mergeDelta(base, d, ctx),
  };
}

async function fold(
  state: InvestigationState,
  keyQuestions: unknown[],
  stored: InvestigationState = state,
): Promise<InvestigationState> {
  const result = await foldSynthesisDelta(
    context(() => stored),
    {
      caseId: "c1",
      state,
      delta: delta(keyQuestions),
      markers: [],
      scopedEvents: state.forensicTimeline,
      playbookTasks: [],
    },
  );
  return result.next;
}

const byId = (s: InvestigationState, id: string) => s.keyQuestions.find((q) => q.id === id);
const withQs = (...keyQuestions: InvestigationQuestion[]): InvestigationState => ({
  ...emptyState("c1"),
  keyQuestions,
});

describe("the synthesis fold keeps Watson answers", () => {
  it("keeps Watson's answer and records a different synthesis status as a disagreement", async () => {
    const next = await fold(withQs(watsonQ), [
      { id: "q-access", question: "Initial access?", status: "partial", answer: "Maybe a VPN login" },
    ]);
    const q = byId(next, "q-access");
    expect(q).toMatchObject({
      status: "answered",
      answer: watsonQ.answer,
      pointer: watsonQ.pointer,
      question: watsonQ.question,
      pinned: true,
      author: "watson",
    });
    expect(q?.synthesisDisagrees).toEqual({ status: "partial", answer: "Maybe a VPN login" });
  });

  it("clears an old disagreement when synthesis now agrees", async () => {
    const stale = { ...watsonQ, synthesisDisagrees: { status: "unknown" as const, answer: "" } };
    const next = await fold(withQs(stale), [
      { id: "q-access", question: "Initial access?", status: "answered", answer: "Phishing" },
    ]);
    const q = byId(next, "q-access");
    expect(q?.answer).toBe(watsonQ.answer);
    expect(q?.synthesisDisagrees).toBeUndefined();
  });

  it("keeps a Watson question synthesis did not return", async () => {
    const next = await fold(withQs(watsonQ), []);
    expect(byId(next, "q-access")).toMatchObject({ answer: watsonQ.answer, author: "watson", pinned: true });
  });

  it("leaves an analyst-pinned question without an author exactly as today: synthesis answers it", async () => {
    const next = await fold(withQs(analystPinned), [
      { id: "q-pinned", question: "Backup?", status: "answered", answer: "Yes, at 10:02" },
    ]);
    const q = byId(next, "q-pinned");
    expect(q).toMatchObject({ status: "answered", answer: "Yes, at 10:02", pinned: true });
    expect(q?.author).toBeUndefined();
    expect(q?.synthesisDisagrees).toBeUndefined();
  });

  it("survives the key-question correction that resets an answer resting on a dropped finding", async () => {
    const resting = { ...watsonQ, relatedFindingIds: ["f-gone"] };
    const state = withQs(resting);
    // Synthesis agrees on the status, but the finding the answer cites is no longer in the case, so
    // the deterministic correction would force the question back to "unknown".
    const next = await fold(state, [
      { id: "q-access", question: "Initial access?", status: "answered", answer: "Phishing" },
    ]);
    const q = byId(next, "q-access");
    expect(q).toMatchObject({ status: "answered", answer: watsonQ.answer, author: "watson", pinned: true });
    expect(q?.synthesisDisagrees?.status).toBe("unknown");
  });

  it("restores Watson's answer when it changed after the snapshot synthesis reasoned over", async () => {
    const older = { ...watsonQ, status: "partial" as const, answer: "older Watson answer" };
    const next = await fold(
      withQs(older),
      [{ id: "q-access", question: "Initial access?", status: "unknown" }],
      {
        ...withQs(watsonQ),
      },
    );
    const q = byId(next, "q-access");
    expect(q).toMatchObject({ status: "answered", answer: watsonQ.answer });
    expect(q?.synthesisDisagrees).toBeUndefined();
  });

  it("restores Watson's answer after the coverage backstop, the fold's last key-question pass", async () => {
    // Detections only on WS01, nothing raw: the backstop would downgrade a "nothing observed"
    // answer to "partial" and attach a collection request.
    const sigma = (id: string, severity: ForensicEvent["severity"]): ForensicEvent => ({
      id,
      timestamp: "2026-08-26T13:00:00.000Z",
      description: `Sigma hit ${id}`,
      severity,
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
      asset: "WS01",
      sources: ["Chainsaw"],
    });
    const events = [sigma("e1", "Medium"), sigma("e2", "Medium")];
    const impact: InvestigationQuestion = {
      id: "q_impact",
      question: "What was the impact?",
      status: "answered",
      answer: "No confirmed data encryption or destruction was observed.",
      pointer: "",
      pinned: true,
      author: "watson",
    };
    const state = { ...withQs(impact), forensicTimeline: events };
    const result = await foldSynthesisDelta(
      context(() => state),
      {
        caseId: "c1",
        state,
        delta: delta([{ id: "q_impact", question: "Impact?", status: "answered", answer: impact.answer }]),
        markers: [],
        scopedEvents: events,
        playbookTasks: [],
        inventory: buildCollectionInventory({ events }),
      },
    );
    const q = byId(result.next, "q_impact");
    expect(q).toMatchObject({ status: "answered", answer: impact.answer, author: "watson", pinned: true });
    expect(q?.synthesisDisagrees?.status).toBe("partial");
    expect(q?.collect?.host).toBe("WS01"); // the backstop's collection request is kept
  });

  it("CURRENT RULE, a decision for the caller: an applied but unanswered Watson question stays unknown", async () => {
    // A question_new (and each of the six standard seeds) is stored "unknown" with no answer and
    // author "watson". The binding rule restores every Watson question, so synthesis's answer lands
    // in synthesisDisagrees instead of on the question. See the task-7 report, concern 1.
    const asked: InvestigationQuestion = { ...watsonQ, status: "unknown", answer: "", pointer: "" };
    const next = await fold(withQs(asked), [
      { id: "q-access", question: "Initial access?", status: "answered", answer: "Phishing" },
    ]);
    const q = byId(next, "q-access");
    expect(q).toMatchObject({ status: "unknown", answer: "" });
    expect(q?.synthesisDisagrees).toEqual({ status: "answered", answer: "Phishing" });
  });

  it("does not bring back a Watson question undone after the snapshot", async () => {
    const next = await fold(
      withQs(watsonQ),
      [{ id: "q-access", question: "Initial access?", status: "partial" }],
      {
        ...withQs(),
      },
    );
    expect(byId(next, "q-access")).toBeUndefined();
  });
});

function memoryStore(initial: InvestigationState) {
  let current = initial;
  const store = {
    load: async () => current,
    save: async (s: InvestigationState) => {
      current = s;
    },
  } as unknown as StateStore;
  return { store, set: (s: InvestigationState) => (current = s) };
}

const persist = (loaded: InvestigationState, next: InvestigationState, latest: InvestigationState) => {
  const mem = memoryStore(latest);
  return persistSynthesis({ opts: { stateStore: mem.store, stateLock: new StateLock() } }, "c1", {
    loaded,
    next,
    findingsDiff: { added: [], removed: [], severityChanged: [] },
  });
};

describe("the synthesis persist keeps Watson writes that landed during the run", () => {
  const disagreeing = { ...watsonQ, synthesisDisagrees: { status: "partial" as const, answer: "VPN" } };

  it("keeps the run's protected copy, disagreement included, when nothing changed meanwhile", async () => {
    const loaded = withQs(watsonQ);
    const out = await persist(loaded, withQs(disagreeing), loaded);
    expect(byId(out, "q-access")).toEqual(disagreeing);
  });

  it("an apply during the run wins over the run's copy, with no disagreement invented", async () => {
    const before = {
      ...watsonQ,
      status: "unknown" as const,
      answer: "",
      author: undefined,
      pinned: undefined,
    };
    const loaded = withQs(before);
    const runCopy = { ...before, status: "partial" as const, answer: "synthesis view" };
    const out = await persist(loaded, withQs(runCopy), withQs(watsonQ));
    expect(byId(out, "q-access")).toEqual(watsonQ);
  });

  it("a Watson re-apply during the run wins over the run's older Watson copy", async () => {
    const newer = { ...watsonQ, status: "partial" as const, answer: "Watson revised it" };
    const out = await persist(withQs(watsonQ), withQs(disagreeing), withQs(newer));
    expect(byId(out, "q-access")).toEqual(newer);
  });

  it("an undo of a new question during the run removes it from the save", async () => {
    const out = await persist(
      withQs(watsonQ, analystPinned),
      withQs(watsonQ, analystPinned),
      withQs(analystPinned),
    );
    expect(byId(out, "q-access")).toBeUndefined();
    expect(byId(out, "q-pinned")).toEqual(analystPinned);
  });

  it("an undo of an update during the run restores the pre-Watson question", async () => {
    const restored = {
      ...watsonQ,
      status: "unknown" as const,
      answer: "",
      author: undefined,
      pinned: undefined,
    };
    const out = await persist(withQs(watsonQ), withQs(disagreeing), withQs(restored));
    expect(byId(out, "q-access")).toEqual(restored);
  });

  it("keeps the collection stamp the run put on a Watson question's request", async () => {
    const asked = { ...watsonQ, collect: { host: "WS01", artifact: "Windows.EventLogs.Evtx" } };
    const stamped = {
      ...asked,
      collect: { ...asked.collect, issuedAfterImportSeq: 3 },
      synthesisDisagrees: { status: "partial" as const, answer: "VPN" },
    };
    const out = await persist(withQs(asked), withQs(stamped), withQs(asked));
    expect(byId(out, "q-access")?.collect?.issuedAfterImportSeq).toBe(3);
  });

  it("keeps today's behavior for non-Watson questions: the run's conclusions win", async () => {
    const runAnswer = { ...analystPinned, status: "answered" as const, answer: "run answer" };
    const latest = withQs({ ...analystPinned, answer: "edited meanwhile" });
    const out = await persist(withQs(analystPinned), withQs(runAnswer), latest);
    expect(byId(out, "q-pinned")).toEqual(runAnswer);
  });
});

describe("the synthesis prompt shows the current key questions with their answers", () => {
  it("lists each question with id, status and answer, and marks Watson's", () => {
    const block = buildCurrentKeyQuestionsBlock(withQs(watsonQ, analystPinned));
    expect(block).toContain("CURRENT KEY QUESTIONS");
    expect(block).toContain("[q-access] (answered)");
    expect(block).toContain(watsonQ.answer);
    expect(block).toMatch(/\[q-access\][^\n]*Watson/);
    expect(block).toContain("[q-pinned] (unknown)");
    expect(block).not.toMatch(/\[q-pinned\][^\n]*Watson/);
  });

  it("does not call an unanswered Watson question an applied answer", () => {
    const asked = { ...watsonQ, status: "unknown" as const, answer: "" };
    const block = buildCurrentKeyQuestionsBlock(withQs(asked));
    expect(block).toContain("[q-access] (unknown)");
    expect(block).not.toContain("applied by the analyst");
  });

  it("is empty when the case has no key questions", () => {
    expect(buildCurrentKeyQuestionsBlock(withQs())).toBe("");
  });

  it("keeps each question on one line and clips long answers", () => {
    const long = { ...watsonQ, answer: `first line\nsecond line ${"x".repeat(2000)}` };
    const block = buildCurrentKeyQuestionsBlock(withQs(long));
    const line = block.split("\n").find((l) => l.startsWith("[q-access]")) ?? "";
    expect(line).toContain("first line second line");
    expect(line.length).toBeLessThan(700);
  });

  it("caps the number of questions and says how many it left out", () => {
    const many = Array.from({ length: 80 }, (_, i) => ({ ...analystPinned, id: `q${i}` }));
    const block = buildCurrentKeyQuestionsBlock(withQs(...many));
    const listed = block.split("\n").filter((l) => /^\[q\d+\]/.test(l));
    expect(listed.length).toBeLessThan(80);
    expect(block).toContain(`${80 - listed.length} more`);
  });
});

// End to end through the real synthesize: the prompt the model gets, and the state the run saves.
describe("synthesize end to end", () => {
  const event: ForensicEvent = {
    id: "e1",
    timestamp: "2026-06-01T00:00:00.000Z",
    description: "logon from an unmanaged host",
    severity: "Medium",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
  };
  const reply = JSON.stringify({
    findings: [],
    iocs: [],
    mitreTechniques: [],
    attackerPath: "p",
    summary: "s",
    forensicEvents: [],
    threadsOpened: [],
    threadsClosed: [],
    timelineNote: "",
    keyQuestions: [{ id: "q-access", question: "Initial access?", status: "partial", answer: "Maybe VPN" }],
  });

  async function run(during?: (store: CaseStateStore) => Promise<void>) {
    const root = await mkdtemp(join(tmpdir(), "watson-synth-"));
    try {
      const caseStore = new CaseStore(root);
      await caseStore.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
      const stateStore = new CaseStateStore(caseStore);
      await stateStore.save({ ...withQs(watsonQ, analystPinned), forensicTimeline: [event] });
      const sent: string[] = [];
      const provider = {
        name: "spy",
        model: "spy-model",
        analyze: async (req: AnalyzeRequest): Promise<AnalyzeResult> => {
          sent.push(req.userPrompt);
          if (during) await during(stateStore);
          return { rawText: reply };
        },
      };
      const pipeline = new AnalysisPipeline({
        provider,
        stateStore,
        imageLoader: async () => ({ base64: "A", mimeType: "image/webp" }),
      });
      await pipeline.synthesize("c1");
      return { prompt: sent[0] ?? "", saved: await stateStore.load("c1") };
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }

  it("shows the current answers in the prompt and saves Watson's answer with the disagreement", async () => {
    const { prompt, saved } = await run();
    expect(prompt).toContain("CURRENT KEY QUESTIONS");
    expect(prompt).toContain(watsonQ.answer);
    const q = byId(saved, "q-access");
    expect(q).toMatchObject({ status: "answered", answer: watsonQ.answer, author: "watson", pinned: true });
    expect(q?.synthesisDisagrees).toEqual({ status: "partial", answer: "Maybe VPN" });
  });

  it("an apply that lands while the model is thinking is the one saved", async () => {
    const revised = { ...watsonQ, status: "partial" as const, answer: "Watson revised it" };
    const { saved } = await run(async (store) => {
      const now = await store.loadOverview("c1");
      await store.saveOverview({
        ...now,
        keyQuestions: now.keyQuestions.map((q) => (q.id === revised.id ? revised : q)),
      });
    });
    expect(byId(saved, "q-access")).toEqual(revised);
  });
});
