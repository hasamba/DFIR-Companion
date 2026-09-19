import { describe, it, expect, afterEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import { HypothesisStore } from "../../src/analysis/hypothesisStore.js";
import { HostScopeStore } from "../../src/analysis/hostScopeStore.js";
import { DwellWindowStore } from "../../src/analysis/dwellWindowStore.js";
import { HuntOutcomeStore } from "../../src/analysis/huntOutcomeStore.js";
import { TagsStore } from "../../src/analysis/tags.js";
import { CommentsStore } from "../../src/analysis/comments.js";
import { NotebookStore } from "../../src/analysis/notebookStore.js";
import { AiControlStore } from "../../src/analysis/aiControl.js";
import type { AIProvider, AnalyzeRequest, AnalyzeResult } from "../../src/providers/provider.js";

// #1411: ask() reads the analyst's own decisions (side files) into the prompt, carries the panel's
// short Q&A history, and reports how many in-scope events the model actually saw.
class CapturingProvider implements AIProvider {
  readonly name = "capture";
  readonly model = "mock-model";
  lastReq?: AnalyzeRequest;
  async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
    this.lastReq = req;
    return {
      rawText: JSON.stringify({ answer: "ok", status: "partial", pointer: "n/a", relatedEventIds: ["e1"] }),
    };
  }
}

function ev(p: Partial<ForensicEvent> & { id: string }): ForensicEvent {
  return {
    timestamp: "2026-01-01T00:00:00Z",
    description: `event ${p.id}`,
    severity: "High",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...p,
  };
}

async function makeCase(timeline: ForensicEvent[]) {
  const root = await mkdtemp(join(tmpdir(), "dfir-askdec-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(cases);
  const s = emptyState("c1");
  s.forensicTimeline = timeline;
  await stateStore.save(s);
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
  const provider = new CapturingProvider();
  const pipeline = new AnalysisPipeline({
    provider,
    stateStore,
    imageLoader: async () => ({ base64: "", mimeType: "image/webp" }),
    ...stores,
  });
  return { pipeline, provider, stores };
}

const ORDER = [
  "ATTACKER PATH:",
  "FINDINGS:",
  "FORENSIC TIMELINE",
  "CURRENT QUESTIONS:",
  "ANALYST HYPOTHESES",
  "ANALYST HOST-SCOPE DECISIONS",
  "ANALYST DWELL WINDOWS",
  "PRIOR HUNTS",
  "ANALYST MARKS",
  "ANALYST NOTEBOOK",
  "PRIOR Q&A IN THIS SESSION",
  "ANALYST QUESTION:",
];

describe("ask() analyst-decision context (#1411)", () => {
  afterEach(() => {
    delete process.env.DFIR_AI_SYNTH_MAX_EVENTS;
  });

  it("feeds every populated decision block into the prompt, in a fixed order after the case blocks", async () => {
    const { pipeline, provider, stores } = await makeCase([
      ev({ id: "e1", asset: "WS01" }),
      ev({ id: "e2", asset: "DC01" }),
    ]);
    await stores.hypothesisStore.add("c1", {
      title: "Data left via OneDrive",
      expectedOutcome: "egress to onedrive.com",
    });
    await stores.hostScopeStore.append("c1", {
      host: "FS01",
      from: "unknown",
      to: "cleared",
      reason: "full triage, nothing",
      analyst: "carol",
      at: "2026-01-03T00:00:00Z",
      basis: { sources: [], windowCovered: true, tacticsCovered: [], evidenceFingerprint: "" },
    });
    await stores.dwellWindowStore.add("c1", {
      label: "Session 1",
      start: "2026-01-01T10:00:00Z",
      end: "2026-01-01T12:00:00Z",
    });
    await stores.huntOutcomeStore.save("c1", [
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
    await stores.tagsStore.add("c1", {
      targetType: "event",
      targetId: "e1",
      author: "alice",
      label: "starred",
    });
    await stores.commentsStore.add("c1", {
      targetType: "event",
      targetId: "e1",
      author: "bob",
      text: "the staging archive",
    });
    await stores.aiControlStore.save("c1", { enabled: false, lastAnalyzedSeq: 0, includeNotebook: true });
    await stores.notebookStore.add("c1", { text: "check the proxy logs for 1.2.3.4", type: "note" });

    await pipeline.ask("c1", "To where?", {
      history: [{ question: "Was data exfiltrated?", answer: "Partial — an archive left WS01." }],
    });

    const prompt = provider.lastReq!.userPrompt;
    expect(prompt).toContain("- [open] Data left via OneDrive — decided by: egress to onedrive.com");
    expect(prompt).toContain("- FS01: cleared — full triage, nothing (carol, 2026-01-03)");
    expect(prompt).toContain("- Session 1: 2026-01-01T10:00:00.000Z → 2026-01-01T12:00:00.000Z");
    expect(prompt).toContain('[collected] "Sweep for the staging archive" — no results');
    expect(prompt).toContain('- [event e1] tags: starred · "the staging archive" (bob)');
    expect(prompt).toContain("[NOTE] check the proxy logs for 1.2.3.4");
    expect(prompt).toContain("Q: Was data exfiltrated?\nA: Partial — an archive left WS01.");
    expect(prompt).toContain("ANALYST QUESTION: To where?");

    const positions = ORDER.map((h) => prompt.indexOf(h));
    expect(positions.every((p) => p >= 0)).toBe(true);
    expect([...positions].sort((a, b) => a - b)).toEqual(positions);
  });

  it("emits none of the decision blocks on a fresh case, and no history block without history", async () => {
    const { pipeline, provider } = await makeCase([ev({ id: "e1" })]);
    await pipeline.ask("c1", "Anything?");
    const prompt = provider.lastReq!.userPrompt;
    for (const h of ORDER.slice(4, 11)) expect(prompt).not.toContain(h);
    expect(prompt).toContain("ANALYST QUESTION: Anything?");
  });

  it("keeps the notebook out of the prompt unless the analyst opted in", async () => {
    const { pipeline, provider, stores } = await makeCase([ev({ id: "e1" })]);
    await stores.notebookStore.add("c1", { text: "private note", type: "note" });
    await pipeline.ask("c1", "Anything?");
    expect(provider.lastReq!.userPrompt).not.toContain("private note");
  });

  it("reports how many in-scope events the model saw, and that it is fewer when the timeline was trimmed", async () => {
    const { pipeline } = await makeCase([ev({ id: "e1" }), ev({ id: "e2" }), ev({ id: "e3" })]);
    const full = await pipeline.ask("c1", "Anything?");
    expect(full.eventCount).toBe(3);
    expect(full.usedEvents).toBe(3);

    process.env.DFIR_AI_SYNTH_MAX_EVENTS = "1";
    const trimmed = await pipeline.ask("c1", "Anything?");
    expect(trimmed.eventCount).toBe(3);
    expect(trimmed.usedEvents).toBe(1);
    expect(trimmed.answer).toBe("ok"); // the model's own fields survive alongside the counts
  });
});
