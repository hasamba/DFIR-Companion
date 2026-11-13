import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { AnalysisPipeline } from "../../../src/analysis/pipeline.js";
import { StateStore as CaseStateStore } from "../../../src/analysis/stateStore.js";
import type { AnalyzeRequest, AnalyzeResult } from "../../../src/providers/provider.js";
import { CaseStore } from "../../../src/storage/caseStore.js";
import { createApp } from "../../../src/server.js";
import {
  foldSynthesisDelta,
  gradeFindings,
  type DeltaFoldContext,
} from "../../../src/analysis/ai/synthesisMerge.js";
import { persistSynthesis } from "../../../src/analysis/ai/synthesisPersist.js";
import { buildWatsonFindingsBlock } from "../../../src/analysis/ai/watsonFindingsBlock.js";
import { applyIncidentTypeToState, parseIncidentType } from "../../../src/analysis/incidentTypes.js";
import { deltaSchema } from "../../../src/analysis/responseSchema.js";
import { StateLock } from "../../../src/analysis/stateLock.js";
import { mergeDelta } from "../../../src/analysis/stateMerge.js";
import type { StateStore } from "../../../src/analysis/stateStore.js";
import type { FalsePositiveMarker } from "../../../src/analysis/falsePositive.js";
import {
  emptyState,
  type Finding,
  type ForensicEvent,
  type InvestigationState,
  type NextStep,
} from "../../../src/analysis/stateTypes.js";
import {
  keepWatsonItems,
  watsonFindingDisagreement,
  WATSON_MARKER,
} from "../../../src/analysis/timeline/watsonItems.js";

// Findings and next steps the analyst applied from Watson survive every path that replaces findings
// or next steps: the synthesis fold and its locked persist, grading, import/MCP merges, the
// incident-type apply and the false-positive cascade. Synthesis may say it disagrees; it never
// overwrites, re-grades or duplicates a Watson item.

const TS = "2026-06-01T00:00:00.000Z";

const ev = (id: string, extra: Partial<ForensicEvent> = {}): ForensicEvent => ({
  id,
  timestamp: TS,
  description: `event ${id}`,
  severity: "Medium",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
  ...extra,
});

const watsonFinding: Finding = {
  id: "f-watson-1a2b3c4d",
  severity: "High",
  confidence: 90,
  title: "Phishing mail delivered the loader",
  description: "The pasted mail log shows the loader attached to a mail from mailer.example.com.",
  relatedIocs: [],
  sourceScreenshots: [],
  mitreTechniques: ["T1566.001"],
  relatedEventIds: ["e1"],
  firstSeen: TS,
  lastUpdated: TS,
  status: "open",
  author: "watson",
};

const pasteOnly: Finding = {
  ...watsonFinding,
  id: "f-watson-0badf00d",
  title: "Mail gateway let the archive through",
  description: "Line 4 of the pasted gateway log shows the archive was allowed.",
  mitreTechniques: [],
  relatedEventIds: [],
  citedPasteLines: [{ pasteId: "p1", line: 4 }],
};

const watsonStep: NextStep = {
  id: "s-watson-1",
  priority: "high",
  action: "Pull the mail gateway log for mailer.example.com",
  rationale: "Confirms the delivery Watson found",
  pointer: "mail gateway",
  author: "watson",
};

const synthFinding = (id: string, extra: Record<string, unknown> = {}) => ({
  id,
  severity: "Medium",
  title: "Scheduled task created for persistence",
  description: "A task runs the loader at logon.",
  relatedIocs: [],
  mitreTechniques: ["T1053.005"],
  status: "open",
  relatedEventIds: ["e2"],
  ...extra,
});

const delta = (findings: unknown[], extra: Record<string, unknown> = {}) =>
  deltaSchema.parse({
    findings,
    iocs: [],
    mitreTechniques: [],
    threadsOpened: [],
    threadsClosed: [],
    timelineNote: "n",
    summary: "s",
    ...extra,
  });

const base = (over: Partial<InvestigationState> = {}): InvestigationState => ({
  ...emptyState("c1"),
  forensicTimeline: [ev("e1", { relatedFindingIds: [watsonFinding.id] }), ev("e2")],
  findings: [watsonFinding],
  nextSteps: [watsonStep],
  ...over,
});

function context(stored: () => InvestigationState): DeltaFoldContext {
  return {
    opts: { stateStore: { load: async () => stored() } } as unknown as DeltaFoldContext["opts"],
    mergeWithAliases: async (b, d, ctx) => mergeDelta(b, d, ctx),
  };
}

async function fold(
  state: InvestigationState,
  d: ReturnType<typeof delta>,
  opts: { stored?: InvestigationState; markers?: FalsePositiveMarker[] } = {},
) {
  return foldSynthesisDelta(
    context(() => opts.stored ?? state),
    {
      caseId: "c1",
      state,
      delta: d,
      markers: opts.markers ?? [],
      scopedEvents: state.forensicTimeline,
      playbookTasks: [],
    },
  );
}

function memoryStore(initial: InvestigationState) {
  let current = initial;
  const store = {
    load: async () => current,
    save: async (s: InvestigationState) => {
      current = s;
    },
  } as unknown as StateStore;
  return store;
}

/** The full fold, then the locked persist against `latest` (the store at save time). */
async function foldAndPersist(
  state: InvestigationState,
  d: ReturnType<typeof delta>,
  latest: InvestigationState = state,
  markers: FalsePositiveMarker[] = [],
): Promise<InvestigationState> {
  const { next } = await fold(state, d, { stored: latest, markers });
  return persistSynthesis({ opts: { stateStore: memoryStore(latest), stateLock: new StateLock() } }, "c1", {
    loaded: state,
    next,
    findingsDiff: { added: [], removed: [], severityChanged: [] },
  });
}

const findingById = (s: InvestigationState, id: string) => s.findings.find((f) => f.id === id);
const eventById = (s: InvestigationState, id: string) => s.forensicTimeline.find((e) => e.id === id);

describe("the synthesis fold and persist keep Watson findings and next steps", () => {
  it("(a) keeps a Watson finding and next step the delta does not mention, exactly as stored", async () => {
    const out = await foldAndPersist(base(), delta([synthFinding("f-1")], { nextSteps: [] }));
    expect(findingById(out, watsonFinding.id)).toEqual(watsonFinding);
    expect(out.nextSteps).toContainEqual(watsonStep);
    expect(findingById(out, "f-1")).toBeDefined();
  });

  it("rebuilds event back-links with the kept Watson findings' citations", async () => {
    const out = await foldAndPersist(base(), delta([synthFinding("f-1")]));
    expect(eventById(out, "e1")?.relatedFindingIds).toEqual([watsonFinding.id]);
    expect(eventById(out, "e2")?.relatedFindingIds).toEqual(["f-1"]);
  });

  it("(b) drops a re-issued Watson id from the delta and records the disagreement", async () => {
    const reissue = synthFinding(watsonFinding.id, {
      severity: "Low",
      title: watsonFinding.title,
      description: "Probably a newsletter.",
      relatedEventIds: ["e1"],
    });
    const out = await foldAndPersist(base(), delta([reissue]));
    const kept = findingById(out, watsonFinding.id);
    const { synthesisDisagrees, ...rest } = kept ?? ({} as Finding);
    expect(rest).toEqual(watsonFinding);
    expect(synthesisDisagrees).toEqual({
      severity: "Low",
      title: watsonFinding.title,
      description: "Probably a newsletter.",
    });
    expect(out.findings.filter((f) => f.id === watsonFinding.id)).toHaveLength(1);
    expect(out.findings.some((f) => f.id.startsWith("f-model-"))).toBe(false);
  });

  it("records no disagreement when the re-issue matches, and clears an old one", async () => {
    const stale = {
      ...watsonFinding,
      synthesisDisagrees: { severity: "Low" as const, title: "t", description: "d" },
    };
    const same = synthFinding(watsonFinding.id, {
      severity: watsonFinding.severity,
      title: watsonFinding.title,
      description: watsonFinding.description,
    });
    const out = await foldAndPersist(base({ findings: [stale] }), delta([same]));
    expect(findingById(out, watsonFinding.id)).toEqual(watsonFinding);
  });

  it("renames a model finding wearing an f-watson- id that is not a Watson finding", async () => {
    const { delta: applied } = await fold(base(), delta([synthFinding("f-watson-deadbeef")]));
    expect(applied.findings.map((f) => f.id)).toEqual(["f-model-f-watson-deadbeef"]);
  });

  it("(c) keeps a synthesis finding with the same semantic key, and links it as similar", async () => {
    const twin = synthFinding("f-9", {
      title: watsonFinding.title,
      mitreTechniques: watsonFinding.mitreTechniques,
      relatedEventIds: ["e1"],
    });
    const out = await foldAndPersist(base(), delta([twin]));
    expect(findingById(out, "f-9")).toBeDefined();
    expect(findingById(out, watsonFinding.id)).toEqual({ ...watsonFinding, similarSynthesisId: "f-9" });
  });

  it("(d) carries a Watson finding and next step applied while the model call ran", async () => {
    const applied: Finding = { ...watsonFinding, id: "f-watson-0000beef", title: "Second loader stage" };
    const appliedStep: NextStep = { ...watsonStep, id: "s-watson-2", action: "Image the mail server" };
    const latest = { ...base(), findings: [watsonFinding, applied], nextSteps: [watsonStep, appliedStep] };
    const out = await foldAndPersist(base(), delta([synthFinding("f-1")], { nextSteps: [] }), latest);
    expect(findingById(out, applied.id)).toEqual(applied);
    expect(out.nextSteps).toEqual(expect.arrayContaining([watsonStep, appliedStep]));
  });

  it("does not bring back a Watson finding and its paste-line event undone while the model call ran", async () => {
    const pasteEvent = ev("e-paste-1", {
      provenance: [WATSON_MARKER],
      relatedFindingIds: [watsonFinding.id],
    });
    const state = base({ forensicTimeline: [...base().forensicTimeline, pasteEvent] });
    const latest = { ...state, findings: [], nextSteps: [], forensicTimeline: base().forensicTimeline };
    const out = await foldAndPersist(state, delta([synthFinding("f-1")]), latest);
    expect(findingById(out, watsonFinding.id)).toBeUndefined();
    expect(out.nextSteps).toEqual([]);
    expect(eventById(out, "e-paste-1")).toBeUndefined();
  });

  it("marks cited evidence changed when every cited event is a false positive, not for paste citations", async () => {
    const marker: FalsePositiveMarker = {
      id: "event:e1",
      kind: "event",
      ref: "e1",
      reason: "known-good-tool",
      note: "sanctioned",
      markedAt: TS,
      markedBy: "analyst",
    };
    const state = base({ findings: [watsonFinding, pasteOnly] });
    const out = await foldAndPersist(state, delta([synthFinding("f-1")]), state, [marker]);
    expect(findingById(out, watsonFinding.id)?.citationsChanged).toBe(true);
    expect(findingById(out, pasteOnly.id)?.citationsChanged).toBeUndefined();
    // A cited event the analyst rejected gets no back-link from the Watson finding.
    expect(eventById(out, "e1")?.relatedFindingIds).toEqual([]);
  });

  it("is not re-graded by the deterministic graders", async () => {
    const state = base({ findings: [watsonFinding, pasteOnly] });
    const folded = await fold(state, delta([synthFinding("f-1")]));
    const graded = gradeFindings({
      next: folded.next,
      delta: folded.delta,
      surviving: folded.surviving,
      eligibleIds: folded.eligibleIds,
      sourceTrust: {},
      kevCatalog: undefined,
    });
    expect(findingById(graded, watsonFinding.id)).toEqual(watsonFinding);
    expect(findingById(graded, pasteOnly.id)).toEqual(pasteOnly);
  });
});

describe("Watson items across the fold's edges", () => {
  it("keeps the import stamp the run put on a Watson step's collection request", async () => {
    const asked = { ...watsonStep, collect: { host: "WS01", artifact: "Windows.EventLogs.Evtx" } };
    const stamped = { ...asked, collect: { ...asked.collect, issuedAfterImportSeq: 3 } };
    const loaded = base({ nextSteps: [asked] });
    const out = await persistSynthesis(
      { opts: { stateStore: memoryStore(loaded), stateLock: new StateLock() } },
      "c1",
      {
        loaded,
        next: { ...loaded, nextSteps: [stamped] },
        findingsDiff: { added: [], removed: [], severityChanged: [] },
      },
    );
    expect(out.nextSteps).toEqual([stamped]);
  });

  it("leaves no back-link to a Watson finding undone while the model call ran", async () => {
    const latest = { ...base(), findings: [] };
    const out = await foldAndPersist(base(), delta([synthFinding("f-1")]), latest);
    expect(eventById(out, "e1")?.relatedFindingIds).not.toContain(watsonFinding.id);
  });

  it("back-links a citation correlation folded into another row to that row", async () => {
    const state = base({
      forensicTimeline: [ev("e2")],
      eventAliases: { e1: "e2" },
    });
    const { next } = await fold(state, delta([]));
    expect(eventById(next, "e2")?.relatedFindingIds).toEqual([watsonFinding.id]);
    expect(findingById(next, watsonFinding.id)?.citationsChanged).toBeUndefined();
  });
});

describe("paths outside synthesis never drop a Watson item", () => {
  it("an import delta re-issuing a Watson id and replacing next steps keeps both Watson items", () => {
    const out = mergeDelta(
      base(),
      delta([synthFinding(watsonFinding.id, { severity: "Low" })], { nextSteps: [] }),
      {
        windowSequence: 1,
        timestamp: TS,
        sourceScreenshots: [],
      },
    );
    expect(findingById(out, watsonFinding.id)).toEqual(watsonFinding);
    expect(out.nextSteps).toEqual([watsonStep]);
  });

  it("(e) the incident-type apply (replace) keeps a Watson next step", () => {
    const type = parseIncidentType({
      id: "t1",
      name: "Phishing",
      initialKeyQuestions: [],
      initialNextSteps: [{ priority: "high", action: "Collect the mailbox", rationale: "r", pointer: "p" }],
      findingsSeeds: [],
      synthesisHint: "",
      recommendedImportOrder: [],
    });
    expect(type).not.toBeNull();
    const out = applyIncidentTypeToState(base(), type!, { replace: true }).state;
    expect(out.nextSteps).toContainEqual(watsonStep);
    expect(out.nextSteps.some((s) => s.action === "Collect the mailbox")).toBe(true);
  });

  it("the false-positive cascade keeps a Watson finding and next step", async () => {
    const store = new CaseStore(await mkdtemp(join(tmpdir(), "watson-items-fp-")));
    const stateStore = new CaseStateStore(store);
    const app = createApp(store, { stateStore });
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const step = { ...watsonStep, relatedFindingIds: [watsonFinding.id] };
    await stateStore.save(base({ nextSteps: [step] }));
    const res = await request(app)
      .post("/cases/c1/false-positive")
      .send({ kind: "finding", ref: watsonFinding.title, reason: "known-good-tool", note: "sanctioned" });
    expect(res.status).toBe(200);
    const saved = await stateStore.load("c1");
    expect(findingById(saved, watsonFinding.id)).toEqual(watsonFinding);
    expect(saved.nextSteps.find((s) => s.id === step.id)).toMatchObject(step);
  });
});

describe("keepWatsonItems", () => {
  it("restores the stored copy, keeps the run's annotations, and drops one undone", () => {
    const runCopy = { ...watsonFinding, severity: "Low" as const, similarSynthesisId: "f-9" };
    const latest = { findings: [watsonFinding], nextSteps: [] };
    const next = { ...base(), findings: [runCopy], nextSteps: [watsonStep] };
    const out = keepWatsonItems(next, latest);
    expect(out.findings).toEqual([{ ...watsonFinding, similarSynthesisId: "f-9" }]);
    expect(out.nextSteps).toEqual([]);
    expect(keepWatsonItems(out, latest)).toEqual(out);
  });

  it("watsonFindingDisagreement is undefined when severity, title and description agree", () => {
    expect(watsonFindingDisagreement(watsonFinding, watsonFinding)).toBeUndefined();
    expect(watsonFindingDisagreement({ ...watsonFinding, title: "other" }, watsonFinding)).toEqual({
      severity: watsonFinding.severity,
      title: "other",
      description: watsonFinding.description,
    });
  });
});

describe("the WATSON FINDINGS prompt block", () => {
  it("is empty when the case has no Watson findings", () => {
    expect(buildWatsonFindingsBlock(base({ findings: [] }))).toBe("");
  });

  it("lists id, severity, title, clipped description and cited events, one line each", () => {
    const long = { ...watsonFinding, description: `first\nsecond ${"x".repeat(1000)}` };
    const block = buildWatsonFindingsBlock(base({ findings: [long] }));
    expect(block).toContain("WATSON FINDINGS (analyst-approved; do not re-issue, do not duplicate)");
    const line = block.split("\n").find((l) => l.startsWith(`[${watsonFinding.id}]`)) ?? "";
    expect(line).toContain("(High)");
    expect(line).toContain(watsonFinding.title);
    expect(line).toContain("first second");
    expect(line).toContain("e1");
    expect(line.length).toBeLessThan(600);
  });

  it("caps the rows at 40 and the cited events at 10", () => {
    const many = Array.from({ length: 50 }, (_, i) => ({
      ...watsonFinding,
      id: `f-watson-${String(i).padStart(8, "0")}`,
      relatedEventIds: Array.from({ length: 15 }, (_, j) => `ev${j}`),
    }));
    const block = buildWatsonFindingsBlock(base({ findings: many }));
    const rows = block.split("\n").filter((l) => l.startsWith("[f-watson-"));
    expect(rows).toHaveLength(40);
    expect(rows[0]).toContain("ev9");
    expect(rows[0]).not.toContain("ev10");
    expect(block).toContain("10 more");
  });

  it("leaves out findings Watson did not write", () => {
    const { author: _a, ...plain } = watsonFinding;
    expect(buildWatsonFindingsBlock(base({ findings: [plain] }))).toBe("");
  });
});

// Through the real synthesize: the prompt the model gets, and what the run saves.
describe("synthesize end to end", () => {
  const reply = (findings: unknown[]) =>
    JSON.stringify({
      findings,
      iocs: [],
      mitreTechniques: [],
      attackerPath: "p",
      summary: "s",
      forensicEvents: [],
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: "",
      keyQuestions: [],
      nextSteps: [{ id: "s-1", priority: "medium", action: "Check e2", rationale: "r", pointer: "e2" }],
    });

  async function run(seed: InvestigationState, findings: unknown[]) {
    const root = await mkdtemp(join(tmpdir(), "watson-items-"));
    try {
      const caseStore = new CaseStore(root);
      await caseStore.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
      const stateStore = new CaseStateStore(caseStore);
      await stateStore.save(seed);
      const sent: string[] = [];
      const provider = {
        name: "spy",
        model: "spy-model",
        analyze: async (req: AnalyzeRequest): Promise<AnalyzeResult> => {
          sent.push(req.userPrompt);
          return { rawText: reply(findings) };
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

  const prior: Finding = {
    ...watsonFinding,
    id: "f-prior",
    title: "Encoded PowerShell launched from Word",
    mitreTechniques: ["T1059.001"],
    relatedEventIds: ["e2"],
    author: undefined,
  };
  const { author: _drop, ...priorFinding } = prior;
  const plainStep: NextStep = {
    id: "s-0",
    priority: "low",
    action: "Review e1",
    rationale: "r",
    pointer: "e1",
  };

  it("(f) a case with no Watson items sends the same prompt as before", async () => {
    const seed = base({
      findings: [priorFinding],
      nextSteps: [plainStep],
      forensicTimeline: [ev("e1"), ev("e2", { relatedFindingIds: ["f-prior"] })],
    });
    const { prompt } = await run(seed, [synthFinding("f-1")]);
    await expect(prompt).toMatchFileSnapshot("./__snapshots__/synthesisPromptNoWatson.txt");
  });

  it("shows Watson findings to the model once and saves them unchanged, ungraded", async () => {
    const seed = base({ findings: [watsonFinding, pasteOnly, priorFinding], nextSteps: [watsonStep] });
    const { prompt, saved } = await run(seed, [synthFinding("f-1")]);
    expect(prompt).toContain("WATSON FINDINGS");
    expect(prompt.split(watsonFinding.id).length - 1).toBe(1);
    expect(findingById(saved, watsonFinding.id)).toEqual(watsonFinding);
    expect(findingById(saved, pasteOnly.id)).toEqual(pasteOnly);
    expect(saved.nextSteps).toContainEqual(watsonStep);
    expect(eventById(saved, "e1")?.relatedFindingIds).toContain(watsonFinding.id);
  });
});
