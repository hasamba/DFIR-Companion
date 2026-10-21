import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { AnonControlStore, anonControlVersion } from "../../src/analysis/anonControl.js";
import { CustomEntitiesStore } from "../../src/analysis/anonEntities.js";
import { DiscoveredEntitiesStore } from "../../src/analysis/anonDiscovered.js";
import { PresidioDecisions, forgetAround } from "../../src/analysis/presidioDecisions.js";
import { PresidioPendingStore } from "../../src/analysis/presidioPending.js";
import { AiAuthoredTextStore } from "../../src/analysis/aiAuthoredText.js";
import { SecondOpinionStore } from "../../src/analysis/secondOpinionStore.js";
import { PresidioApprovalRequired, type PresidioClient } from "../../src/analysis/presidio.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import { bumpAnonRevision } from "../../src/analysis/anonRevision.js";
import type { AIProvider, AnalyzeRequest, AnalyzeResult } from "../../src/providers/provider.js";

// The approval loop, end to end through a real synthesis: the model's summary rides in the next
// synthesis prompt, and Presidio tags a tool name in it as a PERSON. Before the fix, that second run
// stopped on a value no analyst could have cleared before the first run wrote it.

const SUMMARY = "The operator ran Velkor on the server to read cached credentials.";

class SummaryProvider implements AIProvider {
  readonly name = "stub";
  readonly model = "stub-model";
  prompts: string[] = [];
  async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
    this.prompts.push(req.userPrompt);
    return {
      rawText: JSON.stringify({
        findings: [],
        iocs: [],
        mitreTechniques: [],
        attackerPath: "",
        summary: SUMMARY,
        threadsOpened: [],
        threadsClosed: [],
        keyQuestions: [],
        nextSteps: [],
        forensicEvents: [],
        timelineNote: "",
      }),
    };
  }
}

/**
 * Flags every bounded "Velkor" as a PERSON — a made-up tool name. A real one such as Mimikatz is
 * already dropped by the DFIR-vocabulary filter (presidioPersonFilter.ts), so it would test nothing.
 */
const toolNameAsPerson: PresidioClient = {
  analyze: async (text) =>
    /\bVelkor\b/.test(text) ? [{ entityType: "PERSON", value: "Velkor", score: 0.9 }] : [],
};

const event = (id: string, description: string): ForensicEvent => ({
  id,
  timestamp: "2026-01-01T00:00:00Z",
  description,
  severity: "High",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
});

async function setup(withAuthoredStore = true) {
  const cases = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-authored-pipe-")));
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(cases);
  const s = emptyState("c1");
  s.forensicTimeline = [event("e1", "lsass.exe memory read by procdump.exe")];
  await stateStore.save(s);
  const provider = new SummaryProvider();
  const authoredStore = new AiAuthoredTextStore(cases);
  const pendingStore = new PresidioPendingStore(cases);
  const pipeline = new AnalysisPipeline({
    provider,
    stateStore,
    anonStore: new AnonControlStore(cases),
    presidioPendingStore: pendingStore,
    presidio: { client: toolNameAsPerson, url: "http://localhost:5002", minScore: 0.6 },
    ...(withAuthoredStore ? { aiAuthoredStore: authoredStore } : {}),
    imageLoader: async () => ({ base64: "", mimeType: "image/webp" }),
  });
  return { pipeline, provider, stateStore, authoredStore, pendingStore };
}

describe("Presidio and AI-written text", () => {
  it("records the synthesis answer's own text", async () => {
    const { pipeline, authoredStore } = await setup();
    await pipeline.synthesize("c1", { force: true });
    expect(await authoredStore.load("c1")).toContain(SUMMARY);
  });

  it("does not hold the next run on a value found only in the model's summary", async () => {
    const { pipeline, provider, pendingStore } = await setup();
    await pipeline.synthesize("c1", { force: true });
    await pipeline.synthesize("c1", { force: true });
    expect(provider.prompts).toHaveLength(2);
    expect(provider.prompts[1]).toContain("Velkor"); // the summary did ride in the second prompt
    expect(await pendingStore.load("c1")).toEqual([]);
  });

  it("still holds the value once an event carries it", async () => {
    const { pipeline, stateStore, pendingStore } = await setup();
    await pipeline.synthesize("c1", { force: true });
    const s = await stateStore.load("c1");
    await stateStore.save({
      ...s,
      forensicTimeline: [...s.forensicTimeline, event("e2", "Process created by user Velkor on the server")],
    });
    await expect(pipeline.synthesize("c1", { force: true })).rejects.toBeInstanceOf(PresidioApprovalRequired);
    expect(await pendingStore.load("c1")).toEqual([{ value: "Velkor", category: "PERSON" }]);
  });

  it("holds every value when no AI-written text is recorded — the old behaviour", async () => {
    const { pipeline } = await setup(false);
    await pipeline.synthesize("c1", { force: true });
    await expect(pipeline.synthesize("c1", { force: true })).rejects.toBeInstanceOf(PresidioApprovalRequired);
  });
});

// The reported loop itself: a 2nd opinion whose referee prompt quotes model B's finding. B wrote
// "Velkor" during the run, so no analyst could have cleared it before the run started.
describe("a 2nd opinion whose model B names a tool Presidio tags as a person", () => {
  const synthesisAnswer = (findings: unknown[], summary: string) =>
    JSON.stringify({
      findings,
      iocs: [],
      mitreTechniques: [],
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: "",
      summary,
      forensicEvents: [],
    });
  const finding = (id: string, title: string, description: string) => ({
    id,
    severity: "High",
    title,
    description,
    relatedIocs: [],
    mitreTechniques: [],
    status: "open",
    relatedEventIds: ["e1"],
  });
  const A_ANSWER = synthesisAnswer(
    [finding("f1", "Credential access on the server", "LSASS memory was read by procdump.")],
    "Credential access on the server.",
  );
  const B_ANSWER = synthesisAnswer(
    [
      finding("f1", "Credential access on the server", "LSASS memory was read by procdump."),
      finding("g2", "Lateral movement with Velkor", "The operator used Velkor to move to the file server."),
    ],
    "Credential access, then lateral movement with Velkor.",
  );
  const isReferee = (req: AnalyzeRequest) => req.systemPrompt.includes("RECONCILING");

  /** Model A: writes the synthesis and judges every disagreement in the referee prompt. */
  class ModelA implements AIProvider {
    readonly name = "a";
    readonly model = "a-model";
    refereePrompts: string[] = [];
    async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
      if (!isReferee(req)) return { rawText: A_ANSWER };
      this.refereePrompts.push(req.userPrompt);
      const ids = [...new Set(req.userPrompt.match(/\b[a-z_]+:[a-z0-9-]+/g) ?? [])];
      return {
        rawText: JSON.stringify({
          summary: "judged",
          verdicts: ids.map((id) => ({ id, rationale: "r", recommendation: "review" })),
        }),
      };
    }
  }
  const modelB: AIProvider = {
    name: "b",
    model: "b-model",
    analyze: async () => ({ rawText: B_ANSWER }),
  };

  async function run(withAuthoredStore: boolean) {
    const cases = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-authored-so-")));
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const stateStore = new StateStore(cases);
    const s = emptyState("c1");
    s.forensicTimeline = [event("e1", "lsass.exe memory read by procdump.exe")];
    await stateStore.save(s);
    const modelA = new ModelA();
    const pendingStore = new PresidioPendingStore(cases);
    const pipeline = new AnalysisPipeline({
      provider: modelA,
      synthesisProvider: modelA,
      stateStore,
      secondOpinionStore: new SecondOpinionStore(cases),
      secondOpinionProvider: modelB,
      anonStore: new AnonControlStore(cases),
      presidioPendingStore: pendingStore,
      presidio: { client: toolNameAsPerson, url: "http://localhost:5002", minScore: 0.6 },
      ...(withAuthoredStore ? { aiAuthoredStore: new AiAuthoredTextStore(cases) } : {}),
      imageLoader: async () => ({ base64: "", mimeType: "image/webp" }),
      retries: 0,
      backoffMs: 0,
    });
    await pipeline.synthesize("c1", { force: true });
    const record = await pipeline.secondOpinion("c1");
    return { record, modelA, pending: await pendingStore.load("c1") };
  }

  it("lets the referee judge without a Presidio stop", async () => {
    const { record, modelA, pending } = await run(true);
    expect(modelA.refereePrompts.join("\n")).toContain("Velkor"); // B's finding did reach the referee
    expect(record.refereeError).toBeUndefined();
    expect(pending).toEqual([]);
  });

  it("stopped at the referee before the fix", async () => {
    const { record, pending } = await run(false);
    expect(record.refereeError).toBeDefined();
    expect(pending).toEqual([{ value: "Velkor", category: "PERSON" }]);
  });
});

// Every bypass the two Codex adversarial reviews reproduced, through the real gate: the model wrote a
// summary naming "Jane Doe", and the case then gains other text that carries the same value.
describe("Presidio holds a value that event or analyst text carries (Codex reviews)", () => {
  const AI_SUMMARY = "Investigate Jane Doe after suspicious activity on the domain controller.";

  /** Flags every "Jane Doe", whatever whitespace separates the words, as Presidio would slice it. */
  const janeDoe: PresidioClient = {
    analyze: async (text) =>
      [...text.matchAll(/Jane\s+Doe/g)].map((m) => ({ entityType: "PERSON", value: m[0], score: 0.9 })),
  };

  class JaneProvider extends SummaryProvider {
    override async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
      const r = await super.analyze(req);
      return { rawText: r.rawText.replace(JSON.stringify(SUMMARY), JSON.stringify(AI_SUMMARY)) };
    }
  }

  async function caseWith(extra: { events?: string[]; notes?: string[] } = {}) {
    const cases = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-authored-codex-")));
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const stateStore = new StateStore(cases);
    const s = emptyState("c1");
    s.forensicTimeline = [event("e1", "lsass.exe memory read by procdump.exe")];
    await stateStore.save(s);
    const provider = new JaneProvider();
    const notes: string[] = []; // filled after run 1, like the events
    const pipeline = new AnalysisPipeline({
      provider,
      stateStore,
      anonStore: new AnonControlStore(cases),
      presidioPendingStore: new PresidioPendingStore(cases),
      presidio: { client: janeDoe, url: "http://localhost:5002", minScore: 0.6 },
      aiAuthoredStore: new AiAuthoredTextStore(cases),
      // The notebook block renders "[NOTE] text" — the shape Codex showed passing the old matcher.
      notebookStore: {
        load: async () => notes.map((text, i) => ({ id: `n${i}`, type: "note", text })),
      } as never,
      aiControlStore: { load: async () => ({ includeNotebook: notes.length > 0 }) } as never,
      imageLoader: async () => ({ base64: "", mimeType: "image/webp" }),
    });
    // Run 1 writes the summary; then the case gains the extra text; run 2 must decide on it.
    await pipeline.synthesize("c1", { force: true });
    notes.push(...(extra.notes ?? []));
    const after = await stateStore.load("c1");
    await stateStore.save({
      ...after,
      forensicTimeline: [...after.forensicTimeline, ...(extra.events ?? []).map((d, i) => event(`x${i}`, d))],
    });
    return { second: () => pipeline.synthesize("c1", { force: true }), provider };
  }

  it("skips the value when only the model's summary carries it", async () => {
    const { second, provider } = await caseWith();
    await expect(second()).resolves.toBeDefined();
    expect(provider.prompts[1]).toContain("Jane Doe");
  });

  it("sends every prompt without a marker when anonymization is off for the case", async () => {
    const cases = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-authored-off-")));
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const stateStore = new StateStore(cases);
    await stateStore.save({ ...emptyState("c1"), forensicTimeline: [event("e1", "lsass.exe memory read")] });
    const anonStore = new AnonControlStore(cases);
    await anonStore.save("c1", { ...(await anonStore.load("c1")), enabled: false });
    const provider = new JaneProvider();
    const pipeline = new AnalysisPipeline({
      provider,
      stateStore,
      anonStore,
      aiAuthoredStore: new AiAuthoredTextStore(cases),
      imageLoader: async () => ({ base64: "", mimeType: "image/webp" }),
    });
    await pipeline.synthesize("c1", { force: true });
    await pipeline.synthesize("c1", { force: true });
    expect(provider.prompts[1]).toContain(AI_SUMMARY);
    for (const p of provider.prompts) expect(p).not.toMatch(/[\uE000-\uE002\uE100-\uE1FF]/);
  });

  it("sends every prompt without a marker", async () => {
    const { second, provider } = await caseWith();
    await second();
    for (const p of provider.prompts) expect(p).not.toMatch(/[--]/);
  });

  it.each([
    ["round 1: an event that extends the AI string", "Investigate Jane Doe after an unauthorized login"],
    ["round 1: an event with repeated spaces", "Jane   Doe logged in from the VPN"],
    ["round 1: an event with a tab", "Jane\tDoe logged in from the VPN"],
    [
      "round 2: an event cut with an ellipsis that goes on",
      "Investigate Jane Doe… login confirmed from the VPN",
    ],
    ["an event identical to the AI summary", AI_SUMMARY],
  ])("holds the value for %s", async (_label, description) => {
    const { second } = await caseWith({ events: [description] });
    await expect(second()).rejects.toBeInstanceOf(PresidioApprovalRequired);
  });

  it("holds the value for round 2: an analyst note that repeats the AI summary", async () => {
    const { second } = await caseWith({ notes: [AI_SUMMARY] });
    await expect(second()).rejects.toBeInstanceOf(PresidioApprovalRequired);
  });

  it("holds the value for round 5: an analyst note where the name runs into other text", async () => {
    const { second } = await caseWith({ notes: ["Jane Doe_ VPN login"] });
    await expect(second()).rejects.toBeInstanceOf(PresidioApprovalRequired);
  });
});

// Codex adversarial review, round 3: an answer written while the model saw clear text must never
// excuse a value. Presidio (or masking) off → the model copies a real name into its summary →
// protection back on → the event that carried the name is gone, the summary is not.
describe("an answer written without protection is never recorded as AI text", () => {
  const COPIED = "Jane Doe signed in to the domain controller from the VPN at night.";
  const janeDoe: PresidioClient = {
    analyze: async (text) =>
      [...text.matchAll(/Jane\s+Doe/g)].map((m) => ({ entityType: "PERSON", value: m[0], score: 0.9 })),
  };
  class Copier extends SummaryProvider {
    override async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
      const r = await super.analyze(req);
      return { rawText: r.rawText.replace(JSON.stringify(SUMMARY), JSON.stringify(COPIED)) };
    }
  }

  async function setupCase() {
    const cases = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-authored-unprotected-")));
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const stateStore = new StateStore(cases);
    await stateStore.save({
      ...emptyState("c1"),
      forensicTimeline: [event("e1", "User Jane Doe signed in")],
    });
    const anonStore = new AnonControlStore(cases);
    const authoredStore = new AiAuthoredTextStore(cases);
    const pendingStore = new PresidioPendingStore(cases);
    const pipeline = new AnalysisPipeline({
      provider: new Copier(),
      stateStore,
      anonStore,
      presidioPendingStore: pendingStore,
      presidio: { client: janeDoe, url: "http://localhost:5002", minScore: 0.6 },
      aiAuthoredStore: authoredStore,
      imageLoader: async () => ({ base64: "", mimeType: "image/webp" }),
    });
    const decisions = new PresidioDecisions(
      new CustomEntitiesStore(cases),
      new DiscoveredEntitiesStore(cases),
      pendingStore,
      anonStore,
      authoredStore,
    );
    /** Change the case's settings the way the Anonymization modal's Save does. */
    const setControl = async (patch: { enabled?: boolean; presidio?: boolean }) => {
      const cur = await anonStore.load("c1");
      const outcome = await decisions.replaceControl(
        "c1",
        (c) => ({ ...c, ...patch }),
        anonControlVersion(cur),
      );
      expect(outcome.applied).toBe(true);
    };
    /** Drop the event that carried the name; the model's summary stays in the case. */
    const dropSource = async () => {
      const s = await stateStore.load("c1");
      await stateStore.save({
        ...s,
        forensicTimeline: [event("e2", "lsass.exe memory read by procdump.exe")],
      });
    };
    return { pipeline, authoredStore, setControl, dropSource, stateStore };
  }

  it.each([
    ["Presidio", { presidio: false }, { presidio: true }],
    ["masking", { enabled: false }, { enabled: true }],
  ] as const)("holds the copied name after %s comes back on", async (_label, off, on) => {
    const { pipeline, authoredStore, setControl, dropSource, stateStore } = await setupCase();
    await setControl(off);
    await pipeline.synthesize("c1", { force: true }); // the model copies the name, unprotected
    expect((await stateStore.load("c1")).lastSummary).toBe(COPIED);
    expect(await authoredStore.load("c1")).toEqual([]); // nothing recorded from that call
    await setControl(on);
    await dropSource();
    await expect(pipeline.synthesize("c1", { force: true })).rejects.toBeInstanceOf(PresidioApprovalRequired);
  });

  it("forgets the record when Presidio is switched off, so it cannot excuse a value later", async () => {
    const { pipeline, authoredStore, setControl, dropSource } = await setupCase();
    await dropSource(); // the name is only in what the model will write
    // A protected run that records its own text — here, the summary that names Jane Doe.
    await pipeline.synthesize("c1", { force: true });
    expect(await authoredStore.load("c1")).toContain(COPIED);
    await setControl({ presidio: false });
    expect(await authoredStore.load("c1")).toEqual([]);
    await setControl({ presidio: true });
    await expect(pipeline.synthesize("c1", { force: true })).rejects.toBeInstanceOf(PresidioApprovalRequired);
  });
});

// Codex adversarial review, round 4: the case restores real values into the model's answer. A
// hidden name the model only echoed as a placeholder must not become "the model's own word".
describe("a restored value is never recorded as the model's word", () => {
  const janeDoe: PresidioClient = {
    analyze: async (text) =>
      [...text.matchAll(/Jane\s+Doe/g)].map((m) => ({ entityType: "PERSON", value: m[0], score: 0.9 })),
  };
  /** Echoes the PERSON placeholder it was shown, as a model does. */
  class Echoer extends SummaryProvider {
    override async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
      const r = await super.analyze(req);
      const token = /ANON_PERSON_\d+/.exec(req.userPrompt)?.[0] ?? "nobody";
      const summary = `${token} signed in to the domain controller from the VPN at night.`;
      return { rawText: r.rawText.replace(JSON.stringify(SUMMARY), JSON.stringify(summary)) };
    }
  }

  it("holds the name after it is removed from the hidden list and its event is gone", async () => {
    const cases = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-authored-restored-")));
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const stateStore = new StateStore(cases);
    await stateStore.save({
      ...emptyState("c1"),
      forensicTimeline: [event("e1", "Interactive logon by Jane Doe")],
    });
    const custom = new CustomEntitiesStore(cases);
    await custom.save("c1", [{ value: "Jane Doe", category: "PERSON" }]); // hidden from the AI
    const authoredStore = new AiAuthoredTextStore(cases);
    const pipeline = new AnalysisPipeline({
      provider: new Echoer(),
      stateStore,
      anonStore: new AnonControlStore(cases),
      customEntitiesStore: custom,
      presidioPendingStore: new PresidioPendingStore(cases),
      presidio: { client: janeDoe, url: "http://localhost:5002", minScore: 0.6 },
      aiAuthoredStore: authoredStore,
      imageLoader: async () => ({ base64: "", mimeType: "image/webp" }),
    });

    await pipeline.synthesize("c1", { force: true });
    const summary = (await stateStore.load("c1")).lastSummary;
    expect(summary).toContain("Jane Doe"); // the case's copy holds the restored name
    expect((await authoredStore.load("c1")).join("\n")).not.toContain("Jane Doe"); // the record does not

    await custom.save("c1", []); // the analyst un-hides the name
    const s = await stateStore.load("c1");
    await stateStore.save({ ...s, forensicTimeline: [event("e2", "lsass.exe memory read by procdump.exe")] });
    await expect(pipeline.synthesize("c1", { force: true })).rejects.toBeInstanceOf(PresidioApprovalRequired);
  });
});

// Codex adversarial review, round 6: "Leave visible" sends the value to the model in clear. An answer
// that copies it must not become trusted AI text, or un-suppressing the value later would not bring
// the gate back for it.
describe("a value the analyst left visible is never trusted as AI text", () => {
  const COPIED = "Jane Doe signed in to the domain controller from the VPN at night.";
  /** Flags the full name, and the first name on its own, as Presidio would. */
  const janeDoe: PresidioClient = {
    analyze: async (text) =>
      [...text.matchAll(/Jane(?:\s+Doe)?/g)].map((m) => ({ entityType: "PERSON", value: m[0], score: 0.9 })),
  };
  class Copier extends SummaryProvider {
    /** Runs inside each call, as an analyst click that lands mid-call would. */
    during: () => void = () => {};
    summary = COPIED;
    override async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
      this.during();
      const r = await super.analyze(req);
      return { rawText: r.rawText.replace(JSON.stringify(SUMMARY), JSON.stringify(this.summary)) };
    }
  }

  async function setupCase(description: string) {
    const cases = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-authored-visible-")));
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const stateStore = new StateStore(cases);
    await stateStore.save({ ...emptyState("c1"), forensicTimeline: [event("e1", description)] });
    const anonStore = new AnonControlStore(cases);
    const discovered = new DiscoveredEntitiesStore(cases);
    const pendingStore = new PresidioPendingStore(cases);
    const authoredStore = new AiAuthoredTextStore(cases);
    const custom = new CustomEntitiesStore(cases);
    const provider = new Copier();
    const pipeline = new AnalysisPipeline({
      provider,
      stateStore,
      anonStore,
      customEntitiesStore: custom,
      discoveredStore: discovered,
      presidioPendingStore: pendingStore,
      presidio: { client: janeDoe, url: "http://localhost:5002", minScore: 0.6 },
      aiAuthoredStore: authoredStore,
      imageLoader: async () => ({ base64: "", mimeType: "image/webp" }),
    });
    const decisions = new PresidioDecisions(custom, discovered, pendingStore, anonStore, authoredStore);
    const dropSource = async () => {
      const s = await stateStore.load("c1");
      await stateStore.save({
        ...s,
        forensicTimeline: [event("e2", "lsass.exe memory read by procdump.exe")],
      });
    };
    const addSource = async () => {
      const s = await stateStore.load("c1");
      await stateStore.save({
        ...s,
        forensicTimeline: [...s.forensicTimeline, event("e3", "User Jane Doe signed in")],
      });
    };
    return {
      pipeline,
      provider,
      discovered,
      decisions,
      custom,
      authoredStore,
      stateStore,
      dropSource,
      addSource,
    };
  }

  it("holds the name after Leave visible → synthesis → un-suppress, once its event is gone", async () => {
    const { pipeline, discovered, decisions, authoredStore, stateStore, dropSource } =
      await setupCase("User Jane Doe signed in");
    await expect(pipeline.synthesize("c1", { force: true })).rejects.toBeInstanceOf(PresidioApprovalRequired);
    expect((await decisions.suppress("c1", "Jane Doe")).applied).toBe(true); // Leave visible
    await pipeline.synthesize("c1", { force: true }); // the model sees the name and copies it
    expect((await stateStore.load("c1")).lastSummary).toBe(COPIED);
    expect(await authoredStore.load("c1")).not.toContain(COPIED);

    await discovered.unsuppress("c1", "Jane Doe"); // the analyst takes Leave visible back
    await dropSource();
    await expect(pipeline.synthesize("c1", { force: true })).rejects.toBeInstanceOf(PresidioApprovalRequired);
  });

  // Codex adversarial review, round 7: text recorded BEFORE the value was left visible.
  it("holds the name after record → Leave visible → Hide → custom removal → event removal", async () => {
    const { pipeline, decisions, custom, authoredStore, dropSource, addSource } = await setupCase(
      "lsass.exe memory read by procdump.exe",
    );
    await pipeline.synthesize("c1", { force: true }); // a quiet, protected call records the summary
    expect(await authoredStore.load("c1")).toContain(COPIED);
    await addSource();
    await expect(pipeline.synthesize("c1", { force: true })).rejects.toBeInstanceOf(PresidioApprovalRequired);
    expect((await decisions.suppress("c1", "Jane Doe")).applied).toBe(true); // Leave visible
    expect((await decisions.approve("c1", { value: "Jane Doe", category: "PERSON" })).applied).toBe(true); // Hide
    await custom.save("c1", []); // the analyst removes it from the custom list
    await dropSource();
    await expect(pipeline.synthesize("c1", { force: true })).rejects.toBeInstanceOf(PresidioApprovalRequired);
  });

  // Codex adversarial review, round 8: the model learns from a visible value without repeating it whole.
  it("holds the first name after Leave visible → first-name-only synthesis → un-suppress → event removal", async () => {
    const FIRST = "Jane performed the suspicious login on the domain controller.";
    const { pipeline, provider, discovered, decisions, authoredStore, dropSource } =
      await setupCase("User Jane Doe signed in");
    provider.summary = FIRST;
    await expect(pipeline.synthesize("c1", { force: true })).rejects.toBeInstanceOf(PresidioApprovalRequired);
    expect((await decisions.suppress("c1", "Jane Doe")).applied).toBe(true); // Leave visible
    await pipeline.synthesize("c1", { force: true }); // the model saw "Jane Doe", wrote only "Jane"
    expect(await authoredStore.load("c1")).not.toContain(FIRST); // it holds part of a visible value
    // The un-suppress route's write, in the same order.
    await forgetAround(authoredStore, "c1", "Jane Doe", () => discovered.unsuppress("c1", "Jane Doe"));
    expect(await authoredStore.load("c1")).not.toContain(FIRST);
    await dropSource();
    await expect(pipeline.synthesize("c1", { force: true })).rejects.toBeInstanceOf(PresidioApprovalRequired);
  });

  // Codex adversarial review, round 9: no visibility change at all — the value stays left visible.
  it("holds the first name while Jane Doe stays left visible, once its event is gone", async () => {
    const FIRST = "Jane performed the suspicious login on the domain controller.";
    const { pipeline, provider, decisions, authoredStore, dropSource } =
      await setupCase("User Jane Doe signed in");
    provider.summary = FIRST;
    await expect(pipeline.synthesize("c1", { force: true })).rejects.toBeInstanceOf(PresidioApprovalRequired);
    expect((await decisions.suppress("c1", "Jane Doe")).applied).toBe(true); // Leave visible, and it stays
    await pipeline.synthesize("c1", { force: true }); // the model saw "Jane Doe", wrote only "Jane"
    expect(await authoredStore.load("c1")).not.toContain(FIRST);
    await dropSource();
    await expect(pipeline.synthesize("c1", { force: true })).rejects.toBeInstanceOf(PresidioApprovalRequired);
  });

  it("records nothing from a call an analyst decision landed during", async () => {
    const run = async (during: () => void) => {
      const { pipeline, provider, authoredStore, dropSource } = await setupCase("User Jane Doe signed in");
      await dropSource(); // the name is only in what the model writes
      provider.during = during;
      await pipeline.synthesize("c1", { force: true });
      return authoredStore.load("c1");
    };
    expect(await run(() => bumpAnonRevision("c1"))).toEqual([]);
    expect(await run(() => {})).toContain(COPIED); // a quiet call still records
  });
});
