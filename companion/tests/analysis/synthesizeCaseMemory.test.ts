import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { MockProvider } from "../../src/providers/provider.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { emptyState, type Finding, type ForensicEvent, type InvestigationState, type TimelineEntry } from "../../src/analysis/stateTypes.js";

// Case memory (#165): synthesis logs itself to the Investigation Log (never wiping prior entries),
// and the known-unknowns / candidate-actor blocks are injected into the synthesis + hunt prompts.

let caseStore: CaseStore;
let stateStore: StateStore;

const SYNTH_DELTA = JSON.stringify({
  findings: [{ id: "f1", severity: "High", title: "PS abuse", description: "encoded cmd",
    relatedIocs: [], mitreTechniques: ["T1059"], status: "open", relatedEventIds: ["e1"] }],
  iocs: [], mitreTechniques: [{ id: "T1059", name: "Command Interpreter" }],
  attackerPath: "p", summary: "s", forensicEvents: [], threadsOpened: [], threadsClosed: [], timelineNote: "",
});

function event(id: string, timestamp = "2026-05-20T09:00:00Z"): ForensicEvent {
  return { id, timestamp, description: "x", severity: "High", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [] };
}

// A pre-existing Critical finding covering a few common tactics — drives both the known-unknowns
// "uncovered phases" line and (with broadly-used techniques) the adversary-hint overlap.
function seriousFinding(): Finding {
  return {
    id: "pf1", severity: "Critical", title: "Initial compromise", description: "",
    relatedIocs: [], sourceScreenshots: [], mitreTechniques: ["T1059", "T1566", "T1027", "T1003", "T1105"],
    firstSeen: "2026-05-20T08:00:00Z", lastUpdated: "2026-05-20T08:00:00Z", status: "open",
  };
}

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-casemem-"));
  caseStore = new CaseStore(root);
  await caseStore.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
  stateStore = new StateStore(caseStore);
});

afterEach(() => {
  delete process.env.DFIR_SYNTH_ADVERSARY_HINTS;
});

describe("synthesize → Investigation Log (#165)", () => {
  it("appends one synthesis entry and preserves prior timeline entries", async () => {
    const seeded = emptyState("c1");
    seeded.forensicTimeline.push(event("e1"));
    const prior: TimelineEntry = { timestamp: "2026-05-20T08:30:00Z", windowSequence: 1, description: "THOR import: 5 finding(s) kept", sourceScreenshots: [] };
    seeded.timeline.push(prior);
    await stateStore.save(seeded);

    const pipeline = new AnalysisPipeline({
      provider: new MockProvider("mock", SYNTH_DELTA),
      stateStore,
      imageLoader: async () => ({ base64: "A", mimeType: "image/webp" }),
    });
    await pipeline.synthesize("c1");

    const reloaded = await stateStore.load("c1");
    // prior entry survived (never wiped by synthesis)
    expect(reloaded.timeline.some((t) => t.description === prior.description)).toBe(true);
    // exactly one new synthesis entry was added
    const synthEntries = reloaded.timeline.filter((t) => t.description.startsWith("Synthesis:"));
    expect(synthEntries).toHaveLength(1);
    expect(synthEntries[0].description).toMatch(/Synthesis: 1 finding\(s\) \(1 new, 0 reclassified\), 1 event\(s\), 0 IOC\(s\)/);
  });

  it("does not append a log entry when synthesis is skipped (unchanged inputs)", async () => {
    const seeded = emptyState("c1");
    seeded.forensicTimeline.push(event("e1"));
    await stateStore.save(seeded);

    const provider = new MockProvider("mock", SYNTH_DELTA);
    const analyze = vi.spyOn(provider, "analyze");
    const pipeline = new AnalysisPipeline({ provider, stateStore, imageLoader: async () => ({ base64: "A", mimeType: "image/webp" }) });

    await pipeline.synthesize("c1");
    const afterFirst = (await stateStore.load("c1")).timeline.filter((t) => t.description.startsWith("Synthesis:")).length;
    expect(afterFirst).toBe(1);
    expect(analyze).toHaveBeenCalledTimes(1);

    await pipeline.synthesize("c1"); // unchanged → skipped
    expect(analyze).toHaveBeenCalledTimes(1);
    const afterSkip = (await stateStore.load("c1")).timeline.filter((t) => t.description.startsWith("Synthesis:")).length;
    expect(afterSkip).toBe(1); // no second entry
  });
});

describe("synthesize → prompt grounding blocks (#165)", () => {
  async function captureSynthPrompt(state: InvestigationState): Promise<string> {
    await stateStore.save(state);
    const provider = new MockProvider("mock", SYNTH_DELTA);
    const analyze = vi.spyOn(provider, "analyze");
    const pipeline = new AnalysisPipeline({ provider, stateStore, imageLoader: async () => ({ base64: "A", mimeType: "image/webp" }) });
    await pipeline.synthesize("c1", { force: true });
    // analyze(req) takes one AnalyzeRequest object — grab its userPrompt.
    return String(analyze.mock.calls[0]?.[0]?.userPrompt ?? "");
  }

  it("injects the known-unknowns block (uncovered ATT&CK phases) into the synthesis prompt", async () => {
    const state = emptyState("c1");
    state.forensicTimeline.push(event("e1"));
    state.findings.push(seriousFinding());
    const prompt = await captureSynthPrompt(state);
    expect(prompt).toContain("KNOWN UNKNOWNS / OPEN GAPS");
    expect(prompt).toContain("No finding yet explains these ATT&CK phases");
    expect(prompt).toContain("Lateral Movement"); // a core phase the seeded finding doesn't cover
  });

  it("omits the candidate-actor block by default, includes it when DFIR_SYNTH_ADVERSARY_HINTS is on", async () => {
    const state = emptyState("c1");
    state.forensicTimeline.push(event("e1"));
    state.findings.push(seriousFinding());

    const off = await captureSynthPrompt(state);
    expect(off).not.toContain("CANDIDATE THREAT ACTORS");

    process.env.DFIR_SYNTH_ADVERSARY_HINTS = "1";
    const on = await captureSynthPrompt(state);
    expect(on).toContain("CANDIDATE THREAT ACTORS");
    expect(on).toContain("NOT attribution");
  });
});

describe("suggestHunts → known-unknowns block (#165)", () => {
  it("injects the known-unknowns block into the hunt-suggestion prompt", async () => {
    const state = emptyState("c1");
    state.forensicTimeline.push(event("e1"));
    state.findings.push(seriousFinding());
    await stateStore.save(state);

    const provider = new MockProvider("mock", JSON.stringify({ suggestions: [] }));
    const analyze = vi.spyOn(provider, "analyze");
    const pipeline = new AnalysisPipeline({ provider, stateStore, imageLoader: async () => ({ base64: "A", mimeType: "image/webp" }) });

    await pipeline.suggestHunts("c1");
    expect(analyze).toHaveBeenCalledTimes(1);
    const prompt = String(analyze.mock.calls[0]?.[0]?.userPrompt ?? "");
    expect(prompt).toContain("KNOWN UNKNOWNS / OPEN GAPS");
  });
});
