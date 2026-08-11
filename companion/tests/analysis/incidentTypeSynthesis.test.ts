import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { IncidentTypeStore } from "../../src/analysis/incidentTypeStore.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import type { AIProvider, AnalyzeRequest, AnalyzeResult } from "../../src/providers/provider.js";

// The incident type's synthesis hint must reach the synthesis PROMPT (#236). It used to be stamped
// onto state.lastSummary instead, which both printed it as the report's executive summary and let
// the first synthesis overwrite it — so these tests pin the prompt, not the state.

const SYNTH_DELTA = JSON.stringify({
  findings: [],
  iocs: [],
  mitreTechniques: [],
  attackerPath: "p",
  summary: "s",
  forensicEvents: [],
  threadsOpened: [],
  threadsClosed: [],
  timelineNote: "",
});

class CapturingProvider implements AIProvider {
  readonly name = "capture";
  readonly model = "capture-model";
  lastReq?: AnalyzeRequest;
  async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
    this.lastReq = req;
    return { rawText: SYNTH_DELTA };
  }
}

function ev(p: Partial<ForensicEvent> & { id: string }): ForensicEvent {
  return {
    timestamp: "2026-01-01T00:00:00Z",
    description: "",
    severity: "High",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...p,
  };
}

async function makePipeline(opts: { withStore?: boolean } = {}) {
  const root = await mkdtemp(join(tmpdir(), "dfir-itype-synth-"));
  const casesRoot = join(root, "cases");
  const cases = new CaseStore(casesRoot);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(cases);
  const state = emptyState("c1");
  state.forensicTimeline = [ev({ id: "e1", description: "vssadmin delete shadows /all /quiet" })];
  await stateStore.save(state);

  const incidentTypeStore = new IncidentTypeStore(cases, join(root, "incident-types"));
  const provider = new CapturingProvider();
  const pipeline = new AnalysisPipeline({
    provider,
    synthesisProvider: provider,
    stateStore,
    imageLoader: async () => ({ base64: "", mimeType: "image/webp" }),
    ...(opts.withStore === false ? {} : { incidentTypeStore }),
  });
  return { pipeline, provider, stateStore, incidentTypeStore };
}

describe("incident-type synthesis hint (#236)", () => {
  it("prepends the chosen type's hint to the synthesis prompt", async () => {
    const { pipeline, provider, incidentTypeStore } = await makePipeline();
    await incidentTypeStore.saveRecord("c1", "ransomware");

    await pipeline.synthesize("c1", { force: true });

    const prompt = provider.lastReq!.userPrompt;
    expect(prompt).toContain("INCIDENT TYPE: Ransomware.");
    expect(prompt).toContain("T1486");
    // Framing belongs at the top, before the evidence it is meant to frame.
    expect(prompt.indexOf("INCIDENT TYPE:")).toBeLessThan(prompt.indexOf("FORENSIC TIMELINE"));
  });

  it("sends no hint when the case has no incident type", async () => {
    const { pipeline, provider } = await makePipeline();
    await pipeline.synthesize("c1", { force: true });
    expect(provider.lastReq!.userPrompt).not.toContain("INCIDENT TYPE:");
  });

  it("sends no hint when the store is not wired (CLI / tests)", async () => {
    const { pipeline, provider } = await makePipeline({ withStore: false });
    await pipeline.synthesize("c1", { force: true });
    expect(provider.lastReq!.userPrompt).not.toContain("INCIDENT TYPE:");
  });

  it("survives synthesis — unlike the old lastSummary stamp, which the first run overwrote", async () => {
    const { pipeline, provider, stateStore, incidentTypeStore } = await makePipeline();
    await incidentTypeStore.saveRecord("c1", "ransomware");

    await pipeline.synthesize("c1", { force: true });
    // Synthesis wrote its own summary into lastSummary; the hint is unaffected because it never
    // lived there.
    expect((await stateStore.load("c1")).lastSummary).toBe("s");

    await pipeline.synthesize("c1", { force: true });
    expect(provider.lastReq!.userPrompt).toContain("INCIDENT TYPE: Ransomware.");
  });

  it("changing the incident type re-synthesizes instead of skipping as unchanged", async () => {
    const { pipeline, provider, incidentTypeStore } = await makePipeline();
    await incidentTypeStore.saveRecord("c1", "ransomware");
    await pipeline.synthesize("c1", { force: true });

    // No force this time: only the type changed, and that must be enough to invalidate the
    // skip-if-unchanged hash.
    await incidentTypeStore.saveRecord("c1", "bec");
    await pipeline.synthesize("c1");
    expect(provider.lastReq!.userPrompt).toContain("INCIDENT TYPE: BEC / Email Compromise.");
  });
});
