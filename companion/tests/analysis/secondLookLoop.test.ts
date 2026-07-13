import { describe, it, expect, beforeEach, vi } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { SynthMetaStore } from "../../src/analysis/synthMeta.js";
import { MockProvider } from "../../src/providers/provider.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";

// End-to-end second-look loop (investigation-guidance #11): a synthesis that emits an evidenceRequest
// for data it wasn't shown triggers a raw re-query of the super-timeline, promotes the matching row,
// and re-synthesizes ONCE. A request that matches nothing surfaces as a collection lead without any
// re-synthesis. Uses MockProvider (fixed delta) so behavior is deterministic.

let caseStore: CaseStore;
let stateStore: StateStore;
let superStore: SuperTimelineStore;
let synthMetaStore: SynthMetaStore;

function event(id: string, timestamp: string, description = "benign"): ForensicEvent {
  return { id, timestamp, description, severity: "High", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [] };
}

// Synthesis delta with a model-issued evidenceRequest for "rsync" — the keyword the seeded raw
// super-timeline row carries but the analyzed timeline does not.
function deltaWithRequest(keyword: string): string {
  return JSON.stringify({
    findings: [{ id: "f1", severity: "High", title: "PS abuse", description: "d", relatedIocs: [], mitreTechniques: ["T1059"], status: "open", relatedEventIds: ["e1"] }],
    iocs: [], mitreTechniques: [{ id: "T1059", name: "Command Interpreter" }],
    attackerPath: "p", summary: "s", forensicEvents: [], threadsOpened: [], threadsClosed: [], timelineNote: "",
    hypotheses: [{ title: "Data was staged before exfil", expectedOutcome: "an archive written before transfer", status: "open", relatedTechniques: ["T1560"], relatedEventIds: [], relatedIocIds: [] }],
    evidenceRequests: [{ keywords: [keyword], reason: "confirm the staging/exfil hypothesis with rows not shown" }],
  });
}

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-secondlook-"));
  caseStore = new CaseStore(root);
  await caseStore.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
  stateStore = new StateStore(caseStore);
  superStore = new SuperTimelineStore(caseStore);
  synthMetaStore = new SynthMetaStore(caseStore);

  const seeded = emptyState("c1");
  seeded.forensicTimeline.push(event("e1", "2026-05-20T09:00:00.000Z"));
  seeded.forensicTimeline.push(event("e2", "2026-05-20T11:00:00.000Z"));
  await stateStore.save(seeded);
});

function makePipeline(delta: string) {
  const provider = new MockProvider("mock", delta);
  const analyze = vi.spyOn(provider, "analyze");
  const pipeline = new AnalysisPipeline({
    provider,
    stateStore,
    superTimelineStore: superStore,
    synthMetaStore,
    imageLoader: async () => ({ base64: "A", mimeType: "image/webp" }),
  });
  return { pipeline, analyze };
}

describe("second-look loop end-to-end (#11)", () => {
  it("promotes a matching raw super-timeline row and re-synthesizes exactly once", async () => {
    // A raw host-triage row that only lives in the super-timeline (not the analyzed timeline), within
    // the incident window, carrying the keyword the model will request.
    await superStore.append("c1", [
      event("sraw1", "2026-05-20T10:00:00.000Z", "rsync -a /data nfs-01:/backup archive.zip"),
      event("sraw2", "2026-05-20T10:05:00.000Z", "unrelated noise"),
    ]);

    const { pipeline, analyze } = makePipeline(deltaWithRequest("rsync"));
    await pipeline.synthesize("c1");

    // The raw row was promoted into the analyzed timeline …
    const state = await stateStore.load("c1");
    const promoted = state.forensicTimeline.find((e) => e.id === "sraw1");
    expect(promoted).toBeDefined();
    // … tagged with second-look provenance …
    expect(promoted!.provenance?.some((p) => p.startsWith("[second-look:"))).toBe(true);
    // … the unrelated raw row was NOT promoted …
    expect(state.forensicTimeline.some((e) => e.id === "sraw2")).toBe(false);
    // … exactly one bounded re-synthesis ran (2 AI calls total: initial + second look) …
    expect(analyze).toHaveBeenCalledTimes(2);
    // … and the sweep is recorded on the synth-meta card.
    const meta = await synthMetaStore.load("c1");
    expect(meta.secondLook?.promoted).toBe(1);
    expect(meta.secondLook?.summary).toContain("promoted");
  });

  it("surfaces a zero-match evidence request as a collection lead without re-synthesizing", async () => {
    await superStore.append("c1", [event("sraw1", "2026-05-20T10:00:00.000Z", "totally different content")]);

    const { pipeline, analyze } = makePipeline(deltaWithRequest("kerberoast"));
    await pipeline.synthesize("c1");

    const state = await stateStore.load("c1");
    expect(state.forensicTimeline.some((e) => e.id === "sraw1")).toBe(false); // nothing promoted
    expect(analyze).toHaveBeenCalledTimes(1);                                 // no re-synthesis

    const meta = await synthMetaStore.load("c1");
    expect(meta.secondLook?.promoted).toBe(0);
    expect(meta.secondLook?.leads.length).toBeGreaterThan(0);
  });

  it("does not sweep when superTimelineStore is not wired", async () => {
    const provider = new MockProvider("mock", deltaWithRequest("rsync"));
    const analyze = vi.spyOn(provider, "analyze");
    const pipeline = new AnalysisPipeline({ provider, stateStore, synthMetaStore, imageLoader: async () => ({ base64: "A", mimeType: "image/webp" }) });
    await pipeline.synthesize("c1");
    expect(analyze).toHaveBeenCalledTimes(1); // no second-look pass at all
  });
});
