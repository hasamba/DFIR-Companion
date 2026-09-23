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

// The second look, end to end, as TWO EXPLICIT CALLS (#1554).
//
// It used to be one: `synthesize()` swept the raw record for itself, promoted what it found and
// re-synthesized, so one press of "analyze" made two AI calls and wrote rows into the forensic
// timeline nobody had asked for. That made synthesis the only automatic writer to the evidence
// record. It is a button now, and the call count is how the two halves are told apart:
//
//   * a bare `synthesize()` calls the provider EXACTLY ONCE and promotes NOTHING;
//   * `secondLook()` is what promotes, and what produces the second call.
//
// Counting alone would not catch a regression: a sweep that ran and silently promoted nothing would
// also leave the count at one and look like a pass. Every case below therefore asserts the state of
// the forensic timeline after each call, not only how often the model was asked.

let caseStore: CaseStore;
let stateStore: StateStore;
let superStore: SuperTimelineStore;
let synthMetaStore: SynthMetaStore;

function event(id: string, timestamp: string, description = "benign"): ForensicEvent {
  return {
    id,
    timestamp,
    description,
    severity: "High",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
  };
}

// Synthesis delta with a model-issued evidenceRequest for "rsync" — the keyword the seeded raw
// super-timeline row carries but the analyzed timeline does not.
function deltaWithRequest(keyword: string): string {
  return JSON.stringify({
    findings: [
      {
        id: "f1",
        severity: "High",
        title: "PS abuse",
        description: "d",
        relatedIocs: [],
        mitreTechniques: ["T1059"],
        status: "open",
        relatedEventIds: ["e1"],
      },
    ],
    iocs: [],
    mitreTechniques: [{ id: "T1059", name: "Command Interpreter" }],
    attackerPath: "p",
    summary: "s",
    forensicEvents: [],
    threadsOpened: [],
    threadsClosed: [],
    timelineNote: "",
    hypotheses: [
      {
        title: "Data was staged before exfil",
        expectedOutcome: "an archive written before transfer",
        status: "open",
        relatedTechniques: ["T1560"],
        relatedEventIds: [],
        relatedIocIds: [],
      },
    ],
    evidenceRequests: [
      { keywords: [keyword], reason: "confirm the staging/exfil hypothesis with rows not shown" },
    ],
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

describe("synthesis no longer sweeps for itself (#1554)", () => {
  it("makes exactly one AI call and promotes nothing, even with a raw row matching its own request", async () => {
    await superStore.append("c1", [
      event("sraw1", "2026-05-20T10:00:00.000Z", "rsync -a /data nfs-01:/backup archive.zip"),
    ]);

    const { pipeline, analyze } = makePipeline(deltaWithRequest("rsync"));
    await pipeline.synthesize("c1");

    // The count AND the record. A sweep that ran but promoted nothing would leave the count at one
    // too, so the timeline assertion is what actually distinguishes "did not sweep".
    expect(analyze).toHaveBeenCalledTimes(1);
    const state = await stateStore.load("c1");
    expect(state.forensicTimeline.map((e) => e.id).sort()).toEqual(["e1", "e2"]);
  });

  it("persists the model's own evidence requests, so the button can still act on them later", async () => {
    const { pipeline } = makePipeline(deltaWithRequest("rsync"));
    await pipeline.synthesize("c1");

    // They lived in a closure on the synthesis call until #1554. Decoupled from that call, an
    // unpersisted request would simply cease to exist between the synthesis and the button.
    const meta = await synthMetaStore.load("c1");
    expect(meta.modelEvidenceRequests).toHaveLength(1);
    expect(meta.modelEvidenceRequests?.[0].keywords).toEqual(["rsync"]);
    expect(meta.modelEvidenceRequests?.[0].reason).toContain("staging/exfil");
  });
});

describe("the second-look button (#11, #1554)", () => {
  it("promotes a matching raw super-timeline row and re-synthesizes exactly once", async () => {
    // A raw host-triage row that only lives in the super-timeline (not the analyzed timeline), within
    // the incident window, carrying the keyword the model requested.
    await superStore.append("c1", [
      event("sraw1", "2026-05-20T10:00:00.000Z", "rsync -a /data nfs-01:/backup archive.zip"),
      event("sraw2", "2026-05-20T10:05:00.000Z", "unrelated noise"),
    ]);

    const { pipeline, analyze } = makePipeline(deltaWithRequest("rsync"));
    await pipeline.synthesize("c1");
    expect(analyze).toHaveBeenCalledTimes(1); // the synthesis, and nothing else

    const result = await pipeline.secondLook("c1");

    // The raw row was promoted into the analyzed timeline …
    const state = await stateStore.load("c1");
    const promoted = state.forensicTimeline.find((e) => e.id === "sraw1");
    expect(promoted).toBeDefined();
    // … tagged with second-look provenance …
    expect(promoted!.provenance?.some((p) => p.startsWith("[second-look:"))).toBe(true);
    // … the unrelated raw row was NOT promoted …
    expect(state.forensicTimeline.some((e) => e.id === "sraw2")).toBe(false);
    // … exactly one bounded re-synthesis ran (2 AI calls total: the synthesis, then the button) …
    expect(analyze).toHaveBeenCalledTimes(2);
    expect(result?.promoted).toBe(1);
    expect(result?.resynthesized).toBe(true);
    // … and the sweep is recorded on the synth-meta card, AFTER the re-synthesis rewrote it.
    const meta = await synthMetaStore.load("c1");
    expect(meta.secondLook?.promoted).toBe(1);
    expect(meta.secondLook?.summary).toContain("promoted");
  });

  it("promotes but does NOT re-synthesize when the analyst opts out", async () => {
    await superStore.append("c1", [
      event("sraw1", "2026-05-20T10:00:00.000Z", "rsync -a /data nfs-01:/backup archive.zip"),
    ]);

    const { pipeline, analyze } = makePipeline(deltaWithRequest("rsync"));
    await pipeline.synthesize("c1");
    const result = await pipeline.secondLook("c1", { resynthesize: false });

    expect(result?.promoted).toBe(1);
    expect(result?.resynthesized).toBe(false);
    expect((await stateStore.load("c1")).forensicTimeline.some((e) => e.id === "sraw1")).toBe(true);
    expect(analyze).toHaveBeenCalledTimes(1); // no second call — the conclusions stay as they were
  });

  it("surfaces a zero-match evidence request as a collection lead without re-synthesizing", async () => {
    await superStore.append("c1", [event("sraw1", "2026-05-20T10:00:00.000Z", "totally different content")]);

    const { pipeline, analyze } = makePipeline(deltaWithRequest("kerberoast"));
    await pipeline.synthesize("c1");
    const result = await pipeline.secondLook("c1");

    const state = await stateStore.load("c1");
    expect(state.forensicTimeline.some((e) => e.id === "sraw1")).toBe(false); // nothing promoted
    expect(analyze).toHaveBeenCalledTimes(1); // nothing new to fold in, so no second call
    expect(result?.resynthesized).toBe(false);

    const meta = await synthMetaStore.load("c1");
    expect(meta.secondLook?.promoted).toBe(0);
    expect(meta.secondLook?.leads.length).toBeGreaterThan(0);
  });

  // #932 item 5 part B: a pending lab row (sandbox behaviour nobody promoted) is out of the
  // candidate pool ENTIRELY. It must not be promoted — and it must not satisfy the request either,
  // or hidden lab evidence would silently close a collection request.
  it("never promotes a lab row, and a request matching only a lab row still becomes a collection lead", async () => {
    await superStore.append("c1", [
      {
        ...event(
          "sblab",
          "2026-05-20T10:00:00.000Z",
          "CAPE signature: [run 42] rsync_exfil — rsync archive.zip to remote",
        ),
        origin: "lab",
        sources: ["CAPEv2"],
      },
    ]);

    const { pipeline, analyze } = makePipeline(deltaWithRequest("rsync"));
    await pipeline.synthesize("c1");
    await pipeline.secondLook("c1");

    const state = await stateStore.load("c1");
    expect(state.forensicTimeline.some((e) => e.id === "sblab")).toBe(false);
    expect(analyze).toHaveBeenCalledTimes(1);
    const meta = await synthMetaStore.load("c1");
    expect(meta.secondLook?.promoted).toBe(0);
    expect(meta.secondLook?.leads.length).toBeGreaterThan(0);
  });

  it("lets a lab row the analyst promoted satisfy a request (it is forensic evidence by their choice)", async () => {
    const seeded = await stateStore.load("c1");
    seeded.forensicTimeline.push({
      ...event(
        "sbprom",
        "2026-05-20T10:00:00.000Z",
        "CAPE signature: [run 42] rsync_exfil — rsync archive.zip to remote",
      ),
      origin: "lab",
      sources: ["CAPEv2"],
      severity: "Info",
      provenance: ["[promoted]"],
    });
    await stateStore.save(seeded);

    const { pipeline, analyze } = makePipeline(deltaWithRequest("rsync"));
    await pipeline.synthesize("c1");
    await pipeline.secondLook("c1");

    const meta = await synthMetaStore.load("c1");
    expect(meta.secondLook?.promoted).toBe(0); // already forensic — nothing to promote
    expect(meta.secondLook?.leads).toHaveLength(0); // the request was satisfied by the promoted row
    expect(analyze).toHaveBeenCalledTimes(1);
  });

  it("has nothing to offer when superTimelineStore is not wired", async () => {
    const provider = new MockProvider("mock", deltaWithRequest("rsync"));
    const analyze = vi.spyOn(provider, "analyze");
    const pipeline = new AnalysisPipeline({
      provider,
      stateStore,
      synthMetaStore,
      imageLoader: async () => ({ base64: "A", mimeType: "image/webp" }),
    });
    await pipeline.synthesize("c1");
    expect(analyze).toHaveBeenCalledTimes(1);

    // No raw record to re-query. The preview says so rather than reporting an empty sweep, and the
    // run returns null so the route can answer 501 instead of pretending it did something.
    expect((await pipeline.secondLookPreview("c1")).configured).toBe(false);
    expect(await pipeline.secondLook("c1")).toBeNull();
    expect(analyze).toHaveBeenCalledTimes(1);
  });
});

describe("the second-look preview is a true dry run", () => {
  it("counts what the sweep would promote without touching the forensic timeline", async () => {
    await superStore.append("c1", [
      event("sraw1", "2026-05-20T10:00:00.000Z", "rsync -a /data nfs-01:/backup archive.zip"),
      event("sraw2", "2026-05-20T10:05:00.000Z", "unrelated noise"),
    ]);

    const { pipeline, analyze } = makePipeline(deltaWithRequest("rsync"));
    await pipeline.synthesize("c1");

    const preview = await pipeline.secondLookPreview("c1");
    expect(preview.configured).toBe(true);
    expect(preview.modelRequests).toBe(1);
    expect(preview.requests).toBe(1);
    expect(preview.wouldPromote).toBe(1);
    expect(preview.leads).toEqual([]);

    // The whole point: after a preview the case is exactly as it was, and no model was asked.
    const state = await stateStore.load("c1");
    expect(state.forensicTimeline.map((e) => e.id).sort()).toEqual(["e1", "e2"]);
    expect(analyze).toHaveBeenCalledTimes(1);
  });

  it("reports an unresolved request as a lead it would record", async () => {
    await superStore.append("c1", [event("sraw1", "2026-05-20T10:00:00.000Z", "totally different content")]);

    const { pipeline } = makePipeline(deltaWithRequest("kerberoast"));
    await pipeline.synthesize("c1");

    const preview = await pipeline.secondLookPreview("c1");
    expect(preview.wouldPromote).toBe(0);
    expect(preview.leads.length).toBeGreaterThan(0);
  });
});
