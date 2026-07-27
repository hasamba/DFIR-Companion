import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { AnonControlStore } from "../../src/analysis/anonControl.js";
import { DiscoveredEntitiesStore } from "../../src/analysis/anonDiscovered.js";
import { PresidioPendingStore } from "../../src/analysis/presidioPending.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import { PresidioApprovalRequired, type PresidioClient, type PresidioFinding } from "../../src/analysis/presidio.js";
import type { AIProvider, AnalyzeRequest, AnalyzeResult } from "../../src/providers/provider.js";
import type { CustomEntity } from "../../src/analysis/anonymize.js";
import type { CaptureMetadata } from "../../src/types.js";

// End-to-end coverage of the Presidio gate GLUE in analyzeRestored (the chokepoint all 27 AI call
// sites funnel through). Presidio runs AFTER the local anonymizer on already-masked text, so this
// proves the pipeline (a) masks first, (b) throws + persists on an unseen value, (c) proceeds once
// approved, and (d) fails closed when the client itself errors. No socket is ever opened — the
// client is a stub injected via AnalysisPipelineOptions.presidio.

class StubProvider implements AIProvider {
  readonly name = "stub";
  async analyze(_req: AnalyzeRequest): Promise<AnalyzeResult> {
    return {
      rawText: JSON.stringify({
        findings: [], iocs: [], mitreTechniques: [], threadsOpened: [], threadsClosed: [],
        forensicEvents: [], timelineNote: "", summary: "",
      }),
    };
  }
}

function stubClient(findings: PresidioFinding[], seen: string[] = []): PresidioClient {
  return {
    analyze: async (text: string) => {
      seen.push(text);
      return findings;
    },
  };
}

function capture(): CaptureMetadata {
  return {
    caseId: "c1", sequenceNumber: 1, timestamp: "2026-05-28T10:01:00.000Z",
    url: "https://velociraptor.local", tabTitle: "VR", triggerType: "timer",
    contentHash: "0000000000000000", isDuplicate: false, screenshotFile: "000001_t.webp",
  };
}

// host defaults to a value the anonymizer will tokenize, so the masked-text assertion has
// something real to look for. `discoveredStoreOverride` lets a test substitute a fake store (e.g.
// one that returns non-lowercased `suppressed` values) instead of the real, always-lowercasing one.
async function makePipeline(
  client: PresidioClient,
  discovered: CustomEntity[] = [],
  host = "DC01.victim.local",
  discoveredStoreOverride?: DiscoveredEntitiesStore,
) {
  const root = await mkdtemp(join(tmpdir(), "dfir-presidiopipe-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(cases);
  const s = emptyState("c1");
  s.forensicTimeline = [{
    id: "e1", timestamp: "2026-01-01T00:00:00Z", description: `process run on ${host}`,
    severity: "High", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], asset: host,
  }];
  await stateStore.save(s);

  const discoveredStore = discoveredStoreOverride ?? new DiscoveredEntitiesStore(cases);
  if (!discoveredStoreOverride && discovered.length > 0) await discoveredStore.addDiscovered("c1", discovered);
  const presidioPendingStore = new PresidioPendingStore(cases);

  const pipeline = new AnalysisPipeline({
    provider: new StubProvider(),
    stateStore,
    anonStore: new AnonControlStore(cases), // anonymization defaults ON
    discoveredStore,
    presidioPendingStore,
    presidio: { client, url: "http://localhost:5002", minScore: 0.6 },
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/png" }),
  });
  return { pipeline, presidioPendingStore, discoveredStore };
}

// A fake DiscoveredEntitiesStore that returns `suppressed` values EXACTLY as given — bypassing the
// real store's sanitizeDiscovered(), which always lower-cases them. Used to prove the gate itself
// case-folds `known.suppressed` rather than trusting the store to have done so already.
function fakeDiscoveredStore(suppressed: string[]): DiscoveredEntitiesStore {
  return {
    load: async () => ({ discovered: [], suppressed }),
    addDiscovered: async () => ({ discovered: [], suppressed }),
    suppress: async () => ({ discovered: [], suppressed }),
    unsuppress: async () => ({ discovered: [], suppressed }),
  } as unknown as DiscoveredEntitiesStore;
}

describe("analyzeRestored + Presidio", () => {
  it("throws PresidioApprovalRequired when a value is new to the case", async () => {
    const { pipeline } = await makePipeline(stubClient([{ entityType: "PERSON", value: "Jane Doe", score: 0.9 }]));
    await expect(pipeline.analyzeWindow("c1", [capture()])).rejects.toBeInstanceOf(PresidioApprovalRequired);
  });

  it("persists the pending findings so the dashboard can render them", async () => {
    const { pipeline, presidioPendingStore } = await makePipeline(
      stubClient([{ entityType: "PERSON", value: "Jane Doe", score: 0.9 }]),
    );
    await expect(pipeline.analyzeWindow("c1", [capture()])).rejects.toBeInstanceOf(PresidioApprovalRequired);
    expect(await presidioPendingStore.load("c1")).toEqual([{ value: "Jane Doe", category: "PERSON" }]);
  });

  it("proceeds once the value is already in the discovered list", async () => {
    // `seen`/`presidioPendingStore` prove the gate actually RAN and cleared, not merely that the
    // call resolved — resolves.toBeDefined() alone passes even with the whole feature deleted,
    // since analyzeWindow resolves to state on the happy path regardless of Presidio.
    const seen: string[] = [];
    const { pipeline, presidioPendingStore } = await makePipeline(
      stubClient([{ entityType: "PERSON", value: "Jane Doe", score: 0.9 }], seen),
      [{ value: "Jane Doe", category: "PERSON" }],
    );
    await expect(pipeline.analyzeWindow("c1", [capture()])).resolves.toBeDefined();
    expect(seen).toHaveLength(1);
    expect(await presidioPendingStore.load("c1")).toEqual([]);
  });

  it("does not gate on a suppressed value even if the store's case-folding invariant is violated", async () => {
    // known.suppressed is DOCUMENTED as pre-lowercased and the real store enforces it, but the
    // gate must not silently depend on that — a fake store here hands back "Jane Doe" (mixed
    // case) as the analyst's suppression veto, deliberately bypassing sanitizeDiscovered().
    const seen: string[] = [];
    const { pipeline } = await makePipeline(
      stubClient([{ entityType: "PERSON", value: "Jane Doe", score: 0.9 }], seen),
      [],
      "DC01.victim.local",
      fakeDiscoveredStore(["Jane Doe"]),
    );
    await expect(pipeline.analyzeWindow("c1", [capture()])).resolves.toBeDefined();
    expect(seen).toHaveLength(1);
  });

  it("sends Presidio MASKED text, never raw values", async () => {
    const seen: string[] = [];
    const { pipeline } = await makePipeline(stubClient([], seen));
    await pipeline.analyzeWindow("c1", [capture()]);
    expect(seen).toHaveLength(1);
    expect(seen[0]).not.toContain("DC01.victim.local");
    expect(seen[0]).toMatch(/ANON_HOST_1/);
  });

  it("fails the AI call when the client throws", async () => {
    const dead: PresidioClient = { analyze: async () => { throw new Error("ECONNREFUSED"); } };
    const { pipeline } = await makePipeline(dead);
    await expect(pipeline.analyzeWindow("c1", [capture()])).rejects.toThrow(/not reachable/);
  });

  it("does not retry the approval gate", async () => {
    const seen: string[] = [];
    const { pipeline } = await makePipeline(
      stubClient([{ entityType: "PERSON", value: "Jane Doe", score: 0.9 }], seen),
    );
    await expect(pipeline.analyzeWindow("c1", [capture()])).rejects.toBeInstanceOf(PresidioApprovalRequired);
    expect(seen).toHaveLength(1);
  });
});
