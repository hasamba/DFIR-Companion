import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { MockProvider } from "../../src/providers/provider.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import type { CaptureMetadata } from "../../src/types.js";

let caseStore: CaseStore;
let stateStore: StateStore;

function capture(seq: number): CaptureMetadata {
  return {
    caseId: "c1", sequenceNumber: seq, timestamp: `2026-05-28T10:0${seq}:00.000Z`,
    url: "https://velociraptor.local", tabTitle: "VR", triggerType: "timer",
    perceptualHash: "0000000000000000", isDuplicate: false, screenshotFile: `00000${seq}_t.webp`,
  };
}

const validDelta = JSON.stringify({
  findings: [{ id: "f1", severity: "High", title: "PS abuse", description: "encoded cmd",
    relatedIocs: [], mitreTechniques: ["T1059"], status: "open" }],
  iocs: [], mitreTechniques: [{ id: "T1059", name: "Command Interpreter" }],
  threadsOpened: [], threadsClosed: [], timelineNote: "reviewed processes", summary: "found PS abuse",
});

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-pipeline-"));
  caseStore = new CaseStore(root);
  await caseStore.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
  stateStore = new StateStore(caseStore);
});

describe("AnalysisPipeline", () => {
  it("analyzes a window and persists merged state", async () => {
    const pipeline = new AnalysisPipeline({
      provider: new MockProvider("mock", validDelta),
      stateStore,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });

    const state = await pipeline.analyzeWindow("c1", [capture(1)]);
    expect(state.findings).toHaveLength(1);
    expect(state.findings[0].title).toBe("PS abuse");

    const reloaded = await stateStore.load("c1");
    expect(reloaded.findings).toHaveLength(1);
  });

  it("parses a delta even when the model wraps it in a ```json markdown fence", async () => {
    const fenced = "```json\n" + validDelta + "\n```";
    const pipeline = new AnalysisPipeline({
      provider: new MockProvider("mock", fenced),
      stateStore,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });

    const state = await pipeline.analyzeWindow("c1", [capture(1)]);
    expect(state.findings).toHaveLength(1);
    expect(state.findings[0].title).toBe("PS abuse");
  });

  it("throws on malformed AI response and leaves state unchanged", async () => {
    const pipeline = new AnalysisPipeline({
      provider: new MockProvider("mock", "not json at all"),
      stateStore,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
      retries: 0,
    });

    await expect(pipeline.analyzeWindow("c1", [capture(1)])).rejects.toThrow();
    const state = await stateStore.load("c1");
    expect(state.findings).toHaveLength(0);
  });

  it("invokes onState after a successful analysis", async () => {
    let received: string | null = null;
    const pipeline = new AnalysisPipeline({
      provider: new MockProvider("mock", validDelta),
      stateStore,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
      onState: (s) => { received = s.caseId; },
    });
    await pipeline.analyzeWindow("c1", [capture(1)]);
    expect(received).toBe("c1");
  });

  it("synthesize derives findings + attacker path from the forensic timeline", async () => {
    // Seed a forensic timeline (as per-window extraction would build) but no findings.
    const seeded = emptyState("c1");
    seeded.forensicTimeline.push(
      { id: "e1", timestamp: "2026-05-20T09:00:00Z", description: "phish opened", severity: "High",
        mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: ["s1.webp"] },
      { id: "e2", timestamp: "2026-05-20T15:00:00Z", description: "defender disabled", severity: "Critical",
        mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: ["s2.webp"] },
    );
    await stateStore.save(seeded);

    const synthDelta = JSON.stringify({
      findings: [{ id: "f1", severity: "Critical", title: "Defender disabled to evade detection",
        description: "AV turned off before payload", relatedIocs: [], mitreTechniques: ["T1562.001"], status: "confirmed" }],
      iocs: [], mitreTechniques: [{ id: "T1562.001", name: "Impair Defenses" }],
      attackerPath: "Phishing at 09:00, then Defender disabled at 15:00 to enable execution.",
      summary: "Phishing-led intrusion with defense evasion.",
      forensicEvents: [], threadsOpened: [], threadsClosed: [], timelineNote: "",
    });
    const pipeline = new AnalysisPipeline({
      provider: new MockProvider("mock", synthDelta),
      stateStore,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });

    const state = await pipeline.synthesize("c1");
    expect(state.findings).toHaveLength(1);
    expect(state.findings[0].title).toContain("Defender disabled");
    expect(state.mitreTechniques.map((t) => t.id)).toContain("T1562.001");
    expect(state.attackerPath).toContain("Phishing");
    // synthesis must not wipe the forensic timeline it read from
    expect(state.forensicTimeline).toHaveLength(2);
  });

  it("synthesize uses synthesisProvider (stronger model) when provided", async () => {
    const seeded = emptyState("c1");
    seeded.forensicTimeline.push({ id: "e1", timestamp: "2026-05-20T09:00:00Z", description: "phish",
      severity: "High", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: ["s1.webp"] });
    await stateStore.save(seeded);

    const synthDelta = JSON.stringify({
      findings: [{ id: "f1", severity: "High", title: "from synth model", description: "d",
        relatedIocs: [], mitreTechniques: [], status: "open" }],
      iocs: [], mitreTechniques: [], attackerPath: "p", summary: "s",
      forensicEvents: [], threadsOpened: [], threadsClosed: [], timelineNote: "",
    });
    const pipeline = new AnalysisPipeline({
      provider: new MockProvider("cheap", "EXTRACTION MODEL SHOULD NOT BE CALLED FOR SYNTHESIS"),
      synthesisProvider: new MockProvider("strong", synthDelta),
      stateStore,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });

    const state = await pipeline.synthesize("c1");
    expect(state.findings).toHaveLength(1);
    expect(state.findings[0].title).toBe("from synth model");
  });

  it("synthesize is a no-op when there is no forensic timeline", async () => {
    const pipeline = new AnalysisPipeline({
      provider: new MockProvider("mock", "should not be called"),
      stateStore,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });
    const state = await pipeline.synthesize("c1");
    expect(state.findings).toHaveLength(0);
    expect(state.forensicTimeline).toHaveLength(0);
  });
});
