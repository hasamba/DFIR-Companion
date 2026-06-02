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

  it("synthesis prompt asks for granular per-technique findings (not one campaign finding)", async () => {
    const { SYNTHESIS_PROMPT } = await import("../../src/analysis/pipeline.js");
    expect(SYNTHESIS_PROMPT).toContain("SEPARATE finding for EACH distinct");
    expect(SYNTHESIS_PROMPT).toMatch(/do not collapse/i);
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

  it("synthesize back-links forensic events to the correct findings via relatedEventIds", async () => {
    const seeded = emptyState("c1");
    seeded.forensicTimeline.push(
      { id: "e1", timestamp: "2026-05-20T09:00:00Z", description: "SharpHound ran", severity: "High",
        mitreTechniques: [], relatedFindingIds: ["f99"], sourceScreenshots: [] }, // stale wrong guess
      { id: "e2", timestamp: "2026-05-20T15:00:00Z", description: "Mimikatz ran", severity: "Critical",
        mitreTechniques: [], relatedFindingIds: ["f99"], sourceScreenshots: [] },
    );
    await stateStore.save(seeded);

    const synthDelta = JSON.stringify({
      findings: [
        { id: "f1", severity: "High", title: "AD recon", description: "x", relatedIocs: [], mitreTechniques: [], status: "open", relatedEventIds: ["e1"] },
        { id: "f2", severity: "Critical", title: "Credential dumping", description: "y", relatedIocs: [], mitreTechniques: [], status: "open", relatedEventIds: ["e2"] },
      ],
      iocs: [], mitreTechniques: [], attackerPath: "p", summary: "s",
      forensicEvents: [], threadsOpened: [], threadsClosed: [], timelineNote: "",
    });
    const pipeline = new AnalysisPipeline({
      provider: new MockProvider("mock", synthDelta),
      stateStore,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });

    const state = await pipeline.synthesize("c1");
    const e1 = state.forensicTimeline.find((e) => e.id === "e1")!;
    const e2 = state.forensicTimeline.find((e) => e.id === "e2")!;
    expect(e1.relatedFindingIds).toEqual(["f1"]); // corrected from stale "f99"
    expect(e2.relatedFindingIds).toEqual(["f2"]);
  });

  it("synthesize opens new threads and closes existing ones by id", async () => {
    const seeded = emptyState("c1");
    seeded.forensicTimeline.push({ id: "e1", timestamp: "2026-05-20T09:00:00Z", description: "phish",
      severity: "High", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: ["s1.webp"] });
    seeded.openThreads.push({ id: "t0", description: "how did they get in?", status: "open",
      openedAt: "2026-05-20T08:00:00Z", closedAt: null });
    await stateStore.save(seeded);

    const synthDelta = JSON.stringify({
      findings: [], iocs: [], mitreTechniques: [], attackerPath: "p", summary: "s",
      forensicEvents: [], timelineNote: "",
      threadsOpened: [{ id: "t1", description: "identify the C2 domain" }], // new lead
      threadsClosed: ["t0"],                                               // resolved by evidence
    });
    const pipeline = new AnalysisPipeline({
      provider: new MockProvider("mock", synthDelta),
      stateStore,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });

    const state = await pipeline.synthesize("c1");
    const t0 = state.openThreads.find((t) => t.id === "t0")!;
    const t1 = state.openThreads.find((t) => t.id === "t1")!;
    expect(t0.status).toBe("closed");
    expect(t0.closedAt).not.toBeNull();
    expect(t1.status).toBe("open");
    expect(t1.description).toBe("identify the C2 domain");
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

  it("synthesize excludes client-confirmed legitimate findings/IOCs even if the model returns them", async () => {
    const { LegitimateStore } = await import("../../src/analysis/legitimate.js");
    const seeded = emptyState("c1");
    seeded.forensicTimeline.push({ id: "e1", timestamp: "2026-05-20T09:00:00Z", description: "SharpHound ran",
      severity: "High", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: ["s1.webp"] });
    await stateStore.save(seeded);

    const legitimateStore = new LegitimateStore(caseStore);
    await legitimateStore.save("c1", [
      { id: "finding:sharphound ad recon", kind: "finding", ref: "SharpHound AD recon", note: "authorized", markedAt: "" },
      { id: "ioc:sharphound.exe", kind: "ioc", ref: "SharpHound.exe", note: "", markedAt: "" },
    ]);

    // Model still (wrongly) returns the legitimate finding + IOC.
    const synthDelta = JSON.stringify({
      findings: [
        { id: "f1", severity: "High", title: "SharpHound AD recon", description: "x", relatedIocs: [], mitreTechniques: [], status: "open" },
        { id: "f2", severity: "Critical", title: "Mimikatz credential dumping", description: "y", relatedIocs: [], mitreTechniques: [], status: "open" },
      ],
      iocs: [{ id: "i1", type: "process", value: "SharpHound.exe" }, { id: "i2", type: "ip", value: "10.0.0.5" }],
      mitreTechniques: [], attackerPath: "p", summary: "s",
      forensicEvents: [], threadsOpened: [], threadsClosed: [], timelineNote: "",
    });
    const pipeline = new AnalysisPipeline({
      provider: new MockProvider("mock", synthDelta),
      legitimateStore,
      stateStore,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });

    const state = await pipeline.synthesize("c1");
    expect(state.findings.map((f) => f.title)).toEqual(["Mimikatz credential dumping"]);
    expect(state.iocs.map((i) => i.value)).toEqual(["10.0.0.5"]);
  });

  it("synthesize only sends in-scope events to the model and replaces stale findings", async () => {
    const { ScopeStore } = await import("../../src/analysis/scope.js");
    const seeded = emptyState("c1");
    seeded.forensicTimeline.push(
      { id: "old", timestamp: "2024-06-01T00:00:00Z", description: "ancient event", severity: "High",
        mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [] },
      { id: "in", timestamp: "2026-01-15T00:00:00Z", description: "in-scope event", severity: "High",
        mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [] },
    );
    // A stale finding from a previous (unscoped) run that must be dropped on re-synthesis.
    seeded.findings.push({ id: "fold", severity: "Critical", title: "stale", description: "", relatedIocs: [],
      mitreTechniques: [], sourceScreenshots: [], firstSeen: "", lastUpdated: "", status: "open" });
    await stateStore.save(seeded);

    const scopeStore = new ScopeStore(caseStore);
    await scopeStore.save("c1", { start: "2026-01-01T00:00:00Z", end: "2026-12-31T00:00:00Z" });

    let sentPrompt = "";
    const provider = {
      name: "spy",
      analyze: async (req: { userPrompt: string }) => {
        sentPrompt = req.userPrompt;
        return { rawText: JSON.stringify({
          findings: [{ id: "f1", severity: "High", title: "scoped finding", description: "x", relatedIocs: [], mitreTechniques: [], status: "open", relatedEventIds: ["in"] }],
          iocs: [], mitreTechniques: [], attackerPath: "p", summary: "s",
          forensicEvents: [], threadsOpened: [], threadsClosed: [], timelineNote: "",
        }) };
      },
    };
    const pipeline = new AnalysisPipeline({
      provider, scopeStore, stateStore,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });

    const state = await pipeline.synthesize("c1");
    expect(sentPrompt).toContain("in-scope event");
    expect(sentPrompt).not.toContain("ancient event");        // out-of-scope not sent
    expect(state.findings.map((f) => f.title)).toEqual(["scoped finding"]); // stale "fold" replaced
    expect(state.forensicTimeline).toHaveLength(2);            // raw events preserved
  });

  it("analyzeCsv extracts forensic events from rows and keeps event ids unique across batches", async () => {
    // Each batch independently emits an event with id "e1"; the import must renumber
    // them so chunked CSVs accumulate instead of overwriting (merge dedupes by id).
    const oneEvent = JSON.stringify({
      findings: [], iocs: [{ id: "i1", type: "process", value: "mimikatz.exe" }], mitreTechniques: [],
      threadsOpened: [], threadsClosed: [], timelineNote: "read rows", attackerPath: "", summary: "",
      forensicEvents: [{ id: "e1", timestamp: "2026-05-20T09:00:00Z", description: "row event",
        severity: "High", mitreTechniques: [], relatedFindingIds: [] }],
    });
    const pipeline = new AnalysisPipeline({
      provider: new MockProvider("mock", oneEvent),
      stateStore,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });

    const csv = "Time,Process\n09:00,a.exe\n09:01,b.exe\n09:02,c.exe\n"; // 3 rows
    const state = await pipeline.analyzeCsv("c1", csv, {
      label: "0001_results.csv", idPrefix: "m1", importedAt: "2026-06-01T00:00:00Z", rowsPerBatch: 2,
    });

    // 3 rows / 2 per batch = 2 batches → 2 events with distinct ids, both from the CSV.
    expect(state.forensicTimeline).toHaveLength(2);
    expect(new Set(state.forensicTimeline.map((e) => e.id)).size).toBe(2);
    expect(state.forensicTimeline.every((e) => e.sourceScreenshots.includes("0001_results.csv"))).toBe(true);
  });

  it("synthesize hides client-confirmed legitimate events from the model but preserves them in state", async () => {
    const { LegitimateStore, markerId } = await import("../../src/analysis/legitimate.js");
    const seeded = emptyState("c1");
    seeded.forensicTimeline.push(
      { id: "e1", timestamp: "2026-05-28T09:00:00Z", description: "attacker process create", severity: "High",
        mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [] },
      { id: "e2", timestamp: "2026-05-28T09:05:00Z", description: "client admin maintenance task", severity: "Medium",
        mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [] },
    );
    await stateStore.save(seeded);

    const legitimateStore = new LegitimateStore(caseStore);
    await legitimateStore.save("c1", [
      { id: markerId("event", "e2"), kind: "event", ref: "e2", note: "client's own admin", markedAt: "2026-05-28T10:00:00Z", label: "client admin maintenance task" },
    ]);

    let sentPrompt = "";
    const provider = {
      name: "spy",
      analyze: async (req: { userPrompt: string }) => {
        sentPrompt = req.userPrompt;
        return { rawText: JSON.stringify({
          findings: [], iocs: [], mitreTechniques: [], attackerPath: "", summary: "s",
          forensicEvents: [], threadsOpened: [], threadsClosed: [], timelineNote: "",
        }) };
      },
    };
    const pipeline = new AnalysisPipeline({
      provider, legitimateStore, stateStore,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });

    const state = await pipeline.synthesize("c1");
    expect(sentPrompt).toContain("attacker process create");        // legit-untouched event still sent
    expect(sentPrompt).not.toContain("client admin maintenance task"); // legit event excluded from input
    expect(state.forensicTimeline.map((e) => e.id)).toEqual(["e1", "e2"]); // both preserved (reversible)
  });

  it("analyzeLog extracts forensic events from log lines and renumbers ids across batches", async () => {
    // Mirrors the CSV path: each batch independently emits "e1"; the import must
    // renumber so chunked log batches accumulate instead of overwriting.
    const oneEvent = JSON.stringify({
      findings: [], iocs: [{ id: "i1", type: "ip", value: "10.0.0.5" }], mitreTechniques: [],
      threadsOpened: [], threadsClosed: [], timelineNote: "read lines", attackerPath: "", summary: "",
      forensicEvents: [{ id: "e1", timestamp: "2026-05-28T09:00:00Z", description: "line event",
        severity: "High", mitreTechniques: [], relatedFindingIds: [] }],
    });
    const pipeline = new AnalysisPipeline({
      provider: new MockProvider("mock", oneEvent),
      stateStore,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });

    const log = [
      "May 28 09:00:01 host sshd[1]: Failed password for root from 10.0.0.5",
      "May 28 09:00:02 host sshd[2]: Failed password for admin from 10.0.0.5",
      "May 28 09:00:03 host sshd[3]: Accepted password for admin from 10.0.0.5",
    ].join("\n") + "\n";
    const state = await pipeline.analyzeLog("c1", log, {
      label: "0001_auth.log", idPrefix: "l1", importedAt: "2026-06-01T00:00:00Z", linesPerBatch: 2,
    });

    // 3 lines / 2 per batch = 2 batches → 2 events with distinct ids, both sourced from the log.
    expect(state.forensicTimeline).toHaveLength(2);
    expect(new Set(state.forensicTimeline.map((e) => e.id)).size).toBe(2);
    expect(state.forensicTimeline.every((e) => e.sourceScreenshots.includes("0001_auth.log"))).toBe(true);
  });

  it("analyzeLog is a no-op for an empty log file", async () => {
    const pipeline = new AnalysisPipeline({
      provider: new MockProvider("mock", "should not be called"),
      stateStore,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });
    const state = await pipeline.analyzeLog("c1", "\n\n   \n", {
      label: "x.log", idPrefix: "l1", importedAt: "2026-06-01T00:00:00Z",
    });
    expect(state.forensicTimeline).toHaveLength(0);
  });

  it("analyzeCsv is a no-op for a header-only CSV (no data rows)", async () => {
    const pipeline = new AnalysisPipeline({
      provider: new MockProvider("mock", "should not be called"),
      stateStore,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });
    const state = await pipeline.analyzeCsv("c1", "Time,Process\n", {
      label: "x.csv", idPrefix: "m1", importedAt: "2026-06-01T00:00:00Z",
    });
    expect(state.forensicTimeline).toHaveLength(0);
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
