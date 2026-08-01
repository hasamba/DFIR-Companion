import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import type { AIProvider, AnalyzeRequest, AnalyzeResult } from "../../src/providers/provider.js";

class CapturingProvider implements AIProvider {
  readonly name = "capture";
  readonly model = "mock-model";
  lastReq?: AnalyzeRequest;
  private readonly response: object;
  constructor(response: object) { this.response = response; }
  async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
    this.lastReq = req;
    return { rawText: JSON.stringify(this.response) };
  }
}

const VALID_RESPONSE = {
  summary: "PowerShell launched from Word document",
  whyItMatters: "This is a classic macro-based initial access indicator.",
  normalContext: "PowerShell is rarely spawned by Word in a non-incident environment.",
  suspiciousIndicators: "Parent process is WINWORD.EXE; command includes encoded payload.",
  attackMapping: "T1059.001: Command and Scripting Interpreter: PowerShell — attacker uses encoded PS to download stager.",
  pivotQueries: [
    { platform: "velociraptor", query: "SELECT * FROM Windows.EventLogs.System WHERE EventId=4688", rationale: "Confirm process creation" },
  ],
  evidenceFor: "WINWORD.EXE → powershell.exe spawn chain with encoded command.",
  evidenceAgainst: "No network connection seen yet; could be benign macro.",
  relatedEventIds: ["e2"],
};

function ev(p: Partial<ForensicEvent> & { id: string }): ForensicEvent {
  return { timestamp: "2026-01-01T00:00:00Z", description: "", severity: "Info", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], ...p };
}

async function makePipeline(timeline: ForensicEvent[], providerResponse: object = VALID_RESPONSE) {
  const root = await mkdtemp(join(tmpdir(), "dfir-explain-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(cases);
  const s = emptyState("c1");
  s.forensicTimeline = timeline;
  await stateStore.save(s);
  const provider = new CapturingProvider(providerResponse);
  const pipeline = new AnalysisPipeline({ provider, stateStore, imageLoader: async () => ({ base64: "", mimeType: "image/webp" }) });
  return { pipeline, provider };
}

describe("explainEvent()", () => {
  it("returns a structured explanation for an existing event", async () => {
    const { pipeline } = await makePipeline([
      ev({ id: "e1", description: "powershell.exe spawned by WINWORD.EXE", severity: "High",
           processName: "powershell.exe", parentName: "WINWORD.EXE", asset: "WS01",
           mitreTechniques: ["T1059.001"] }),
      ev({ id: "e2", description: "network connection to 1.2.3.4:443", severity: "Medium", asset: "WS01" }),
    ]);
    const result = await pipeline.explainEvent("c1", "e1");
    expect(result.summary).toBeTruthy();
    expect(result.whyItMatters).toBeTruthy();
    expect(result.pivotQueries).toBeInstanceOf(Array);
  });

  it("puts the focal event prominently in the prompt", async () => {
    const { pipeline, provider } = await makePipeline([
      ev({ id: "e1", description: "suspiciousProcess.exe ran", severity: "Critical",
           processName: "suspiciousProcess.exe", asset: "HOST-A" }),
    ]);
    await pipeline.explainEvent("c1", "e1");
    const prompt = provider.lastReq!.userPrompt;
    expect(prompt).toContain("FOCAL EVENT");
    expect(prompt).toContain("e1");
    expect(prompt).toContain("suspiciousProcess.exe");
  });

  it("includes context events (nearby + same asset) in the prompt", async () => {
    const { pipeline, provider } = await makePipeline([
      ev({ id: "ctx1", description: "earlier event on same host", severity: "Info",
           timestamp: "2026-01-01T00:00:00Z", asset: "SERVER-X" }),
      ev({ id: "e2", description: "focal event", severity: "High",
           timestamp: "2026-01-01T01:00:00Z", asset: "SERVER-X" }),
      ev({ id: "ctx2", description: "later event on same host", severity: "Info",
           timestamp: "2026-01-01T02:00:00Z", asset: "SERVER-X" }),
    ]);
    await pipeline.explainEvent("c1", "e2");
    const prompt = provider.lastReq!.userPrompt;
    expect(prompt).toContain("ctx1");
    expect(prompt).toContain("ctx2");
  });

  it("PROMOTES a super-only event, then explains it from the forensic timeline (#384)", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-explain-super-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const stateStore = new StateStore(cases);
    await stateStore.save(emptyState("c1"));   // forensic timeline is EMPTY
    // The event lives only in the super-timeline store (a raw host-triage artifact, never promoted).
    const superTimelineStore = new SuperTimelineStore(cases);
    await superTimelineStore.append("c1", [
      ev({ id: "super1", description: "prefetch: EVIL.EXE executed", severity: "Info",
           processName: "EVIL.EXE", asset: "TRIAGE-HOST", path: "C:\\Users\\x\\evil.exe" }),
      ev({ id: "super2", description: "amcache: EVIL.EXE first seen", severity: "Info",
           asset: "TRIAGE-HOST", timestamp: "2026-01-01T00:05:00Z" }),
    ]);
    const provider = new CapturingProvider(VALID_RESPONSE);
    const pipeline = new AnalysisPipeline({
      provider, stateStore, superTimelineStore,
      imageLoader: async () => ({ base64: "", mimeType: "image/webp" }),
    });
    const result = await pipeline.explainEvent("c1", "super1");
    expect(result.summary).toBeTruthy();
    const prompt = provider.lastReq!.userPrompt;
    expect(prompt).toContain("FOCAL EVENT");
    expect(prompt).toContain("super1");
    expect(prompt).toContain("EVIL.EXE");

    // The asked-about event is now IN the forensic timeline -- that is what makes showing it to the
    // model legal under forensicGate.ts's rule. Asking is the analyst declaring it interesting.
    const after = await stateStore.load("c1");
    expect(after.forensicTimeline.map((e) => e.id)).toEqual(["super1"]);

    // And super2 must NOT be there. It used to be: the old code handed the model the raw record as
    // context, so explaining one Info event dragged its raw neighbours in with it. That is the
    // behaviour the rule forbids, and this assertion is inverted from what it used to be.
    expect(prompt).not.toContain("super2");
    expect(after.forensicTimeline.map((e) => e.id)).not.toContain("super2");
  });

  it("resolves a super-only event past the store's default page size (#406)", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-explain-paging-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const stateStore = new StateStore(cases);
    await stateStore.save(emptyState("c1"));
    const superTimelineStore = new SuperTimelineStore(cases);

    // 600 rows: past DEFAULT_SUPER_QUERY_LIMIT (500). The old lookup called query(caseId, {}), which
    // returns only the first page, and searched THAT for the id -- so anything beyond row 500 threw
    // "event not found" for an event that plainly existed. The failure scaled with case size: the
    // bigger the import, the more of it became unexplainable.
    const many = Array.from({ length: 600 }, (_, i) =>
      ev({ id: `bulk${i}`, description: `row ${i}`, severity: "Info", asset: "TRIAGE-HOST" }),
    );
    await superTimelineStore.append("c1", many);

    const provider = new CapturingProvider(VALID_RESPONSE);
    const pipeline = new AnalysisPipeline({
      provider, stateStore, superTimelineStore,
      imageLoader: async () => ({ base64: "", mimeType: "image/webp" }),
    });

    const result = await pipeline.explainEvent("c1", "bulk599");
    expect(result.summary).toBeTruthy();
    expect(provider.lastReq!.userPrompt).toContain("bulk599");
    const after = await stateStore.load("c1");
    expect(after.forensicTimeline.map((e) => e.id)).toEqual(["bulk599"]);
  });

  it("throws when the event id does not exist", async () => {
    const { pipeline } = await makePipeline([
      ev({ id: "e1", description: "some event", severity: "Low" }),
    ]);
    await expect(pipeline.explainEvent("c1", "nonexistent")).rejects.toThrow("event not found");
  });

  it("tolerates a partial model response via .catch() lenient schema", async () => {
    const partial = { summary: "something happened" }; // missing all other fields
    const { pipeline } = await makePipeline([
      ev({ id: "e1", description: "test event", severity: "Info" }),
    ], partial);
    const result = await pipeline.explainEvent("c1", "e1");
    expect(result.summary).toBe("something happened");
    expect(result.whyItMatters).toBe("");    // .catch("") default
    expect(result.pivotQueries).toEqual([]); // .catch([]) default
  });
});
