import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import type { AIProvider, AnalyzeRequest, AnalyzeResult } from "../../src/providers/provider.js";

class CapturingProvider implements AIProvider {
  readonly name = "capture";
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
