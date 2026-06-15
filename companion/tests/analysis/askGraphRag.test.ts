import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import type { AIProvider, AnalyzeRequest, AnalyzeResult } from "../../src/providers/provider.js";

// GraphRAG wiring test (#98): proves ask() serializes the evidence-chain graph into the prompt so
// the model can trace multi-hop paths through real relationships, not just the flat timeline.
class CapturingProvider implements AIProvider {
  readonly name = "capture";
  lastReq?: AnalyzeRequest;
  async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
    this.lastReq = req;
    return { rawText: JSON.stringify({ answer: "ok", status: "unknown", pointer: "n/a", relatedEventIds: [] }) };
  }
}

function ev(p: Partial<ForensicEvent> & { id: string }): ForensicEvent {
  return { timestamp: "2026-01-01T00:00:00Z", description: "", severity: "Info", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], ...p };
}

async function makePipeline(timeline: ForensicEvent[]) {
  const root = await mkdtemp(join(tmpdir(), "dfir-askgraph-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(cases);
  const s = emptyState("c1");
  s.forensicTimeline = timeline;
  await stateStore.save(s);
  const provider = new CapturingProvider();
  // No anonStore → real names survive in the captured prompt, so we can assert on them directly.
  const pipeline = new AnalysisPipeline({ provider, stateStore, imageLoader: async () => ({ base64: "", mimeType: "image/webp" }) });
  return { pipeline, provider };
}

describe("ask() GraphRAG grounding (#98)", () => {
  it("serializes the evidence-chain graph (spawns + network flows) into the ask prompt", async () => {
    const { pipeline, provider } = await makePipeline([
      ev({ id: "e1", asset: "WEB01", parentName: "excel.exe", processName: "powershell.exe", severity: "High" }),
      ev({ id: "e2", asset: "WEB01", dstIp: "1.2.3.4", port: 443, severity: "High" }),
    ]);
    await pipeline.ask("c1", "Trace the path from the document to the C2 server");

    const prompt = provider.lastReq!.userPrompt;
    expect(prompt).toContain("ATTACK GRAPH");
    expect(prompt).toContain("Process spawns (parent → child):");
    expect(prompt).toContain("excel.exe → powershell.exe on WEB01");
    expect(prompt).toContain("[e1]");                                   // backing event id is citable
    expect(prompt).toContain("Network connections (source → destination):");
    expect(prompt).toContain("1.2.3.4:443");
  });

  it("omits the ATTACK GRAPH block when the case has no causal edges", async () => {
    const { pipeline, provider } = await makePipeline([
      ev({ id: "e1", description: "a lone observation with no process/file/network edges", severity: "Low" }),
    ]);
    await pipeline.ask("c1", "anything?");
    expect(provider.lastReq!.userPrompt).not.toContain("ATTACK GRAPH");
  });
});
