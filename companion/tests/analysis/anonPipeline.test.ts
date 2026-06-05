import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { AnonControlStore } from "../../src/analysis/anonControl.js";
import { CustomEntitiesStore } from "../../src/analysis/anonEntities.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import type { AIProvider, AnalyzeRequest, AnalyzeResult } from "../../src/providers/provider.js";

// Captures the request it receives and returns a canned synthesis delta that references the
// host token the anonymizer will have assigned (ALCLIENT07 is the only known host → ANON_HOST_1).
class CapturingProvider implements AIProvider {
  readonly name = "capture";
  lastReq?: AnalyzeRequest;
  async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
    this.lastReq = req;
    return { rawText: JSON.stringify({
      findings: [{ id: "f1", severity: "High", title: "exec on ANON_HOST_1", description: "activity on ANON_HOST_1", relatedIocs: [], mitreTechniques: [], status: "open", relatedEventIds: ["e1"] }],
      iocs: [], mitreTechniques: [], attackerPath: "", summary: "", threadsOpened: [], threadsClosed: [], keyQuestions: [], nextSteps: [], forensicEvents: [], timelineNote: "",
    }) };
  }
}

async function makePipeline() {
  const root = await mkdtemp(join(tmpdir(), "dfir-anonpipe-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(cases);
  const s = emptyState("c1");
  s.forensicTimeline = [{ id: "e1", timestamp: "2026-01-01T00:00:00Z", description: "process run on ALCLIENT07", severity: "High", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], asset: "ALCLIENT07" }];
  await stateStore.save(s);
  const provider = new CapturingProvider();
  const anonStore = new AnonControlStore(cases);
  const pipeline = new AnalysisPipeline({ provider, stateStore, anonStore, imageLoader: async () => ({ base64: "", mimeType: "image/webp" }) });
  return { pipeline, provider, stateStore, anonStore };
}

describe("pipeline anonymization (default on)", () => {
  it("tokenizes the host in the prompt and restores it in the stored findings", async () => {
    const { pipeline, provider, stateStore } = await makePipeline();
    await pipeline.synthesize("c1", { force: true });
    expect(provider.lastReq!.userPrompt).toContain("ANON_HOST_1");
    expect(provider.lastReq!.userPrompt).not.toContain("ALCLIENT07"); // real host never sent
    const out = await stateStore.load("c1");
    expect(out.findings[0].description).toContain("ALCLIENT07"); // restored on the way back
    expect(out.findings[0].description).not.toContain("ANON_HOST_1");
  });

  it("when disabled, sends the real host (no tokenization)", async () => {
    const { pipeline, provider, anonStore } = await makePipeline();
    await anonStore.save("c1", { enabled: false, categories: { IP: true, EMAIL: true, USER: true, HOST: true, DOMAIN: true, PATH: true }, redactSecrets: true });
    await pipeline.synthesize("c1", { force: true });
    expect(provider.lastReq!.userPrompt).toContain("ALCLIENT07");
    expect(provider.lastReq!.userPrompt).not.toContain("ANON_HOST_1");
  });
});

describe("pipeline anonymization — custom entities", () => {
  it("tokenizes an analyst-added public IP (from the custom list) in the prompt", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-anonpipe2-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const stateStore = new StateStore(cases);
    const s = emptyState("c1");
    s.forensicTimeline = [{ id: "e1", timestamp: "2026-01-01T00:00:00Z", description: "exfil to 203.0.113.50", severity: "High", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], asset: "" }];
    await stateStore.save(s);
    const provider = new CapturingProvider();
    const anonStore = new AnonControlStore(cases);
    const customEntitiesStore = new CustomEntitiesStore(cases);
    await customEntitiesStore.save("c1", [{ value: "203.0.113.50", category: "IP" }]);
    const pipeline = new AnalysisPipeline({ provider, stateStore, anonStore, customEntitiesStore, imageLoader: async () => ({ base64: "", mimeType: "image/webp" }) });
    await pipeline.synthesize("c1", { force: true });
    // A public IP is NOT tokenized by the internal-IP detector — so if it's gone, the custom-entity wiring worked.
    expect(provider.lastReq!.userPrompt).not.toContain("203.0.113.50");
    expect(provider.lastReq!.userPrompt).toMatch(/ANON_IP_/);
  });
});
