import { beforeEach, describe, expect, it } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { AnalysisRunStore } from "../../src/analysis/analysisRunStore.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { MockProvider } from "../../src/providers/provider.js";
import { CaseStore } from "../../src/storage/caseStore.js";

describe("analysis pipeline run manifests", () => {
  let cases: CaseStore;
  let stateStore: StateStore;
  let runStore: AnalysisRunStore;

  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-pipeline-runs-"));
    cases = new CaseStore(root);
    await cases.createCase({
      caseId: "c1",
      name: "n",
      investigator: "i",
      aiProvider: "mock",
    });
    stateStore = new StateStore(cases);
    runStore = new AnalysisRunStore(cases, { appVersion: "0.33.0" });
  });

  it("records the exact synthesis evidence and pinned model", async () => {
    const seeded = emptyState("c1");
    seeded.forensicTimeline.push({
      id: "evidence-1",
      timestamp: "2026-07-31T10:00:00.000Z",
      description: "PowerShell launched an encoded command",
      severity: "High",
      mitreTechniques: ["T1059.001"],
      relatedFindingIds: [],
      sourceScreenshots: [],
    });
    await stateStore.save(seeded);
    const response = JSON.stringify({
      findings: [
        {
          id: "finding-1",
          severity: "High",
          title: "Encoded PowerShell",
          description: "PowerShell executed an encoded command.",
          relatedIocs: [],
          relatedEventIds: ["evidence-1"],
          mitreTechniques: ["T1059.001"],
          status: "open",
        },
      ],
      iocs: [],
      mitreTechniques: [{ id: "T1059.001", name: "PowerShell" }],
      attackerPath: "Encoded PowerShell execution.",
      forensicEvents: [],
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: "",
      summary: "PowerShell activity.",
    });
    const pipeline = new AnalysisPipeline({
      provider: new MockProvider("mock-provider", response, "mock-model"),
      stateStore,
      analysisRunStore: runStore,
      imageLoader: async () => ({ base64: "A", mimeType: "image/webp" }),
    });

    await pipeline.synthesize("c1", { force: true });

    const run = (await runStore.list("c1"))[0];
    expect(run.kind).toBe("synthesis");
    expect(run.input.eventIds).toContain("evidence-1");
    expect(run.configuration?.provider).toBe("mock-provider");
    expect(run.configuration?.model).toBe("mock-model");
    expect(run.configuration?.promptHash).toMatch(/^[a-f0-9]{64}$/);
    expect(run.output.claims[0].evidenceEventIds).toContain("evidence-1");
  });
});
