// #1714, synthesis path: synthesis re-correlates the stored timeline with the case's own window, which
// can fold rows the import-time default did not. A stored finding citing the folded-away row must
// follow it to the survivor before the prompt and the grader read it.
import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../../src/storage/caseStore.js";
import { buildRuntimePipeline } from "../../../src/server.js";
import { StateStore } from "../../../src/analysis/stateStore.js";
import { emptyState, type Finding, type ForensicEvent } from "../../../src/analysis/stateTypes.js";
import type { AIProvider, AnalyzeRequest, AnalyzeResult } from "../../../src/providers/provider.js";

class CapturingProvider implements AIProvider {
  readonly name = "mock";
  readonly model = "mock-model";
  prompts: string[] = [];
  async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
    this.prompts.push(req.userPrompt);
    return {
      rawText: JSON.stringify({
        findings: [],
        iocs: [],
        mitreTechniques: [],
        threadsOpened: [],
        threadsClosed: [],
        timelineNote: "",
        summary: "s",
      }),
    };
  }
}

const PATH = "C:\\Users\\Public\\stage\\payload-9f3.exe";
function ev(id: string, timestamp: string, description: string): ForensicEvent {
  return {
    id,
    timestamp,
    description,
    path: PATH,
    severity: "High",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
  };
}

afterEach(() => {
  delete process.env.DFIR_CORRELATE_WINDOW_S;
});

describe("synthesis keeps a stored finding's evidence when its window folds the cited row (#1714)", () => {
  it("rewrites the stored citation to the surviving event", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-1714-"));
    const store = new CaseStore(root);
    await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
    const stateStore = new StateStore(store);
    const f1 = {
      id: "f1",
      severity: "High",
      title: "Payload staged",
      description: "staged payload",
      relatedIocs: [],
      mitreTechniques: [],
      status: "open",
      relatedEventIds: ["e-early"],
      sourceScreenshots: [],
      firstSeen: "2026-05-26T08:00:00.000Z",
      lastUpdated: "2026-05-26T08:00:00.000Z",
    } as unknown as Finding;
    await stateStore.save({
      ...emptyState("c1"),
      forensicTimeline: [
        ev("e-early", "2026-05-26T08:35:20Z", "File written"),
        ev("e-late", "2026-05-26T08:35:27Z", "Suspicious file detected"),
      ],
      findings: [f1],
    });
    process.env.DFIR_CORRELATE_WINDOW_S = "10";
    const provider = new CapturingProvider();
    const pipeline = buildRuntimePipeline({
      provider,
      synthesisProvider: provider,
      stateStore,
      store,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });
    await pipeline.synthesize("c1", { force: true });
    const saved = await stateStore.load("c1");
    expect(saved.forensicTimeline.map((e) => e.id)).toEqual(["e-late"]);
    const live = new Set(saved.forensicTimeline.map((e) => e.id));
    for (const f of saved.findings) for (const id of f.relatedEventIds ?? []) expect(live.has(id)).toBe(true);
    expect(provider.prompts.join("\n")).not.toContain("e-early");
  });
});
