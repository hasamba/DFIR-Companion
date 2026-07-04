import { describe, it, expect } from "vitest";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AIProvider, AnalyzeRequest, AnalyzeResult } from "../../src/providers/provider.js";

function fakeProvider(rawText: string): AIProvider {
  return { name: "fake", analyze: async (_req: AnalyzeRequest): Promise<AnalyzeResult> => ({ rawText }) };
}

describe("AnalysisPipeline.suggestFalsePositiveSimilarAi", () => {
  it("only returns ids present in the candidate list, dropping any hallucinated id", async () => {
    const dir = await mkdtemp(join(tmpdir(), "dfir-fpai-"));
    const store = new CaseStore(dir);
    const stateStore = new StateStore(store);
    await store.createCase({ caseId: "c1", name: "c1", investigator: "tester", aiProvider: null });
    const provider = fakeProvider(JSON.stringify({ candidateIds: ["e2", "e999-does-not-exist"] }));
    const pipeline = new AnalysisPipeline({ stateStore, synthesisProvider: provider, imageLoader: async () => ({ base64: "", mimeType: "image/webp" }) });

    const result = await pipeline.suggestFalsePositiveSimilarAi("c1", "e1", "PsExec run", ["e2", "e3"], ["PsExec run again", "unrelated login"]);
    expect(result).toEqual(["e2"]);
  });

  it("passes through the full candidate list unfiltered when every returned id is genuinely valid", async () => {
    const dir = await mkdtemp(join(tmpdir(), "dfir-fpai-"));
    const store = new CaseStore(dir);
    const stateStore = new StateStore(store);
    await store.createCase({ caseId: "c1", name: "c1", investigator: "tester", aiProvider: null });
    const provider = fakeProvider(JSON.stringify({ candidateIds: ["e2", "e3"] }));
    const pipeline = new AnalysisPipeline({ stateStore, synthesisProvider: provider, imageLoader: async () => ({ base64: "", mimeType: "image/webp" }) });

    const result = await pipeline.suggestFalsePositiveSimilarAi("c1", "e1", "PsExec run", ["e2", "e3"], ["PsExec run again", "unrelated login"]);
    expect(result).toEqual(["e2", "e3"]);
  });
});
