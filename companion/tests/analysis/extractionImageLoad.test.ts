// #2251: one unreadable screenshot failed the whole analysis window — analyzeWindow loaded every
// image with Promise.all, so a missing file (or a refused cross-case link) took the good
// screenshots in the same window down with it. A failed image is now skipped and logged, and the
// rest of the window is analyzed. Only a window where NO image loads still throws.
import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import type { AIProvider, AnalyzeRequest, AnalyzeResult } from "../../src/providers/provider.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import type { CaptureMetadata } from "../../src/types.js";

const DELTA = JSON.stringify({
  findings: [],
  iocs: [],
  mitreTechniques: [],
  threadsOpened: [],
  threadsClosed: [],
  timelineNote: "n",
  summary: "ok",
});

function capture(seq: number): CaptureMetadata {
  return {
    caseId: "c1",
    sequenceNumber: seq,
    timestamp: "2026-05-28T10:00:00.000Z",
    url: "https://example.test",
    tabTitle: "t",
    triggerType: "timer",
    contentHash: "0",
    isDuplicate: false,
    screenshotFile: `00000${seq}_t.webp`,
  };
}

let stateStore: StateStore;
const requests: AnalyzeRequest[] = [];
const provider: AIProvider = {
  name: "rec",
  model: "m",
  async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
    requests.push(req);
    return { rawText: DELTA };
  },
};

beforeEach(async () => {
  requests.length = 0;
  const root = await mkdtemp(join(tmpdir(), "dfir-extract-images-"));
  const caseStore = new CaseStore(root);
  await caseStore.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
  stateStore = new StateStore(caseStore);
});

function pipelineMissing(missing: Set<string>) {
  return new AnalysisPipeline({
    provider,
    stateStore,
    backoffMs: 0,
    imageLoader: async (_caseId, file) => {
      if (missing.has(file)) throw new Error(`ENOENT: no such file ${file}`);
      return { base64: "AAAA", mimeType: "image/webp" };
    },
  });
}

describe("screenshot window with an unreadable image (#2251)", () => {
  it("skips the missing image and analyzes the other two", async () => {
    const pipeline = pipelineMissing(new Set(["000002_t.webp"]));
    await expect(pipeline.analyzeWindow("c1", [capture(1), capture(2), capture(3)])).resolves.toBeDefined();
    expect(requests).toHaveLength(1);
    expect(requests[0].images).toHaveLength(2);
    expect(requests[0].userPrompt).not.toContain("000002_t.webp");
    expect(requests[0].userPrompt).toContain("000003_t.webp");
  });

  it("throws when no image in the window can be loaded", async () => {
    const pipeline = pipelineMissing(new Set(["000001_t.webp", "000002_t.webp"]));
    await expect(pipeline.analyzeWindow("c1", [capture(1), capture(2)])).rejects.toThrow(/ENOENT/);
    expect(requests).toHaveLength(0);
  });
});
