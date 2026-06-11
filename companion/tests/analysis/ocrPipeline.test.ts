import { describe, it, expect, afterEach } from "vitest";
import { mkdtemp, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import sharp from "sharp";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { AnonControlStore } from "../../src/analysis/anonControl.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import type { OcrRunner, OcrWord } from "../../src/analysis/ocrRedact.js";
import type { AIProvider, AnalyzeRequest, AnalyzeResult } from "../../src/providers/provider.js";
import type { CaptureMetadata } from "../../src/types.js";

// End-to-end coverage of the OCR redaction GLUE in analyzeWindow (the unit tests cover
// ocrRedactImage in isolation; this proves the pipeline actually swaps the redacted copy in
// before the provider call, and honours DFIR_OCR_DEBUG_DIR). The OCR runner is mocked — no real
// Tesseract — but everything between the runner and the provider is the production path.

class CapturingProvider implements AIProvider {
  readonly name = "capture";
  lastReq?: AnalyzeRequest;
  async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
    this.lastReq = req;
    return {
      rawText: JSON.stringify({
        findings: [], iocs: [], mitreTechniques: [], threadsOpened: [], threadsClosed: [],
        forensicEvents: [], timelineNote: "", summary: "",
      }),
    };
  }
}

// OCR "reads" one sensitive word (the known host) at a box that fits the test image.
function hostRunner(): OcrRunner {
  const words: OcrWord[] = [
    { text: "ALCLIENT07", bbox: { x: 10, y: 10, w: 120, h: 24 }, confidence: 92 },
  ];
  return { recognize: async () => words };
}

function capture(seq: number): CaptureMetadata {
  return {
    caseId: "c1", sequenceNumber: seq, timestamp: `2026-05-28T10:0${seq}:00.000Z`,
    url: "https://velociraptor.local", tabTitle: "VR", triggerType: "timer",
    contentHash: "0000000000000000", isDuplicate: false, screenshotFile: `00000${seq}_t.webp`,
  };
}

async function whitePngBase64(width = 200, height = 60): Promise<string> {
  const buf = await sharp({
    create: { width, height, channels: 3, background: { r: 255, g: 255, b: 255 } },
  })
    .png()
    .toBuffer();
  return buf.toString("base64");
}

async function makePipeline(ocrRunner: OcrRunner, imageBase64: string) {
  const root = await mkdtemp(join(tmpdir(), "dfir-ocrpipe-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(cases);
  const s = emptyState("c1");
  // event.asset makes ALCLIENT07 a known host the anonymizer will flag.
  s.forensicTimeline = [{
    id: "e1", timestamp: "2026-01-01T00:00:00Z", description: "process run on ALCLIENT07",
    severity: "High", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], asset: "ALCLIENT07",
  }];
  await stateStore.save(s);
  const provider = new CapturingProvider();
  const anonStore = new AnonControlStore(cases); // anonymization defaults ON
  const pipeline = new AnalysisPipeline({
    provider, stateStore, anonStore, ocrRunner,
    imageLoader: async () => ({ base64: imageBase64, mimeType: "image/png" }),
  });
  return { pipeline, provider };
}

afterEach(() => {
  delete process.env.DFIR_OCR_DEBUG_DIR;
  delete process.env.DFIR_OCR_DEBUG;
});

describe("analyzeWindow OCR redaction (pipeline glue)", () => {
  it("redacts the screenshot in-memory before sending it to the provider", async () => {
    const original = await whitePngBase64();
    const { pipeline, provider } = await makePipeline(hostRunner(), original);

    await pipeline.analyzeWindow("c1", [capture(1)]);

    // The provider must have received a DIFFERENT (redacted) image than the loader produced.
    expect(provider.lastReq).toBeDefined();
    expect(provider.lastReq!.images).toHaveLength(1);
    expect(provider.lastReq!.images[0].base64).not.toBe(original);
    expect(provider.lastReq!.images[0].base64.length).toBeGreaterThan(0);
  });

  it("does not alter the image when OCR finds nothing sensitive", async () => {
    const original = await whitePngBase64();
    const benign: OcrRunner = {
      recognize: async () => [{ text: "welcome", bbox: { x: 10, y: 10, w: 80, h: 20 }, confidence: 95 }],
    };
    const { pipeline, provider } = await makePipeline(benign, original);

    await pipeline.analyzeWindow("c1", [capture(1)]);

    // Nothing matched → the same buffer is forwarded untouched.
    expect(provider.lastReq!.images[0].base64).toBe(original);
  });

  it("writes the redacted copy to DFIR_OCR_DEBUG_DIR when set", async () => {
    const dumpRoot = await mkdtemp(join(tmpdir(), "dfir-ocrdump-"));
    process.env.DFIR_OCR_DEBUG_DIR = dumpRoot;
    process.env.DFIR_OCR_DEBUG = "1";
    const original = await whitePngBase64();
    const { pipeline } = await makePipeline(hostRunner(), original);

    await pipeline.analyzeWindow("c1", [capture(1)]);

    // A per-case subfolder with one dumped image (the source mime was image/png).
    const files = await readdir(join(dumpRoot, "c1"));
    expect(files).toHaveLength(1);
    expect(files[0]).toMatch(/\.png$/);
  });
});
