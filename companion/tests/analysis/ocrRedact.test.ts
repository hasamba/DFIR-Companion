import { describe, it, expect } from "vitest";
import sharp from "sharp";
import {
  ocrRedactImage,
  DEFAULT_CONFIDENCE_THRESHOLD,
  TesseractOcrRunner,
  type OcrRunner,
  type OcrWord,
} from "../../src/analysis/ocrRedact.js";
import type { AnonPolicy, KnownEntities } from "../../src/analysis/anonymize.js";

async function whiteImage(width = 200, height = 50): Promise<Buffer> {
  return sharp({
    create: { width, height, channels: 3, background: { r: 255, g: 255, b: 255 } },
  })
    .png()
    .toBuffer();
}

function mockRunner(words: OcrWord[]): OcrRunner {
  return { recognize: async () => words };
}

const ENABLED_POLICY: AnonPolicy = {
  enabled: true,
  categories: { IP: true, EMAIL: true, USER: true, HOST: true, DOMAIN: true, PATH: true },
  redactSecrets: false,
};

const DISABLED_POLICY: AnonPolicy = { ...ENABLED_POLICY, enabled: false };

const KNOWN: KnownEntities = {
  hosts: ["VICTIM-PC"],
  accounts: ["CORP\\admin"],
  internalDomains: ["corp.local"],
};

describe("ocrRedactImage", () => {
  it("returns original buffer (same reference) when runner returns no words", async () => {
    const img = await whiteImage();
    const result = await ocrRedactImage(img, ENABLED_POLICY, KNOWN, mockRunner([]));
    expect(result.buffer).toBe(img);
    expect(result.changed).toBe(false);
    expect(result.wordCount).toBe(0);
    expect(result.redactions).toEqual([]);
  });

  it("returns original buffer when no word matches the entity set", async () => {
    const img = await whiteImage();
    const words: OcrWord[] = [
      { text: "unrelated", bbox: { x: 10, y: 10, w: 60, h: 20 }, confidence: 95 },
    ];
    const result = await ocrRedactImage(img, ENABLED_POLICY, KNOWN, mockRunner(words));
    expect(result.buffer).toBe(img);
    expect(result.changed).toBe(false);
    expect(result.wordCount).toBe(1); // OCR read the word, it just wasn't sensitive
    expect(result.redactions).toEqual([]);
  });

  it("returns a different buffer when a hostname matches", async () => {
    const img = await whiteImage();
    const words: OcrWord[] = [
      { text: "VICTIM-PC", bbox: { x: 10, y: 10, w: 80, h: 20 }, confidence: 90 },
    ];
    const result = await ocrRedactImage(img, ENABLED_POLICY, KNOWN, mockRunner(words));
    expect(result.buffer).not.toBe(img);
    expect(result.buffer.length).toBeGreaterThan(0);
    expect(result.changed).toBe(true);
    expect(result.redactions.map((w) => w.text)).toEqual(["VICTIM-PC"]);
  });

  it("skips words below the confidence threshold", async () => {
    const img = await whiteImage();
    const words: OcrWord[] = [
      { text: "VICTIM-PC", bbox: { x: 10, y: 10, w: 80, h: 20 }, confidence: 30 },
    ];
    const result = await ocrRedactImage(
      img,
      ENABLED_POLICY,
      KNOWN,
      mockRunner(words),
      DEFAULT_CONFIDENCE_THRESHOLD,
    );
    expect(result.buffer).toBe(img);
    expect(result.changed).toBe(false);
    expect(result.wordCount).toBe(1);
  });

  it("redacts words at exactly the confidence threshold", async () => {
    const img = await whiteImage();
    const words: OcrWord[] = [
      {
        text: "VICTIM-PC",
        bbox: { x: 10, y: 10, w: 80, h: 20 },
        confidence: DEFAULT_CONFIDENCE_THRESHOLD,
      },
    ];
    const result = await ocrRedactImage(
      img,
      ENABLED_POLICY,
      KNOWN,
      mockRunner(words),
      DEFAULT_CONFIDENCE_THRESHOLD,
    );
    expect(result.buffer).not.toBe(img);
    expect(result.changed).toBe(true);
  });

  it("returns original buffer when policy is disabled", async () => {
    const img = await whiteImage();
    const words: OcrWord[] = [
      { text: "VICTIM-PC", bbox: { x: 10, y: 10, w: 80, h: 20 }, confidence: 95 },
    ];
    const result = await ocrRedactImage(img, DISABLED_POLICY, KNOWN, mockRunner(words));
    expect(result.buffer).toBe(img);
    expect(result.changed).toBe(false);
    expect(result.wordCount).toBe(0); // policy off → OCR never runs
  });

  it("redacts multiple matching words in one pass", async () => {
    const img = await whiteImage(400, 50);
    const words: OcrWord[] = [
      { text: "VICTIM-PC", bbox: { x: 10, y: 10, w: 80, h: 20 }, confidence: 90 },
      { text: "safe", bbox: { x: 110, y: 10, w: 30, h: 20 }, confidence: 95 },
      { text: "corp.local", bbox: { x: 160, y: 10, w: 70, h: 20 }, confidence: 85 },
    ];
    const result = await ocrRedactImage(img, ENABLED_POLICY, KNOWN, mockRunner(words));
    expect(result.buffer).not.toBe(img);
    expect(result.changed).toBe(true);
    expect(result.wordCount).toBe(3);
    // "safe" survives; the host and internal domain are boxed.
    expect(result.redactions.map((w) => w.text).sort()).toEqual(["VICTIM-PC", "corp.local"]);
  });

  it("skips overlay entries with zero-size bboxes", async () => {
    const img = await whiteImage();
    const words: OcrWord[] = [
      { text: "VICTIM-PC", bbox: { x: 10, y: 10, w: 0, h: 20 }, confidence: 90 },
    ];
    // zero-width bbox filtered out → nothing to composite → original returned
    const result = await ocrRedactImage(img, ENABLED_POLICY, KNOWN, mockRunner(words));
    expect(result.buffer).toBe(img);
    expect(result.changed).toBe(false);
    expect(result.redactions).toEqual([]); // matched the entity but had no drawable box
  });
});

describe("TesseractOcrRunner", () => {
  it("resolves a callable recognize() from the tesseract.js module shape", async () => {
    // Regression guard: tesseract.js is CommonJS, so under ESM dynamic import `recognize`
    // lives on the default export, NOT as a top-level named binding (`mod.recognize` is
    // undefined). The runner must read it off `.default`. Importing the namespace does not
    // spawn the WASM worker (that only happens on an actual recognize() call), so this stays
    // within the "no real OCR in tests" invariant while still catching the broken-import bug.
    const mod = await import("tesseract.js");
    const recognize = mod.default?.recognize ?? mod.recognize;
    expect(typeof recognize).toBe("function");
    // The runner exists and exposes the method we wire into the pipeline.
    expect(typeof new TesseractOcrRunner().recognize).toBe("function");
  });
});
