import { describe, it, expect } from "vitest";
import sharp from "sharp";
import {
  ocrRedactImage,
  DEFAULT_CONFIDENCE_THRESHOLD,
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
    expect(result).toBe(img);
  });

  it("returns original buffer when no word matches the entity set", async () => {
    const img = await whiteImage();
    const words: OcrWord[] = [
      { text: "unrelated", bbox: { x: 10, y: 10, w: 60, h: 20 }, confidence: 95 },
    ];
    const result = await ocrRedactImage(img, ENABLED_POLICY, KNOWN, mockRunner(words));
    expect(result).toBe(img);
  });

  it("returns a different buffer when a hostname matches", async () => {
    const img = await whiteImage();
    const words: OcrWord[] = [
      { text: "VICTIM-PC", bbox: { x: 10, y: 10, w: 80, h: 20 }, confidence: 90 },
    ];
    const result = await ocrRedactImage(img, ENABLED_POLICY, KNOWN, mockRunner(words));
    expect(result).not.toBe(img);
    expect(result.length).toBeGreaterThan(0);
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
    expect(result).toBe(img);
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
    expect(result).not.toBe(img);
  });

  it("returns original buffer when policy is disabled", async () => {
    const img = await whiteImage();
    const words: OcrWord[] = [
      { text: "VICTIM-PC", bbox: { x: 10, y: 10, w: 80, h: 20 }, confidence: 95 },
    ];
    const result = await ocrRedactImage(img, DISABLED_POLICY, KNOWN, mockRunner(words));
    expect(result).toBe(img);
  });

  it("redacts multiple matching words in one pass", async () => {
    const img = await whiteImage(400, 50);
    const words: OcrWord[] = [
      { text: "VICTIM-PC", bbox: { x: 10, y: 10, w: 80, h: 20 }, confidence: 90 },
      { text: "safe", bbox: { x: 110, y: 10, w: 30, h: 20 }, confidence: 95 },
      { text: "corp.local", bbox: { x: 160, y: 10, w: 70, h: 20 }, confidence: 85 },
    ];
    const result = await ocrRedactImage(img, ENABLED_POLICY, KNOWN, mockRunner(words));
    expect(result).not.toBe(img);
  });

  it("skips overlay entries with zero-size bboxes", async () => {
    const img = await whiteImage();
    const words: OcrWord[] = [
      { text: "VICTIM-PC", bbox: { x: 10, y: 10, w: 0, h: 20 }, confidence: 90 },
    ];
    // zero-width bbox filtered out → nothing to composite → original returned
    const result = await ocrRedactImage(img, ENABLED_POLICY, KNOWN, mockRunner(words));
    expect(result).toBe(img);
  });
});
