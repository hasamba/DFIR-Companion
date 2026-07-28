import { describe, it, expect } from "vitest";
import sharp from "sharp";
import { redactScreenshot } from "../../src/analysis/imageRedact.js";
import type { OcrRunner, OcrWord } from "../../src/analysis/ocrRedact.js";
import type { AnonPolicy, KnownEntities } from "../../src/analysis/anonymize.js";

const POLICY: AnonPolicy = {
  enabled: true,
  // Every category ON. CARD/PHONE/NATID were missing here — no test file was type-checked, so
  // Record<AnonCategory, boolean> never caught it and those three detectors were silently OFF in
  // every screenshot-redaction test. See tsconfig.test.json.
  categories: { IP: true, EMAIL: true, USER: true, HOST: true, DOMAIN: true, PATH: true, CMD: true, REG: true, CARD: true, PHONE: true, NATID: true },
  redactSecrets: true,
  maskPublicIps: true, // AI-wire screenshot pass — matches the AI-wire policy this always runs under
};
const KNOWN: KnownEntities = { hosts: [], accounts: [], internalDomains: [] };

function runnerReturning(words: OcrWord[]): OcrRunner {
  return { recognize: async () => words };
}

async function whiteJpegWithExif(): Promise<Buffer> {
  return sharp({ create: { width: 120, height: 40, channels: 3, background: { r: 250, g: 250, b: 250 } } })
    .jpeg()
    .withExif({ IFD0: { Copyright: "secret-corp internal" } })
    .toBuffer();
}

describe("redactScreenshot", () => {
  it("strips image metadata (EXIF) even when no PII is blurred", async () => {
    const input = await whiteJpegWithExif();
    expect((await sharp(input).metadata()).exif).toBeDefined(); // sanity: input carries EXIF

    const result = await redactScreenshot(input, { policy: POLICY, known: KNOWN, runner: runnerReturning([]), blur: false });

    expect(result.blurred).toBe(false);
    expect(result.redactionCount).toBe(0);
    expect(result.metadataStripped).toBe(true);
    expect((await sharp(result.buffer).metadata()).exif).toBeUndefined();
  });

  it("blurs PII text the anonymizer would tokenize and reports the redaction count", async () => {
    const input = await whiteJpegWithExif();
    const result = await redactScreenshot(input, {
      policy: POLICY,
      known: KNOWN,
      runner: runnerReturning([{ text: "10.0.0.5", bbox: { x: 5, y: 5, w: 40, h: 12 }, confidence: 95 }]),
      blur: true,
    });

    expect(result.blurred).toBe(true);
    expect(result.redactionCount).toBe(1);
    expect(result.metadataStripped).toBe(true);
    expect(result.buffer.equals(input)).toBe(false);
    expect((await sharp(result.buffer).metadata()).exif).toBeUndefined();
  });

  it("falls back to a metadata strip when OCR finds nothing sensitive", async () => {
    const input = await whiteJpegWithExif();
    const result = await redactScreenshot(input, {
      policy: POLICY,
      known: KNOWN,
      // an ordinary word the anonymizer never tokenizes, so nothing is boxed
      runner: runnerReturning([{ text: "the", bbox: { x: 1, y: 1, w: 10, h: 10 }, confidence: 90 }]),
      blur: true,
    });

    expect(result.blurred).toBe(false);
    expect(result.redactionCount).toBe(0);
    expect((await sharp(result.buffer).metadata()).exif).toBeUndefined();
  });

  it("blurs a public IP when maskPublicIps is on (screenshot IOC-loss path)", async () => {
    const input = await whiteJpegWithExif();
    const result = await redactScreenshot(input, {
      policy: POLICY, // maskPublicIps: true
      known: KNOWN,
      runner: runnerReturning([{ text: "45.61.136.10", bbox: { x: 5, y: 5, w: 40, h: 12 }, confidence: 95 }]),
      blur: true,
    });

    expect(result.blurred).toBe(true);
    expect(result.redactionCount).toBe(1);
  });

  it("leaves a public IP visible when maskPublicIps is off", async () => {
    const input = await whiteJpegWithExif();
    const result = await redactScreenshot(input, {
      policy: { ...POLICY, maskPublicIps: false },
      known: KNOWN,
      runner: runnerReturning([{ text: "45.61.136.10", bbox: { x: 5, y: 5, w: 40, h: 12 }, confidence: 95 }]),
      blur: true,
    });

    expect(result.blurred).toBe(false);
    expect(result.redactionCount).toBe(0);
  });
});
