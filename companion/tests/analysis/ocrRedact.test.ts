import { describe, it, expect, vi } from "vitest";
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
  // Every category ON — CARD/PHONE/NATID used to be missing, silently disabling those detectors
  // in every OCR-redaction test. See tsconfig.test.json.
  categories: { IP: true, EMAIL: true, USER: true, HOST: true, DOMAIN: true, PATH: true, CMD: true, REG: true, CARD: true, PHONE: true, NATID: true },
  redactSecrets: false,
  maskPublicIps: true, // AI-wire OCR pass — matches the AI-wire policy this pass always runs under
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

  it("boxes a public IP as EXTIP when maskPublicIps is on (screenshot IOC-loss path)", async () => {
    // Covers the AI-wire OCR path this task changed: a public/adversary IP visible in a
    // screenshot must still be boxed out (one-way — pipeline.ts then warns it can't be recovered
    // as an IOC from this capture), not left visible just because it isn't victim-internal.
    const img = await whiteImage();
    const words: OcrWord[] = [
      { text: "45.61.136.10", bbox: { x: 10, y: 10, w: 80, h: 20 }, confidence: 90 },
    ];
    const result = await ocrRedactImage(img, ENABLED_POLICY, KNOWN, mockRunner(words));
    expect(result.changed).toBe(true);
    expect(result.redactions.map((w) => w.text)).toEqual(["45.61.136.10"]);
    expect(result.discovered).toContainEqual({ value: "45.61.136.10", category: "EXTIP" });
  });

  it("leaves a public IP visible when maskPublicIps is off (redacted export policy)", async () => {
    const img = await whiteImage();
    const words: OcrWord[] = [
      { text: "45.61.136.10", bbox: { x: 10, y: 10, w: 80, h: 20 }, confidence: 90 },
    ];
    const exportPolicy: AnonPolicy = { ...ENABLED_POLICY, maskPublicIps: false };
    const result = await ocrRedactImage(img, exportPolicy, KNOWN, mockRunner(words));
    expect(result.changed).toBe(false);
    expect(result.redactions).toEqual([]);
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
  it("resolves a callable createWorker() from the tesseract.js module shape", async () => {
    // Regression guard: tesseract.js is CommonJS, so under ESM dynamic import `createWorker`
    // lives on the default export, NOT as a top-level named binding (`mod.createWorker` is
    // undefined). The runner must read it off `.default`. Importing the namespace does not
    // spawn the WASM worker (that only happens on an actual createWorker() call), so this stays
    // within the "no real OCR in tests" invariant while still catching the broken-import bug.
    const mod = await import("tesseract.js");
    const createWorker = mod.default?.createWorker ?? mod.createWorker;
    expect(typeof createWorker).toBe("function");
    // The runner exists and exposes the method we wire into the pipeline.
    expect(typeof new TesseractOcrRunner().recognize).toBe("function");
  });

  // The whole point of the explicit worker lifecycle: tesseract.js's onMessage handler does
  // `if (errorHandler) errorHandler(data); else throw Error(data)` (createWorker.js). That bare
  // throw runs on the worker's message loop, so nothing in our call stack can catch it and a
  // single malformed screenshot takes the server down. Passing an errorHandler turns it into a
  // rejected recognize() promise, which pumpOcrQueue already handles.
  it("passes an errorHandler so a worker-side abort rejects instead of throwing uncaught", async () => {
    const seen: { errorHandler?: unknown; terminated: boolean } = { terminated: false };
    vi.doMock("tesseract.js", () => ({
      default: {
        createWorker: async (_langs: string, _oem: number, options: { errorHandler?: unknown }) => {
          seen.errorHandler = options?.errorHandler;
          return {
            // A WASM abort surfaces here as a rejection once an errorHandler is installed.
            recognize: async () => { throw new Error("Aborted(). Build with -sASSERTIONS"); },
            terminate: async () => { seen.terminated = true; },
          };
        },
      },
    }));
    // Re-import so the runner's dynamic `import("tesseract.js")` resolves to the mock above.
    vi.resetModules();
    const { TesseractOcrRunner: Runner } = await import("../../src/analysis/ocrRedact.js");
    try {
      await expect(new Runner().recognize(Buffer.from("not a real png"))).rejects.toThrow(/Aborted/);
      expect(typeof seen.errorHandler).toBe("function"); // without this the library throws uncaught
      expect(seen.terminated).toBe(true);                // and the worker is not leaked
    } finally {
      vi.doUnmock("tesseract.js");
      vi.resetModules();
    }
  });
});
