import { createAnonymizer } from "./anonymize.js";
import type { AnonPolicy, KnownEntities } from "./anonymize.js";
import sharp from "sharp";

export interface OcrWord {
  text: string;
  bbox: { x: number; y: number; w: number; h: number };
  confidence: number; // 0–100
}

/** Injectable OCR backend. Tests supply a mock; the real app uses TesseractOcrRunner. */
export interface OcrRunner {
  recognize(imageBuffer: Buffer): Promise<OcrWord[]>;
}

export const DEFAULT_CONFIDENCE_THRESHOLD = 60;

/**
 * Return a copy of `imageBuffer` with opaque black rectangles composited over every
 * OCR word that the anonymizer would tokenize. Returns the ORIGINAL buffer (same
 * reference, no copy) when there is nothing to redact — evidence-first invariant:
 * the caller's original screenshot buffer is never mutated.
 */
export async function ocrRedactImage(
  imageBuffer: Buffer,
  policy: AnonPolicy,
  known: KnownEntities,
  runner: OcrRunner,
  confidenceThreshold = DEFAULT_CONFIDENCE_THRESHOLD,
): Promise<Buffer> {
  if (!policy.enabled) return imageBuffer;

  const words = await runner.recognize(imageBuffer);
  if (words.length === 0) return imageBuffer;

  const anon = createAnonymizer(policy, known);
  const toRedact = words.filter(
    (w) =>
      w.confidence >= confidenceThreshold &&
      w.text.trim().length > 0 &&
      anon.apply(w.text) !== w.text,
  );
  if (toRedact.length === 0) return imageBuffer;

  const overlays = toRedact
    .filter((w) => w.bbox.w > 0 && w.bbox.h > 0)
    .map((w) => ({
      input: Buffer.from(
        `<svg xmlns="http://www.w3.org/2000/svg" width="${w.bbox.w}" height="${w.bbox.h}">` +
          `<rect width="${w.bbox.w}" height="${w.bbox.h}" fill="black"/>` +
          `</svg>`,
      ),
      left: w.bbox.x,
      top: w.bbox.y,
    }));

  if (overlays.length === 0) return imageBuffer;
  return sharp(imageBuffer).composite(overlays).toBuffer();
}

/**
 * Tesseract.js-backed OCR runner. The module is loaded via a dynamic import so the
 * heavy WASM payload is not pulled in at startup and tests can inject their own runner
 * without touching Tesseract at all.
 */
export class TesseractOcrRunner implements OcrRunner {
  async recognize(imageBuffer: Buffer): Promise<OcrWord[]> {
    // tesseract.js is CommonJS: under ESM dynamic import `recognize` is on the default
    // export, not a top-level named binding (`mod.recognize` is undefined). Fall back to
    // the namespace in case a future ESM build hoists it.
    const mod = await import("tesseract.js");
    const recognize = mod.default?.recognize ?? mod.recognize;
    const { data } = await recognize(imageBuffer, "eng", { logger: () => {} });
    return (data.words ?? []).map((w) => ({
      text: w.text.trim(),
      bbox: {
        x: w.bbox.x0,
        y: w.bbox.y0,
        w: w.bbox.x1 - w.bbox.x0,
        h: w.bbox.y1 - w.bbox.y0,
      },
      confidence: w.confidence,
    }));
  }
}
