import { createAnonymizer } from "./anonymize.js";
import type { AnonPolicy, KnownEntities, CustomEntity } from "./anonymize.js";
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

/** Outcome of one OCR-redact pass — the image plus what OCR saw, for logging/inspection. */
export interface OcrRedactResult {
  /** The redacted image, or the ORIGINAL buffer (same reference) when nothing was redacted. */
  buffer: Buffer;
  /** True when at least one black box was composited (the buffer differs from the input). */
  changed: boolean;
  /** Total words OCR read from the image (0 if OCR did not run, e.g. policy disabled). */
  wordCount: number;
  /** The words that were boxed — sensitive matches with a usable bounding box. */
  redactions: OcrWord[];
  /** Entities the anonymizer tokenized out of the OCR'd text, with their category — fed back into
   *  the case's auto-discovery list. Never includes one-way secrets. */
  discovered: CustomEntity[];
}

/**
 * Return a copy of `imageBuffer` with opaque black rectangles composited over every
 * OCR word that the anonymizer would tokenize, plus what OCR saw (for logging). The
 * returned `buffer` is the ORIGINAL buffer (same reference, no copy) when there is
 * nothing to redact — evidence-first invariant: the caller's original screenshot
 * buffer is never mutated.
 */
export async function ocrRedactImage(
  imageBuffer: Buffer,
  policy: AnonPolicy,
  known: KnownEntities,
  runner: OcrRunner,
  confidenceThreshold = DEFAULT_CONFIDENCE_THRESHOLD,
): Promise<OcrRedactResult> {
  const unchanged = (wordCount: number): OcrRedactResult => ({
    buffer: imageBuffer,
    changed: false,
    wordCount,
    redactions: [],
    discovered: [],
  });

  if (!policy.enabled) return unchanged(0);

  const words = await runner.recognize(imageBuffer);
  if (words.length === 0) return unchanged(0);

  const anon = createAnonymizer(policy, known);
  const matched = words.filter(
    (w) =>
      w.confidence >= confidenceThreshold &&
      w.text.trim().length > 0 &&
      anon.apply(w.text) !== w.text,
  );
  // What the anonymizer tokenized out of this image — surfaced into the case's auto-discovery
  // list. Captured before the bbox filter so an entity is recorded even if it couldn't be drawn.
  const discovered = anon.discoveries();
  // A match with a zero-size bbox can't be drawn — exclude it from the boxes AND the count,
  // so `redactions` reflects exactly what was painted onto the image.
  const redactions = matched.filter((w) => w.bbox.w > 0 && w.bbox.h > 0);
  if (redactions.length === 0) {
    return { buffer: imageBuffer, changed: false, wordCount: words.length, redactions: [], discovered };
  }

  const overlays = redactions.map((w) => ({
    input: Buffer.from(
      `<svg xmlns="http://www.w3.org/2000/svg" width="${w.bbox.w}" height="${w.bbox.h}">` +
        `<rect width="${w.bbox.w}" height="${w.bbox.h}" fill="black"/>` +
        `</svg>`,
    ),
    left: w.bbox.x,
    top: w.bbox.y,
  }));

  const buffer = await sharp(imageBuffer).composite(overlays).toBuffer();
  return { buffer, changed: true, wordCount: words.length, redactions, discovered };
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
