import sharp from "sharp";
import { ocrRedactImage, type OcrRunner } from "./ocrRedact.js";
import type { AnonPolicy, KnownEntities } from "./anonymize.js";

// Screenshot redaction for the redacted case export (#54). Two guarantees:
//   1. METADATA is ALWAYS stripped — EXIF/GPS/ICC/etc. are dropped by re-encoding through sharp,
//      which does not copy input metadata to its output unless explicitly told to.
//   2. PII TEXT is optionally blurred — reuses the OCR-redact pass (black boxes over any word the
//      anonymizer would tokenize). This is the same machinery the live AI vision path uses.
// The input buffer is never mutated; a new buffer is always returned.

export interface ScreenshotRedactResult {
  buffer: Buffer;
  blurred: boolean;        // OCR painted at least one box
  redactionCount: number;  // number of boxes painted
  metadataStripped: boolean;
}

export interface ScreenshotRedactOptions {
  policy: AnonPolicy;
  known: KnownEntities;
  runner: OcrRunner;
  blur: boolean;
}

export async function redactScreenshot(
  buf: Buffer,
  opts: ScreenshotRedactOptions,
): Promise<ScreenshotRedactResult> {
  if (opts.blur) {
    const result = await ocrRedactImage(buf, opts.policy, opts.known, opts.runner);
    if (result.changed) {
      // The composite output is already metadata-free (sharp drops input metadata on encode).
      return {
        buffer: result.buffer,
        blurred: true,
        redactionCount: result.redactions.length,
        metadataStripped: true,
      };
    }
  }
  // Nothing was blurred (no PII found, OCR returned nothing, or blur disabled): still re-encode to
  // strip metadata. A plain decode -> encode yields a metadata-free image in the original format.
  const stripped = await sharp(buf).toBuffer();
  return { buffer: stripped, blurred: false, redactionCount: 0, metadataStripped: true };
}
