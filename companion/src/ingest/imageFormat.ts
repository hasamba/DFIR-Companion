/**
 * What a buffer of image bytes actually is — the one place the answer is decided (#425).
 *
 * Capture ingest accepts PNG, JPEG, GIF and WebP, and used to store every one of them under a
 * `.webp` filename. The image loader then reported `image/webp` to the AI provider whatever the
 * bytes were, and the evidence route derived its Content-Type from that wrong extension. So a PNG
 * capture was described incorrectly to every consumer, and its filename — which for evidence is
 * part of the record — said something untrue about the file.
 *
 * The fix preserves the source format rather than transcoding to WebP. Transcoding would re-encode
 * evidence before it is hashed, so the recorded content hash would cover bytes that never existed
 * on the analyst's screen; for a forensic tool that is the worse of the two options.
 *
 * Sniffing beats trusting a name: it also heals the screenshots already on disk with the wrong
 * suffix, without a migration.
 */
export interface ImageFormat {
  /** Filename extension, including the dot. */
  ext: string;
  mimeType: string;
}

const WEBP: ImageFormat = { ext: ".webp", mimeType: "image/webp" };
const PNG: ImageFormat = { ext: ".png", mimeType: "image/png" };
const JPEG: ImageFormat = { ext: ".jpg", mimeType: "image/jpeg" };
const GIF: ImageFormat = { ext: ".gif", mimeType: "image/gif" };

/**
 * Identify image bytes by their magic number, or null when they are not one of the four formats
 * capture ingest accepts.
 *
 * WebP: `RIFF....WEBP` | PNG: `89 PNG\r\n` | JPEG: `FF D8 FF` | GIF: `GIF8`
 */
export function detectImageFormat(bytes: Buffer): ImageFormat | null {
  if (bytes.length < 12) return null;
  if (bytes.subarray(0, 4).toString("ascii") === "RIFF" && bytes.subarray(8, 12).toString("ascii") === "WEBP")
    return WEBP;
  if (bytes[0] === 0x89 && bytes.subarray(1, 4).toString("ascii") === "PNG") return PNG;
  if (bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) return JPEG;
  if (bytes.subarray(0, 4).toString("ascii") === "GIF8") return GIF;
  return null;
}
