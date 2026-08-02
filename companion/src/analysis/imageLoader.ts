import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import { detectImageFormat } from "../ingest/imageFormat.js";
import type { AnalyzeImage } from "../providers/provider.js";

export function makeImageLoader(store: CaseStore) {
  return async (caseId: string, screenshotFile: string): Promise<AnalyzeImage> => {
    const bytes = await readFile(join(store.screenshotsDir(caseId), screenshotFile));
    // From the BYTES, not the filename. Capture ingest accepts PNG, JPEG and GIF as well as WebP,
    // and this reported image/webp for all of them — a media type a provider can reject outright
    // or quietly mis-decode (#425). Sniffing rather than reading the extension also heals the
    // screenshots already on disk under the old fixed ".webp" suffix, with no migration.
    // The fallback covers only bytes that are none of the four accepted formats, which ingest
    // refuses — so it is unreachable for anything this app wrote.
    const mimeType = detectImageFormat(bytes)?.mimeType ?? "image/webp";
    return { base64: bytes.toString("base64"), mimeType };
  };
}
