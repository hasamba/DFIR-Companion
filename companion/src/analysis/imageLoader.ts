import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import type { AnalyzeImage } from "../providers/provider.js";

export function makeImageLoader(store: CaseStore) {
  return async (caseId: string, screenshotFile: string): Promise<AnalyzeImage> => {
    const bytes = await readFile(join(store.screenshotsDir(caseId), screenshotFile));
    return { base64: bytes.toString("base64"), mimeType: "image/webp" };
  };
}
