import { z } from "zod";
import type { CaptureMetadata } from "../types.js";
import type { CaseStore } from "../storage/caseStore.js";
import { computeHash, isDuplicate } from "../dedup/perceptualHash.js";

const DUP_THRESHOLD = 5;

const payloadSchema = z.object({
  caseId: z.string().min(1),
  timestamp: z.string().min(1),
  url: z.string().min(1),
  tabTitle: z.string(),
  triggerType: z.enum(["timer", "navigation", "tab_switch", "click"]),
  imageBase64: z.string().min(1),
});

// In-memory cache of the last hash per case, to decide duplicates without re-reading disk.
const lastHashByCase = new Map<string, string>();

export async function ingestCapture(
  store: CaseStore,
  rawPayload: unknown,
  threshold = DUP_THRESHOLD,
): Promise<CaptureMetadata> {
  const payload = payloadSchema.parse(rawPayload);

  const bytes = Buffer.from(payload.imageBase64, "base64");
  const hash = await computeHash(bytes);

  const previous = lastHashByCase.get(payload.caseId);
  const duplicate = previous !== undefined && isDuplicate(previous, hash, threshold);
  lastHashByCase.set(payload.caseId, hash);

  const sequenceNumber = await store.nextSequenceNumber(payload.caseId);
  const tsSafe = payload.timestamp.replace(/[:.]/g, "-");
  const screenshotFile = `${String(sequenceNumber).padStart(6, "0")}_${tsSafe}.webp`;

  // Evidence first: write the image before recording metadata.
  await store.saveScreenshot(payload.caseId, screenshotFile, bytes);

  const metadata: CaptureMetadata = {
    caseId: payload.caseId,
    sequenceNumber,
    timestamp: payload.timestamp,
    url: payload.url,
    tabTitle: payload.tabTitle,
    triggerType: payload.triggerType,
    perceptualHash: hash,
    isDuplicate: duplicate,
    screenshotFile,
  };
  await store.appendCapture(payload.caseId, metadata);
  return metadata;
}

// Exposed for test isolation.
export function _resetDedupCache(): void {
  lastHashByCase.clear();
}
