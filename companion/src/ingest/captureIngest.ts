import { z } from "zod";
import type { CaptureMetadata } from "../types.js";
import type { CaseStore } from "../storage/caseStore.js";
import { isValidCaseId } from "../storage/caseStore.js";
import { computeContentHash } from "../dedup/contentHash.js";
import { slugifyTitle } from "./titleSlug.js";

// Is deduplication enabled? Default on. `DFIR_DEDUP=off` (also false/no/0) turns it off so
// EVERY capture is analyzed. Read per call so a restart picks up the change. When on, a capture
// is a duplicate only if its content hash is byte-identical to the previous capture's (exact
// match — see contentHash.ts); any on-screen change at all → analyzed.
export function isDedupEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  const sw = (env.DFIR_DEDUP ?? "").trim().toLowerCase();
  return !(sw === "off" || sw === "false" || sw === "no" || sw === "0");
}

const payloadSchema = z.object({
  caseId: z.string().min(1).refine(isValidCaseId, "invalid caseId"),
  timestamp: z.string().min(1),
  url: z.string().min(1),
  tabTitle: z.string(),
  triggerType: z.enum(["timer", "navigation", "tab_switch", "click"]),
  imageBase64: z.string().min(1),
});

// Thrown when a capture targets a case that was never created. The companion never
// creates a case as a side effect of ingesting evidence — creation is an explicit
// dashboard action — so an unknown caseId is a 404, not an auto-create.
export class CaseNotFoundError extends Error {
  constructor(public readonly caseId: string) {
    super(`case not found: ${caseId}`);
    this.name = "CaseNotFoundError";
  }
}

// In-memory cache of the last content hash per case, to decide duplicates without re-reading disk.
const lastHashByCase = new Map<string, string>();

export async function ingestCapture(
  store: CaseStore,
  rawPayload: unknown,
  dedup: boolean = isDedupEnabled(),
): Promise<CaptureMetadata> {
  const payload = payloadSchema.parse(rawPayload);

  // The case must already exist (created in the dashboard). Reject an unknown case
  // before touching disk — never auto-create a case from a stray capture.
  if (!(await store.caseExists(payload.caseId))) {
    throw new CaseNotFoundError(payload.caseId);
  }

  const bytes = Buffer.from(payload.imageBase64, "base64");
  const hash = computeContentHash(bytes);

  const previous = lastHashByCase.get(payload.caseId);
  // Exact match only: a duplicate is a byte-identical re-capture of the previous frame (the
  // screen didn't change). Any difference → not a duplicate → analyzed. dedup=false disables it.
  const duplicate = dedup && previous !== undefined && previous === hash;
  lastHashByCase.set(payload.caseId, hash);

  const sequenceNumber = await store.nextSequenceNumber(payload.caseId);
  const tsSafe = payload.timestamp.replace(/[:.]/g, "-");
  // Include the captured window's tab title in the filename so evidence is
  // self-describing on disk. Slug strips OS-reserved chars and caps length;
  // an empty/all-unsafe title is omitted cleanly (no dangling underscore).
  const titleSlug = slugifyTitle(payload.tabTitle);
  const seq = String(sequenceNumber).padStart(6, "0");
  const screenshotFile = titleSlug
    ? `${seq}_${tsSafe}_${titleSlug}.webp`
    : `${seq}_${tsSafe}.webp`;

  // Evidence first: write the image before recording metadata.
  await store.saveScreenshot(payload.caseId, screenshotFile, bytes);

  const metadata: CaptureMetadata = {
    caseId: payload.caseId,
    sequenceNumber,
    timestamp: payload.timestamp,
    url: payload.url,
    tabTitle: payload.tabTitle,
    triggerType: payload.triggerType,
    contentHash: hash,
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
