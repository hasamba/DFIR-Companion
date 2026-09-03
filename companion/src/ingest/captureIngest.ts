import { z } from "zod";
import type { CaptureMetadata } from "../types.js";
import type { CaseStore } from "../storage/caseStore.js";
import { isValidCaseId } from "../storage/caseStore.js";
import { computeContentHash } from "../dedup/contentHash.js";
import { slugifyTitle } from "./titleSlug.js";
import { detectImageFormat } from "./imageFormat.js";

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
  triggerType: z.enum(["timer", "navigation", "tab_switch", "click", "manual"]),
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

// Thrown when the posted bytes aren't a recognized image. A caller sending junk is a BAD REQUEST,
// so this is typed rather than a bare Error — the route's fallback maps unknown errors to 500, which
// would report a client mistake as a server fault.
export class InvalidImageError extends Error {
  constructor() {
    super("captured image is not a recognized image format (expected WebP/PNG/JPEG/GIF)");
    this.name = "InvalidImageError";
  }
}

// In-memory cache of the last PERSISTED content hash per case, to decide duplicates without
// re-reading disk. Only a frame that actually landed is recorded here.
const lastHashByCase = new Map<string, string>();

// One queue per case, so the read-decide-write sequence below never interleaves with another
// capture for the same case. Without it the dedup decision races its own write: two overlapping
// identical frames both read the stale hash and are both analyzed, and a frame that failed to
// persist can leave a hash behind that makes the extension's retry look like a duplicate. Trying
// to patch those windows with a claim token and rollback only moves them around — a pending claim
// is not the same fact as a persisted hash. Different cases still run in parallel.
const caseQueues = new Map<string, Promise<unknown>>();

function withCaseLock<T>(caseId: string, run: () => Promise<T>): Promise<T> {
  const previous = caseQueues.get(caseId) ?? Promise.resolve();
  // Run whether the previous capture resolved or rejected: one failure must not stall the case.
  // (A capture that never settles at all would, but a hung evidence write already blocks that
  // case's captures downstream — they share the store's sequence allocation.)
  const result = previous.then(run, run);
  const settled = result.then(
    () => undefined,
    () => undefined,
  );
  caseQueues.set(caseId, settled);
  // Drop the entry once this is the tail and nothing is waiting on it, so the map holds only
  // active chains rather than one dead promise per case the process has ever seen.
  void settled.then(() => {
    if (caseQueues.get(caseId) === settled) caseQueues.delete(caseId);
  });
  return result;
}

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

  // Validate that the bytes are a real image (magic-byte sniff) — reject arbitrary binary stored
  // as a screenshot — and keep WHICH image it is, so the file on disk is named for what it holds.
  const format = detectImageFormat(bytes);
  if (!format) {
    throw new InvalidImageError();
  }

  const hash = computeContentHash(bytes);

  return withCaseLock(payload.caseId, async () => {
    const previous = lastHashByCase.get(payload.caseId);
    // Exact match only: a duplicate is a byte-identical re-capture of the previous frame (the
    // screen didn't change). Any difference → not a duplicate → analyzed. dedup=false disables it.
    const duplicate = dedup && previous !== undefined && previous === hash;
    const metadata = await persistCapture(store, payload, {
      bytes,
      hash,
      duplicate,
      ext: format.ext,
    });
    // Only a frame that is on disk AND in the log is remembered. Recording it any earlier means a
    // failed write poisons the cache: the extension retries the identical bytes after a 5xx (its
    // queue keeps the entry at the head) and that retry comes back a duplicate — which willAnalyze,
    // the OCR indexer and captureAnalysis all skip, so it is stored but never analyzed (#513).
    lastHashByCase.set(payload.caseId, hash);
    return metadata;
  });
}

/** Everything after the dedup claim: allocate the sequence, name the file, write both records. */
async function persistCapture(
  store: CaseStore,
  payload: {
    caseId: string;
    timestamp: string;
    url: string;
    tabTitle: string;
    triggerType: CaptureMetadata["triggerType"];
  },
  frame: { bytes: Buffer; hash: string; duplicate: boolean; ext: string },
): Promise<CaptureMetadata> {
  const sequenceNumber = await store.nextSequenceNumber(payload.caseId);
  const tsSafe = payload.timestamp.replace(/[:.]/g, "-");
  // Include the captured window's tab title in the filename so evidence is
  // self-describing on disk. Slug strips OS-reserved chars and caps length;
  // an empty/all-unsafe title is omitted cleanly (no dangling underscore).
  const titleSlug = slugifyTitle(payload.tabTitle);
  const seq = String(sequenceNumber).padStart(6, "0");
  // The extension is the DETECTED format, not a fixed ".webp". Every accepted buffer used to be
  // stored as WebP whatever it was, which made the filename — part of the evidence record — wrong,
  // and the evidence route derives its Content-Type from exactly this name (#425).
  const screenshotFile = titleSlug
    ? `${seq}_${tsSafe}_${titleSlug}${frame.ext}`
    : `${seq}_${tsSafe}${frame.ext}`;

  const metadata: CaptureMetadata = {
    caseId: payload.caseId,
    sequenceNumber,
    timestamp: payload.timestamp,
    url: payload.url,
    tabTitle: payload.tabTitle,
    triggerType: payload.triggerType,
    contentHash: frame.hash,
    isDuplicate: frame.duplicate,
    screenshotFile,
  };

  // Evidence first: write the image before recording metadata. The provenance goes with the write
  // because this is the only layer that still knows where the frame came from — the store below
  // sees bytes and a filename, and custody wants the origin URL and what triggered the shot (#231).
  await store.saveScreenshot(payload.caseId, screenshotFile, frame.bytes, {
    source: payload.url,
    trigger: payload.triggerType,
    collectedBy: "browser-extension",
  });
  await store.appendCapture(payload.caseId, metadata);
  return metadata;
}

// Exposed for test isolation.
export function _resetDedupCache(): void {
  lastHashByCase.clear();
  // Deliberately NOT clearing caseQueues: dropping a live chain would let a post-reset capture run
  // alongside one still in flight, which is the interleaving the queue exists to prevent. Settled
  // chains remove themselves, so there is nothing left to clear anyway.
}
