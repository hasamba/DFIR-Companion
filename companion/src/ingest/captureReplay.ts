import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { basename, resolve } from "node:path";
import type { CaptureMetadata } from "../types.js";
import type { CaseStore } from "../storage/caseStore.js";
import { CaseKeyedMap } from "../storage/caseKeyedState.js";
import { AuditLogNeedsRepairError } from "../storage/auditLogNeedsRepairError.js";

/**
 * Recognising a capture the extension sends twice (#2397).
 *
 * The extension keeps a screenshot in its offline queue until the companion has answered, and
 * re-sends it after anything ambiguous: no answer, a 5xx, a timeout, or a worker suspended between
 * the companion's 201 and the queue row's removal. Each screenshot carries a random `captureId`,
 * so a repeat of one already stored is answered with the stored record instead of becoming a
 * second copy of the same evidence.
 *
 * A repeat must match on everything the extension sends unchanged — the id, the image bytes and
 * the capture's own details. Anything else is treated as new evidence and stored: different bytes
 * are never discarded on the strength of an id alone.
 *
 * The index lives as long as the case, so it keeps only what a match needs (#2446): a SHA-256
 * digest of the compared fields, plus the three stored fields the reply needs. The rest of the
 * reply comes from the re-send itself — on a match those fields are equal by definition. A cap was
 * not used (an evicted id would store a duplicate) and neither was a streaming load (the sequence
 * allocator reads the same log in full at the same moment, so the peak would not drop).
 */

/** The fields a genuine re-send carries unchanged. */
export interface ReplayKey {
  captureId: string;
  contentHash: string;
  timestamp: string;
  url: string;
  tabTitle: string;
  triggerType: CaptureMetadata["triggerType"];
}

/** What a re-send must match, plus what the reply needs. Everything else comes from the request. */
interface ReplayEntry {
  keyDigest: string;
  sequenceNumber: number;
  screenshotFile: string;
  isDuplicate: boolean;
}

type IdIndex = Map<string, ReplayEntry[]>;

// One index per cases root, keyed by (case id, generation) and forgotten on delete, like the dedup
// hash cache: a same-id successor case never inherits its predecessor's ids.
const indexByRoot = new Map<string, CaseKeyedMap<IdIndex>>();

function indexes(store: CaseStore): CaseKeyedMap<IdIndex> {
  const root = resolve(String(store.casesRoot ?? ""));
  let map = indexByRoot.get(root);
  if (!map) {
    map = new CaseKeyedMap<IdIndex>(root);
    indexByRoot.set(root, map);
  }
  return map;
}

type ComparedFields = Pick<CaptureMetadata, "contentHash" | "timestamp" | "url" | "tabTitle" | "triggerType">;

/**
 * One digest of the five compared fields. A false match would answer new evidence with an old
 * record and drop it, so this is a full SHA-256 — never truncated, never a non-cryptographic hash
 * (the same SHA-256 already identifies the screenshot bytes). The fields go in as a JSON array so
 * no two tuples encode alike: ["a","bc"] is not ["ab","c"]. A hand-edited row with a missing or
 * non-string field still digests (undefined becomes null); a zod-validated request never matches
 * it, so that capture is stored, not dropped.
 */
function keyDigest(fields: ComparedFields): string {
  const tuple = [fields.contentHash, fields.timestamp, fields.url, fields.tabTitle, fields.triggerType];
  return createHash("sha256").update(JSON.stringify(tuple)).digest("hex");
}

function addTo(index: IdIndex, metadata: CaptureMetadata): void {
  if (!metadata.captureId) return;
  const entry: ReplayEntry = {
    keyDigest: keyDigest(metadata),
    sequenceNumber: metadata.sequenceNumber,
    screenshotFile: metadata.screenshotFile,
    isDuplicate: metadata.isDuplicate,
  };
  const list = index.get(metadata.captureId) ?? [];
  index.set(metadata.captureId, [...list, entry]);
}

/** The stored record, rebuilt in the same key order as the log row persistCapture writes. */
function rebuildRecord(caseId: string, key: ReplayKey, entry: ReplayEntry): CaptureMetadata {
  return {
    caseId,
    sequenceNumber: entry.sequenceNumber,
    timestamp: key.timestamp,
    url: key.url,
    tabTitle: key.tabTitle,
    triggerType: key.triggerType,
    contentHash: key.contentHash,
    isDuplicate: entry.isDuplicate,
    screenshotFile: entry.screenshotFile,
    captureId: key.captureId,
  };
}

/**
 * Build the case's id index from captures.jsonl. A malformed line fails CLOSED with the same
 * needs-repair refusal the sequence allocator gives (#2252): an index built past the damage could
 * miss the very capture being re-sent and store it twice. The extension keeps the capture queued
 * on that 409, and the next capture re-reads the log once it is repaired.
 */
async function loadIndex(store: CaseStore, caseId: string): Promise<IdIndex> {
  let raw: string;
  try {
    raw = await readFile(store.capturesLogPath(caseId), "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return new Map();
    throw err;
  }
  const index: IdIndex = new Map();
  for (const [lineIndex, line] of raw.split("\n").entries()) {
    if (!line.trim()) continue;
    try {
      addTo(index, JSON.parse(line) as CaptureMetadata);
    } catch (err) {
      const logFile = basename(store.capturesLogPath(caseId));
      throw new AuditLogNeedsRepairError(caseId, "capture", logFile, lineIndex + 1, (err as Error).message);
    }
  }
  return index;
}

/**
 * The stored record for a genuine re-send of this capture, if there is one. Call under the case's
 * capture lock, so the lookup and the following write cannot interleave with another capture.
 */
export async function findReplay(
  store: CaseStore,
  caseId: string,
  key: ReplayKey,
): Promise<CaptureMetadata | undefined> {
  const cache = indexes(store);
  let index = cache.get(caseId);
  if (!index) {
    index = await loadIndex(store, caseId);
    cache.set(caseId, index);
  }
  const digest = keyDigest(key);
  const entry = index.get(key.captureId)?.find((stored) => stored.keyDigest === digest);
  return entry ? rebuildRecord(caseId, key, entry) : undefined;
}

/** Record a capture that just landed (on disk and in the log). */
export function rememberCapture(store: CaseStore, metadata: CaptureMetadata): void {
  if (!metadata.captureId) return;
  const index = indexes(store).get(metadata.caseId);
  // No index yet: the next capture with an id builds it from the log, which includes this row.
  if (index) addTo(index, metadata);
}

/** True when an id was reused for different content — worth a warning, never a refusal. */
export function isIdReusedForOtherContent(store: CaseStore, caseId: string, captureId: string): boolean {
  return (indexes(store).get(caseId)?.get(captureId)?.length ?? 0) > 0;
}

// Exposed for test isolation.
export function _resetReplayIndex(): void {
  indexByRoot.clear();
}

// Exposed for tests: what the index holds for one capture id (#2446).
export function _replayIndexEntry(
  store: CaseStore,
  caseId: string,
  captureId: string,
): readonly ReplayEntry[] | undefined {
  return indexes(store).get(caseId)?.get(captureId);
}
