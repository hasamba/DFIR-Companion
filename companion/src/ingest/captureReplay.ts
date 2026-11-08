import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import type { CaptureMetadata } from "../types.js";
import type { CaseStore } from "../storage/caseStore.js";
import { CaseKeyedMap } from "../storage/caseKeyedState.js";

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
 */

/** The fields a genuine re-send carries unchanged. */
export interface ReplayKey {
  captureId: string;
  contentHash: string;
  timestamp: string;
  url: string;
  tabTitle: string;
  triggerType: string;
}

type IdIndex = Map<string, CaptureMetadata[]>;

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

function sameCapture(stored: CaptureMetadata, key: ReplayKey): boolean {
  return (
    stored.contentHash === key.contentHash &&
    stored.timestamp === key.timestamp &&
    stored.url === key.url &&
    stored.tabTitle === key.tabTitle &&
    stored.triggerType === key.triggerType
  );
}

function addTo(index: IdIndex, metadata: CaptureMetadata): void {
  if (!metadata.captureId) return;
  const list = index.get(metadata.captureId) ?? [];
  index.set(metadata.captureId, [...list, metadata]);
}

/**
 * Build the case's id index from captures.jsonl. Returns undefined when the log has a malformed
 * line: such a log is refused by the sequence allocator anyway (needs repair), and an index built
 * past the damage must never be cached as complete.
 */
async function loadIndex(store: CaseStore, caseId: string): Promise<IdIndex | undefined> {
  let raw: string;
  try {
    raw = await readFile(store.capturesLogPath(caseId), "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return new Map();
    throw err;
  }
  const index: IdIndex = new Map();
  for (const line of raw.split("\n")) {
    if (!line.trim()) continue;
    try {
      addTo(index, JSON.parse(line) as CaptureMetadata);
    } catch {
      return undefined;
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
    if (!index) return undefined;
    cache.set(caseId, index);
  }
  return index.get(key.captureId)?.find((stored) => sameCapture(stored, key));
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
