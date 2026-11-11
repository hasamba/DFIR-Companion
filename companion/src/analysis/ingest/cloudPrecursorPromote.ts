// The S3 ransomware-precursor join, check-first order (#2563, user decision 2026-11-11).
//
// A bucket recovery check that arrives BEFORE its access key's privileged change is graded Info in
// its own file and demoted to the super-timeline, so the merge-chain pass (cloudPrecursorMerge.ts)
// never sees it again. When a CloudTrail import then brings the change, this looks the check up in
// the super-timeline and promotes it into the forensic delta at High, with the precursor note.
//
// This is a DELIBERATE, DOCUMENTED EXCEPTION to "nothing automatic reads the raw record"
// (ARCHITECTURE.md → "The forensic / super-timeline boundary"; forensicBoundary.test.ts enforces it).
// It stays narrow:
//   - it runs only when the import holds a precursor change or check row, keyed by that row's access
//     key (an AWS key id shape only), at most PRECURSOR_KEYS_MAX keys;
//   - it reads only through the super-timeline's text query on that key, at most
//     PRECURSOR_SCAN_ROWS rows per key, and keeps only rows whose importer-stamped block says they
//     are a check by that key with an occurrence later than the change;
//   - it promotes at most PRECURSOR_PROMOTE_MAX rows, in time order, and the import's case timeline
//     note says how many it promoted, how many it left, and when a key or scan cap stopped it;
//   - no AI is involved. The model sees a promoted row only once it is in the forensic timeline, as
//     after explainEvent / starredReport's promote-first.
// The stored change a check-only import joins to is read from the forensic timeline, by key.

import type { ForensicEvent } from "../stateTypes.js";
import type { EntityPage, EntityQuery } from "../stateStore.js";
import type { SuperQuery, SuperQueryResult } from "../superTimeline.js";
import {
  earliestPrecursorChanges,
  isOpenPrecursorCheck,
  isPrecursorChange,
  precursorKey,
  raisePrecursorCheck,
  type PrecursorChange,
} from "../cloudPrecursorMerge.js";

export const PRECURSOR_PROMOTE_MAX = 50;
export const PRECURSOR_KEYS_MAX = 20;
export const PRECURSOR_SCAN_ROWS = 5_000;
const PAGE_ROWS = 500;
/** Keys one streamed import remembers; past it a key is counted only if it made a change. */
const SEEN_KEYS_MAX = 1_000;
/** An AWS access key id: letters and digits only, so it is safe as a search term and a LIKE pattern. */
const KEY_SHAPE = /^[a-z0-9]{16,128}$/;

/** The join halves one import holds: every key on a change or check row, and its earliest change. */
export interface PrecursorSeen {
  keys: Set<string>;
  changes: Map<string, PrecursorChange>;
}

export function emptyPrecursorSeen(): PrecursorSeen {
  return { keys: new Set(), changes: new Map() };
}

/** `seen` with the halves among `rows` added (a new value; `seen` is left as it was). */
export function withPrecursorRows(
  seen: PrecursorSeen,
  rows: readonly Pick<ForensicEvent, "timestamp" | "canonical">[],
): PrecursorSeen {
  const events = rows.map((r) => ({ ...r, id: "", description: "", severity: "Info" }) as ForensicEvent);
  const halves = events.filter((e) => isPrecursorChange(e) || isOpenPrecursorCheck(e));
  if (!halves.length) return seen;
  const changes = new Map(seen.changes);
  for (const [key, change] of earliestPrecursorChanges(halves)) {
    const cur = changes.get(key);
    if (!cur || change.time < cur.time) changes.set(key, change);
  }
  const keys = new Set(seen.keys);
  for (const key of changes.keys()) keys.add(key);
  for (const key of halves.map(precursorKey)) if (keys.size < SEEN_KEYS_MAX) keys.add(key);
  return { keys, changes };
}

export interface PrecursorPromoteDeps {
  superTimeline?: { query(caseId: string, q: SuperQuery): Promise<SuperQueryResult> };
  forensic: {
    queryForensicTimeline(caseId: string, q: EntityQuery): Promise<EntityPage<ForensicEvent>>;
    hasForensicEventIds(caseId: string, ids: readonly string[]): Promise<Set<string>>;
  };
}

/** A promoted row, in the shape an importer delta carries. */
export type PromotedPrecursor = ForensicEvent & { sources: string[]; mitreTechniques: string[] };

export interface PrecursorPromotion {
  /** The promoted rows, raised, in time order. */
  events: PromotedPrecursor[];
  /** Every matching check found, promoted or not. */
  found: number;
  /** Access keys past PRECURSOR_KEYS_MAX, never looked up. */
  keysSkipped: number;
  /** A key's super-timeline scan stopped at PRECURSOR_SCAN_ROWS. */
  scanTruncated: boolean;
}

const NONE: PrecursorPromotion = { events: [], found: 0, keysSkipped: 0, scanTruncated: false };

/** The earliest change by `key` the forensic timeline holds, read by key. */
async function storedChange(
  deps: PrecursorPromoteDeps,
  caseId: string,
  key: string,
): Promise<PrecursorChange | undefined> {
  const rows: ForensicEvent[] = [];
  let cursor: number | undefined;
  for (let read = 0; read < PRECURSOR_SCAN_ROWS;) {
    const page = await deps.forensic.queryForensicTimeline(caseId, {
      searchLike: `%${key}%`,
      limit: PAGE_ROWS,
      includeTotal: false,
      ...(cursor !== undefined ? { cursor } : {}),
    });
    read += page.entities.length;
    rows.push(...page.entities.filter((e) => isPrecursorChange(e) && precursorKey(e) === key));
    if (page.nextCursor === null || !page.entities.length) break;
    cursor = page.nextCursor;
  }
  return earliestPrecursorChanges(rows).get(key);
}

/**
 * The super-timeline checks by `key` with an occurrence after `change`, raised — the one raw-record
 * read. No time bound in the query: a folded check row keeps its FIRST occurrence as its time, and
 * may straddle the change. `truncated` when the per-key scan cap stopped it.
 */
async function superChecks(
  store: NonNullable<PrecursorPromoteDeps["superTimeline"]>,
  caseId: string,
  key: string,
  change: PrecursorChange,
): Promise<{ rows: ForensicEvent[]; truncated: boolean }> {
  const changes = new Map([[key, change]]);
  const rows: ForensicEvent[] = [];
  for (let offset = 0; offset < PRECURSOR_SCAN_ROWS; offset += PAGE_ROWS) {
    const { events } = await store.query(caseId, { search: key, offset, limit: PAGE_ROWS });
    for (const e of events) {
      const raised = raisePrecursorCheck(e, changes, "promoted");
      if (raised) rows.push(raised);
    }
    if (events.length < PAGE_ROWS) return { rows, truncated: false };
  }
  return { rows, truncated: true };
}

const byTime = (a: ForensicEvent, b: ForensicEvent): number =>
  Date.parse(a.timestamp) - Date.parse(b.timestamp) || a.id.localeCompare(b.id);

/**
 * The super-timeline checks this import's change rows (or a stored change, for this import's check
 * rows) make precursors, raised and capped, never one the forensic timeline already holds or one of
 * `exclude` (this import's own rows).
 */
export async function promoteCrossUploadPrecursors(
  deps: PrecursorPromoteDeps,
  caseId: string,
  seen: PrecursorSeen,
  exclude: ReadonlySet<string> = new Set(),
): Promise<PrecursorPromotion> {
  const store = deps.superTimeline;
  if (!store || !seen.keys.size) return NONE;
  // This import's change keys first: a change is what the check-first order waits for.
  const shaped = [...seen.keys]
    .filter((k) => KEY_SHAPE.test(k))
    .sort((a, b) => Number(seen.changes.has(b)) - Number(seen.changes.has(a)) || a.localeCompare(b));
  const keys = shaped.slice(0, PRECURSOR_KEYS_MAX);
  const found = new Map<string, ForensicEvent>();
  let scanTruncated = false;
  for (const key of keys) {
    const stored = await storedChange(deps, caseId, key);
    const own = seen.changes.get(key);
    const change = !stored || (own && own.time < stored.time) ? own : stored;
    if (!change) continue;
    const scan = await superChecks(store, caseId, key, change);
    scanTruncated ||= scan.truncated;
    for (const e of scan.rows) if (!exclude.has(e.id) && !found.has(e.id)) found.set(e.id, e);
  }
  const limits = { keysSkipped: shaped.length - keys.length, scanTruncated };
  if (!found.size) return { ...NONE, ...limits };
  const held = await deps.forensic.hasForensicEventIds(caseId, [...found.keys()]);
  const fresh = [...found.values()].filter((e) => !held.has(e.id)).sort(byTime);
  const events = fresh.slice(0, PRECURSOR_PROMOTE_MAX).map((e) => ({
    ...e,
    sources: e.sources?.length ? e.sources : ["AWS CloudTrail"],
    mitreTechniques: e.mitreTechniques ?? [],
  }));
  return { events, found: fresh.length, ...limits };
}

/** The import's case timeline clause: what was promoted, and every bound that stopped the lookup. */
export function precursorPromotionNote(p: PrecursorPromotion): string {
  const left = p.found - p.events.length;
  const parts = [
    p.events.length
      ? `${p.events.length} earlier S3 recovery check(s) promoted from the super-timeline to High ` +
        `(ransomware precursor join)` +
        (left > 0 ? `, ${left} more not promoted (cap ${PRECURSOR_PROMOTE_MAX})` : "")
      : "",
    p.keysSkipped
      ? `precursor lookup skipped ${p.keysSkipped} access key(s) (cap ${PRECURSOR_KEYS_MAX} per import)`
      : "",
    p.scanTruncated
      ? `precursor lookup stopped after ${PRECURSOR_SCAN_ROWS} super-timeline rows for a key`
      : "",
  ].filter(Boolean);
  return parts.length ? `; ${parts.join("; ")}` : "";
}
