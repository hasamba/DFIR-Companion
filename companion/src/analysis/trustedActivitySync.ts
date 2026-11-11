// The whole-case recompute of the `trusted-activity` tags (#2561). trustedSourceMarks.ts decides
// which rows a friendly mark tags; this brings the stored tags in line with that decision over the
// CURRENT forensic timeline and the CURRENT marks: stale tags are removed, missing ones added. It
// never touches the super-timeline and never writes a grade.
//
// Called when a mark is set, cleared or relabelled (routes/iocAttribution.ts), after an import
// settles while the case has a friendly mark (routes/routeSettleDeps.ts importTagger), and after a
// manual tagger run or "clear tagger tags" (routes/tagger.ts) — the clear wipes every `tagger:` tag,
// this one included, and a run can raise a row out of eligibility.
//
// Runs serialized per case and reads the marks afresh each time, so the last run always reflects
// the latest marks. Best effort: a failure is logged, never thrown into an import or a route — and
// it cannot hide anything, because every consumer re-checks tags with honouredTrustedRows().

import type { IocAttributionMap } from "./iocAttribution.js";
import type { ForensicEvent } from "./stateTypes.js";
import type { NewTag, Tag } from "./tags.js";
import { TRUSTED_AUTHOR_PREFIX, parseTrustedMarks, trustedActivityTags } from "./trustedSourceMarks.js";

export interface TrustedSyncDeps {
  loadMarks(caseId: string): Promise<IocAttributionMap>;
  loadRows(caseId: string): Promise<readonly ForensicEvent[]>;
  tags: {
    taggerTagsFor(caseId: string, targetIds: readonly string[]): Promise<Tag[]>;
    addMany(caseId: string, inputs: readonly NewTag[]): Promise<readonly unknown[]>;
    remove(caseId: string, tagId: string): Promise<unknown>;
  };
  onTags?: (caseId: string) => void;
  logLine?: (message: string) => void;
}

export interface TrustedSyncResult {
  added: number;
  removed: number;
  /** Rows carrying a trusted tag after the run. */
  tagged: number;
}

const EMPTY: TrustedSyncResult = { added: 0, removed: 0, tagged: 0 };
const chains = new Map<string, Promise<unknown>>();

/** Run `fn` after every earlier sync of this case has settled. */
function serialized<T>(caseId: string, fn: () => Promise<T>): Promise<T> {
  const prior = chains.get(caseId) ?? Promise.resolve();
  const next = prior.then(fn, fn);
  const tail = next.catch(() => undefined);
  chains.set(caseId, tail);
  void tail.then(() => {
    if (chains.get(caseId) === tail) chains.delete(caseId);
  });
  return next;
}

async function reconcile(deps: TrustedSyncDeps, caseId: string): Promise<TrustedSyncResult> {
  const rows = await deps.loadRows(caseId);
  if (!rows.length) return EMPTY;
  const desired = new Map(
    trustedActivityTags(rows, parseTrustedMarks(await deps.loadMarks(caseId))).map((t) => [t.targetId, t]),
  );
  const existing = (
    await deps.tags.taggerTagsFor(
      caseId,
      rows.map((r) => r.id),
    )
  ).filter((t) => t.author.startsWith(TRUSTED_AUTHOR_PREFIX));
  const keep = new Set<string>();
  let removed = 0;
  for (const tag of existing) {
    if (desired.get(tag.targetId)?.author === tag.author && !keep.has(tag.targetId)) keep.add(tag.targetId);
    else if (await deps.tags.remove(caseId, tag.id)) removed++;
  }
  const missing = [...desired.values()].filter((t) => !keep.has(t.targetId));
  const added = missing.length ? (await deps.tags.addMany(caseId, missing)).length : 0;
  if (added || removed) deps.onTags?.(caseId);
  return { added, removed, tagged: keep.size + added };
}

/** Bring the case's trusted tags in line with its current marks and rows. Never throws. */
export function syncTrustedActivity(deps: TrustedSyncDeps, caseId: string): Promise<TrustedSyncResult> {
  return serialized(caseId, async () => {
    try {
      return await reconcile(deps, caseId);
    } catch (err) {
      deps.logLine?.(`trusted-activity tags not refreshed for case ${caseId}: ${(err as Error).message}`);
      return EMPTY;
    }
  });
}
