/**
 * Per-case AI on/off toggle + last-analyzed capture sequence, read through a write-through cache.
 * Lifted out of createApp by #416.
 *
 * Every AI-bearing path in the app asks "is AI on for this case?" before spending a token —
 * imports, the capture flush, re-synthesis, the Velociraptor upload step — so this is one of the
 * hottest reads in the server, and it is backed by a small JSON file. The cache makes the repeat
 * reads free; `setControl` writes THROUGH it so the cache can never be staler than the disk.
 *
 * Deliberately NOT invalidated by anything: the file has exactly one writer (this cache), because
 * the routes that change the toggle all go through setControl.
 *
 * #2153: setControl is a read-modify-write, so it runs under a per-case StateLock. Unserialized, a
 * capture flush writing lastAnalyzedSeq at the moment the analyst paused AI read the old base and
 * wrote `enabled: true` back. The cache is updated only after the save succeeds, so a failed save
 * cannot leave the cache ahead of the disk. getControl stays unlocked — free reads are the point.
 */
import type { CaseStore } from "../storage/caseStore.js";
import { AiControlStore, type AiControl } from "../analysis/aiControl.js";
import { CaseKeyedMap } from "../storage/caseKeyedState.js";
import { StateLock } from "../analysis/stateLock.js";

export interface AiControlCache {
  getControl(caseId: string): Promise<AiControl>;
  setControl(caseId: string, patch: Partial<AiControl>): Promise<AiControl>;
}

export function createAiControlCache(store: CaseStore): AiControlCache {
  const aiControl = new AiControlStore(store);
  // #1866: keyed by (case id, generation) and forgotten on delete, so a same-id successor never
  // inherits the deleted case's toggle or lastAnalyzedSeq, and an old run's setControl (its save
  // refused) cannot poison the successor's entry.
  const cache = new CaseKeyedMap<AiControl>(() => store.casesRoot);
  const lock = new StateLock();

  async function getControl(caseId: string): Promise<AiControl> {
    let c = cache.get(caseId);
    if (!c) {
      c = await aiControl.load(caseId);
      cache.set(caseId, c);
    }
    return c;
  }

  return {
    getControl,
    setControl(caseId, patch) {
      return lock.runExclusive(caseId, async () => {
        const next = { ...(await getControl(caseId)), ...patch };
        await aiControl.save(caseId, next);
        cache.set(caseId, next);
        return next;
      });
    },
  };
}
