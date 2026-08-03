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
 */
import type { CaseStore } from "../storage/caseStore.js";
import { AiControlStore, type AiControl } from "../analysis/aiControl.js";

export interface AiControlCache {
  getControl(caseId: string): Promise<AiControl>;
  setControl(caseId: string, patch: Partial<AiControl>): Promise<AiControl>;
}

export function createAiControlCache(store: CaseStore): AiControlCache {
  const aiControl = new AiControlStore(store);
  const cache = new Map<string, AiControl>();

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
    async setControl(caseId, patch) {
      const next = { ...(await getControl(caseId)), ...patch };
      cache.set(caseId, next);
      await aiControl.save(caseId, next);
      return next;
    },
  };
}
