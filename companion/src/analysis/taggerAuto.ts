// The AUTOMATIC post-import tagger hook. Every import path dual-writes its newly-added events into
// the super-timeline; immediately after that append, this runs the ruleset over just those NEW
// events (so cost is O(new × rules), not the whole 100k-event store) and applies the result:
//   • tags   — written for every match (tags are keyed by event id, so they light up BOTH the
//              forensic timeline and the super-timeline filters);
//   • forensic severity/MITRE — raised/unioned on the forensic timeline, UNLESS scope is super-only.
//
// Entirely best-effort and non-fatal: a missing store, TAGGER_AUTO=false, an empty/invalid ruleset,
// or any error just skips tagging — an import must never fail because of the tagger. Gated by the
// TAGGER_AUTO / TAGGER_SCOPE settings (analysis/taggerRun.ts).

import type { ForensicEvent, InvestigationState } from "./stateTypes.js";
import type { TagsStore } from "./tags.js";
import type { TaggerStore } from "./taggerStore.js";
import type { StateStore } from "./stateStore.js";
import { runAndApplyTagger, readTaggerSettings } from "./taggerRun.js";

export interface AutoTagDeps {
  taggerStore?: TaggerStore;
  tagsStore?: TagsStore;
  stateStore?: StateStore;
  onTags?: (caseId: string) => void;
  onState?: (state: InvestigationState) => void;
  logLine?: (msg: string) => void;
}

/**
 * Tag the just-imported events. `added` is the set newly appended to the super-timeline. Safe to call
 * from any import site; never throws.
 */
export async function autoTagNewEvents(deps: AutoTagDeps, caseId: string, added: readonly ForensicEvent[]): Promise<void> {
  const { taggerStore, tagsStore, stateStore } = deps;
  if (!taggerStore || !tagsStore || !added.length) return;
  const settings = readTaggerSettings();
  if (!settings.auto) return;
  try {
    const ruleset = await taggerStore.load(); // throws on an invalid hand-edited file → skip (below)
    if (!ruleset.rules.length) return;

    const mutateForensic = settings.scope !== "super" && !!stateStore;
    const state = mutateForensic ? await stateStore!.load(caseId) : null;

    const applied = await runAndApplyTagger({
      caseId,
      events: added,
      ruleset,
      forensicTimeline: state?.forensicTimeline ?? [],
      tagsStore,
      mutateForensic,
    });

    if (state && applied.mutatedCount > 0) {
      const next: InvestigationState = { ...state, forensicTimeline: applied.forensicTimeline, updatedAt: new Date().toISOString() };
      await stateStore!.save(next);
      deps.onState?.(next);
    }
    if (applied.tagsWritten > 0) deps.onTags?.(caseId);
    if (applied.result.totalMatched > 0) {
      deps.logLine?.(`[tagger] ${caseId} auto-tagged ${applied.result.totalMatched} event(s), +${applied.tagsWritten} tag(s), ${applied.mutatedCount} severity/MITRE update(s)`);
    }
  } catch (err) {
    deps.logLine?.(`[tagger] ${caseId} auto-tag skipped: ${(err as Error).message}`);
  }
}
