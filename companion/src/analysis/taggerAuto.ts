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
import type { AnalysisRunStore } from "./analysisRunStore.js";
import { hashManifestValue } from "./analysisRunHash.js";
import type { OperationalMetricsStore } from "./operationalMetrics.js";

export interface AutoTagDeps {
  taggerStore?: TaggerStore;
  tagsStore?: TagsStore;
  stateStore?: StateStore;
  analysisRunStore?: AnalysisRunStore;
  operationalMetrics?: OperationalMetricsStore;
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
    const startedAt = new Date().toISOString();
    const active = await taggerStore.readActive();
    const ruleset = await taggerStore.load(); // throws on an invalid hand-edited file → skip (below)
    if (!ruleset.rules.length) return;

    const mutateForensic = settings.scope !== "super" && !!stateStore;
    const state = mutateForensic ? await stateStore.load(caseId) : null;

    const applied = await runAndApplyTagger({
      caseId,
      events: added,
      ruleset,
      forensicTimeline: state?.forensicTimeline ?? [],
      tagsStore,
      mutateForensic,
    });
    const byId = new Map(applied.forensicTimeline.map((event) => [event.id, event]));
    const promoted = added.filter((event) => event.severity === "Info" && byId.get(event.id)?.severity !== "Info").length;
    if (promoted > 0) await deps.operationalMetrics?.record({ type: "import_promotion", promoted });

    if (state && applied.mutatedCount > 0) {
      const next: InvestigationState = { ...state, forensicTimeline: applied.forensicTimeline, updatedAt: new Date().toISOString() };
      await stateStore!.save(next);
      deps.onState?.(next);
    }
    if (applied.tagsWritten > 0) deps.onTags?.(caseId);
    if (applied.result.totalMatched > 0) {
      deps.logLine?.(`[tagger] ${caseId} auto-tagged ${applied.result.totalMatched} event(s), +${applied.tagsWritten} tag(s), ${applied.mutatedCount} severity/MITRE update(s)`);
    }
    await deps.analysisRunStore?.record(caseId, {
      kind: "deterministic",
      startedAt,
      finishedAt: new Date().toISOString(),
      versions: {
        schema: "tagger/v1",
        rules: hashManifestValue(active.text),
      },
      input: {
        artifacts: [],
        eventIds: added.map((event) => event.id),
        entityIds: [],
        selectionHash: hashManifestValue(added.map((event) => event.id)),
      },
      configuration: {
        parameters: { analyzer: "tagger", mode: "automatic" },
        filteringPolicy: { scope: settings.scope },
      },
      output: {
        entityIds: applied.result.perEvent.map((event) => event.eventId),
        hashes: [{
          id: "tagger-result",
          sha256: hashManifestValue(applied.result),
        }],
        claims: [],
      },
    });
  } catch (err) {
    deps.logLine?.(`[tagger] ${caseId} auto-tag skipped: ${(err as Error).message}`);
  }
}
