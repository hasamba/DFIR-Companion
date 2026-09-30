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
import { applyToForensicEvent } from "./tagger.js";
import { rewriteRows } from "./forensicRowRewrite.js";
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
  /** The case's state lock: the read → apply → write of the tagged rows runs inside it (#1874). */
  runStateExclusive?: <T>(caseId: string, fn: () => Promise<T>) => Promise<T>;
  logLine?: (msg: string) => void;
}

/**
 * Tag the just-imported events. `added` is the set newly appended to the super-timeline. Safe to call
 * from any import site; never throws.
 */
export async function autoTagNewEvents(
  deps: AutoTagDeps,
  caseId: string,
  added: readonly ForensicEvent[],
): Promise<void> {
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
    // Tags first, from the rows handed in; the forensic grade/MITRE change after, below.
    const applied = await runAndApplyTagger({
      caseId,
      events: added,
      ruleset,
      forensicTimeline: [],
      tagsStore,
      mutateForensic: false,
    });
    // #1874: only the rows a rule matched can change, so only they are read and written — by row id
    // and version, inside the state lock — never the whole case.
    const matched = new Map(applied.result.perEvent.map((r) => [r.eventId, r]));
    const lock = deps.runStateExclusive ?? (<T>(_: string, fn: () => Promise<T>) => fn());
    const written =
      mutateForensic && matched.size
        ? await lock(caseId, async () => {
            const rows = await stateStore.forensicRowsById(caseId, [...matched.keys()]);
            const out = await rewriteRows(stateStore, caseId, rows, (e) => {
              const r = matched.get(e.id);
              return r ? applyToForensicEvent(e, r) : e;
            });
            if (out.length) await stateStore.patchStateMeta(caseId, { updatedAt: new Date().toISOString() });
            return out;
          })
        : [];
    const byId = new Map(written.map((r) => [r.event.id, r.event]));
    const promoted = added.filter(
      (event) => event.severity === "Info" && (byId.get(event.id)?.severity ?? "Info") !== "Info",
    ).length;
    if (promoted > 0) await deps.operationalMetrics?.record({ type: "import_promotion", promoted });
    if (written.length && deps.onState) {
      deps.onState(await stateStore!.load(caseId)); // a caller that asked for a state broadcast
    }
    const mutatedCount = written.length;
    if (applied.tagsWritten > 0) deps.onTags?.(caseId);
    if (applied.result.totalMatched > 0) {
      deps.logLine?.(
        `[tagger] ${caseId} auto-tagged ${applied.result.totalMatched} event(s), +${applied.tagsWritten} tag(s), ${mutatedCount} severity/MITRE update(s)`,
      );
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
        hashes: [
          {
            id: "tagger-result",
            sha256: hashManifestValue(applied.result),
          },
        ],
        claims: [],
      },
    });
  } catch (err) {
    deps.logLine?.(`[tagger] ${caseId} auto-tag skipped: ${(err as Error).message}`);
  }
}
