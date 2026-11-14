import { capBuildTimeRow, type BuildTimeWindow } from "../../buildTimeWindow.js";
import { engineBootOf, stampEngineBoot, withEngineBoot } from "../../defenderEngineBoot.js";
import { capLabSetupRow } from "../../labSetupTransfer.js";
import type { ForensicEvent } from "../../stateTypes.js";
import { applyToForensicEvent } from "../../tagger.js";
import { readTaggerSettings, runAndApplyTagger } from "../../taggerRun.js";
import type { TagsStore } from "../../tags.js";
import type { TaggerStore } from "../../taggerStore.js";
import { WATSON_MARKER } from "../../timeline/watsonItems.js";

// The content tagger for a Watson chat paste (spec §14). It writes the tags exactly as the import
// tagger does, but changes no grade: a row a rule would raise out of Info stays Info (so demote
// moves it to the super-timeline like any Info row) and its raised copy is collected instead, to be
// held as a pending Watson proposal the analyst approves. Same gates as autoTagNewEvents
// (TAGGER_AUTO, TAGGER_SCOPE=super raises nothing, an empty or invalid ruleset skips) and, like it,
// it never throws: a paste must never fail because of the tagger.
//
// Only rows the tagger would raise OUT OF Info are held. A row an importer already graded above
// Info keeps the importer's grade; the tagger's raise of it is not applied and not held.

export interface HeldTaggerDeps {
  taggerStore?: TaggerStore;
  tagsStore?: TagsStore;
  onTags?: (caseId: string) => void;
  logLine?: (message: string) => void;
}

export interface HeldTagger {
  /** Stands in for the content-tagger step of the settle's `autoTagImported`. */
  tag(caseId: string, added: readonly ForensicEvent[]): Promise<void>;
  /** Raised copies of the rows the tagger would have taken out of Info, before the corrections. */
  held(): ForensicEvent[];
  /** Every row the settle offered the tagger (this import's added rows, pre-demote). */
  offered(): ForensicEvent[];
}

export function heldContentTagger(deps: HeldTaggerDeps): HeldTagger {
  let held: ForensicEvent[] = [];
  let offered: ForensicEvent[] = [];
  const tag = async (caseId: string, added: readonly ForensicEvent[]): Promise<void> => {
    offered = [...offered, ...added];
    const { taggerStore, tagsStore } = deps;
    if (!taggerStore || !tagsStore || !added.length) return;
    const settings = readTaggerSettings();
    if (!settings.auto) return;
    try {
      const ruleset = await taggerStore.load();
      if (!ruleset.rules.length) return;
      const applied = await runAndApplyTagger({
        caseId,
        events: added,
        ruleset,
        forensicTimeline: [],
        tagsStore,
        mutateForensic: false,
      });
      if (applied.tagsWritten > 0) deps.onTags?.(caseId);
      if (settings.scope === "super") return;
      const byId = new Map(applied.result.perEvent.map((r) => [r.eventId, r] as const));
      const raised = added.flatMap((e) => {
        const r = byId.get(e.id);
        if (!r || e.severity !== "Info") return [];
        const up = applyToForensicEvent(e, r);
        return up.severity === "Info" ? [] : [up];
      });
      held = [...held, ...raised];
      if (applied.result.totalMatched > 0) {
        deps.logLine?.(
          `[tagger] ${caseId} Watson paste: tagged ${applied.result.totalMatched} event(s), +${applied.tagsWritten} tag(s), ${raised.length} held for approval`,
        );
      }
    } catch (err) {
      deps.logLine?.(`[tagger] ${caseId} Watson paste tagging skipped: ${(err as Error).message}`);
    }
  };
  return { tag, held: () => held, offered: () => offered };
}

/** What the post-tagger corrections need beside the candidates. */
export interface HeldCorrectionContext {
  /** Build-time windows, discovered from the forensic timeline plus this import's rows. */
  windows: readonly BuildTimeWindow[];
  /** The lab-setup folders (labSetupPaths()). */
  labPaths: readonly string[];
  /** This import's rows as the tagger saw them (the engine start-up anchor reads them). */
  offered: readonly ForensicEvent[];
}

/**
 * The held candidates through the same post-tagger corrections the settle applies, in its order
 * (build-time cap → lab-setup cap → Defender engine start-up), then marked as Watson's. A candidate
 * the corrections return to Info is not held. Pure: returns new rows.
 */
export function finalizeHeld(
  candidates: readonly ForensicEvent[],
  ctx: HeldCorrectionContext,
): ForensicEvent[] {
  const raisedById = new Map(candidates.map((e) => [e.id, e] as const));
  const asSeen = ctx.offered.map((e) => raisedById.get(e.id) ?? e);
  const boots = new Map(stampEngineBoot(asSeen).map((e) => [e.id, engineBootOf(e)] as const));
  return candidates.flatMap((e) => {
    const capped = capLabSetupRow(capBuildTimeRow(e, ctx.windows), ctx.labPaths);
    if (capped.severity === "Info") return [];
    const stamped = withEngineBoot(capped, boots.get(e.id));
    return [{ ...stamped, provenance: [...new Set([...(stamped.provenance ?? []), WATSON_MARKER])] }];
  });
}
