// "Measure against this case" for a staged rule pack (#2349): how many rows of the open case would
// be graded or tagged differently by the pack's rules than by the rules in use now. It CHANGES
// NOTHING — both rule sets run in memory over the same rows and only counts come back.
//
// The tagger only RAISES a grade (tagger.ts raiseSeverity). So a rule the pack removes or narrows
// lowers nothing that is already in the case: "would no longer be raised" counts rows that an
// import graded with the pack would leave lower, and existing grades stay until the case is
// re-imported. The result says so, to the analyst.

import type { ForensicEvent, Severity } from "./stateTypes.js";
import type { CompiledRuleset } from "./taggerRules.js";
import { SEVERITIES } from "./taggerRules.js";
import { applyToForensicEvent, runTagger, type EventTagResult, type TaggerScope } from "./tagger.js";

export interface PackMeasure {
  scanned: number;
  /** Rows the pack would grade higher than the rules in use. */
  raised: number;
  /** Rows the rules in use raise and the pack would not (a fresh import only — see the header). */
  noLongerRaised: number;
  /** Info rows the pack would raise above Info: they would enter the forensic timeline. */
  intoForensic: number;
  /** Rows the rules in use raise above Info and the pack would leave at Info. */
  wouldStayOut: number;
  /** Rows whose tagger tags would differ. */
  tagsChanged: number;
  note: string;
}

export const MEASURE_NOTE =
  "Nothing was changed. The tagger only raises grades, so a rule the pack removes or narrows does not lower a grade already in this case; " +
  "'no longer raised' counts rows a new import graded with the pack would leave lower.";

const rank = (s: Severity): number => {
  const i = SEVERITIES.indexOf(s);
  return i === -1 ? SEVERITIES.length : i;
};

function gradeAndTags(e: ForensicEvent, r: EventTagResult | undefined): { sev: Severity; tags: string } {
  if (!r) return { sev: e.severity, tags: "" };
  return { sev: applyToForensicEvent(e, r).severity, tags: [...r.tags].sort().join("\u0000") };
}

export function createPackMeasure(current: CompiledRuleset, candidate: CompiledRuleset) {
  const m = { scanned: 0, raised: 0, noLongerRaised: 0, intoForensic: 0, wouldStayOut: 0, tagsChanged: 0 };
  return {
    add(events: readonly ForensicEvent[]): void {
      if (!events.length) return;
      const cur = new Map(runTagger(events, current).perEvent.map((r) => [r.eventId, r]));
      const next = new Map(runTagger(events, candidate).perEvent.map((r) => [r.eventId, r]));
      for (const e of events) {
        m.scanned++;
        const a = gradeAndTags(e, cur.get(e.id));
        const b = gradeAndTags(e, next.get(e.id));
        if (rank(b.sev) < rank(a.sev)) m.raised++;
        if (rank(a.sev) < rank(b.sev)) m.noLongerRaised++;
        if (e.severity === "Info" && a.sev === "Info" && b.sev !== "Info") m.intoForensic++;
        if (e.severity === "Info" && a.sev !== "Info" && b.sev === "Info") m.wouldStayOut++;
        if (a.tags !== b.tags) m.tagsChanged++;
      }
    },
    finish(): PackMeasure {
      return { ...m, note: MEASURE_NOTE };
    },
  };
}

/** Run the measure over the case's rows in the tagger's scope (as the single-rule preview does). */
export async function measurePack(
  current: CompiledRuleset,
  candidate: CompiledRuleset,
  scope: TaggerScope,
  forensic: readonly ForensicEvent[],
  superBatches: AsyncIterable<readonly ForensicEvent[]> | null,
): Promise<PackMeasure> {
  const acc = createPackMeasure(current, candidate);
  if (scope !== "super") acc.add(forensic);
  if (scope !== "forensic" && superBatches) {
    const seen = scope === "both" ? new Set(forensic.map((e) => e.id)) : null;
    for await (const batch of superBatches) acc.add(seen ? batch.filter((e) => !seen.has(e.id)) : batch);
  }
  return acc.finish();
}
