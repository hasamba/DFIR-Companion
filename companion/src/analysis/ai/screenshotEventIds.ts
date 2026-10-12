import { lastImportEventSequence } from "../importResume.js";
import type { AnalysisDelta } from "../responseSchema.js";
import type { ForensicEvent } from "../stateTypes.js";
import { toUtcIso } from "../timeUtc.js";

/**
 * Give screenshot-pass events ids that cannot overwrite an unrelated stored event (#2175).
 *
 * The model picks its own event ids (the prompt's example is `e1`), and the merge updates any stored
 * event with the same id in place. The CSV/log import path renumbers every batch for the same reason.
 * Here one case is kept: the state summary tells the model to "extend by id" the events it is shown,
 * so a reused id is kept ONLY when it was shown to this window, it is its first use in this delta, and
 * the timestamps agree (or either side is undated). Every other event gets `<prefix>e<n>`, continuing
 * after any ids already stored under that prefix. Citations in the same delta's findings and
 * hypotheses follow the renumbered events. Pure: the input delta is never mutated.
 */
export function renumberScreenshotEvents(
  delta: AnalysisDelta,
  timeline: readonly ForensicEvent[],
  shownIds: ReadonlySet<string>,
  prefix: string,
): AnalysisDelta {
  if (!delta.forensicEvents?.length) return delta;
  const byId = new Map(timeline.map((e) => [e.id, e]));
  const used = new Set<string>();
  const renamed = new Map<string, string>();
  let seq = lastImportEventSequence(timeline, prefix);

  const forensicEvents = delta.forensicEvents.map((event) => {
    const first = !used.has(event.id);
    used.add(event.id);
    if (first && shownIds.has(event.id) && sameTime(event.timestamp, byId.get(event.id))) return event;
    const id = `${prefix}e${++seq}`;
    // A citation in this delta names the FIRST event with that id; if that one kept its id, so do they.
    if (first) renamed.set(event.id, id);
    return { ...event, id };
  });

  return remapCitations({ ...delta, forensicEvents }, renamed);
}

function sameTime(incoming: string, existing: ForensicEvent | undefined): boolean {
  if (!existing) return false;
  const a = toUtcIso(incoming);
  const b = toUtcIso(existing.timestamp);
  return !a || !b || a === b;
}

function remapCitations(delta: AnalysisDelta, renamed: ReadonlyMap<string, string>): AnalysisDelta {
  if (renamed.size === 0) return delta;
  const remap = (ids: readonly string[]): string[] => ids.map((id) => renamed.get(id) ?? id);
  const findings = delta.findings.map((f) =>
    f.relatedEventIds ? { ...f, relatedEventIds: remap(f.relatedEventIds) } : f,
  );
  const hypotheses = delta.hypotheses?.map((h) => ({
    ...h,
    relatedEventIds: remap(h.relatedEventIds),
    contradictingEventIds: remap(h.contradictingEventIds),
  }));
  return { ...delta, findings, ...(hypotheses ? { hypotheses } : {}) };
}
