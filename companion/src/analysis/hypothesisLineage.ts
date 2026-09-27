// A hypothesis links observations by event id, and an analyst-authored or analyst-touched one is
// frozen against the synthesis refresh — so when correlation folds a linked event into another, its
// link kept naming an event that no longer existed and the reading counted the observation as gone
// (#1715). These read a hypothesis through the case lineage (eventAliases.ts) without rewriting it.
//
// Several stored ids can resolve to one event, so one observation the analyst sees may stand for
// several stored links. Excluding or restoring it acts on every one of them.

import type { Hypothesis } from "./hypothesis.js";
import type { EventResolver } from "./eventAliasLookup.js";

const resolveAll = (ids: readonly string[], resolve: EventResolver): string[] => [
  ...new Set(ids.map(resolve)),
];

/**
 * The hypothesis as the analyst should see it today: every link on the event it lives on now, and
 * every exclusion on that event too, with the id it was recorded against kept as `recordedEventId`.
 */
export function resolveHypothesisLinks<H extends Hypothesis>(h: H, resolve: EventResolver): H {
  const related = resolveAll(h.relatedEventIds, resolve);
  const contradicting = resolveAll(h.contradictingEventIds, resolve);
  const moved = (x: { eventId: string }) => resolve(x.eventId) !== x.eventId;
  const changed =
    related.join("\u0000") !== h.relatedEventIds.join("\u0000") ||
    contradicting.join("\u0000") !== h.contradictingEventIds.join("\u0000") ||
    h.excludedEvidence.some(moved);
  if (!changed) return h;
  return {
    ...h,
    relatedEventIds: related,
    contradictingEventIds: contradicting,
    excludedEvidence: h.excludedEvidence.map((x) =>
      moved(x) ? { ...x, eventId: resolve(x.eventId), recordedEventId: x.eventId } : x,
    ),
  };
}

/** The stored link ids of `h` that the observation `eventId` (as the analyst sees it) stands for. */
export function storedLinksFor(h: Hypothesis, eventId: string, resolve: EventResolver): string[] {
  const linked = [...new Set([...h.relatedEventIds, ...h.contradictingEventIds])];
  const matched = linked.filter((id) => id === eventId || resolve(id) === eventId);
  return matched.length ? matched : [eventId];
}

/** The stored ids of `h`'s ACTIVE exclusions that the observation `eventId` stands for. */
export function activeExclusionsFor(h: Hypothesis, eventId: string, resolve: EventResolver): string[] {
  const active = h.excludedEvidence.filter((x) => !x.restoredAt).map((x) => x.eventId);
  const matched = [...new Set(active.filter((id) => id === eventId || resolve(id) === eventId))];
  return matched.length ? matched : [eventId];
}
