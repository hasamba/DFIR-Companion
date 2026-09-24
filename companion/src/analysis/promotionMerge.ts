// Promotion marks through a correlation merge (#932 item 5 part B, #1586).
//
// correlate.mergeGroup spreads the PRIMARY member, and the primary is picked for severity and trust,
// not for which member an analyst promoted. So both marks of a promotion are taken from every member:
//
// - provenance is a union — an analyst's "[promoted]" on a lab row survives a merge with an
//   incidental copy whose longer description wins primary.
// - promotedAt is the LATEST stamp of any member. A promoted Low row that correlates into a
//   non-promoted High primary must still read as promoted, or synthesis — which shows a freshly
//   promoted row once as new evidence — never learns the evidence is new. Unparsable stamps are
//   ignored.
//
// A mark no member carries adds no key, so an unpromoted merge keeps the primary's shape.

import type { ForensicEvent } from "./stateTypes.js";

type PromotionMarks = Pick<ForensicEvent, "provenance" | "promotedAt">;

/** The provenance union and latest promotedAt across a merge group, as a spreadable object. */
export function promotionMarks(events: readonly ForensicEvent[]): PromotionMarks {
  const provenance = [...new Set(events.flatMap((e) => e.provenance ?? []))];
  const promotedAt = latestPromotedAt(events);
  return {
    ...(provenance.length ? { provenance } : {}),
    ...(promotedAt ? { promotedAt } : {}),
  };
}

function latestPromotedAt(events: readonly ForensicEvent[]): string | undefined {
  let best: string | undefined;
  let bestMs = -Infinity;
  for (const e of events) {
    const ms = e.promotedAt ? Date.parse(e.promotedAt) : NaN;
    if (!Number.isNaN(ms) && ms > bestMs) {
      best = e.promotedAt;
      bestMs = ms;
    }
  }
  return best;
}
