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
//
// The partly read mark (#1651) is coverage provenance, not display attribution, so it too is read from
// every member, never from the primary alone — see partlyReadArtifactOf.

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

/**
 * The partly read artifact a merge group keeps (#1651): a stamped member's artifact, unless a member
 * read in full from that same artifact holds the same record — a complete re-read supersedes the
 * partial one. A full member of ANOTHER artifact never clears it. undefined when nothing stays stamped.
 */
export function partlyReadArtifactOf(events: readonly ForensicEvent[]): string | undefined {
  const fromArtifact = (name: string | undefined, artifact: string): boolean =>
    !!name && (name === artifact || name.startsWith(`${artifact}/`));
  const stamped = [...new Set(events.map((e) => e.partlyReadArtifact).filter((a): a is string => !!a))];
  return stamped.find((a) => !events.some((e) => !e.partlyReadArtifact && fromArtifact(e.artifactName, a)));
}

/**
 * The time basis a merge group keeps (#2684): "scan" only when every member dated at the kept
 * timestamp was dated by a scanner. An artifact-dated member at that time wins, so a merged row never
 * claims scan time for a timestamp some record actually wrote — that would mute a gap's grade.
 */
export function timeBasisOf(events: readonly ForensicEvent[], timestamp: string): "scan" | undefined {
  const atTime = events.filter((e) => e.timestamp === timestamp);
  return atTime.length > 0 && atTime.every((e) => e.timeBasis === "scan") ? "scan" : undefined;
}

/**
 * The grade mark a correlation merge keeps (#2891, #2909; analysis/gradeMark.ts): any member still
 * waiting for the tagger → the merged row waits too. "held" wins over true, so a fold never lets a
 * plain re-grade apply a raise a Watson paste only proposed.
 */
export function gradeMarkUnion(events: readonly ForensicEvent[]): Pick<ForensicEvent, "gradePending"> {
  if (events.some((e) => e.gradePending === "held")) return { gradePending: "held" };
  return events.some((e) => e.gradePending) ? { gradePending: true } : {};
}
