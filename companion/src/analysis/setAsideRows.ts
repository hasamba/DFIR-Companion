// Rows a named rule set aside on purpose, and what the super-timeline's cap owes them (#1535).
//
// THE EXPOSURE. An Info row never reaches the forensic timeline (ARCHITECTURE.md → "The forensic /
// super-timeline boundary"), so the super-timeline is its only home. That store has a cap, and the
// cap evicts in insertion order. A row a NAMED RULE pushed to Info on purpose — the collector
// footprint (#1500), first-party update egress (#1530), a build-time provisioning window (#1529) —
// is evidence the case decided to set aside, not bulk telemetry. Evicting it on the same footing as
// a prefetch row makes it leave the case entirely.
//
// THE DECISION (issue #1535, case owner, 2026-09-22). Such a row is evicted LAST, behind ordinary
// bulk Info. It is an ORDER, enforced in the store, not a pin any pass gets to set: no pass has an
// API to protect a row, and `append` takes no new argument from its callers. And it is honest —
// "evicted last" is not "never evicted". A case large enough still loses these rows; what changed
// is that everything else goes first, and the cap now reports what it dropped.
//
// WHAT QUALIFIES. Two things together, both read off the row itself:
//
//   1. The row reads `Info`. A note alone is not enough. veloDetectionNoise.ts appends the same
//      collector note to a CRITICAL row it explicitly refuses to demote, and buildTimeWindow.ts
//      caps at LOW — neither is a row this protects, and neither has the disappearance problem,
//      because a row at Low or above is in the forensic timeline too.
//   2. Its description carries a registered demotion reason. Every named pass already writes one,
//      because the record has to explain its own grade to the analyst.
//
// HOW A FUTURE DEMOTER QUALIFIES. There is no honest way to prove statically that any future pass
// will be classified, so this does the two enforceable things instead:
//
//   - A PREFIX, not a sentence. `[DFIR collector ` covers every collector footprint and deployment
//     note that exists and every one that will be written, with no registration at all.
//   - THE HOUSE HELPER. A pass that states its reason through derivedNote.ts must register a
//     `*_MARKER` in DERIVED_NOTE_NAMES — tests/analysis/derivedNote.test.ts sweeps src/analysis and
//     fails when one is missing — and DERIVED_NOTE_DOWNGRADES sits beside that list for the passes
//     that LOWER a grade. Registering there is all a new demoter has to do.
//
// And tests/analysis/setAsideRows.test.ts runs each named pass FOR REAL and asserts the row it
// produces qualifies, so a reworded note fails loudly instead of quietly losing its standing.

import { DERIVED_NOTE_DOWNGRADES } from "./derivedNote.js";
import type { ForensicEvent } from "./stateTypes.js";

/**
 * Every collector demotion note, in one prefix: `collectorChildren.ts`, `collectorLineage.ts`,
 * `collectorDeployment.ts` and `veloDetectionNoise.ts` all open with it, and a new one in that
 * family qualifies without touching this file. `tests/analysis/setAsideRows.test.ts` sweeps
 * src/analysis for `[DFIR collector ` literals and fails if one ever stops matching.
 */
export const COLLECTOR_NOTE_PREFIX = " [DFIR collector ";

/**
 * The stated reason analysis/firstPartyEgress.ts writes, as a stable prefix. It lives here rather
 * than in that module because the store that enforces the cap may not import upward into the
 * detection layer; that pass imports it from here and builds its note on it, so there is one
 * string. Reword the tail freely; do not reword this.
 */
export const FIRST_PARTY_EGRESS_MARKER = " [first-party update traffic —";

/** The stated demotion reasons a set-aside row may carry. Prefixes — the tail is free text. */
export const SET_ASIDE_NOTE_MARKERS: readonly string[] = [
  COLLECTOR_NOTE_PREFIX,
  FIRST_PARTY_EGRESS_MARKER,
  ...DERIVED_NOTE_DOWNGRADES.map((name) => `[${name}:`),
];

/**
 * A short fingerprint of the registry above. The store records it beside the relation it derives,
 * so shipping a new demoter re-derives membership over the rows a case ALREADY holds instead of
 * only helping rows imported afterwards. Change the list, and every case re-derives once.
 */
export const SET_ASIDE_REGISTRY_VERSION = ((): string => {
  let hash = 5381;
  for (const marker of SET_ASIDE_NOTE_MARKERS) {
    for (let i = 0; i < marker.length; i++) hash = ((hash * 33) ^ marker.charCodeAt(i)) >>> 0;
  }
  return `v1:${SET_ASIDE_NOTE_MARKERS.length}:${hash.toString(36)}`;
})();

/**
 * True when a named rule deliberately graded this row Info and said why in the row. Both halves
 * are required; see the header. Reads only `severity` and `description`, which is exactly what the
 * store's own predicate reads out of a stored row, so the two can never disagree.
 */
export function isSetAsideRow(event: Pick<ForensicEvent, "severity" | "description"> | undefined): boolean {
  if (!event || event.severity !== "Info") return false;
  const description = event.description ?? "";
  if (!description) return false;
  return SET_ASIDE_NOTE_MARKERS.some((marker) => description.includes(marker));
}
