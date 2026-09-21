// A silence between two visits of our own collector is not a gap in the host's telemetry (#1500).
//
// On INC-2026-033 Velociraptor ran Windows.Forensics.PersistenceSniper twice, thirty minutes apart.
// Nothing else in the scoped timeline fell between the two runs, so the detector reported the idle
// time as a complete coverage gap, synthesis built "Anti-Forensic Log Clearing — Unconfirmed" on it,
// and the case's one Critical next step was to collect the logs for those thirty minutes.
//
// When the LAST thing logged before a silence and the FIRST thing after it are both rows the
// import attributed to the case's own collector (`origin: "collector"` — collectorDeployment.ts,
// collectorChildren.ts), the silence is bounded by our own activity: the host was quiet between
// two things WE did there. That is idle time, not evidence that anything went dark. Such a gap is
// not emitted, so no finding, hypothesis prompt, report row or next step can be seeded by it.
//
// Deliberately narrow: only a COMPLETE gap (every source silent), and only when BOTH edges are
// collector rows. A partial per-source gap keeps its own bounding rows and is untouched — the
// collector's presence at one tool's edges says nothing about another tool's coverage. Where one
// edge is real host activity the gap stands, whatever the other edge is.
//
// This reads the timeline it is given. Collector rows are Info, so on a case whose forensic floor
// is Low or above they are not in the forensic timeline at all — and then the silence between two
// real host rows IS a gap of the forensic record, correctly bounded by real rows, and stays. The
// gap this exists for came from a case whose floor kept the Info rows (INC-2026-033's forensic
// timeline holds them, verified in its state store). Nothing here reads the super-timeline.

import type { ForensicEvent } from "./stateTypes.js";
import type { TimelineGap } from "./gapDetect.js";

function isCollectorRow(e: ForensicEvent | undefined): boolean {
  return e?.origin === "collector";
}

/** The gaps minus every complete gap whose two bounding events are both the collector's own rows. */
export function dropCollectorBoundedGaps(
  gaps: readonly TimelineGap[],
  events: readonly ForensicEvent[],
): TimelineGap[] {
  const byId = new Map(events.map((e) => [e.id, e] as const));
  return gaps.filter(
    (g) =>
      !(g.complete && isCollectorRow(byId.get(g.beforeEventId)) && isCollectorRow(byId.get(g.afterEventId))),
  );
}
