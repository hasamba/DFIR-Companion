import { worstSeverity, type ForensicEvent, type Severity } from "./stateTypes.js";
import { byEventTime } from "./forensicSort.js";
import { KILL_CHAIN_ORDER, tacticForTechniques, type IrisTactic } from "./mitreTactics.js";

// Temporal burst / attack-phase detection. A real intrusion arrives in bursts: a dense cluster
// of events within minutes (initial access), a gap, then another burst (persistence), and so on.
// The raw forensic timeline is strictly chronological, so the analyst has to eyeball the clusters.
// This groups the timeline into PHASES by the time gap BETWEEN consecutive events — events closer
// together than `gapSeconds` belong to the same phase; a larger gap starts a new one. Each phase
// is labelled with the dominant ATT&CK tactic of its events (reusing the canonical
// `tacticForTechniques` mapping — same logic the kill-chain view and IRIS export use).
//
// This is the TEMPORAL axis (when did activity cluster), complementary to the categorical
// kill-chain view (which tactic). Pure, deterministic, NO AI call — a time-gap algorithm.

export interface AttackPhase {
  id: string; // stable per-timeline id: "phase-1", "phase-2", …
  label: string; // inferred phase name — an ATT&CK tactic, or "Activity burst" when undetermined
  startTimestamp: string; // first event's time in the burst
  endTimestamp: string; // last event's time in the burst (uses endTimestamp for aggregated rows)
  eventIds: string[]; // forensic-event ids in this phase, chronological
  inferredTechniques: string[]; // distinct MITRE technique ids across the burst, sorted
  eventCount: number; // events in the burst (sums aggregated `count` where present)
  maxSeverity: Severity; // worst severity observed in the burst
}

export interface BurstOptions {
  // Events more than this many seconds apart start a new phase. Default 5 minutes.
  gapSeconds?: number;
}

export const DEFAULT_GAP_SECONDS = 300;

// Kill-chain order — used only to tie-break the dominant-tactic vote deterministically (the
// earliest stage represented wins a tie, so a phase reads as the stage it leads with).
const CHAIN_ORDER = KILL_CHAIN_ORDER;

// Pick the phase label from the tactics of its events: the most frequent tactic wins; ties break
// toward the earliest kill-chain stage. Undetermined (no event mapped to a tactic) → undefined.
function dominantTactic(events: ForensicEvent[]): IrisTactic | undefined {
  const counts = new Map<IrisTactic, number>();
  for (const e of events) {
    const tac = tacticForTechniques(e.mitreTechniques, e.description);
    if (tac) counts.set(tac, (counts.get(tac) ?? 0) + 1);
  }
  let best: IrisTactic | undefined;
  let bestCount = 0;
  for (const tac of CHAIN_ORDER) {
    // iterate in chain order so the earliest stage wins ties
    const c = counts.get(tac) ?? 0;
    if (c > bestCount) {
      best = tac;
      bestCount = c;
    }
  }
  return best;
}

// One position on the time axis. An event contributes its start. A row that stands for MANY
// occurrences (`count` > 1, merged by aggregation) also contributes its end as a point with no event
// of its own: the row proves activity at its first and last occurrence, not in between. Treating the
// whole span as continuous let one row of routine logons (3,133 events over 24 hours) or a handful of
// connections over six days bridge every silence in the case into a single phase. A row with a span
// but no count (a tool-reported or AI-reported duration) is one continuous stretch, as before.
interface TimePoint {
  ms: number; // where this point sits
  coverMs: number; // how far the burst reaches from here (a continuous span reaches its end)
  ts: string; // display string for `ms` (or for the end of a continuous span, its end string)
  coverTs: string;
  event?: ForensicEvent; // the event this point starts; absent for an aggregate's end point
}

function endOf(e: ForensicEvent): { ms: number; ts: string } | undefined {
  const ms = e.endTimestamp ? Date.parse(e.endTimestamp) : NaN;
  return Number.isNaN(ms) ? undefined : { ms, ts: e.endTimestamp! };
}

function pointsFor(e: ForensicEvent): TimePoint[] {
  const ms = Date.parse(e.timestamp);
  const end = endOf(e);
  if (!end || end.ms <= ms) return [{ ms, coverMs: ms, ts: e.timestamp, coverTs: e.timestamp, event: e }];
  if (e.count && e.count > 1) {
    return [
      { ms, coverMs: ms, ts: e.timestamp, coverTs: e.timestamp, event: e },
      { ms: end.ms, coverMs: end.ms, ts: end.ts, coverTs: end.ts },
    ];
  }
  return [{ ms, coverMs: end.ms, ts: e.timestamp, coverTs: end.ts, event: e }];
}

function summarizePhase(index: number, points: TimePoint[]): AttackPhase {
  const events = points.flatMap((pt) => (pt.event ? [pt.event] : []));
  const tactic = dominantTactic(events);
  const techniques = new Set<string>();
  let count = 0;
  let maxSeverity: Severity = "Info";
  for (const e of events) {
    for (const t of e.mitreTechniques) techniques.add(t);
    count += e.count && e.count > 1 ? e.count : 1;
    maxSeverity = worstSeverity(maxSeverity, e.severity);
  }
  let end = points[0];
  for (const pt of points) if (pt.coverMs > end.coverMs) end = pt;
  return {
    id: `phase-${index + 1}`,
    label: tactic ?? "Activity burst",
    startTimestamp: points[0].ts,
    endTimestamp: end.coverTs,
    eventIds: events.map((e) => e.id),
    inferredTechniques: [...techniques].sort(),
    eventCount: count,
    maxSeverity,
  };
}

// Group a forensic timeline into temporal attack phases. Only DATED events participate (an
// unparseable/empty timestamp has no position on the time axis). Returns phases in chronological
// order; an empty or fully-undated timeline yields no phases.
export function buildAttackPhases(events: ForensicEvent[], opts: BurstOptions = {}): AttackPhase[] {
  const gapMs = Math.max(0, (opts.gapSeconds ?? DEFAULT_GAP_SECONDS) * 1000);
  const dated = events.filter((e) => !Number.isNaN(Date.parse(e.timestamp))).sort(byEventTime);
  if (dated.length === 0) return [];

  // Start points keep the event order; an aggregate's end point is merged in by time.
  const points = dated.flatMap(pointsFor).sort((a, b) => a.ms - b.ms);
  const clusters: TimePoint[][] = [];
  let current: TimePoint[] = [points[0]];
  // Gap is measured from the END of the running burst so a long continuous event doesn't
  // spuriously split from a follow-on that overlaps it.
  let prevEndMs = points[0].coverMs;
  for (let i = 1; i < points.length; i++) {
    const pt = points[i];
    if (pt.ms - prevEndMs > gapMs) {
      clusters.push(current);
      current = [pt];
      prevEndMs = pt.coverMs;
    } else {
      current.push(pt);
      prevEndMs = Math.max(prevEndMs, pt.coverMs);
    }
  }
  clusters.push(current);
  // A cluster made only of aggregate end points has no event to show.
  return clusters.filter((c) => c.some((pt) => pt.event)).map((c, i) => summarizePhase(i, c));
}
