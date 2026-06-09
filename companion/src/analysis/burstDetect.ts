import type { ForensicEvent, Severity } from "./stateTypes.js";
import { byEventTime } from "./forensicSort.js";
import { tacticForTechniques, type IrisTactic } from "../integrations/iris/mitreTactics.js";

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
  id: string;                    // stable per-timeline id: "phase-1", "phase-2", …
  label: string;                 // inferred phase name — an ATT&CK tactic, or "Activity burst" when undetermined
  startTimestamp: string;        // first event's time in the burst
  endTimestamp: string;          // last event's time in the burst (uses endTimestamp for aggregated rows)
  eventIds: string[];            // forensic-event ids in this phase, chronological
  inferredTechniques: string[];  // distinct MITRE technique ids across the burst, sorted
  eventCount: number;            // events in the burst (sums aggregated `count` where present)
  maxSeverity: Severity;         // worst severity observed in the burst
}

export interface BurstOptions {
  // Events more than this many seconds apart start a new phase. Default 5 minutes.
  gapSeconds?: number;
}

export const DEFAULT_GAP_SECONDS = 300;

const SEV_RANK: Record<Severity, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
function worse(a: Severity, b: Severity): Severity {
  return SEV_RANK[b] < SEV_RANK[a] ? b : a;
}

// Kill-chain order — used only to tie-break the dominant-tactic vote deterministically (the
// earliest stage represented wins a tie, so a phase reads as the stage it leads with).
const CHAIN_ORDER: IrisTactic[] = [
  "Initial Access", "Execution", "Persistence", "Privilege Escalation",
  "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
  "Collection", "Command and Control", "Exfiltration", "Impact",
];

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
  for (const tac of CHAIN_ORDER) {                 // iterate in chain order so the earliest stage wins ties
    const c = counts.get(tac) ?? 0;
    if (c > bestCount) { best = tac; bestCount = c; }
  }
  return best;
}

// The end of an event's real-world span: the aggregated `endTimestamp` when present and valid,
// else its `timestamp`. Used so a burst's window covers aggregated rows correctly.
function eventEndMs(e: ForensicEvent): number {
  const end = e.endTimestamp ? Date.parse(e.endTimestamp) : NaN;
  return Number.isNaN(end) ? Date.parse(e.timestamp) : end;
}

function summarizePhase(index: number, events: ForensicEvent[]): AttackPhase {
  const tactic = dominantTactic(events);
  const techniques = new Set<string>();
  let count = 0;
  let maxSeverity: Severity = "Info";
  let endTs = events[0].endTimestamp || events[0].timestamp;
  let endMs = eventEndMs(events[0]);
  for (const e of events) {
    for (const t of e.mitreTechniques) techniques.add(t);
    count += e.count && e.count > 1 ? e.count : 1;
    maxSeverity = worse(maxSeverity, e.severity);
    const ms = eventEndMs(e);
    if (ms > endMs) { endMs = ms; endTs = e.endTimestamp || e.timestamp; }
  }
  return {
    id: `phase-${index + 1}`,
    label: tactic ?? "Activity burst",
    startTimestamp: events[0].timestamp,
    endTimestamp: endTs,
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
  const dated = events
    .filter((e) => !Number.isNaN(Date.parse(e.timestamp)))
    .sort(byEventTime);
  if (dated.length === 0) return [];

  const phases: AttackPhase[] = [];
  let current: ForensicEvent[] = [dated[0]];
  let prevEndMs = eventEndMs(dated[0]);
  for (let i = 1; i < dated.length; i++) {
    const e = dated[i];
    const startMs = Date.parse(e.timestamp);
    // Gap is measured from the END of the running burst so a long aggregated event doesn't
    // spuriously split from a follow-on that overlaps it.
    if (startMs - prevEndMs > gapMs) {
      phases.push(summarizePhase(phases.length, current));
      current = [e];
      prevEndMs = eventEndMs(e);
    } else {
      current.push(e);
      prevEndMs = Math.max(prevEndMs, eventEndMs(e));
    }
  }
  phases.push(summarizePhase(phases.length, current));
  return phases;
}
