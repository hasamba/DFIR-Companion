import type { ForensicEvent, Severity } from "./stateTypes.js";
import { byEventTime } from "./forensicSort.js";
import { tacticForTechniques, type IrisTactic } from "../integrations/iris/mitreTactics.js";

// Attacker session / story reconstruction (#229). The raw forensic timeline is a flat
// chronological stream of events across every host; an analyst reading it has to mentally
// re-thread the attacker's story per host ("they did this on DC01, went quiet, then came
// back and did that"). This segments the timeline into labeled SESSIONS — a contiguous run
// of events on one host with no gap larger than the threshold — so the UI/report can show
// the attacker's per-host story as discrete, titled chapters instead of a wall of rows.
//
// Segmentation axis is (host, time-gap): events on DIFFERENT known hosts never join the same
// session even when back-to-back, and a gap larger than `gapSeconds` on the SAME host
// starts a new session. Each session is summarized with its dominant ATT&CK tactic (most
// common technique across its events) and an auto-generated human-readable label. Pure,
// deterministic, NO AI call — a host-partitioned time-gap algorithm.
//
// Events with no `asset` are collected under the explicit UNKNOWN_HOST bucket rather than
// dropped or given a blank host. Not every importer fills `asset`, so this bucket can hold
// events that really came from several different machines — it is NOT a claim that they share
// a host, only that the host is unrecorded. It is named rather than empty precisely so the UI
// and the report say "we don't know" instead of rendering a blank that reads like a real host.

// The pseudo-host for events whose `asset` is missing or empty. See the note above: sessions in
// this bucket group by time alone, so treat their host as unknown, not as one machine.
export const UNKNOWN_HOST = "(unknown host)";

export interface Session {
  id: string;                    // stable per-timeline id: "session-1", "session-2", …
  host: string;                   // the asset this session occurred on, or UNKNOWN_HOST when unrecorded
  startTime: string;              // first event's timestamp in the session
  endTime: string;                // last event's timestamp (uses endTimestamp for aggregated rows)
  eventCount: number;             // events in the session (sums aggregated `count` where present)
  severityRange: Severity[];      // distinct severities observed, worst-first
  dominantTactic: IrisTactic | undefined;  // most common ATT&CK tactic across the session's events
  label: string;                  // auto-generated: "{dominantTactic} {host} → {startTime}-{endTime}, {eventCount} events"
}

export interface SessionOptions {
  // Events on the same host more than this many seconds apart start a new session. Default 5 minutes.
  gapSeconds?: number;
}

export const DEFAULT_SESSION_GAP_SECONDS = 300;

const SEV_RANK: Record<Severity, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };

// Kill-chain order — used only to tie-break the dominant-tactic vote deterministically (the
// earliest stage represented wins a tie, so a session reads as the stage it leads with).
const CHAIN_ORDER: IrisTactic[] = [
  "Initial Access", "Execution", "Persistence", "Privilege Escalation",
  "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
  "Collection", "Command and Control", "Exfiltration", "Impact",
];

// The most common ATT&CK tactic across the session's events, with ties broken toward the
// earliest kill-chain stage (so the session reads as the stage it leads with). Returns
// undefined when no event mapped to a tactic
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
// else its `timestamp`. Used so a session's window covers aggregated rows correctly.
function eventEndMs(e: ForensicEvent): number {
  const end = e.endTimestamp ? Date.parse(e.endTimestamp) : NaN;
  return Number.isNaN(end) ? Date.parse(e.timestamp) : end;
}

function summarizeSession(index: number, host: string, events: ForensicEvent[]): Session {
  const tactic = dominantTactic(events);
  const sevSet = new Set<Severity>();
  let count = 0;
  let endTs = events[0].endTimestamp || events[0].timestamp;
  let endMs = eventEndMs(events[0]);
  for (const e of events) {
    sevSet.add(e.severity);
    count += e.count && e.count > 1 ? e.count : 1;
    const ms = eventEndMs(e);
    if (ms > endMs) { endMs = ms; endTs = e.endTimestamp || e.timestamp; }
  }
  const severityRange = [...sevSet].sort((a, b) => SEV_RANK[a] - SEV_RANK[b]);
  const start = events[0].timestamp;
  const label = `${tactic ?? "Activity"} ${host} → ${start}-${endTs}, ${count} events`;
  return {
    id: `session-${index + 1}`,
    host,
    startTime: start,
    endTime: endTs,
    eventCount: count,
    severityRange,
    dominantTactic: tactic,
    label,
  };
}

// Segment a forensic timeline into per-host attacker sessions. Only DATED events participate
// (an unparseable/empty timestamp has no position on the time axis); events without an `asset`
// are grouped under UNKNOWN_HOST so they still appear (never silently dropped). The returned
// sessions are ordered chronologically by start time; ties break by host for determinism. An
// empty or fully-undated timeline yields no sessions.
export function segmentSessions(events: ForensicEvent[], opts: SessionOptions = {}): Session[] {
  const gapMs = Math.max(0, (opts.gapSeconds ?? DEFAULT_SESSION_GAP_SECONDS) * 1000);
  const dated = events
    .filter((e) => !Number.isNaN(Date.parse(e.timestamp)))
    .sort(byEventTime);
  if (dated.length === 0) return [];

  // Partition by host first so a back-to-back cross-host run never joins the same session.
  const byHost = new Map<string, ForensicEvent[]>();
  for (const e of dated) {
    // `||` not `??`: an importer that writes an empty-string asset means the same thing as one
    // that omits the field, and both must land in the same bucket rather than a blank-named host.
    const host = e.asset || UNKNOWN_HOST;
    (byHost.get(host) ?? byHost.set(host, []).get(host)!).push(e);
  }

  const sessions: Session[] = [];
  for (const [host, hostEvents] of byHost) {
    // hostEvents is already sorted (dated was sorted; partition preserves order).
    let current: ForensicEvent[] = [hostEvents[0]];
    let prevEndMs = eventEndMs(hostEvents[0]);
    for (let i = 1; i < hostEvents.length; i++) {
      const e = hostEvents[i];
      const startMs = Date.parse(e.timestamp);
      // Gap is measured from the END of the running session so a long aggregated event doesn't
      // spuriously split from a follow-on that overlaps it.
      if (startMs - prevEndMs > gapMs) {
        sessions.push(summarizeSession(sessions.length, host, current));
        current = [e];
        prevEndMs = eventEndMs(e);
      } else {
        current.push(e);
        prevEndMs = Math.max(prevEndMs, eventEndMs(e));
      }
    }
    sessions.push(summarizeSession(sessions.length, host, current));
  }

  // Sessions were appended in host-map iteration order; re-sort chronologically by start time so
  // the caller gets a single coherent attack story. Session ids were assigned in that final
  // order, so re-number after the sort to keep them stable and human-readable.
  sessions.sort((a, b) => {
    const t = Date.parse(a.startTime) - Date.parse(b.startTime);
    return t !== 0 ? t : (a.host < b.host ? -1 : a.host > b.host ? 1 : 0);
  });
  for (let i = 0; i < sessions.length; i++) {
    sessions[i] = { ...sessions[i], id: `session-${i + 1}` };
  }
  return sessions;
}