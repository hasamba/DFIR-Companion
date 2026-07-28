import type { ForensicEvent, Severity } from "./stateTypes.js";
import { byEventTime } from "./forensicSort.js";
import { parseLoginEvent } from "./loginGraph.js";
import { tacticForTechniques, type IrisTactic } from "../integrations/iris/mitreTactics.js";

// Attacker session / story reconstruction (#229). The raw forensic timeline is a flat
// chronological stream of events across every host; an analyst reading it has to mentally
// re-thread the attacker's story per host ("they did this on DC01, went quiet, then came
// back and did that"). This segments the timeline into labeled SESSIONS — a contiguous run
// of events on one host with no gap larger than the threshold — so the UI/report can show
// the attacker's per-host story as discrete, titled chapters instead of a wall of rows.
//
// Segmentation axis is (host, account, time-gap, shared indicators): events on DIFFERENT known
// hosts never join the same session even when back-to-back; a gap larger than `gapSeconds` on the
// SAME host starts a new session unless the next event shares a concrete indicator with the running
// one; and a successful logon under a different account always starts a new session. Each session is
// summarized with its dominant ATT&CK tactic (most common technique across its events) and an
// auto-generated human-readable label. Pure, deterministic, NO AI call.
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
  // The account this session ran under, when a logon row inside it named one (#344). Absent when no
  // logon was observed — most sessions have no account signal at all, so this is a bonus, not a key.
  account?: string;
  // Every event id in the session, chronological. Lets the UI filter the timeline to exactly this
  // session and lets the per-session AI summary slice the same set the analyst is looking at.
  eventIds: string[];
}

export interface SessionOptions {
  // Events on the same host more than this many seconds apart start a new session. Default 5 minutes.
  gapSeconds?: number;
  // When a gap exceeds `gapSeconds` but the next event shares a concrete indicator (hash, path, IP,
  // or a decoded-payload IOC id) with the running session, allow the session to absorb it up to this
  // multiple of the gap (#344). 1 disables the grace entirely. Default 3.
  iocGraceFactor?: number;
}

export const DEFAULT_SESSION_GAP_SECONDS = 300;
export const DEFAULT_IOC_GRACE_FACTOR = 3;

// Env-derived options, so the route, the report section, and the per-session AI summary all segment
// with the SAME thresholds — a session the report calls "Session 3" must be the one the dashboard
// shows under that name. `|| DEFAULT` deliberately also catches 0 and NaN: a zero gap would make
// every event its own session and a typo'd value would silently do something arbitrary.
export function sessionEnvOptions(): Required<SessionOptions> {
  return {
    gapSeconds: Number(process.env.DFIR_SESSION_GAP_S) || DEFAULT_SESSION_GAP_SECONDS,
    iocGraceFactor: Number(process.env.DFIR_SESSION_IOC_GRACE) || DEFAULT_IOC_GRACE_FACTOR,
  };
}

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

// The account a SUCCESSFUL logon row establishes on its host (#344). There is no `account` field on
// ForensicEvent, so this reuses loginGraph's parser, which reads the deterministic description
// mapWindows() renders at import time and carries an injection guard against a CommandLine that
// merely echoes a logon string. Failed logons (4625) are deliberately ignored: a rejected logon
// never establishes a session, and treating a brute-force burst as N account changes would shatter
// exactly the run an analyst most wants to read as one block.
function accountEstablishedBy(e: ForensicEvent): string | undefined {
  const parsed = parseLoginEvent(e);
  if (!parsed || parsed.outcome !== "success") return undefined;
  return parsed.account;
}

// Concrete indicators an event carries, used to decide whether a slightly-too-large gap is really a
// break in the story or the same thread of activity resuming (#344). Deliberately CONCRETE fields
// only — a shared tactic or severity would match nearly everything and glue the whole timeline into
// one session. Values are lowercased so two tools spelling the same hash differently still match.
function iocKeys(e: ForensicEvent): string[] {
  const keys: string[] = [];
  if (e.sha256) keys.push(`sha256:${e.sha256.toLowerCase()}`);
  if (e.md5) keys.push(`md5:${e.md5.toLowerCase()}`);
  if (e.path) keys.push(`path:${e.path.toLowerCase()}`);
  if (e.srcIp) keys.push(`ip:${e.srcIp.toLowerCase()}`);
  if (e.dstIp) keys.push(`ip:${e.dstIp.toLowerCase()}`);
  for (const id of e.deobfuscated?.iocs ?? []) keys.push(`ioc:${id.toLowerCase()}`);
  return keys;
}

function summarizeSession(index: number, host: string, events: ForensicEvent[]): Session {
  const tactic = dominantTactic(events);
  const sevSet = new Set<Severity>();
  let count = 0;
  let endTs = events[0].endTimestamp || events[0].timestamp;
  let endMs = eventEndMs(events[0]);
  let account: string | undefined;
  for (const e of events) {
    sevSet.add(e.severity);
    count += e.count && e.count > 1 ? e.count : 1;
    const ms = eventEndMs(e);
    if (ms > endMs) { endMs = ms; endTs = e.endTimestamp || e.timestamp; }
    // First successful logon in the session names it; the splitter guarantees a session never spans
    // two different accounts, so there is no "last one wins" ambiguity to resolve here.
    account ??= accountEstablishedBy(e);
  }
  const severityRange = [...sevSet].sort((a, b) => SEV_RANK[a] - SEV_RANK[b]);
  const start = events[0].timestamp;
  // The account, when known, goes in the label right after the host — "who on which box" is the
  // question the label exists to answer, and it is the part an analyst scans for.
  const who = account ? `${host} (${account})` : host;
  const label = `${tactic ?? "Activity"} ${who} → ${start}-${endTs}, ${count} events`;
  return {
    id: `session-${index + 1}`,
    host,
    startTime: start,
    endTime: endTs,
    eventCount: count,
    severityRange,
    dominantTactic: tactic,
    label,
    ...(account ? { account } : {}),
    eventIds: events.map((e) => e.id),
  };
}

// Segment a forensic timeline into per-host attacker sessions. Only DATED events participate
// (an unparseable/empty timestamp has no position on the time axis); events without an `asset`
// are grouped under UNKNOWN_HOST so they still appear (never silently dropped). The returned
// sessions are ordered chronologically by start time; ties break by host for determinism. An
// empty or fully-undated timeline yields no sessions.
//
// Within a host, three things end a session (#344):
//   1. a time gap larger than `gapSeconds` — unless the next event shares a concrete indicator with
//      the running session, which buys it up to `iocGraceFactor` × the gap before it splits;
//   2. a successful logon under a DIFFERENT account than the one the session is running as — two
//      accounts active on one box in the same minute are two stories, not one;
//   3. nothing else. Severity, tactic and tool never split a session.
export function segmentSessions(events: ForensicEvent[], opts: SessionOptions = {}): Session[] {
  const gapMs = Math.max(0, (opts.gapSeconds ?? DEFAULT_SESSION_GAP_SECONDS) * 1000);
  // Grace below 1 would make a shared indicator SHORTEN the allowed gap, which is backwards.
  const graceMs = gapMs * Math.max(1, opts.iocGraceFactor ?? DEFAULT_IOC_GRACE_FACTOR);
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
    // Indicators seen anywhere in the running session, and the account it is running as. Both are
    // rebuilt from scratch on every split so state never leaks across a session boundary.
    let seenIocs = new Set(iocKeys(hostEvents[0]));
    let account = accountEstablishedBy(hostEvents[0]);

    const startNew = (e: ForensicEvent): void => {
      sessions.push(summarizeSession(sessions.length, host, current));
      current = [e];
      prevEndMs = eventEndMs(e);
      seenIocs = new Set(iocKeys(e));
      account = accountEstablishedBy(e);
    };

    for (let i = 1; i < hostEvents.length; i++) {
      const e = hostEvents[i];
      const startMs = Date.parse(e.timestamp);
      const keys = iocKeys(e);

      // (2) An account change ends the session outright, no matter how tight the timing — the whole
      // point is that two accounts on one host in the same minute are two stories. Checked BEFORE
      // the gap so it cannot be masked by the IOC grace below.
      const established = accountEstablishedBy(e);
      if (established && account && established !== account) { startNew(e); continue; }

      // (1) Gap is measured from the END of the running session so a long aggregated event doesn't
      // spuriously split from a follow-on that overlaps it. A shared concrete indicator means the
      // same thread of activity is resuming rather than a new one starting, so it earns the wider
      // grace window — but only up to it, or a single recurring path would fuse the whole timeline.
      const gap = startMs - prevEndMs;
      const shares = keys.some((k) => seenIocs.has(k));
      if (gap > (shares ? graceMs : gapMs)) { startNew(e); continue; }

      current.push(e);
      prevEndMs = Math.max(prevEndMs, eventEndMs(e));
      for (const k of keys) seenIocs.add(k);
      account ??= established;
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