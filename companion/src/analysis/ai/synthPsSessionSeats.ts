import { SEVERITY_RANK, type ForensicEvent } from "../stateTypes.js";
import { isCollectorRow } from "../scriptBlockCommands.js";
import { psSessionIdOf } from "../canonicalPowerShell.js";
import type { CommandSeat } from "./synthCommandSeats.js";

/**
 * Reserved synthesis-prompt seats for the rest of a PowerShell session already graded High (#2078,
 * design B1).
 *
 * An implant session's later steps (a Run-key write, domain discovery, `net use` to a cloud drive,
 * the cleanup) are logged as Medium/Low script-block and pipeline rows of the SAME PowerShell
 * process the AI already reports. The #1622 command seats never reach them: those need a process
 * command line, and their session is a host + time proxy padded 15 min around each anchor. This
 * module uses the session the import recorded instead (canonical.powershell, psSession.ts) and
 * gives its other rows a bounded, reserved share of the SAME prompt cap.
 *
 * WHAT IS READ. Only the scoped forensic timeline the prompt is built from, before burst collapsing:
 * never the super-timeline (CLAUDE.md §7). Info rows are never candidates.
 *
 * A SESSION is the rows of one host (alias-resolved) and one recorded session id, cut wherever two
 * consecutive rows are more than PS_SESSION_GAP_MS apart: the id is a process id, and Windows
 * recycles them. It QUALIFIES when one of its rows is Critical/High. The collector's own rows
 * (isCollectorRow) neither open a session nor take a seat.
 *
 * A CANDIDATE is a Low/Medium row of a qualifying session. At most PS_SESSION_PER_SESSION_MAX per
 * session, identical text once, nearest in time to one of the session's High rows first, then Medium
 * before Low, then earliest, then id. Sessions share the seats round-robin. Rows imported before
 * #2078 carry no session id and are never candidates, so an old case selects exactly as before.
 */

/** Hard ceiling on reserved session seats per prompt. */
export const PS_SESSION_SEAT_MAX = 50;
/** Share of the prompt cap reserved for session seats (before the ceiling). */
export const PS_SESSION_SEAT_FRACTION = 0.1;
/** Most rows one session may seat. */
export const PS_SESSION_PER_SESSION_MAX = 25;
/** A gap this long between two rows of one host + session id starts a new session (pid reuse). */
export const PS_SESSION_GAP_MS = 12 * 60 * 60 * 1000;

/** Seats reserved for PowerShell session rows at a prompt cap of `max`: at least 1, at most 50. */
export function psSessionSeatCap(max: number): number {
  if (!(max > 0)) return 0;
  return Math.min(PS_SESSION_SEAT_MAX, Math.max(1, Math.floor(max * PS_SESSION_SEAT_FRACTION)));
}

export interface PsSessionSeatInput {
  /** The scoped forensic timeline, uncollapsed. */
  events: readonly ForensicEvent[];
  /** Canonical host for a raw asset spelling (alias-resolved when an index exists). */
  hostOf: (raw: string) => string;
}

interface Member {
  e: ForensicEvent;
  time: number;
}

const isAnchor = (e: ForensicEvent): boolean => e.severity === "Critical" || e.severity === "High";

/** Candidate rows for the reserved session seats, in seat order. Pure. */
export function psSessionSeats(input: PsSessionSeatInput): CommandSeat[] {
  const queues = sessionsOf(input)
    .filter((members) => members.some((m) => isAnchor(m.e)))
    .map(rankSession)
    .filter((q) => q.length > 0);
  return roundRobin(queues).map((e) => ({ event: e, shadowedBy: [] }));
}

/** Every session: rows grouped by host + session id, split at long gaps, each in time order. */
function sessionsOf(input: PsSessionSeatInput): Member[][] {
  const groups = new Map<string, Member[]>();
  for (const e of input.events) {
    const session = psSessionIdOf(e);
    const asset = e.asset?.trim();
    const time = Date.parse(e.timestamp);
    if (!session || !asset || !Number.isFinite(time) || isCollectorRow(e)) continue;
    const key = `${input.hostOf(asset)}\u0000${session}`;
    const list = groups.get(key) ?? [];
    list.push({ e, time });
    groups.set(key, list);
  }
  const sessions: Member[][] = [];
  for (const list of groups.values()) {
    const sorted = [...list].sort((a, b) => a.time - b.time || a.e.id.localeCompare(b.e.id));
    let current: Member[] = [];
    for (const m of sorted) {
      const last = current[current.length - 1];
      if (last && m.time - last.time > PS_SESSION_GAP_MS) {
        sessions.push(current);
        current = [];
      }
      current.push(m);
    }
    if (current.length) sessions.push(current);
  }
  return sessions;
}

function textKey(e: ForensicEvent): string {
  return (e.message || e.description).toLowerCase().replace(/\s+/g, " ").trim();
}

/** One qualifying session's candidates, ranked, deduplicated and capped. */
function rankSession(members: readonly Member[]): ForensicEvent[] {
  const anchorTimes = members.filter((m) => isAnchor(m.e)).map((m) => m.time);
  const distance = (t: number): number => Math.min(...anchorTimes.map((a) => Math.abs(a - t)));
  const ranked = members
    .filter((m) => m.e.severity === "Low" || m.e.severity === "Medium")
    .map((m) => ({ ...m, distance: distance(m.time) }))
    .sort(
      (a, b) =>
        a.distance - b.distance ||
        SEVERITY_RANK[a.e.severity] - SEVERITY_RANK[b.e.severity] ||
        a.time - b.time ||
        a.e.id.localeCompare(b.e.id),
    );
  const seen = new Set(members.filter((m) => isAnchor(m.e)).map((m) => textKey(m.e)));
  const out: ForensicEvent[] = [];
  for (const r of ranked) {
    if (out.length >= PS_SESSION_PER_SESSION_MAX) break;
    const key = textKey(r.e);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(r.e);
  }
  return out;
}

function roundRobin<T>(lists: readonly T[][]): T[] {
  const out: T[] = [];
  const longest = Math.max(0, ...lists.map((l) => l.length));
  for (let i = 0; i < longest; i++) for (const list of lists) if (i < list.length) out.push(list[i]);
  return out;
}
