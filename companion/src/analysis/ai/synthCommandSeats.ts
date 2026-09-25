import { canonicalProcess } from "../canonicalEvent.js";
import { SEVERITY_RANK, type ForensicEvent, type InvestigationState } from "../stateTypes.js";
import { splitSessions } from "./sessionCommandNotes.js";

/**
 * Reserved synthesis-prompt seats for quiet session commands (#1622).
 *
 * The prompt holds at most DFIR_AI_SYNTH_MAX_EVENTS rows. On a detection-heavy case the Critical/High
 * anchors and the context fills can use every seat, so a quiet discovery or staging command graded Low
 * or Medium (`net view /all`, `tasklist /v`, `subst E: C:\e`) never reaches the model and the model
 * cannot name it. This module picks the rows that get a small reserved share of the SAME cap.
 *
 * WHAT IS READ. Only the scoped forensic timeline the prompt is built from, before burst collapsing
 * and before promoted rows are pinned — never the super-timeline (CLAUDE.md §7).
 *
 * THE SESSION — a pre-synthesis PROXY for #1594's attack session. #1594 builds sessions from the rows
 * that graded findings cite, after synthesis. Before synthesis there may be no findings yet, so here
 * the anchor times are every Critical/High row plus every row a live (not dismissed, not build-
 * baseline) Medium-or-higher finding from an earlier run cites. The split and padding are #1594's own
 * (`splitSessions`): per host, cut at gaps over 2 h, widen each cluster by 15 min.
 *
 * A CANDIDATE is a row graded Low or Medium, dated, on a host, inside a session on its own host, that
 * carries a process command line. One per host and command line (lowercased, whitespace collapsed);
 * a command an anchor on the same host already shows takes no seat.
 *
 * ORDER. Round-robin across hosts, so one busy host cannot use every seat. Within a host: nearest in
 * time to an anchor on that host first, then Medium before Low, then earliest, then id. The nearest
 * instance of a repeated command is the one kept.
 */

/** Hard ceiling on reserved command seats per prompt. */
export const COMMAND_SEAT_MAX = 40;
/** Share of the prompt cap reserved for command seats (before the ceiling). */
export const COMMAND_SEAT_FRACTION = 0.1;

/** Seats reserved for session commands at a prompt cap of `max`: at least 1, at most 40. */
export function commandSeatCap(max: number): number {
  if (!(max > 0)) return 0;
  return Math.min(COMMAND_SEAT_MAX, Math.max(1, Math.floor(max * COMMAND_SEAT_FRACTION)));
}

const MEDIUM_RANK = SEVERITY_RANK.Medium;

function isAnchorSeverity(e: ForensicEvent): boolean {
  return e.severity === "Critical" || e.severity === "High";
}

function timeOf(e: ForensicEvent): number {
  const t = Date.parse(e.timestamp);
  return Number.isFinite(t) ? t : NaN;
}

/** The row's process command line, trimmed; the legacy field when the canonical one is empty. */
export function commandLineOf(e: ForensicEvent): string {
  const canonical = (canonicalProcess(e)?.commandLine ?? "").trim();
  return canonical || (e.commandLine ?? "").trim();
}

function commandKey(command: string): string {
  return command.toLowerCase().replace(/\s+/g, " ").trim();
}

/**
 * Ids of the rows that live Medium-or-higher findings from an earlier run cite (forward links and
 * back-links) — the same anchor set #1594 uses, carried into the next prompt.
 */
export function findingSessionRowIds(state: InvestigationState): Set<string> {
  const live = state.findings.filter(
    (f) => f.status !== "dismissed" && !f.buildBaseline && SEVERITY_RANK[f.severity] <= MEDIUM_RANK,
  );
  const ids = new Set<string>();
  if (!live.length) return ids;
  const liveIds = new Set(live.map((f) => f.id));
  for (const f of live) for (const id of f.relatedEventIds ?? []) ids.add(id);
  for (const e of state.forensicTimeline)
    if (e.relatedFindingIds.some((id) => liveIds.has(id))) ids.add(e.id);
  return ids;
}

export interface CommandSeatInput {
  /** The scoped forensic timeline, uncollapsed (pinned rows and every burst member included). */
  events: readonly ForensicEvent[];
  /** Canonical host for a raw asset spelling (alias-resolved when an index exists). */
  hostOf: (raw: string) => string;
  /** Rows cited by live Medium+ findings from an earlier run; they add anchor times. */
  findingRowIds?: ReadonlySet<string>;
}

interface Ranked {
  e: ForensicEvent;
  key: string;
  distance: number;
  sevRank: number;
  time: number;
}

/** Index of the first entry >= target in an ascending list. */
function lowerBound(list: readonly number[], target: number): number {
  let lo = 0;
  let hi = list.length;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (list[mid] < target) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

function nearestDistance(sorted: readonly number[], t: number): number {
  const i = lowerBound(sorted, t);
  const after = i < sorted.length ? sorted[i] - t : Infinity;
  const before = i > 0 ? t - sorted[i - 1] : Infinity;
  return Math.min(after, before);
}

/** Candidate rows for the reserved command seats, in seat order. Pure. */
export function sessionCommandSeats(input: CommandSeatInput): ForensicEvent[] {
  const { anchorTimes, anchorKeys } = collectAnchors(input);
  if (!anchorTimes.size) return [];
  const windowsByHost = new Map([...anchorTimes].map(([h, times]) => [h, splitSessions(times)] as const));

  const perHost = new Map<string, Ranked[]>();
  for (const e of input.events) {
    if (e.severity !== "Low" && e.severity !== "Medium") continue;
    const asset = e.asset?.trim();
    const time = timeOf(e);
    if (!asset || Number.isNaN(time)) continue;
    const host = input.hostOf(asset);
    const windows = windowsByHost.get(host);
    if (!windows?.some(([s, end]) => time >= s && time <= end)) continue;
    const command = commandLineOf(e);
    if (!command) continue;
    const key = commandKey(command);
    if (anchorKeys.get(host)?.has(key)) continue;
    const list = perHost.get(host) ?? [];
    list.push({
      e,
      key,
      distance: nearestDistance(anchorTimes.get(host) ?? [], time),
      sevRank: SEVERITY_RANK[e.severity],
      time,
    });
    perHost.set(host, list);
  }

  const queues = [...perHost.entries()].map(([host, list]) => ({ host, list: rankAndDedupe(list) }));
  queues.sort((a, b) => a.list[0].distance - b.list[0].distance || a.host.localeCompare(b.host));
  return roundRobin(queues.map((q) => q.list.map((r) => r.e)));
}

function collectAnchors(input: CommandSeatInput): {
  anchorTimes: Map<string, number[]>;
  anchorKeys: Map<string, Set<string>>;
} {
  const anchorTimes = new Map<string, number[]>();
  const anchorKeys = new Map<string, Set<string>>();
  for (const e of input.events) {
    const byFinding = input.findingRowIds?.has(e.id) ?? false;
    if (!isAnchorSeverity(e) && !byFinding) continue;
    const asset = e.asset?.trim();
    const time = timeOf(e);
    if (!asset || Number.isNaN(time)) continue;
    const host = input.hostOf(asset);
    const times = anchorTimes.get(host);
    if (times) times.push(time);
    else anchorTimes.set(host, [time]);
    // Only a Critical/High row is certain to be on the prompt as an anchor; a finding-cited Low row
    // is not, so it must not suppress its own command.
    if (!isAnchorSeverity(e)) continue;
    const command = commandLineOf(e);
    if (!command) continue;
    const keys = anchorKeys.get(host) ?? new Set<string>();
    keys.add(commandKey(command));
    anchorKeys.set(host, keys);
  }
  for (const times of anchorTimes.values()) times.sort((x, y) => x - y);
  return { anchorTimes, anchorKeys };
}

function rankAndDedupe(list: Ranked[]): Ranked[] {
  const sorted = [...list].sort(
    (a, b) =>
      a.distance - b.distance || a.sevRank - b.sevRank || a.time - b.time || a.e.id.localeCompare(b.e.id),
  );
  const seen = new Set<string>();
  return sorted.filter((r) => (seen.has(r.key) ? false : (seen.add(r.key), true)));
}

function roundRobin(lists: readonly ForensicEvent[][]): ForensicEvent[] {
  const out: ForensicEvent[] = [];
  const longest = Math.max(0, ...lists.map((l) => l.length));
  for (let i = 0; i < longest; i++) for (const list of lists) if (i < list.length) out.push(list[i]);
  return out;
}
