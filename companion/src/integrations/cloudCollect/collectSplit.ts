// The split tree of a collection (#2312). Pure: no I/O, no clock.
//
// A sub-window whose results the cloud capped (Graph `isRecordCountLimitExceeded`, a page cap) is
// re-collected in full by its children — two halves while each half stays at or above the source's
// minimum window; at the minimum, one child per partition value (region, logName, record type);
// with neither left, it is given up as "incomplete — too dense" and the collection moves on.
//
// Why the WHOLE window again: the capped pages say nothing about which part of the window they
// cover, so re-collecting only "the rest" would leave a gap. The capped pages stay evidence and are
// imported; the #2301 dedup absorbs the records the children return a second time.
//
// The decision is a manifest line (`split`), appended before the first child is fetched, so replay
// rebuilds the same tree. A crash after the capped page but before that line leaves the node
// `capped` (derived from the page line itself) and the next run decides it again — same ids.

import { createHash } from "node:crypto";
import type {
  CollectSourceInfo,
  CollectWindow,
  ManifestEntry,
  ManifestSplit,
  SubWindowStatus,
} from "./collectTypes.js";

/** The default minimum window when a source declares none: one second. */
export const DEFAULT_MIN_WINDOW_MS = 1000;

/** A safety stop: one source never grows past this many sub-windows in one collection. */
export const MAX_SUBWINDOWS_PER_SOURCE = 4096;

export type SplitDecision = Omit<ManifestSplit, "type" | "at">;

function ms(iso: string): number {
  return Date.parse(iso);
}

function iso(value: number): string {
  return new Date(value).toISOString();
}

/** A duration for a reason line: "1 min", "1 s", "250 ms". */
export function describeDuration(durationMs: number): string {
  if (durationMs >= 3_600_000 && durationMs % 3_600_000 === 0) return `${durationMs / 3_600_000} h`;
  if (durationMs >= 60_000 && durationMs % 60_000 === 0) return `${durationMs / 60_000} min`;
  if (durationMs >= 1000 && durationMs % 1000 === 0) return `${durationMs / 1000} s`;
  return `${durationMs} ms`;
}

/** The midpoint, on a whole second when the window allows it, so filters stay readable. */
function midpoint(window: CollectWindow): number {
  const start = ms(window.start);
  const duration = ms(window.end) - start;
  if (duration >= 2000) return start + Math.floor(duration / 2000) * 1000;
  return start + Math.floor(duration / 2);
}

/**
 * A partition child's id: the sibling index plus a digest of the FULL value, so two values that
 * look alike once sanitised ("projects/a", "projects_a") or share a long prefix never collide. The
 * readable value lives in the child's `partition`, for display only.
 */
function partitionChildId(parent: string, key: string, index: number, value: string): string {
  const digest = createHash("sha256").update(value).digest("hex").slice(0, 12);
  return `${parent}.${key}#${index}-${digest}`;
}

function assertUniqueIds(ids: readonly string[], taken: ReadonlySet<string> = new Set()): void {
  const seen = new Set(taken);
  for (const id of ids) {
    if (seen.has(id)) throw new Error(`duplicate sub-window id in a split: ${id}`);
    seen.add(id);
  }
}

/** The reason a too-dense window is missing. */
export function tooDenseReason(sw: Pick<SubWindowStatus, "window" | "partition">): string {
  const duration = describeDuration(ms(sw.window.end) - ms(sw.window.start));
  const slice = sw.partition
    ? ` (${Object.entries(sw.partition)
        .map(([k, v]) => `${k}=${v}`)
        .join(", ")})`
    : "";
  return (
    `incomplete — too dense: the cloud capped even a ${duration} window${slice}, ` +
    "so some of its events were not returned"
  );
}

/** The split decision before its ids are checked. Pure. */
function decideRaw(
  sw: SubWindowStatus,
  source: CollectSourceInfo | undefined,
  partitionValues: readonly string[] | undefined,
  nodesOfSource: number,
): SplitDecision {
  const minWindow = Math.max(1, source?.minWindowMs ?? DEFAULT_MIN_WINDOW_MS);
  const duration = ms(sw.window.end) - ms(sw.window.start);
  const room = nodesOfSource + 2 <= MAX_SUBWINDOWS_PER_SOURCE;
  const base = { subWindowId: sw.id };
  if (room && duration >= 2 * minWindow) {
    const mid = iso(midpoint(sw.window));
    const halves: CollectWindow[] = [
      { start: sw.window.start, end: mid },
      { start: mid, end: sw.window.end },
    ];
    return {
      ...base,
      mode: "time",
      children: halves.map((window, i) => ({
        id: `${sw.id}.${i}`,
        window,
        ...(sw.partition ? { partition: sw.partition } : {}),
      })),
    };
  }
  const key = source?.partition?.key;
  const values = [...new Set(partitionValues ?? [])];
  if (
    key &&
    !sw.partition &&
    values.length > 1 &&
    nodesOfSource + values.length <= MAX_SUBWINDOWS_PER_SOURCE
  ) {
    return {
      ...base,
      mode: "partition",
      children: values.map((value, i) => ({
        id: partitionChildId(sw.id, key, i, value),
        window: sw.window,
        partition: { [key]: value },
      })),
    };
  }
  return { ...base, mode: "too-dense", children: [] };
}

/**
 * How to split a capped sub-window. `partitionValues` are the source's partition values (from the
 * session when it has them, else the source's own list). Throws on a duplicate child id. Pure.
 */
export function decideSplit(
  sw: SubWindowStatus,
  source: CollectSourceInfo | undefined,
  partitionValues: readonly string[] | undefined,
  nodesOfSource: number,
): SplitDecision {
  const decision = decideRaw(sw, source, partitionValues, nodesOfSource);
  assertUniqueIds(decision.children.map((c) => c.id));
  return decision;
}

function childOf(parent: SubWindowStatus, child: ManifestSplit["children"][number]): SubWindowStatus {
  return {
    id: child.id,
    source: parent.source,
    window: child.window,
    state: "pending",
    pages: 0,
    records: 0,
    restarts: 0,
    parent: parent.id,
    ...(child.partition ? { partition: child.partition } : {}),
  };
}

/** The tree after a split line: the parent settled, its children right after it. Pure. */
export function applySplit(subWindows: readonly SubWindowStatus[], line: SplitDecision): SubWindowStatus[] {
  const index = subWindows.findIndex((s) => s.id === line.subWindowId);
  if (index < 0) return [...subWindows];
  const parent = subWindows[index];
  const settled: SubWindowStatus =
    line.mode === "too-dense"
      ? { ...parent, state: "incomplete", pageToken: undefined, reason: tooDenseReason(parent) }
      : { ...parent, state: "split", pageToken: undefined, reason: undefined };
  // Applied once: a parent already split keeps its children (an idempotent replay of the line).
  if (parent.state === "split") return [...subWindows];
  // A child id already in the tree would merge two windows' results: refused, never merged.
  assertUniqueIds(
    line.children.map((c) => c.id),
    new Set(subWindows.map((s) => s.id)),
  );
  const children = line.children.map((c) => childOf(parent, c));
  return [...subWindows.slice(0, index), settled, ...children, ...subWindows.slice(index + 1)];
}

/** Sub-windows re-collected by children: their own pages and restarts no longer matter. */
export function splitParents(entries: readonly ManifestEntry[]): Set<string> {
  return new Set(
    entries
      .filter((e): e is ManifestSplit => e.type === "split" && e.mode !== "too-dense")
      .map((e) => e.subWindowId),
  );
}

/** The leaves: what the result is judged on (a split parent is covered by its children). */
export function leaves(subWindows: readonly SubWindowStatus[]): SubWindowStatus[] {
  return subWindows.filter((s) => s.state !== "split");
}

/** The next sub-window the network stage works on: depth-first, earliest first. */
export function nextWork(subWindows: readonly SubWindowStatus[]): SubWindowStatus | undefined {
  return subWindows.find((s) => s.state === "pending" || s.state === "capped");
}

/** Planned query submissions for a tree with `leafCount` leaves: 2N−1 per source. */
export function splitQueryEstimate(leafCount: number): number {
  return Math.max(1, 2 * leafCount - 1);
}
