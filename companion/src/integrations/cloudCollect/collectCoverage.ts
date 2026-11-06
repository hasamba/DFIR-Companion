// What a collection can and did cover (#2312). Pure.
//
//  - The PRE-CHECK, before the analyst confirms: per source, the part of the window outside the
//    source's retention (nothing there can come back), the "off by default" warnings, and the newest
//    part of the window that may still be arriving (the ingestion-delay overlap).
//  - The DISCLOSURE, after a run: per source, the actual acquired cutoff — the newest time the
//    results are settled up to — measured from when the window's last part was read, minus the
//    overlap, and never later than a cutoff the provider itself stated (a GCS sink's last batch).
//
// The overlaps are DEFAULTS, not completeness guarantees: a cloud can deliver a record later still.

import { describeDuration, leaves } from "./collectSplit.js";
import type {
  CollectSourceInfo,
  CollectWindow,
  RetentionSpec,
  SourceCoverage,
  SubWindowStatus,
} from "./collectTypes.js";

const DAY_MS = 86_400_000;
/** The longest page note kept (#2314). */
export const NOTE_MAX = 600;

/** A sub-window with one more page's disclosure: its note (once) and unverified completeness. Pure. */
export function withPageDisclosure(
  sw: SubWindowStatus,
  page: { note?: string; unverified?: boolean },
): SubWindowStatus {
  const notes = page.note && !sw.notes?.includes(page.note) ? [...(sw.notes ?? []), page.note] : sw.notes;
  return {
    ...sw,
    ...(notes ? { notes } : {}),
    ...(page.unverified || sw.unverified ? { unverified: true } : {}),
  };
}

/** The notes a source's sub-windows disclosed, each once. */
function pageNotes(subWindows: readonly SubWindowStatus[], source: string): string[] {
  return [...new Set(subWindows.filter((s) => s.source === source).flatMap((s) => s.notes ?? []))];
}

const iso = (ms: number): string => new Date(ms).toISOString();

/** The overlap a source discloses with: the collection's own choice, else the source's default. */
export function overlapFor(source: CollectSourceInfo | undefined, chosen?: Record<string, number>): number {
  const pick = source ? chosen?.[source.id] : undefined;
  return Math.max(0, pick ?? source?.overlapMs ?? 0);
}

export interface RetentionCheck {
  /** Before this, nothing can come back under any licence. */
  outOfRetention?: CollectWindow;
  /** Between this and `outOfRetention`, it depends on the licence or configuration. */
  mayBeOutOfRetention?: CollectWindow;
  warnings: string[];
}

function retentionWarnings(spec: RetentionSpec, window: CollectWindow, nowMs: number): RetentionCheck {
  const start = Date.parse(window.start);
  const end = Date.parse(window.end);
  const hardEdge = nowMs - (spec.maxDays ?? spec.minDays) * DAY_MS;
  const softEdge = nowMs - spec.minDays * DAY_MS;
  const out: RetentionCheck = { warnings: [] };
  const days = spec.maxDays ? `${spec.minDays}–${spec.maxDays}` : `${spec.minDays}`;
  if (start < hardEdge) {
    out.outOfRetention = { start: window.start, end: iso(Math.min(end, hardEdge)) };
    out.warnings.push(
      `Outside retention (${days} days): nothing before ${iso(hardEdge)} can come back. ${spec.note}`,
    );
  }
  if (spec.maxDays && start < softEdge && end > hardEdge) {
    out.mayBeOutOfRetention = { start: iso(Math.max(start, hardEdge)), end: iso(Math.min(end, softEdge)) };
    out.warnings.push(`Before ${iso(softEdge)} may be outside retention (${days} days). ${spec.note}`);
  }
  if (spec.offByDefault) out.warnings.push(spec.offByDefault);
  return out;
}

export interface SourcePrecheck extends RetentionCheck {
  source: string;
  label: string;
  overlapMs: number;
}

/** The pre-check for one source and window. */
export function precheckSource(
  source: CollectSourceInfo,
  window: CollectWindow,
  nowMs: number,
  chosenOverlap?: Record<string, number>,
): SourcePrecheck {
  const overlapMs = overlapFor(source, chosenOverlap);
  const retention = source.retention
    ? retentionWarnings(source.retention, window, nowMs)
    : { warnings: [] as string[] };
  const warnings = [...retention.warnings, ...(source.notice ? [source.notice] : [])];
  const settled = nowMs - overlapMs;
  if (overlapMs > 0 && Date.parse(window.end) > settled)
    warnings.push(
      `Events after ${iso(settled)} may still be arriving (ingestion delay, about ` +
        `${describeDuration(overlapMs)}); the result discloses the cutoff it actually reached.`,
    );
  return { ...retention, warnings, source: source.id, label: source.label, overlapMs };
}

function cutoffOf(endLeaves: readonly SubWindowStatus[], end: number, overlapMs: number): number | undefined {
  let cutoff = end;
  for (const leaf of endLeaves) {
    // An item the cloud refused leaves the window unsettled, however much else came back (#2313).
    if (leaf.state !== "done" || !leaf.firstRetrievedAt || leaf.skipped) return undefined;
    cutoff = Math.min(cutoff, Date.parse(leaf.firstRetrievedAt) - overlapMs);
    if (leaf.acquiredUntil) cutoff = Math.min(cutoff, Date.parse(leaf.acquiredUntil));
  }
  return endLeaves.length ? cutoff : undefined;
}

/** The items of a source the cloud refused (#2313), as one note; null when there were none. */
export function skippedNote(sourceLeaves: readonly SubWindowStatus[]): string | null {
  const count = sourceLeaves.reduce((n, s) => n + (s.skipped ?? 0), 0);
  if (!count) return null;
  const listed = sourceLeaves.flatMap((s) => s.skippedItems ?? []);
  const more = count > listed.length ? `; ${count - listed.length} more` : "";
  return (
    `${count} item(s) could not be read and were skipped: ${listed.join("; ")}${more}. ` +
    "Each one is a skip line in the collection's manifest.jsonl; Resume retries them."
  );
}

/** Per source: the acquired cutoff and what the analyst must know about it. */
export function sourceCoverage(
  subWindows: readonly SubWindowStatus[],
  sources: readonly CollectSourceInfo[],
  input: {
    sources: readonly string[];
    window: CollectWindow;
    overlapMs?: Record<string, number>;
    startedAt: string;
  },
): SourceCoverage[] {
  const end = Date.parse(input.window.end);
  const tree = leaves(subWindows);
  return input.sources.map((id) => {
    const info = sources.find((s) => s.id === id);
    const overlapMs = overlapFor(info, input.overlapMs);
    const endLeaves = tree.filter((s) => s.source === id && Date.parse(s.window.end) === end);
    const cutoff = cutoffOf(endLeaves, end, overlapMs);
    const notes: string[] = [];
    if (cutoff === undefined)
      notes.push("The end of the window was not collected — see the missing windows.");
    else if (cutoff < end)
      notes.push(
        `Settled up to ${iso(cutoff)} only: later events may still have been arriving. Collect again ` +
          "from that time to pick them up — overlapping windows are safe, duplicates are removed.",
      );
    const skipped = skippedNote(tree.filter((s) => s.source === id));
    if (skipped) notes.push(skipped);
    if (info?.notice) notes.push(info.notice);
    notes.push(...pageNotes(subWindows, id));
    if (info?.retention) {
      const check = retentionWarnings(info.retention, input.window, Date.parse(input.startedAt));
      notes.push(...check.warnings);
    }
    return {
      source: id,
      requested: input.window,
      overlapMs,
      ...(cutoff !== undefined ? { acquiredCutoff: iso(cutoff) } : {}),
      notes,
    };
  });
}
