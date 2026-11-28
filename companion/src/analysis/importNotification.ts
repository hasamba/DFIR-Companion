import type { NotificationEvent } from "./notifications.js";
import type { TimelineDiff } from "./timelineDiff.js";

// "Import finished" notifications (#2978). An analyst who started a long import — a Velociraptor
// collection, a cloud collection, a drop-folder batch, a big upload — is told on their channels when
// it ends, with what it brought in, instead of watching the dashboard.
//
// EACH IMPORT PATH REPORTS ITS OWN OUTCOME. A job row's status is not the import's result (a
// Velociraptor collect releases its slot with finish() even when the collect failed), and the case's
// last-import record is not this import's numbers (a multi-artifact import records one per artifact,
// and the next import can overwrite it before anyone reads it). So every path builds an ImportOutcome
// at the point where it holds its own settled diff or tally, and this module only formats it.
//
// UNKNOWN IS NOT ZERO. A path that cannot count what it added leaves `counts` out, and the message
// says the counts are not available rather than claiming nothing arrived.
//
// PURE: no I/O. The caller dispatches through the case notifier (composition/caseNotifier.ts).

/** What one import added, read from its POST-tagger, post-demote settle. */
export interface ImportCounts {
  /** Events this import added to the forensic timeline. */
  added: number;
  /** Of those, how many are graded High or Critical. */
  highCritical: number;
  /** Rows the super-timeline retained from this import, when the path knows. */
  superAdded?: number;
}

export interface ImportFailedItem {
  name: string;
  reason: string;
}

export interface ImportOutcome {
  caseId: string;
  /** What the analyst launched: a file name, "velociraptor: Best Practice", "drop import (3 files)". */
  source: string;
  /** False when the import as a whole failed. A partial import is ok with `failed` items. */
  ok: boolean;
  counts?: ImportCounts;
  /** How many files or artifacts the import covered, when that is more than one thing. */
  files?: number;
  /** Items that failed inside an import that otherwise finished. */
  failed?: readonly ImportFailedItem[];
  /** Why the whole import failed (ok: false). */
  reason?: string;
  /** The failure can be retried from the Jobs list. */
  retryable?: boolean;
}

const FAILED_LINES_MAX = 10;
const HIGH_CRITICAL = new Set(["High", "Critical"]);

/**
 * Counts from a settled import's diff — the full diff, so the High/Critical count is never capped. A
 * case with no super-timeline store (`superTimelineAvailable: false`) has no super-timeline count:
 * its zero means "no store", not "nothing added" (#3042).
 */
export function countsFromSettled(settled: {
  timelineDiff: Pick<TimelineDiff, "added">;
  superTimelineAddedCount?: number;
  superTimelineAvailable?: boolean;
}): ImportCounts {
  const added = settled.timelineDiff.added;
  const superKnown =
    typeof settled.superTimelineAddedCount === "number" && settled.superTimelineAvailable !== false;
  return {
    added: added.length,
    highCritical: added.filter((e) => HIGH_CRITICAL.has(e.severity)).length,
    ...(superKnown ? { superAdded: settled.superTimelineAddedCount } : {}),
  };
}

/** Sum of two counts; unknown stays unknown only when both sides are unknown. */
export function addCounts(
  a: ImportCounts | undefined,
  b: ImportCounts | undefined,
): ImportCounts | undefined {
  if (!a) return b;
  if (!b) return a;
  const superAdded =
    a.superAdded === undefined && b.superAdded === undefined
      ? undefined
      : (a.superAdded ?? 0) + (b.superAdded ?? 0);
  return {
    added: a.added + b.added,
    highCritical: a.highCritical + b.highCritical,
    ...(superAdded === undefined ? {} : { superAdded }),
  };
}

const plural = (n: number, word: string): string =>
  `${n.toLocaleString("en-US")} ${word}${n === 1 ? "" : "s"}`;

function titleOf(o: ImportOutcome): string {
  if (!o.ok) return `Import failed: ${o.source}`;
  const failed = o.failed?.length ?? 0;
  return failed ? `Import finished, ${failed} failed: ${o.source}` : `Import finished: ${o.source}`;
}

function countLines(o: ImportOutcome): string[] {
  if (!o.counts) return o.ok ? ["Event counts are not available for this import"] : [];
  const c = o.counts;
  const lines = [
    `Forensic timeline: +${plural(c.added, "event")} (${c.highCritical.toLocaleString("en-US")} High/Critical)`,
  ];
  if (c.superAdded !== undefined) lines.push(`Super-timeline: +${plural(c.superAdded, "row")}`);
  return lines;
}

function failedLines(o: ImportOutcome): string[] {
  const failed = o.failed ?? [];
  const shown = failed.slice(0, FAILED_LINES_MAX).map((f) => `Failed: ${f.name} — ${f.reason}`);
  const more = failed.length - shown.length;
  return more > 0 ? [...shown, `…and ${more} more failed`] : shown;
}

/** The `import` notification for one finished or failed import. Severity colours the message only. */
export function importEvent(o: ImportOutcome, at: string): NotificationEvent {
  const lines = [
    ...(o.files && o.files > 1 ? [`Files: ${o.files.toLocaleString("en-US")}`] : []),
    ...countLines(o),
    ...failedLines(o),
    ...(o.ok || !o.reason ? [] : [`Reason: ${o.reason}`]),
    ...(o.ok || !o.retryable ? [] : ["It can be retried from the Jobs list."]),
    `Case: ${o.caseId}`,
  ];
  const loud = !o.ok || (o.failed?.length ?? 0) > 0 || (o.counts?.highCritical ?? 0) > 0;
  return { kind: "import", caseId: o.caseId, title: titleOf(o), severity: loud ? "High" : "Info", lines, at };
}

/** Build and send, never throwing: a notification is a side channel and must not break an import. */
export function notifyImport(
  dispatch: ((event: NotificationEvent) => void) | undefined,
  outcome: ImportOutcome,
  log?: (line: string) => void,
): void {
  if (!dispatch) return;
  try {
    dispatch(importEvent(outcome, new Date().toISOString()));
  } catch (err) {
    log?.(`[notify] import notification failed for ${outcome.caseId}: ${(err as Error).message}`);
  }
}

/**
 * One import attempt's notification, fed as the attempt goes: `settled` when its diff is in hand,
 * then exactly one of `finished` / `failed`. A second terminal call is ignored, so a path whose
 * catch runs after its own success branch cannot send two messages for one attempt.
 */
export function trackImportOutcome(
  dispatch: ((event: NotificationEvent) => void) | undefined,
  caseId: string,
  source: string,
  log?: (line: string) => void,
): {
  settled(s: Parameters<typeof countsFromSettled>[0] | null | undefined): void;
  finished(extra?: Pick<ImportOutcome, "files" | "failed">): void;
  failed(err: unknown, retryable?: boolean): void;
} {
  let counts: ImportCounts | undefined;
  let sent = false;
  const send = (o: Omit<ImportOutcome, "caseId" | "source">): void => {
    if (sent) return;
    sent = true;
    notifyImport(dispatch, { caseId, source, ...o }, log);
  };
  return {
    settled: (s) => {
      if (s) counts = addCounts(counts, countsFromSettled(s));
    },
    finished: (extra) => send({ ok: true, ...(counts ? { counts } : {}), ...extra }),
    failed: (err, retryable) =>
      send({
        ok: false,
        reason: err instanceof Error ? err.message : String(err),
        ...(retryable ? { retryable } : {}),
      }),
  };
}

/** The gaps a multi-artifact import left, named the way its hunt card names them. */
export function artifactGaps(outcome: {
  failed: readonly { name: string; error: string }[];
  truncated: readonly { name: string }[];
  unread: readonly { name: string }[];
}): ImportFailedItem[] {
  return [
    ...outcome.failed.map((f) => ({ name: f.name, reason: f.error })),
    ...outcome.truncated.map((t) => ({ name: t.name, reason: "cut short at the row cap" })),
    ...outcome.unread.map((u) => ({ name: u.name, reason: "not read in full (source list unknown)" })),
  ];
}
