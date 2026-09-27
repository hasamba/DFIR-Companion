import type { DebugTarget, ImportDebugRecorder } from "./importDebug.js";

/**
 * Small helpers for importers that report their decisions to an import debug recorder (#1736).
 * A parser tallies locally inside its row loop and calls the recorder once per key at the end, so
 * a large file does not pay one recorder call per row. Every code passed here is a literal written
 * in the calling importer; nothing is ever built from a row value.
 */

export interface FieldTally {
  /** Count one row whose `target` field was read from the source key `source`. */
  add(target: DebugTarget, source: string): void;
  /** Report the tallied selections to the recorder (no-op without one). */
  flush(debug: ImportDebugRecorder | undefined): void;
}

export function createFieldTally(): FieldTally {
  const tally = new Map<DebugTarget, Map<string, number>>();
  return {
    add(target, source) {
      let bySource = tally.get(target);
      if (!bySource) tally.set(target, (bySource = new Map()));
      bySource.set(source, (bySource.get(source) ?? 0) + 1);
    },
    flush(debug) {
      if (!debug) return;
      for (const [target, bySource] of tally)
        for (const [source, n] of bySource) debug.field(target, source, n);
    },
  };
}

/** Coded counters for skip reasons, omissions, observations or fallbacks, flushed once. */
export interface CodeTally {
  add(code: string, n?: number): void;
  flush(record: ((code: string, n: number) => void) | undefined): void;
}

export function createCodeTally(): CodeTally {
  const tally = new Map<string, number>();
  return {
    add(code, n = 1) {
      if (n > 0) tally.set(code, (tally.get(code) ?? 0) + n);
    },
    flush(record) {
      if (!record) return;
      for (const [code, n] of tally) record(code, n);
    },
  };
}

/**
 * The common tail of an aggregating parser: `mapped` rows went into `aggregateEvents`, which folded
 * them into `groups` groups and kept `kept` of those under the event cap. Records the rows folded
 * into another row (`aggregated`) and the groups cut by the cap (`over_event_cap`).
 */
export function recordAggregation(
  debug: ImportDebugRecorder | undefined,
  mapped: number,
  groups: number,
  kept: number,
): void {
  if (!debug) return;
  if (mapped > groups) debug.omitted("aggregated", mapped - groups);
  if (groups > kept) debug.omitted("over_event_cap", groups - kept);
}

/** The analyst's severity floor removed `pre - post` mapped events. */
export function recordFloor(debug: ImportDebugRecorder | undefined, pre: number, post: number): void {
  if (debug && pre > post) debug.omitted("below_severity_floor", pre - post);
}

/**
 * The shared result shape of the report-style parsers (capa, FLOSS, olevba, MobSF, FSEvents,
 * Spotlight, BTM login items …): `kept` of `groups` groups survived the parser's event cap, and
 * `post` events survived the analyst's floor. `skipped` maps a literal reason to the parser's own
 * count of rows it could not map; a zero count records nothing.
 */
export function recordParseResult(
  debug: ImportDebugRecorder | undefined,
  r: { total: number; kept: number; dropped: number; groups: number },
  post: number,
  skipped: Readonly<Record<string, number>> = {},
): void {
  if (!debug) return;
  debug.counts({ total: r.total, kept: post, dropped: r.dropped });
  for (const [reason, n] of Object.entries(skipped)) if (n > 0) debug.skipped(reason, n);
  if (r.groups > r.kept) debug.omitted("over_event_cap", r.groups - r.kept);
  recordFloor(debug, r.kept, post);
}
