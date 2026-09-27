import type { DebugTarget, ImportDebugRecorder } from "./importDebug.js";
import { safeColumnName } from "./importShape.js";

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
  /** Distinct source keys held for `target` — for the bounds tests. */
  size(target: DebugTarget): number;
}

/** The recorder's own per-target source cap (importDebug.ts MAX_SOURCES_PER_TARGET). */
export const MAX_FIELD_SOURCES = 16;
/** The recorder's own code cap (importDebug.ts MAX_CODES). */
export const MAX_TALLY_CODES = 32;
const UNLISTED = "<unlisted>";
const OVERFLOW_CODE = "other";

function bumpCount(map: Map<string, number>, key: string, n: number): void {
  map.set(key, Math.min((map.get(key) ?? 0) + n, Number.MAX_SAFE_INTEGER));
}

/**
 * A source key is input-controlled (Velociraptor's fallback time scan reports any time-like column
 * name), so it is reduced to the recorder's allowlist BEFORE it becomes a map key: every other
 * name collapses to `<unlisted>`. At most MAX_FIELD_SOURCES keys are held per target —
 * `<unlisted>` always keeps a slot, and a name past the cap is counted there. The overflow is
 * reported as the `field_sources_truncated` observation.
 */
export function createFieldTally(): FieldTally {
  const tally = new Map<DebugTarget, Map<string, number>>();
  let overflow = 0;
  return {
    add(target, source) {
      let bySource = tally.get(target);
      if (!bySource) tally.set(target, (bySource = new Map()));
      let key = safeColumnName(source);
      if (key !== UNLISTED && !bySource.has(key)) {
        const named = bySource.size - (bySource.has(UNLISTED) ? 1 : 0);
        if (named >= MAX_FIELD_SOURCES - 1) {
          key = UNLISTED;
          overflow += 1;
        }
      }
      bumpCount(bySource, key, 1);
    },
    flush(debug) {
      if (!debug) return;
      for (const [target, bySource] of tally)
        for (const [source, n] of bySource) debug.field(target, source, n);
      if (overflow > 0) debug.observed("field_sources_truncated", overflow);
    },
    size: (target) => tally.get(target)?.size ?? 0,
  };
}

/** Coded counters for skip reasons, omissions, observations or fallbacks, flushed once. */
export interface CodeTally {
  add(code: string, n?: number): void;
  flush(record: ((code: string, n: number) => void) | undefined): void;
}

/** Codes are literals, but the map is still held to the recorder's cap; the rest count as `other`. */
export function createCodeTally(): CodeTally {
  const tally = new Map<string, number>();
  return {
    add(code, n = 1) {
      if (!(n > 0)) return;
      const key = tally.has(code) || tally.size < MAX_TALLY_CODES - 1 ? code : OVERFLOW_CODE;
      bumpCount(tally, key, n);
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
