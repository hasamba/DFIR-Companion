// What the shared SIEM mapping path DECIDED, for the per-import debug recorder (#1736): the key each
// record's host and time came from, which mapper handled it, and where the aggregation step removed
// rows. Tallied locally and flushed once, so a 100k-row export costs a few map bumps per row. The
// keys come from the mapper's own pickers through siemFieldPick's sink — nothing re-scans a record.
//
// Records only KEY NAMES the pickers selected and code-authored slugs — never a value. The recorder
// passes each key through the support bundle's column allowlist on top of that.
import type { ImportDebugRecorder } from "./importDebug.js";
import { setFieldPickSink, type FieldPickSink } from "./siemFieldPick.js";
import type { EventAggregator } from "./eventAggregate.js";
import type { MappedEvent } from "./siemImport.js";
import { SEVERITY_RANK, type Severity } from "./stateTypes.js";

export interface SiemDebugTally {
  /** Call just before a record's host pick: the pickers report the keys they select until `row`. */
  begin(): void;
  /** One mapped record: `windows` is true when the per-EID Windows mapper handled it. */
  row(windows: boolean, m: MappedEvent): void;
  /** Rows that went through the aggregator (after it ran on them), to count the severity floor. */
  floored(rows: Iterable<MappedEvent>): void;
  /** The same count for a streaming aggregator: wraps its add. */
  watch(agg: EventAggregator): EventAggregator;
  /** Emit everything once the result is known. */
  flush(r: { total: number; kept: number; groups: number; dropped: number }): void;
}

const NOOP: SiemDebugTally = {
  begin() {},
  row() {},
  floored() {},
  watch: (agg) => agg,
  flush() {},
};

function bump(map: Map<string, number>, key: string): void {
  map.set(key, (map.get(key) ?? 0) + 1);
}

export function createSiemDebugTally(debug?: ImportDebugRecorder, minSeverity?: Severity): SiemDebugTally {
  setFieldPickSink(undefined); // a sink left behind by a mapping that threw belongs to a dead tally
  if (!debug) return NOOP;
  const floorRank = minSeverity ? SEVERITY_RANK[minSeverity] : Infinity;
  const hostKeys = new Map<string, number>();
  const timeKeys = new Map<string, number>();
  let [windows, generic, noHost, noTime, emptyTime, seen, belowFloor] = [0, 0, 0, 0, 0, 0, 0];
  const floorOne = (m: MappedEvent): void => {
    seen++;
    if (SEVERITY_RANK[m.severity] > floorRank) belowFloor++;
  };

  // One closure for the whole import, so a record costs no allocation beyond two variable writes.
  let [hostKey, timeKey]: (string | undefined)[] = [undefined, undefined];
  const sink: FieldPickSink = (target, key) => {
    if (target === "host") hostKey = key;
    else timeKey = key;
  };

  return {
    begin() {
      hostKey = timeKey = undefined;
      setFieldPickSink(sink);
    },
    row(isWindows, m) {
      setFieldPickSink(undefined);
      if (isWindows) windows++;
      else generic++;
      if (hostKey) bump(hostKeys, hostKey);
      else noHost++;
      // The mapper that handled the record picked its time last (Windows: EventData's UtcTime first).
      if (timeKey) bump(timeKeys, timeKey);
      else noTime++;
      if (timeKey && !m.timestamp) emptyTime++;
    },
    floored(rows) {
      for (const m of rows) floorOne(m);
    },
    watch(agg) {
      return {
        add(m, ordinal) {
          agg.add(m, ordinal);
          floorOne(m); // after add: the aggregator's annotators may regrade the row first
        },
        finish: () => agg.finish(),
      };
    },
    flush(r) {
      for (const [k, n] of hostKeys) debug.field("host", k, n);
      for (const [k, n] of timeKeys) debug.field("timestamp", k, n);
      debug.fallback("windows_mapper", windows);
      debug.fallback("generic_mapper", generic);
      debug.observed("missing_host", noHost);
      debug.observed("no_timestamp", noTime);
      debug.observed("empty_timestamp", emptyTime);
      recordAggregation(debug, { seen, belowFloor, groups: r.groups, kept: r.kept });
      debug.counts({ total: r.total, kept: r.kept, dropped: r.dropped });
    },
  };
}

/** Where aggregation shrank the mapped rows: the floor, the merge into counted groups, the cap. */
export function recordAggregation(
  debug: ImportDebugRecorder | undefined,
  a: { seen: number; belowFloor: number; groups: number; kept: number },
): void {
  debug?.omitted("below_severity_floor", a.belowFloor);
  debug?.omitted("aggregated", Math.max(0, a.seen - a.belowFloor - a.groups));
  debug?.omitted("over_event_cap", Math.max(0, a.groups - a.kept));
}

/**
 * The same three counts for a parser that aggregated a whole `mapped` array at once. Call it after
 * aggregateEvents ran, because the aggregator's annotators may regrade a row before its floor check.
 */
export function recordMappedAggregation(
  debug: ImportDebugRecorder | undefined,
  mapped: readonly MappedEvent[],
  minSeverity: Severity | undefined,
  r: { groups: number; kept: number },
): void {
  if (!debug) return;
  const floor = minSeverity ? SEVERITY_RANK[minSeverity] : Infinity;
  const belowFloor = mapped.filter((m) => SEVERITY_RANK[m.severity] > floor).length;
  recordAggregation(debug, { seen: mapped.length, belowFloor, groups: r.groups, kept: r.kept });
}
