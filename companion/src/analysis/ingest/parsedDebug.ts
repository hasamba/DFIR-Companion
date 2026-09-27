import type { ImportDebugRecorder } from "../importDebug.js";

// The shared tail of a deterministic importer's debug record (#1736). Every parser behind the
// cloud, flow and network wrappers returns the same shape: records read (`total`), rows it could
// not represent (`dropped`), distinct groups before the cap (`groups`) and groups kept after it
// (`kept`). The wrapper then applies the analyst's severity floor. This records those decisions
// as counts only — no row content reaches the recorder.
export interface ParsedShape {
  total: number;
  dropped: number;
  groups: number;
  kept: number;
  events: ReadonlyArray<{ count?: number }>;
}

/**
 * `preFloor` is every event the wrapper offered to the floor (parser rows plus any cross-upload
 * rows); `postFloor` is what survived it. `aggregated` counts rows folded into a kept row.
 */
export function recordParsedImport(
  debug: ImportDebugRecorder | undefined,
  parsed: ParsedShape,
  preFloor: number,
  postFloor: number,
): void {
  if (!debug) return;
  let aggregated = 0;
  for (const e of parsed.events) aggregated += Math.max(0, (e.count ?? 1) - 1);
  if (aggregated > 0) debug.omitted("aggregated", aggregated);
  if (parsed.groups > parsed.kept) debug.omitted("over_event_cap", parsed.groups - parsed.kept);
  const belowFloor = Math.max(0, preFloor - postFloor);
  if (belowFloor > 0) debug.omitted("below_severity_floor", belowFloor);
  debug.counts({ total: parsed.total, kept: postFloor, dropped: parsed.dropped + belowFloor });
}

/** Adds each positive count under its code — a parser's own named counters, recorded as-is. */
export function recordCounts(
  debug: ImportDebugRecorder | undefined,
  kind: "skipped" | "observed",
  counts: ReadonlyArray<readonly [string, number]>,
): void {
  if (!debug) return;
  for (const [code, n] of counts) if (n > 0) debug[kind](code, n);
}
