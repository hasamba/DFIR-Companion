// The time span of the rows a capped Velociraptor read kept (#1950).
//
// The collect read asks for `LIMIT cap+1` with no ORDER BY, so it keeps the FIRST rows the artifact
// returns — for a USN journal or an MFT walk that is source order, not the incident window. A bare
// "partial — kept 100000" line cannot tell the model or the analyst which days are missing. The span
// of the kept rows can: anything outside it was never collected.
//
// Lives in analysis/ingest beside veloRowTime.ts, which dates the rows. veloHuntStore.ts (analysis/case)
// owns the TruncatedArtifact shape and may not import this layer, so the record below is structural.
import { pickTime } from "./veloRowTime.js";

export interface KeptSpan {
  earliest: string;
  latest: string;
}

type Row = Record<string, unknown>;

const isRow = (v: unknown): v is Row => !!v && typeof v === "object" && !Array.isArray(v);

// pickTime's last resort is the `_ts` collection time: when the row was READ, not when it happened.
// Every kept row shares roughly that time, so it would fake a span. Drop it before dating.
function rowTime(row: Row): string {
  if (!("_ts" in row)) return pickTime(row);
  const { _ts: _collected, ...rest } = row;
  return pickTime(rest);
}

/** The earliest and latest artifact time among `rows`, or undefined when no row is dated. */
export function keptSpan(rows: readonly unknown[]): KeptSpan | undefined {
  let lo = Infinity,
    hi = -Infinity,
    earliest = "",
    latest = "";
  for (const row of rows) {
    if (!isRow(row)) continue;
    const t = rowTime(row);
    const ms = t ? Date.parse(t) : NaN;
    if (Number.isNaN(ms)) continue;
    if (ms < lo) [lo, earliest] = [ms, t];
    if (ms > hi) [hi, latest] = [ms, t];
  }
  return earliest ? { earliest, latest } : undefined;
}

/** A TruncatedArtifact for one capped read: kept count, the read's total, and the kept span. */
export function truncatedRecord(
  name: string,
  rows: readonly unknown[],
  total: number,
): { name: string; kept: number; total: number; earliest?: string; latest?: string } {
  return { name, kept: rows.length, total, ...keptSpan(rows) };
}
