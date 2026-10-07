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
import { cleanRereadReason } from "./veloRereadReason.js";

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

/** The incident-window part of a TruncatedArtifact (#1969): set only when a windowed re-read was kept. */
export interface WindowNote {
  windowStart?: string;
  windowEnd?: string;
  windowFull?: boolean; // true = the windowed re-read was NOT cut short: every window row was kept
}

/** The newest-first part of a TruncatedArtifact (#1983): set only when a newest-first re-read was kept. */
export interface OrderNote {
  order?: "newest";
  orderPartial?: boolean; // named sources were never read, so only the rows read were sorted
}

/** Why a cut-short read was kept as is, not re-read (#1992). Set only when a re-read was declined. */
export interface DeclinedNote {
  rereadDeclined?: string;
}

/** What a finished read says about how it was re-read. */
interface ReadNote {
  window?: { start?: string; end?: string };
  truncated?: boolean;
  order?: "newest";
  newest?: { earliest?: string; latest?: string };
  sourcesUnknown?: boolean;
  rereadDeclined?: string;
}

/**
 * A TruncatedArtifact for one capped read: kept count, the read's total, and the kept span. `read`
 * carries the incident window a re-read was kept inside (#1969), and whether that re-read was cut too.
 * A newest-first re-read (#1983) takes its span from the sort key it was ordered by, not pickTime.
 */
export function truncatedRecord(
  name: string,
  rows: readonly unknown[],
  total: number,
  read?: ReadNote,
): { name: string; kept: number; total: number; earliest?: string; latest?: string } & WindowNote &
  OrderNote &
  DeclinedNote {
  if (read?.order === "newest") {
    const n = read.newest;
    const span = n?.earliest && n.latest ? { earliest: n.earliest, latest: n.latest } : {};
    const partial = read.sourcesUnknown ? { orderPartial: true } : {};
    return { name, kept: rows.length, total, ...span, order: "newest", ...partial };
  }
  const w = read?.window;
  const note: WindowNote = w
    ? {
        ...(w.start ? { windowStart: w.start } : {}),
        ...(w.end ? { windowEnd: w.end } : {}),
        windowFull: !read?.truncated,
      }
    : {};
  const why = cleanRereadReason(read?.rereadDeclined);
  return {
    name,
    kept: rows.length,
    total,
    ...keptSpan(rows),
    ...note,
    ...(why ? { rereadDeclined: why } : {}),
  };
}
