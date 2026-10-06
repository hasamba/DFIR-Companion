// Keep the NEWEST rows of a capped Velociraptor read when no incident window is known (#1983).
//
// The collect read asks for `LIMIT cap+1` with no ORDER BY, so a cut-short read keeps the first rows
// in source order: for an MFT that is entry-number order, mostly the oldest files. #1969 re-reads
// inside the incident window when one is known. With no window, the cut-short read is read ONCE more,
// sorted newest-first by the artifact's own time, and the newest rows are kept.
//
// Measured on a 276,380-row MFT (lab, 0.77.2): the plain capped read takes ~15 s warm, the sorted read
// ~36–38 s — about the cost of reading every row. The sort only runs on a read already cut short.
//
// How the sort is built, and why (each point was checked on the lab server):
//   • The key is a fixed per-artifact list of time columns, never analyst text.
//   • Each column is read with `get(member=…)`, not a bare identifier: a column absent on this server
//     version is then NULL, where a bare name logs "Symbol not found" and taints the read.
//   • The FIRST column that parses to a valid time wins (`.UnixMilli > 0`), not the first non-empty
//     raw value: an MFT $FN time of "0001-01-01" falls through to $SI.
//   • A row with no valid time gets key -1, so it sorts LAST.
//   • Each part (each chain ref, each bare/named read) is sorted and limited on its own; the client
//     merges the parts by key and applies ONE final cap. The top N of the union is the top N of the
//     per-part top Ns, so the kept rows are the true newest N.
//   • The key rides as a reserved column until the final cap, then is stripped from the kept rows.

/** The reserved helper column the sort key rides in. Stripped before rows leave the read. */
export const NEWEST_KEY = "_DfirCompanionNewestKey";

/** The sorted re-read reads the whole artifact to sort it, so it gets this many times the query timeout. */
export const SORTED_READ_TIMEOUT_FACTOR = 3;

/**
 * The time columns a newest-first re-read sorts on, per artifact, first valid one wins. Same spellings
 * as WINDOW_TIME_COLUMNS: MFT $FN Created first (harder to timestomp), then $SI Created, each in its
 * top-level and nested spelling (server versions differ). An artifact with no entry is not re-read.
 */
export const NEWEST_SORT_COLUMNS: Readonly<Record<string, readonly string[]>> = {
  "Windows.Forensics.Usn": ["Timestamp"],
  "Windows.NTFS.MFT": ["Created0x30", "FNTimestamps.Created0x30", "Created0x10", "SITimestamps.Created0x10"],
  "Windows.EventLogs.Evtx": ["System.TimeCreated.SystemTime"],
};

/** A newest-first sort for one artifact: the VQL key expression, built only from the table above. */
export interface NewestOrder {
  artifact: string;
  key: string;
}

const COLUMN_RE = /^[A-Za-z0-9_.]+$/;

/** The sort-key VQL for `columns`: epoch milliseconds of the first valid time, else -1. */
export function newestKeyExpr(columns: readonly string[]): string {
  return columns.reduceRight((rest, col) => {
    if (!COLUMN_RE.test(col)) throw new Error(`invalid sort column ${col}`);
    const ms = `timestamp(epoch=get(member='${col}')).UnixMilli`;
    return `if(condition=${ms} > 0, then=${ms}, else=${rest})`;
  }, "-1");
}

/** The newest-first order for `artifact`, or undefined when it has no sort column. */
export function newestOrder(artifact: string): NewestOrder | undefined {
  const cols = NEWEST_SORT_COLUMNS[artifact];
  return cols?.length ? { artifact, key: newestKeyExpr(cols) } : undefined;
}

/** The timeout for a sorted read, from the per-query default. */
export function sortedReadTimeout(timeoutMs: number): number {
  return timeoutMs * SORTED_READ_TIMEOUT_FACTOR;
}

/**
 * One capped read over one or more row sources (`froms`, e.g. `hunt_results(…)`), each limited on its
 * own. Without `order` this is the plain read, text for text. With `order`, each part projects the
 * key and is sorted on it before its LIMIT.
 */
export function cappedReadProgram(
  froms: readonly string[],
  where: string | undefined,
  limit: number,
  order?: NewestOrder,
): string {
  const whereClause = where ? ` WHERE (${where})` : "";
  const proj = order ? `*, ${order.key} AS ${NEWEST_KEY}` : "*";
  const sort = order ? ` ORDER BY ${NEWEST_KEY} DESC` : "";
  const one = (from: string) => `SELECT ${proj} FROM ${from}${whereClause}${sort} LIMIT ${limit}`;
  if (froms.length === 1) return one(froms[0]);
  return `SELECT * FROM chain(${froms.map((f, i) => `q${i}={ ${one(f)} }`).join(", ")})`;
}

/** A capped read, plus what a sorted read needs carried to its acceptance check. */
export interface NewestRun {
  rows: unknown[];
  total: number;
  truncated: boolean;
  diagnostics?: string; // the VQL log errors of a sorted read; any text means "do not trust it"
}

type Row = Record<string, unknown>;
const keyOf = (row: unknown): number => {
  const k = row && typeof row === "object" ? (row as Row)[NEWEST_KEY] : undefined;
  return typeof k === "number" && Number.isFinite(k) ? k : -1;
};

/** Sort keyed rows newest first and hold them to `max`. Stable: equal keys keep their read order. */
export function capNewest(rows: unknown[], max: number, diagnostics = ""): NewestRun {
  const sorted = [...rows].sort((a, b) => keyOf(b) - keyOf(a));
  return {
    rows: sorted.length > max ? sorted.slice(0, max) : sorted,
    total: rows.length,
    truncated: rows.length > max,
    ...(diagnostics ? { diagnostics } : {}),
  };
}

/** What a finished newest-first read kept: how many rows had a valid key, and the span of those keys. */
export interface NewestSpan {
  keyed: number;
  earliest?: string;
  latest?: string;
}

/**
 * Strip the helper column from the kept rows and say what the keys covered. The rows are this read's
 * own freshly parsed objects, so the column is deleted in place — no second copy of a 100k-row array.
 */
export function finishNewest<R extends NewestRun>(run: R): R & { newest: NewestSpan } {
  let keyed = 0;
  let lo = Infinity;
  let hi = -Infinity;
  for (const row of run.rows) {
    const k = keyOf(row);
    if (row && typeof row === "object") delete (row as Row)[NEWEST_KEY];
    if (k <= 0) continue;
    keyed++;
    if (k < lo) lo = k;
    if (k > hi) hi = k;
  }
  const span = keyed ? { earliest: new Date(lo).toISOString(), latest: new Date(hi).toISOString() } : {};
  return { ...run, newest: { keyed, ...span } };
}

/** True when any row already carries the reserved column — the sort would overwrite real data. */
export function hasReservedColumn(rows: readonly unknown[]): boolean {
  return rows.some((r) => !!r && typeof r === "object" && NEWEST_KEY in (r as Row));
}
