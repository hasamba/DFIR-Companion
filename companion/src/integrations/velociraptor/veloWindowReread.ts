// Re-read a capped Velociraptor collect inside the incident window (#1969).
//
// The collect read asks for `LIMIT cap+1` with no ORDER BY, so a cut-short read keeps the FIRST rows
// the artifact returns: on a full disk that is the oldest USN records, or the MFT in entry-number
// order — not the days the analyst cares about. When an incident window is known (the hunt's own
// launch time scope, else the case scope window), a cut-short read is read ONCE more with a WHERE on
// the artifact's own time column, so the cap spends its rows inside the window.
//
// Only a cut-short read is re-read. A case scope window is a reversible view filter; baking it into
// every read would drop out-of-window rows that fit under the cap, and they could not be recovered
// without a new collection.
//
// With NO window known, a cut-short read is re-read newest-first instead (#1983, veloNewestRead.ts).
//
// Lives here, not in velociraptorApi.ts or composition/veloHunts.ts: both sit at their size ceiling.
import { containedWhereOrThrow, MAX_READ_WHERE_LENGTH } from "../../analysis/vqlInput.js";
import { hasReservedColumn, newestOrder, type NewestOrder, type NewestSpan } from "./veloNewestRead.js";

/** An incident window, as ISO-8601 bounds. At least one bound is set. */
export interface ReadWindow {
  start?: string;
  end?: string;
}

/**
 * The time columns a window is applied to, per artifact. A row is kept when ANY listed column falls
 * inside the window. MFT names both the top-level and the nested spellings (server versions differ,
 * see analysis/veloRowTime.ts), $FN Created first, then $SI Created. A file that was only MODIFIED in
 * the window can still drop out. An artifact with no entry keeps today's plain read.
 */
export const WINDOW_TIME_COLUMNS: Readonly<Record<string, readonly string[]>> = {
  "Windows.Forensics.Usn": ["Timestamp"],
  "Windows.NTFS.MFT": ["Created0x30", "FNTimestamps.Created0x30", "Created0x10", "SITimestamps.Created0x10"],
  "Windows.EventLogs.Evtx": ["System.TimeCreated.SystemTime"],
};

// A bound becomes part of a VQL string, so only an ISO-shaped value that parses as a date is kept,
// and it is re-emitted by toISOString — never the stored text as is.
const ISO_DATE_RE = /^\d{4}-\d{2}-\d{2}(T[\d:.]+(Z|[+-]\d{2}:?\d{2})?)?$/;
function isoBound(v: unknown): string | undefined {
  if (typeof v !== "string" || !ISO_DATE_RE.test(v.trim())) return undefined;
  const ms = Date.parse(v);
  return Number.isNaN(ms) ? undefined : new Date(ms).toISOString();
}

function toWindow(start: unknown, end: unknown): ReadWindow | undefined {
  const s = isoBound(start);
  const e = isoBound(end);
  if (!s && !e) return undefined;
  return { ...(s ? { start: s } : {}), ...(e ? { end: e } : {}) };
}

/**
 * What a cut-short read may be re-read inside (#1983), in three distinct states:
 *   - "scoped": the hunt already applied its window to this artifact AT THE SOURCE. The plain read is
 *     inside the window; a re-read would return the same rows. One read only, never newest-first.
 *   - "window": the hunt's own time scope, else the case scope window. Re-read inside it.
 *   - "none": no window at all. A cut-short read is re-read newest-first.
 */
export type ReadScope = { kind: "none" } | { kind: "window"; window: ReadWindow } | { kind: "scoped" };

type TimeScopeIn = { start?: unknown; end?: unknown; scopedArtifactNames?: readonly string[] } | undefined;
type CaseScopeIn = { start?: unknown; end?: unknown } | null | undefined;

/** The read scope for one artifact's collect — see ReadScope. */
export function readScope(timeScope: TimeScopeIn, caseScope: CaseScopeIn, artifact?: string): ReadScope {
  if (artifact && timeScope?.scopedArtifactNames?.includes(artifact)) return { kind: "scoped" };
  const window =
    (timeScope ? toWindow(timeScope.start, timeScope.end) : undefined) ??
    (caseScope ? toWindow(caseScope.start, caseScope.end) : undefined);
  return window ? { kind: "window", window } : { kind: "none" };
}

/**
 * The incident window for one artifact's collect: the hunt's own time scope, else the case scope
 * window. Undefined when there is none, or when the hunt applied its window AT THE SOURCE.
 */
export function incidentWindow(
  timeScope: TimeScopeIn,
  caseScope: CaseScopeIn,
  artifact?: string,
): ReadWindow | undefined {
  const scope = readScope(timeScope, caseScope, artifact);
  return scope.kind === "window" ? scope.window : undefined;
}

/** The VQL WHERE expression that keeps `artifact`'s rows inside `window`, or undefined (no column). */
export function windowWhere(artifact: string, window: ReadWindow): string | undefined {
  const cols = WINDOW_TIME_COLUMNS[artifact];
  if (!cols?.length || (!window.start && !window.end)) return undefined;
  const one = (col: string): string => {
    const t = `timestamp(epoch=${col})`;
    const lo = window.start ? `${t} >= timestamp(epoch='${window.start}')` : "";
    const hi = window.end ? `${t} <= timestamp(epoch='${window.end}')` : "";
    return `(${[lo, hi].filter(Boolean).join(" AND ")})`;
  };
  return `(${cols.map(one).join(" OR ")})`;
}

/** The read shape this module needs from huntArtifactRows. */
export interface CappedRead {
  rows: unknown[];
  truncated: boolean;
  total: number;
  diagnostics?: string; // VQL log errors of a sorted read (#1983)
  newest?: NewestSpan; // set on a sorted read: how many rows had a valid key, and their span
}

/** A read result, plus the window it was re-read inside, or `order` when it was re-read newest-first. */
export type WindowedResult<R extends CappedRead> = R & { window?: ReadWindow; order?: "newest" };

type Read<R> = (where?: string, order?: NewestOrder) => Promise<R>;

const asScope = (s: ReadScope | ReadWindow | undefined): ReadScope =>
  !s ? { kind: "none" } : "kind" in s ? s : { kind: "window", window: s };

/**
 * Run the plain read; when it was cut short, re-read ONCE: inside the window when one is known, else
 * newest-first when the artifact has a sort column, never when the hunt scoped it at the source.
 * The re-read rows replace the plain ones only when the re-read succeeds and returns usable rows: an
 * empty re-read most often means the time column is absent on this server version, and an error
 * (including a timeout) must not lose the rows the plain read already holds. A window re-read that
 * fails keeps the plain rows; it never falls through to newest-first.
 */
export async function readInIncidentWindow<R extends CappedRead>(
  read: Read<R>,
  artifact: string,
  baseWhere: string | undefined,
  scopeIn: ReadScope | ReadWindow | undefined,
  log?: (line: string) => void,
): Promise<WindowedResult<R>> {
  // The analyst's filter meets its own rules first — its own length cap and containment — so an
  // injection attempt is refused before any read, exactly as the plain read alone would refuse it.
  const base = baseWhere ? containedWhereOrThrow(baseWhere) : undefined;
  const plain = await read(base || undefined);
  const scope = asScope(scopeIn);
  if (!plain.truncated || scope.kind === "scoped") return plain;
  if (scope.kind === "none") return readNewest(read, artifact, base, plain, log);
  const window = scope.window;
  try {
    // Built inside the fallback: a failure here must not lose the rows the plain read holds. The
    // generated clause is checked for containment but never cut to the analyst cap (review, #1969).
    const clause = windowWhere(artifact, window);
    if (!clause) return plain;
    const combined = base ? `(${base}) AND ${clause}` : clause;
    const where = containedWhereOrThrow(combined, undefined, MAX_READ_WHERE_LENGTH);
    if (where !== combined) throw new Error("the window filter does not fit the read's WHERE limit");
    const windowed = await read(where);
    return windowed.rows.length ? { ...windowed, window } : plain;
  } catch (e) {
    log?.(
      `[velociraptor] ${artifact}: incident-window re-read failed, kept the plain read — ${(e as Error).message}`,
    );
    return plain;
  }
}

/**
 * The no-window re-read (#1983): sorted newest-first by the artifact's own time, same analyst filter.
 * Accepted only when the query logged no VQL errors and at least one kept row had a valid time key.
 */
async function readNewest<R extends CappedRead>(
  read: Read<R>,
  artifact: string,
  base: string | undefined,
  plain: R,
  log?: (line: string) => void,
): Promise<WindowedResult<R>> {
  const order = newestOrder(artifact);
  if (!order) return plain;
  const keep = (why: string): R => {
    log?.(`[velociraptor] ${artifact}: newest-first re-read not used, kept the plain read — ${why}`);
    return plain;
  };
  if (hasReservedColumn(plain.rows)) return keep("a row already carries the reserved sort column");
  try {
    const sorted = await read(base || undefined, order);
    if (sorted.diagnostics) return keep(sorted.diagnostics);
    if (!sorted.newest?.keyed) return keep("no kept row had a valid time");
    return { ...sorted, order: "newest" };
  } catch (e) {
    return keep((e as Error).message);
  }
}
