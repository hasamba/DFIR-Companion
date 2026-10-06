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
// Lives here, not in velociraptorApi.ts or composition/veloHunts.ts: both sit at their size ceiling.
import { containedWhereOrThrow, MAX_READ_WHERE_LENGTH } from "../../analysis/vqlInput.js";

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
 * The incident window for one artifact's collect: the hunt's own time scope, else the case scope
 * window. Undefined when the hunt already applied its window to this artifact AT THE SOURCE — the
 * plain read is then inside the window, and a re-read would return the same rows.
 */
export function incidentWindow(
  timeScope: { start?: unknown; end?: unknown; scopedArtifactNames?: readonly string[] } | undefined,
  caseScope: { start?: unknown; end?: unknown } | null | undefined,
  artifact?: string,
): ReadWindow | undefined {
  if (artifact && timeScope?.scopedArtifactNames?.includes(artifact)) return undefined;
  return (
    (timeScope ? toWindow(timeScope.start, timeScope.end) : undefined) ??
    (caseScope ? toWindow(caseScope.start, caseScope.end) : undefined)
  );
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
}

/** A read result, plus the window it was re-read inside when the re-read was used. */
export type WindowedResult<R extends CappedRead> = R & { window?: ReadWindow };

/**
 * Run the plain read; when it was cut short and a window is known, re-read once inside the window.
 * The windowed rows replace the plain ones only when the re-read succeeds and returns rows: an empty
 * re-read most often means the time column is absent on this server version, and an error must not
 * lose the rows the plain read already holds.
 */
export async function readInIncidentWindow<R extends CappedRead>(
  read: (where?: string) => Promise<R>,
  artifact: string,
  baseWhere: string | undefined,
  window: ReadWindow | undefined,
  log?: (line: string) => void,
): Promise<WindowedResult<R>> {
  // The analyst's filter meets its own rules first — its own length cap and containment — so an
  // injection attempt is refused before any read, exactly as the plain read alone would refuse it.
  const base = baseWhere ? containedWhereOrThrow(baseWhere) : undefined;
  const plain = await read(base || undefined);
  if (!plain.truncated || !window) return plain;
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
