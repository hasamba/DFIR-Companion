import type { ImportDebugRecorder } from "./importDebug.js";
import { createCodeTally, createFieldTally, type CodeTally, type FieldTally } from "./parseDebugTally.js";
import type { RowHost } from "./hostIdentity.js";
import { getCI, getPath, str, type MappedEvent } from "./siemImport.js";
import { setTimeKeySink } from "./veloRowTime.js";

export type { ImportDebugRecorder };

/**
 * Per-row import decisions for the endpoint importers (Velociraptor, Hayabusa, Chainsaw, KAPE,
 * THOR, Plaso — #1736). A parser tallies locally in its row loop and flushes once at the end, so a
 * large file pays no recorder call per row. Only key NAMES and code-authored slugs are tallied;
 * the recorder's allowlist then decides which names survive. Never a value.
 */

type Row = Record<string, unknown>;

export interface DecisionTally {
  fields: FieldTally;
  skipped: CodeTally;
  omitted: CodeTally;
  observed: CodeTally;
  fallbacks: CodeTally;
  /** Report everything tallied so far to the recorder (no-op without one). */
  flush(debug: ImportDebugRecorder | undefined): void;
}

export function createDecisionTally(): DecisionTally {
  const t = {
    fields: createFieldTally(),
    skipped: createCodeTally(),
    omitted: createCodeTally(),
    observed: createCodeTally(),
    fallbacks: createCodeTally(),
  };
  return {
    ...t,
    flush(debug) {
      if (!debug) return;
      t.fields.flush(debug);
      t.skipped.flush((c, n) => debug.skipped(c, n));
      t.omitted.flush((c, n) => debug.omitted(c, n));
      t.observed.flush((c, n) => debug.observed(c, n));
      t.fallbacks.flush((c, n) => debug.fallback(c, n));
    },
  };
}

/**
 * The first candidate key holding a non-empty string (case-insensitive, dotted paths), as the row
 * spells it ("CmdLine" for the candidate "Cmdline"); a dotted path is returned as listed. "" if none.
 */
export function firstPresentKey(row: Row, keys: readonly string[]): string {
  for (const k of keys) {
    if (!str(k.includes(".") ? getPath(row, k) : getCI(row, k)).trim()) continue;
    if (k.includes(".") || k in row) return k;
    const lower = k.toLowerCase();
    return Object.keys(row).find((key) => key.toLowerCase() === lower) ?? k;
  }
  return "";
}

// The keys resolveRowHost reads (hostIdentity.ts), in its order. Mirrored here, not imported: the
// resolver returns the VALUE it chose, and the debug record needs the key that held it.
const COLLECTOR_KEYS = ["Fqdn", "Hostname"];
const RECORD_KEYS = [
  "Computer",
  "ComputerName",
  "System.Computer",
  "Event.System.Computer",
  "_Event.System.Computer",
  "SystemData.Computer",
  "Host",
];
const ABSENT = new Set(["-", "n/a"]);

function keyHolding(row: Row, keys: readonly string[], want: string): string {
  for (const k of keys) {
    const v = str(k.includes(".") ? getPath(row, k) : getCI(row, k)).trim();
    if (v && !ABSENT.has(v.toLowerCase())) return v === want ? k : "";
  }
  return "";
}

/**
 * Tally where a row's host came from, given the resolver's verdict. `recordKey` names the key a
 * caller unwrapped the record's own name from (Chainsaw's `System.Computer`). The import's fallback
 * host is a decision, not a column: an analyst-declared host (#1496) is `asset_host_declared`, a
 * flow's client (#1458) is `collector_host_fallback`.
 */
export function tallyRowHost(t: DecisionTally, row: Row, rh: RowHost, recordKey?: string): void {
  if (rh.fallbackBasis) {
    t.fallbacks.add(rh.fallbackBasis === "analyst" ? "asset_host_declared" : "collector_host_fallback");
    return;
  }
  if (!rh.asset) {
    t.observed.add("missing_host");
    return;
  }
  const key =
    (rh.collectorIdentity ? keyHolding(row, COLLECTOR_KEYS, rh.asset) : "") ||
    recordKey ||
    keyHolding(row, RECORD_KEYS, rh.formerName ?? rh.asset);
  if (key) t.fields.add("host", key);
  else t.observed.add("host_key_unresolved");
  if (rh.viaRenameEvidence) t.observed.add("host_renamed");
}

// The Velociraptor mappers that date a Windows record through the shared Windows builder, which
// reads the record's System.TimeCreated (veloWinRow.ts) rather than calling pickTime.
const WINDOWS_RECORD_KINDS = new Set(["eventlog", "sigma", "detection", "chainsaw"]);

/**
 * One Velociraptor parse's tally. Inert without a recorder: every method returns at once, so an
 * import that carries no debug recorder pays one property check per row.
 */
export class VrDebugTally {
  private readonly t = createDecisionTally();
  private timeKey = "";
  private readonly catchTimeKey = (key: string): void => {
    this.timeKey = key;
  };

  constructor(private readonly debug?: ImportDebugRecorder) {}

  host(row: Row, rh: RowHost): void {
    if (this.debug) tallyRowHost(this.t, row, rh);
  }

  /** Start listening for the time column the row's mapper picks. */
  beginRow(): void {
    if (!this.debug) return;
    this.timeKey = "";
    setTimeKeySink(this.catchTimeKey);
  }

  /** Stop listening; tally the mapper route, the time column and an undated or empty row. */
  endRow(kind: string, events: readonly (MappedEvent | null | undefined)[]): void {
    if (!this.debug) return;
    setTimeKeySink(undefined);
    if (kind === "generic") this.t.fallbacks.add("generic_artifact");
    const live = events.filter((e): e is MappedEvent => !!e);
    if (live.length === 0) {
      this.t.skipped.add("no_event_mapped");
      return;
    }
    if (this.timeKey) {
      this.t.fields.add("timestamp", this.timeKey);
      if (this.timeKey === "_ts") this.t.observed.add("collection_time_used");
    } else if (live.some((e) => e.timestamp)) {
      if (WINDOWS_RECORD_KINDS.has(kind)) this.t.fields.add("timestamp", "System.TimeCreated.SystemTime");
      else this.t.observed.add("time_from_artifact_mapper");
    }
    if (!live.some((e) => e.timestamp)) this.t.observed.add("empty_timestamp");
  }

  /** Report the tally to the recorder once, at the end of the parse. */
  flush(): void {
    this.t.flush(this.debug);
  }
}

/**
 * Counts for an importer that maps a whole collection at once (WER, persistence, rclone): `total`
 * records read, `pre` events built, `post` left after the analyst's severity floor.
 */
export function recordFloorCounts(
  debug: ImportDebugRecorder | undefined,
  total: number,
  pre: number,
  post: number,
): void {
  if (!debug) return;
  if (pre > post) debug.omitted("below_severity_floor", pre - post);
  debug.counts({ total, kept: post, dropped: Math.max(0, pre - post) });
}
