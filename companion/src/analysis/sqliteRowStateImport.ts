// sqlite-dissect's (DC3) default `-e csv` commit-history export, one CSV per table (#932 item 8,
// "932.13"): a structural fact about one cell's presence/change in one table's commit history —
// main-database, WAL, rollback-journal or carved/freelist provenance. Never a claim about intent,
// never a live database "current state" verdict, and never an independent re-verification of the
// tool's own commit-boundary determination. #1152 adds ONE bounded exception: `latestForRowId`
// names the highest-version, non-Carved row sharing a rowId within this single report — never
// across reports, never claimed as the live database's own current content, skipped entirely when
// the report was truncated. See canonicalSqliteRowState.ts's own SQLITE_ROW_STATE_BASIS_V2 for the
// exact, persisted wording of that bound.
//
// Schema verified live against sqlite-dissect's own csv_export.py (CommitCsvExporter) and
// constants.py — not invented. See RECOMMENDATION-8.md for the full research trail.

import { createHash } from "node:crypto";
import { boundedAggKey } from "./aggKey.js";
import { parseCsvRecords } from "./csvImport.js";
import { createCanonicalEvent } from "./canonicalEvent.js";
import {
  MAX_COLUMNS_PER_ROW,
  MAX_FIELD_LEN,
  MAX_VALUE_LEN,
  SQLITE_ROW_STATE_BASIS_V2,
  sqliteCellSources,
  sqliteFileSources,
  sqliteRowStateOperations,
  type SqliteCellSource,
  type SqliteFileSource,
  type SqliteRowStateOperation,
} from "./canonicalSqliteRowState.js";
import {
  computeLatestForRowId,
  highValueClause,
  latestClause,
  matchHighValueLabel,
  parseHighValueLabels,
  type LatestRowFacts,
} from "./sqliteRowStateLatest.js";
import type { MappedEvent, SiemEvent } from "./siemImport.js";
import { aggregateEvents } from "./eventAggregate.js";

export const MAX_ROWS_SCANNED = 20_000; // report-wide

// The fixed 9-column header prefix `_write_cells()` writes for a B_TREE_TABLE_LEAF page (an
// ordinary rowid table) — the WITHOUT ROWID / index-page shape omits "Row ID" and is deliberately
// out of scope for this item (Codex design review finding: a header lacking it must NOT be
// silently accepted as this format).
const HEADER_PREFIX = [
  "file source",
  "version",
  "page version",
  "cell source",
  "page number",
  "location",
  "operation",
  "file offset",
  "row id",
];

export interface SqliteRowStateOptions {
  aggregate?: boolean;
  maxEvents?: number;
  /** The uploaded file's own name (opts.label from the ingest wrapper) — the CSV's own content
   * carries no table-name field, so this is the only available source, best-effort only. */
  sourceLabel?: string;
}

export interface SqliteRowStateResult {
  events: SiemEvent[];
  iocs: [];
  total: number;
  /** Count of mapped, kept rows only — captured before the per-report Carved/Deleted summary
   * line is appended to `events`, so it never counts that summary as a row (#1289). */
  kept: number;
  dropped: number;
  groups: number;
  format: string;
  malformedRows: number;
  rowsTruncated: boolean;
  tableName: string;
  tableNameSource: "filename" | "unavailable";
}

function clip(text: string, max: number): string {
  return text.length <= max ? text : text.slice(0, max);
}

/** Best-effort only — the CSV's own content carries no table-name field. Strips the companion's
 * own upload sequence prefix and the .csv extension; never claims more precision than that (the
 * remainder may still include sqlite-dissect's own export-file prefix mixed in). */
function deriveTableName(sourceLabel: string | undefined): {
  tableName: string;
  tableNameSource: "filename" | "unavailable";
} {
  const stripped = (sourceLabel ?? "").replace(/^\d+_/, "").replace(/\.csv$/i, "");
  if (!stripped) return { tableName: "", tableNameSource: "unavailable" };
  return { tableName: clip(stripped, MAX_FIELD_LEN), tableNameSource: "filename" };
}

// #1144 — a deterministic, per-report, per-source-combo tally of Carved/Deleted rows. Grouped by
// (operation, fileSource, cellSource) only — never a table-content claim, never a time dimension
// (there is none: see the per-row [undated] disclosure). One CSV import is already exactly one
// table (sqlite-dissect exports one CSV per table), so this tally is scoped to this one import;
// no cross-table aggregation is attempted here. `record()` takes the SAME already-validated
// values mapRow() computed for the row it just accepted — never a second, independent parse of
// the raw CSV columns, so the two can never silently disagree (Ollama code review finding).
class CarvedDeletedTally {
  private readonly counts = new Map<string, number>();
  private carvedTotal = 0;
  private deletedTotal = 0;

  record(
    operation: SqliteRowStateOperation,
    fileSource: SqliteFileSource,
    cellSource: SqliteCellSource,
  ): void {
    if (operation !== "Carved" && operation !== "Deleted") return;
    if (operation === "Carved") this.carvedTotal += 1;
    else this.deletedTotal += 1;
    const key = `${operation}|${fileSource}|${cellSource}`;
    this.counts.set(key, (this.counts.get(key) ?? 0) + 1);
  }

  isEmpty(): boolean {
    return this.carvedTotal === 0 && this.deletedTotal === 0;
  }

  // Ordinal, not localeCompare — the report text must be byte-reproducible across locales/ICU
  // versions, not merely stable within one (Ollama code review finding).
  private breakdown(operation: SqliteRowStateOperation): string {
    return [...this.counts.entries()]
      .filter(([key]) => key.startsWith(`${operation}|`))
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([key, count]) => {
        const [, fileSource, cellSource] = key.split("|");
        return `${count} via ${fileSource}/${cellSource}`;
      })
      .join(", ");
  }

  /** Builds the one summary MappedEvent for this report, or null when nothing to report. Never a
   * timestamp, never an intent claim — mirrors the per-row disclosure convention exactly.
   * `rowsTruncated` must name the SAME MAX_ROWS_SCANNED cap the per-row events were subject to —
   * a partial tally presented as complete would itself be a report-integrity defect (Ollama code
   * review finding). The disclosure clause is a PROTECTED SUFFIX, appended after `clip()`, so an
   * unbounded number of distinct (fileSource, cellSource) combinations can never truncate it away
   * (Ollama code review finding: the hedge was previously inside the clipped portion). */
  toEvent(
    tableName: string,
    tableNameSource: "filename" | "unavailable",
    reportFingerprint: string,
    rowsTruncated: boolean,
    matchedHighValueLabel: string | undefined,
  ): MappedEvent | null {
    if (this.isEmpty()) return null;
    const tableLabel =
      tableNameSource === "filename" && tableName
        ? `(from filename) ${tableName}`
        : "(table name unavailable)";
    const cleanTableLabel = tableLabel.replace(/[[\]]/g, "");
    const parts: string[] = [];
    if (this.carvedTotal > 0) parts.push(`${this.carvedTotal} Carved (${this.breakdown("Carved")})`);
    if (this.deletedTotal > 0) parts.push(`${this.deletedTotal} Deleted (${this.breakdown("Deleted")})`);
    const reportTag = `; report ${reportFingerprint.slice(0, 16)}`;
    const disclosure =
      `; consistent with routine database maintenance as well as intentional record removal; ` +
      `undated, no temporal correlation performed` +
      (rowsTruncated ? `; PARTIAL — counts reflect only the first ${MAX_ROWS_SCANNED} rows scanned` : "");
    // #1290 Part A — the SAME report-level match every row already carries (tableName is a
    // report-level derived value, not per-row content), so no re-matching is done here.
    const highValue = highValueClause(matchedHighValueLabel);
    // Clamped at 0 — a near-max-length analyst-configured label can push the reserved suffix
    // (highValue + disclosure + reportTag) past 600 on its own; `clip()`'s own budget must never go
    // negative, which `String.slice(0, negative)` would read as "trim from the end" instead of
    // "keep nothing" (code review finding, same class as `applyLatestForRowId`'s own fix).
    const variable = clip(
      `sqlite-dissect row-state summary: table ${cleanTableLabel} — ${parts.join(", ")}`,
      Math.max(0, 600 - reportTag.length - disclosure.length - highValue.length),
    );
    const description = `${variable}${disclosure}${highValue}${reportTag}`;
    const aggKey = boundedAggKey(`sqlite-row-state-summary|${reportFingerprint}`);
    return {
      timestamp: "",
      description,
      severity: "Info",
      mitre: [],
      aggKey,
      sources: ["sqlite-dissect"],
      ...(tableNameSource === "filename" && tableName ? { path: tableName } : {}),
      canonical: createCanonicalEvent({
        event: { category: "file", type: "sqlite-row-state-summary", action: "found" },
        time: { observed: "", normalized: "" },
        evidence: {
          rawRecords: [{ source: "sqlite-row-state", locator: `summary:${reportFingerprint.slice(0, 16)}` }],
        },
        // A distinct mapping version from the per-row "sqlite-row-state-v1"/"-v2" — this is a new
        // event type, not a schema revision of the per-row `sqliteRowState` canonical block —
        // Ollama code review finding.
        producer: {
          importer: "sqlite-row-state",
          parserVersion: "1",
          mappingVersion: "sqlite-row-state-summary-v1",
        },
        // #1290 Part B — structured totals so a reader (the Hypothesis-hint route) never has to
        // parse the description's own prose. Genuinely new: the summary event carried no
        // `sqliteRowState`-family block before this, so a single literal version is correct here.
        sqliteRowStateSummary: {
          carvedTotal: this.carvedTotal,
          deletedTotal: this.deletedTotal,
          truncated: rowsTruncated,
          mappingVersion: "sqlite-row-state-summary-v1",
        },
      }),
    };
  }
}

function isValidHeader(header: string[]): boolean {
  if (header.length <= HEADER_PREFIX.length) return false;
  for (let i = 0; i < HEADER_PREFIX.length; i++) {
    if ((header[i] ?? "").trim().toLowerCase() !== HEADER_PREFIX[i]) return false;
  }
  return true;
}

// A strict, digits-only lexical form — never Number()'s own looseness (empty/whitespace coerces
// to 0, hex/scientific notation are accepted, and precision silently drops above 2**53). Codex
// code review finding: a missing page-number cell must be rejected as malformed, never read as
// page 0.
function parseNonNegativeInt(raw: string | undefined): number | null {
  if (raw === undefined || !/^\d+$/.test(raw)) return null;
  const n = Number(raw);
  return Number.isSafeInteger(n) ? n : null;
}

interface MappedRow {
  event: MappedEvent;
  // The SAME validated triple the event itself was built from — exposed so a caller-side tally
  // (CarvedDeletedTally) never independently re-parses the raw CSV columns and risks silently
  // disagreeing with what this function actually accepted (Ollama code review finding).
  operation: SqliteRowStateOperation;
  fileSource: SqliteFileSource;
  cellSource: SqliteCellSource;
  // #1152 — the SAME validated values needed for the deferred "latest per rowId" pass, and the
  // pre-clip/pre-suffix body text + report tag needed to rebuild a flagged row's description
  // within the existing 600-char budget (never appended past it).
  rowId?: string;
  versionNumber: number;
  columnsDigest: string;
  rawBody: string;
  reportTag: string;
  highValue: string;
}

function mapRow(
  header: string[],
  row: string[],
  reportFingerprint: string,
  tableName: string,
  tableNameSource: "filename" | "unavailable",
  matchedHighValueLabel: string | undefined,
): MappedRow | null {
  const fileSource = row[0] as SqliteFileSource;
  if (!(sqliteFileSources as readonly string[]).includes(fileSource)) return null;
  const versionNumber = parseNonNegativeInt(row[1]);
  const pageVersionNumber = parseNonNegativeInt(row[2]);
  const cellSource = row[3] as SqliteCellSource;
  if (!(sqliteCellSources as readonly string[]).includes(cellSource)) return null;
  const pageNumber = parseNonNegativeInt(row[4]);
  const location = parseNonNegativeInt(row[5]);
  const operation = row[6] as SqliteRowStateOperation;
  if (!(sqliteRowStateOperations as readonly string[]).includes(operation)) return null;
  const fileOffset = parseNonNegativeInt(row[7]);
  if (
    versionNumber === null ||
    pageVersionNumber === null ||
    pageNumber === null ||
    location === null ||
    fileOffset === null
  ) {
    return null;
  }
  const rowIdRaw = row[8] ?? "";
  const rowId = rowIdRaw === "" ? undefined : clip(rowIdRaw, MAX_FIELD_LEN);

  const columnNames = header.slice(HEADER_PREFIX.length);
  const boundedColumnNames = columnNames.slice(0, MAX_COLUMNS_PER_ROW);
  const notCitedColumns = Math.max(0, columnNames.length - boundedColumnNames.length);
  const columns = boundedColumnNames.map((name, i) => ({
    name: clip(name, MAX_FIELD_LEN),
    value: clip(row[HEADER_PREFIX.length + i] ?? "", MAX_VALUE_LEN),
  }));

  // No `index` component: two rows that agree on every field below (down to column content) are
  // genuinely the same observation, and collapsing them is the spec's own "correlate genuinely
  // distinct changes... not... every recovered copy" ask, not a collision to guard against.
  const columnsDigest = createHash("sha256").update(JSON.stringify(columns)).digest("hex");
  const findingId = createHash("sha256")
    .update(
      JSON.stringify([
        tableName,
        operation,
        fileSource,
        cellSource,
        pageNumber,
        location,
        fileOffset,
        versionNumber,
        pageVersionNumber,
        rowId ?? null,
        columnsDigest,
      ]),
    )
    .digest("hex");
  const aggKey = boundedAggKey(`sqlite-row-state|${reportFingerprint}|${findingId}`);

  // Brackets stripped (never straight into free-text description) — a crafted upload filename
  // could otherwise forge a `[noteName: ...]` derived-note marker that a later merge picks up as
  // if it were a real provenance annotation (Codex code review finding).
  const tableLabel = (tableName || "(table name unavailable)").replace(/[[\]]/g, "");
  const reportTag = `; report ${reportFingerprint.slice(0, 16)}`;
  // Version/page-version/location/rowId included so two history rows sharing a page/offset (the
  // common case for successive updates to the SAME physical slot) never read as identical text
  // once aggKey is stripped at persistence (Codex code review finding).
  const rowIdPart = rowId ? `, row ${rowId}` : "";
  const rawBody =
    `sqlite-dissect row state: table ${tableLabel} — ${operation} via ${fileSource}/${cellSource} at page ` +
    `${pageNumber} offset ${fileOffset} (v${versionNumber}/pv${pageVersionNumber}, loc ${location}${rowIdPart}); ` +
    `a structural fact, never proof of intent; [undated: sqlite-dissect's report carries no event time]`;
  // #1290 Part A's own clause is known immediately (report-level match, not deferred); #1152's own
  // "latest" clause is NOT known yet (needs every row in the report) — the initial description
  // below carries only the former. `applyLatestForRowId` rebuilds it for any flagged row, reusing
  // `rawBody`/`reportTag`/`highValue` so the 600-char budget is honoured either way.
  const highValue = highValueClause(matchedHighValueLabel);
  // Clamped at 0 for the same reason as the summary's own budget above.
  const description = `${clip(rawBody, Math.max(0, 600 - reportTag.length - highValue.length))}${highValue}${reportTag}`;

  const event: MappedEvent = {
    timestamp: "",
    description,
    severity: "Info",
    mitre: [],
    aggKey,
    sources: ["sqlite-dissect"],
    // Structured, tagger-matchable identity (#1144) — same filename-derived value already carried
    // in the canonical block's own tableName/tableNameSource, never a claim of a verified database
    // identity. Unset when unavailable, never a fabricated path.
    ...(tableNameSource === "filename" && tableName ? { path: tableName } : {}),
    canonical: createCanonicalEvent({
      event: { category: "file", type: "sqlite-row-state", action: "found" },
      time: { observed: "", normalized: "" },
      evidence: { rawRecords: [{ source: "sqlite-row-state", locator: `row:${findingId.slice(0, 16)}` }] },
      producer: { importer: "sqlite-row-state", parserVersion: "1", mappingVersion: "sqlite-row-state-v2" },
      sqliteRowState: {
        tool: "sqlite-dissect",
        tableName: clip(tableName, MAX_FIELD_LEN),
        tableNameSource,
        operation,
        fileSource,
        cellSource,
        ...(rowId ? { rowId } : {}),
        location,
        pageNumber,
        fileOffset,
        versionNumber,
        pageVersionNumber,
        columns,
        notCitedColumns,
        reportFingerprint,
        mappingVersion: "sqlite-row-state-v2",
        basis: SQLITE_ROW_STATE_BASIS_V2,
        ...(matchedHighValueLabel ? { matchedHighValueLabel } : {}),
      },
    }),
  };
  return {
    event,
    operation,
    fileSource,
    cellSource,
    rowId,
    versionNumber,
    columnsDigest,
    rawBody,
    reportTag,
    highValue,
  };
}

/** Phase 2 of the per-report pass (#1152): rebuilds the description and canonical block for every
 * row `computeLatestForRowId` flagged, within the SAME 600-char budget `mapRow` already used —
 * never appended past it. Skipped entirely by the caller when the report was truncated. Mutates
 * `mapped` in place by replacing the flagged indices' own entries with a new object (never mutating
 * the existing `MappedEvent`, which callers may treat as structurally shared). */
function applyLatestForRowId(mapped: MappedEvent[], rows: readonly MappedRow[]): void {
  const facts: LatestRowFacts[] = rows.map((r) => ({
    rowId: r.rowId,
    versionNumber: r.versionNumber,
    columnsDigest: r.columnsDigest,
    operation: r.operation,
  }));
  for (const { index, ambiguous, multiMember, carvedAtOrAboveWinningVersion } of computeLatestForRowId(
    facts,
  )) {
    const row = rows[index];
    const clause = latestClause(
      row.rowId!,
      row.operation,
      ambiguous,
      multiMember,
      carvedAtOrAboveWinningVersion,
    );
    const suffix = `${row.highValue}${clause}${row.reportTag}`;
    // Clamped at 0 — an oversized suffix (a long configured label + a long rowId's own clause)
    // must never flip `clip()`'s own budget negative, which `String.slice(0, negative)` would
    // read as "trim from the end," silently producing a longer-than-intended description instead
    // of the shorter one this budget exists to guarantee (code review finding).
    const description = `${clip(row.rawBody, Math.max(0, 600 - suffix.length))}${suffix}`;
    const prior = mapped[index];
    mapped[index] = {
      ...prior,
      description,
      canonical: {
        ...prior.canonical!,
        sqliteRowState: {
          ...prior.canonical!.sqliteRowState!,
          latestForRowId: ambiguous ? undefined : (true as const),
          latestForRowIdAmbiguous: ambiguous ? (true as const) : undefined,
        },
      },
    };
  }
}

export function parseSqliteRowStateCsv(
  text: string,
  opts: SqliteRowStateOptions = {},
): SqliteRowStateResult | null {
  const it = parseCsvRecords(text);
  const first = it.next();
  if (first.done) return null;
  const header = first.value;
  if (!isValidHeader(header)) return null;

  const { tableName, tableNameSource } = deriveTableName(opts.sourceLabel);
  const reportFingerprint = createHash("sha256").update(text).digest("hex");
  // #1290 Part A — computed ONCE per report: `tableName` is a report-level derived value, not
  // per-row content, so every row in this import shares the same match (or lack of one).
  const highValueLabels = parseHighValueLabels(process.env.DFIR_SQLITE_HIGH_VALUE_LABELS);
  const matchedHighValueLabel = matchHighValueLabel(tableName, tableNameSource, highValueLabels);

  const mapped: MappedEvent[] = [];
  const rows: MappedRow[] = [];
  const tally = new CarvedDeletedTally();
  let total = 0;
  let malformedRows = 0;
  let rowsTruncated = false;
  let scanned = 0;

  for (const row of it) {
    // Report-wide bound checked INSIDE this loop, not only between calls — item 7's own lesson
    // applied from the start.
    if (scanned >= MAX_ROWS_SCANNED) {
      rowsTruncated = true;
      break;
    }
    scanned += 1;
    total += 1;
    if (row.length !== header.length) {
      malformedRows += 1;
      continue;
    }
    const mappedRow = mapRow(
      header,
      row,
      reportFingerprint,
      tableName,
      tableNameSource,
      matchedHighValueLabel,
    );
    if (!mappedRow) {
      malformedRows += 1;
      continue;
    }
    mapped.push(mappedRow.event);
    rows.push(mappedRow);
    tally.record(mappedRow.operation, mappedRow.fileSource, mappedRow.cellSource);
  }

  // #1152 — a partial scan cannot honestly claim "the highest recorded version," so the whole
  // derivation is skipped (never a partial-latest claim) when `rowsTruncated`.
  if (!rowsTruncated) applyLatestForRowId(mapped, rows);

  const { events, groups } = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: "Info",
    maxEvents: opts.maxEvents ?? MAX_ROWS_SCANNED,
  });

  // Captured BEFORE the summary event is pushed below: `kept` reports the count of mapped rows,
  // not row-plus-summary-line, so it stays consistent with `total` (rows scanned) for the
  // "N row(s) from M scanned" string rendered in recoveryImports.ts.
  const kept = events.length;

  // Appended AFTER aggregation/capping, never through it — pushing the summary into `mapped`
  // would leave it subject to the same `maxEvents` slice as every per-row event, and a count-1
  // summary sorts BEHIND any collapsed group with count > 1, so a large report could silently
  // drop the one line meant to survive everything else (Ollama code review finding). Discloses
  // `rowsTruncated` explicitly rather than presenting a partial tally as complete.
  const summaryEvent = tally.toEvent(
    tableName,
    tableNameSource,
    reportFingerprint,
    rowsTruncated,
    matchedHighValueLabel,
  );
  if (summaryEvent) {
    events.push({
      id: "",
      timestamp: "",
      description: summaryEvent.description,
      severity: "Info",
      mitreTechniques: [],
      aggKey: summaryEvent.aggKey,
      sources: summaryEvent.sources ? [...summaryEvent.sources] : undefined,
      ...(summaryEvent.path ? { path: summaryEvent.path } : {}),
      canonical: summaryEvent.canonical,
    });
  }

  return {
    events,
    iocs: [],
    total,
    kept,
    dropped: malformedRows,
    groups,
    format: "SqliteDissectCommitCsv",
    malformedRows,
    rowsTruncated,
    tableName,
    tableNameSource,
  };
}
