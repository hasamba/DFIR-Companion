// sqlite-dissect's (DC3) default `-e csv` commit-history export, one CSV per table (#932 item 8,
// "932.13"): a structural fact about one cell's presence/change in one table's commit history —
// main-database, WAL, rollback-journal or carved/freelist provenance. Never a claim about intent,
// never a "current state" verdict (no latest-wins derivation is attempted here), and never an
// independent re-verification of the tool's own commit-boundary determination.
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
  SQLITE_ROW_STATE_BASIS,
  sqliteCellSources,
  sqliteFileSources,
  sqliteRowStateOperations,
  type SqliteCellSource,
  type SqliteFileSource,
  type SqliteRowStateOperation,
} from "./canonicalSqliteRowState.js";
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

function mapRow(
  header: string[],
  row: string[],
  reportFingerprint: string,
  tableName: string,
  tableNameSource: "filename" | "unavailable",
): MappedEvent | null {
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
  const body = clip(
    `sqlite-dissect row state: table ${tableLabel} — ${operation} via ${fileSource}/${cellSource} at page ` +
      `${pageNumber} offset ${fileOffset} (v${versionNumber}/pv${pageVersionNumber}, loc ${location}${rowIdPart}); ` +
      `a structural fact, never proof of intent; [undated: sqlite-dissect's report carries no event time]`,
    600 - reportTag.length,
  );
  const description = `${body}${reportTag}`;

  return {
    timestamp: "",
    description,
    severity: "Info",
    mitre: [],
    aggKey,
    sources: ["sqlite-dissect"],
    canonical: createCanonicalEvent({
      event: { category: "file", type: "sqlite-row-state", action: "found" },
      time: { observed: "", normalized: "" },
      evidence: { rawRecords: [{ source: "sqlite-row-state", locator: `row:${findingId.slice(0, 16)}` }] },
      producer: { importer: "sqlite-row-state", parserVersion: "1", mappingVersion: "sqlite-row-state-v1" },
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
        mappingVersion: "sqlite-row-state-v1",
        basis: SQLITE_ROW_STATE_BASIS,
      },
    }),
  };
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

  const mapped: MappedEvent[] = [];
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
    const event = mapRow(header, row, reportFingerprint, tableName, tableNameSource);
    if (!event) {
      malformedRows += 1;
      continue;
    }
    mapped.push(event);
  }

  const { events, groups } = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: "Info",
    maxEvents: opts.maxEvents ?? MAX_ROWS_SCANNED,
  });

  return {
    events,
    iocs: [],
    total,
    kept: events.length,
    dropped: malformedRows,
    groups,
    format: "SqliteDissectCommitCsv",
    malformedRows,
    rowsTruncated,
    tableName,
    tableNameSource,
  };
}
