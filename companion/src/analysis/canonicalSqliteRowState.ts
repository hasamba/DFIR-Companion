// The envelope block one sqlite-dissect (DC3) commit-history CSV row carries (#932 item 8,
// "932.13"): a structural fact about one cell's presence/change in one table's commit history —
// main-database, WAL, rollback-journal or carved/freelist provenance. Never a claim about intent
// (a "Deleted" operation is not proof of deliberate deletion), never a "current state" verdict
// (this block only ever describes one observed operation, never a derived latest-wins view), and
// never an independent re-verification of the tool's own commit-boundary/committed-vs-uncommitted
// determination. Kept beside canonicalEvent.ts so the envelope schema stays within its size bound
// (mirrors canonicalOlevbaFinding.ts's own sibling-file pattern, #932 item 7).

import { z } from "zod";

export const sqliteRowStateTools = ["sqlite-dissect"] as const;
export type SqliteRowStateTool = (typeof sqliteRowStateTools)[number];

/** Real, confirmed `Operation` values, fetched live against sqlite-dissect's own
 * CommitCsvExporter._write_cells() call sites (csv_export.py). */
export const sqliteRowStateOperations = ["Added", "Updated", "Deleted", "Carved"] as const;
export type SqliteRowStateOperation = (typeof sqliteRowStateOperations)[number];

/** Real, confirmed FILE_TYPE enum values (constants.py). */
export const sqliteFileSources = ["DATABASE", "WAL", "WAL_INDEX", "ROLLBACK_JOURNAL"] as const;
export type SqliteFileSource = (typeof sqliteFileSources)[number];

/** Real, confirmed CELL_SOURCE enum values (constants.py). */
export const sqliteCellSources = ["B-Tree", "Disparate B-Tree", "Freelist"] as const;
export type SqliteCellSource = (typeof sqliteCellSources)[number];

export const MAX_FIELD_LEN = 300;
export const MAX_VALUE_LEN = 600;
export const MAX_COLUMNS_PER_ROW = 64;

export const SQLITE_ROW_STATE_BASIS =
  "a structural fact sqlite-dissect reported about this row's presence or change in this table's " +
  "commit history — Carved/Freelist-sourced content is recovered from unallocated space and its " +
  "identity, even its content boundaries, are the carving signature's own best-effort " +
  "reconstruction, never a live index read; a Deleted operation means the tool observed this " +
  "row's last known content before removal from the live b-tree, never proof of intent, and a gap " +
  "or an isolated freelist fragment does not by itself establish deliberate deletion; ordering " +
  "(versionNumber) reflects only the tool's own commit-boundary grouping of WAL frames, never an " +
  "independently re-verified committed/uncommitted determination";

export const sqliteRowStateBlockSchema = z.object({
  tool: z.enum(sqliteRowStateTools),
  // Sourced from the uploaded filename (best-effort) — the CSV's own content carries no table-name
  // field at all. No .min(1): an unparseable filename falls back to "" rather than crashing the
  // whole import (Codex design review finding on a prior item: never require non-empty when the
  // code's own fallback for that field is `?? ""`).
  tableName: z.string().max(MAX_FIELD_LEN),
  tableNameSource: z.enum(["filename", "unavailable"]),
  operation: z.enum(sqliteRowStateOperations),
  fileSource: z.enum(sqliteFileSources),
  cellSource: z.enum(sqliteCellSources),
  rowId: z.string().max(MAX_FIELD_LEN).optional(),
  location: z.number().int().nonnegative(),
  pageNumber: z.number().int().nonnegative(),
  fileOffset: z.number().int().nonnegative(),
  versionNumber: z.number().int().nonnegative(),
  pageVersionNumber: z.number().int().nonnegative(),
  columns: z
    .array(z.object({ name: z.string().max(MAX_FIELD_LEN), value: z.string().max(MAX_VALUE_LEN) }))
    .max(MAX_COLUMNS_PER_ROW),
  notCitedColumns: z.number().int().nonnegative(),
  reportFingerprint: z.string().length(64),
  mappingVersion: z.literal("sqlite-row-state-v1"),
  basis: z.literal(SQLITE_ROW_STATE_BASIS),
});
export type SqliteRowStateBlock = z.infer<typeof sqliteRowStateBlockSchema>;
