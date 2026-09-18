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
export const MAX_HIGH_VALUE_LABELS = 64;

export const SQLITE_ROW_STATE_BASIS =
  "a structural fact sqlite-dissect reported about this row's presence or change in this table's " +
  "commit history — Carved/Freelist-sourced content is recovered from unallocated space and its " +
  "identity, even its content boundaries, are the carving signature's own best-effort " +
  "reconstruction, never a live index read; a Deleted operation means the tool observed this " +
  "row's last known content before removal from the live b-tree, never proof of intent, and a gap " +
  "or an isolated freelist fragment does not by itself establish deliberate deletion; ordering " +
  "(versionNumber) reflects only the tool's own commit-boundary grouping of WAL frames, never an " +
  "independently re-verified committed/uncommitted determination";

// v2 (#1152): the one addition to the basis text — `latestForRowId`/`latestForRowIdAmbiguous` are
// a bounded, disclosed derivation, still never a live-database "current state" verdict. Old
// persisted v1 records keep the v1 text verbatim (see the union literal below) — this is a new
// sentence appended for new rows only, never a rewrite of the v1 text.
export const SQLITE_ROW_STATE_BASIS_V2 =
  SQLITE_ROW_STATE_BASIS +
  "; `latestForRowId` names only the highest-version NON-Carved row sharing a rowId within this " +
  "ONE report (never across reports, never claimed as the live database's current content, and " +
  "skipped entirely when the report was truncated) — Carved rows never win because their rowId is " +
  "itself a carving-signature reconstruction; `latestForRowIdAmbiguous` marks rows tied at that " +
  "highest version with different content, where no single latest state can be named; a reused " +
  "rowid can still combine two unrelated records' own history under one group";

const sqliteRowStateBlockObjectSchema = z.object({
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
  // Union, not a single literal (#1152 code review) — old v1 records must keep validating
  // unchanged; only NEW rows stamp v2 (the version that can carry the two fields below).
  mappingVersion: z.union([z.literal("sqlite-row-state-v1"), z.literal("sqlite-row-state-v2")]),
  basis: z.union([z.literal(SQLITE_ROW_STATE_BASIS), z.literal(SQLITE_ROW_STATE_BASIS_V2)]),
  // #1152 — set only on the single highest-version row for its rowId group, within this report,
  // and only when the report was not truncated (a partial scan cannot honestly claim "highest").
  // Carved rows never win (their rowId is a carving-signature reconstruction, not a live index
  // read) — see sqliteRowStateImport.ts's own `applyLatestForRowId`.
  latestForRowId: z.literal(true).optional(),
  // #1152 — set when two or more rows tied for the group's own highest version with DIFFERENT
  // content (`columnsDigest`) — which one is "the" latest cannot be determined from this report.
  latestForRowIdAmbiguous: z.literal(true).optional(),
  // #1290 Part A — the first analyst-configured high-value label (DFIR_SQLITE_HIGH_VALUE_LABELS)
  // that matched this row's own filename-derived `tableName`, stripped of `[`/`]` (same forgery
  // guard as `tableLabel`). Absent when no label list is configured or none matched.
  matchedHighValueLabel: z.string().max(MAX_FIELD_LEN).optional(),
});

// The two unions above are independent zod checks — without this, {mappingVersion: "v1", basis:
// BASIS_V2} or {mappingVersion: "v1", latestForRowId: true} would both validate, even though the
// schema's own comments promise mappingVersion/basis move together and only v2 rows carry the new
// fields (code review finding: the coupling was documented, never enforced).
export const sqliteRowStateBlockSchema = sqliteRowStateBlockObjectSchema.superRefine((val, ctx) => {
  const isV1 = val.mappingVersion === "sqlite-row-state-v1";
  if (isV1 && val.basis !== SQLITE_ROW_STATE_BASIS) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: "mappingVersion v1 must carry the v1 basis text",
      path: ["basis"],
    });
  }
  if (!isV1 && val.basis !== SQLITE_ROW_STATE_BASIS_V2) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: "mappingVersion v2 must carry the v2 basis text",
      path: ["basis"],
    });
  }
  if (isV1 && (val.latestForRowId !== undefined || val.latestForRowIdAmbiguous !== undefined)) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: "latestForRowId/latestForRowIdAmbiguous require mappingVersion v2",
      path: ["mappingVersion"],
    });
  }
});
export type SqliteRowStateBlock = z.infer<typeof sqliteRowStateBlockObjectSchema>;

// #1290 Part B — structured totals on the ONE per-report Carved/Deleted summary event (#1144).
// Genuinely new (the summary event carried no `sqliteRowState` block before this), so no old
// records to reconcile — a single literal mappingVersion is correct here, unlike the per-row block.
export const sqliteRowStateSummaryBlockSchema = z.object({
  carvedTotal: z.number().int().nonnegative(),
  deletedTotal: z.number().int().nonnegative(),
  // Mirrors the per-row `rowsTruncated` disclosure — a Hypothesis-hint reader must know the totals
  // may undercount, never present a partial tally as complete (#1144's own established lesson).
  truncated: z.boolean(),
  mappingVersion: z.literal("sqlite-row-state-summary-v1"),
});
export type SqliteRowStateSummaryBlock = z.infer<typeof sqliteRowStateSummaryBlockSchema>;
