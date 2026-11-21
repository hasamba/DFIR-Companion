// Row counts for imports whose audit line was written before the file was parsed (#2790).
//
// The Import button, Import-from-path and the drop folder append their metadata/imports.jsonl line
// evidence-first, before the importer has read a row, so that line says `rows: 0`. imports.jsonl is
// an append-only audit log where one line is one import (diagnostics, export, restore and the
// Velociraptor prior-import check all count lines), so the count is neither rewritten into it nor
// appended to it. It goes to this side file instead — one append-only line per finished import,
// keyed by the import's sequence number — and Case Statistics overlays it when it reads the log.

import { appendFile, mkdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import type { ImportMetadata } from "../types.js";

export const IMPORT_ROWS_FILE = "import-rows.jsonl";

/** What the import counted: rows read and events kept, as an import debug summary carries them. */
export interface ImportRowCounts {
  total?: number;
  kept?: number;
}

interface RowsStore {
  metadataDir(caseId: string): string;
  withCaseWrite<T>(path: string, fn: () => Promise<T>): Promise<T>;
}

/** The count to record: events kept (what the per-format routes record), else rows read. */
export function importedRowCount(counts: ImportRowCounts | undefined): number | undefined {
  const n = counts?.kept ?? counts?.total;
  return typeof n === "number" && Number.isFinite(n) && n >= 0 ? Math.floor(n) : undefined;
}

/**
 * Append one import's row count. Best-effort: the count feeds a statistics chart, so a failed write
 * never fails the import. Nothing is written when the importer reported no count.
 */
export async function recordImportRows(
  store: RowsStore,
  caseId: string,
  sequenceNumber: number,
  counts: ImportRowCounts | undefined,
): Promise<void> {
  const rows = importedRowCount(counts);
  if (rows === undefined) return;
  const dir = store.metadataDir(caseId);
  const path = join(dir, IMPORT_ROWS_FILE);
  try {
    await store.withCaseWrite(path, async () => {
      await mkdir(dir, { recursive: true });
      await appendFile(path, JSON.stringify({ sequenceNumber, rows }) + "\n", "utf8");
    });
  } catch {
    /* non-fatal — a missing count reads as the audit line's own `rows` */
  }
}

/** sequenceNumber → rows. A retried import may report twice; the last line wins. */
export async function readImportRows(store: RowsStore, caseId: string): Promise<Map<number, number>> {
  const out = new Map<number, number>();
  let text = "";
  try {
    text = await readFile(join(store.metadataDir(caseId), IMPORT_ROWS_FILE), "utf8");
  } catch {
    return out; // no counts recorded yet
  }
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    try {
      const rec = JSON.parse(line) as { sequenceNumber?: unknown; rows?: unknown };
      const rows = importedRowCount({ kept: rec.rows as number });
      if (typeof rec.sequenceNumber === "number" && rows !== undefined) out.set(rec.sequenceNumber, rows);
    } catch {
      /* skip a malformed line */
    }
  }
  return out;
}

/** The audit log with each recorded count laid over a `rows: 0` line. Returns new records. */
export function withRecordedRows(
  log: readonly ImportMetadata[],
  rows: ReadonlyMap<number, number>,
): ImportMetadata[] {
  return log.map((rec) => {
    const recorded = rows.get(rec.sequenceNumber);
    return recorded !== undefined && !rec.rows ? { ...rec, rows: recorded } : rec;
  });
}
