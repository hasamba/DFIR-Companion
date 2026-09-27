// Import debug recording for the memory importer (#1736). memoryImport.ts is frozen at its
// size-ledger cap, so what it records is computed here and called in one line each. Only column
// NAMES and code-authored slugs reach the recorder, never a cell value.

import type { ImportDebugRecorder } from "./importDebug.js";
import type { MemoryImportOptions, MemoryParseResult } from "./memoryImportTypes.js";
import { pickKey, pickTimeKey, PROC_NAME_KEYS, PROCESS_CREATE_KEYS } from "./memoryFields.js";
import { createFieldTally } from "./parseDebugTally.js";

/** Record which export-format parser a memory upload was routed to, and pass its result through. */
export function routed<T>(opts: MemoryImportOptions, code: string, result: T): T {
  opts.debug?.fallback(code);
  return result;
}

/** Record the parse's row counts, and pass its result through. */
export function counted<T extends MemoryParseResult>(opts: MemoryImportOptions, result: T): T {
  opts.debug?.counts({ total: result.total, kept: result.kept, dropped: result.dropped });
  return result;
}

/**
 * Which columns a process listing's name and start time came from. The top-level rows only: a
 * pstree's nested children use the same columns as their parents.
 */
export function recordProcessFields(debug: ImportDebugRecorder | undefined, rows: readonly object[]): void {
  if (!debug) return;
  const fields = createFieldTally();
  let undated = 0;
  for (const r of rows as readonly Record<string, unknown>[]) {
    const nameKey = pickKey(r, PROC_NAME_KEYS);
    if (nameKey) fields.add("process", nameKey);
    const timeKey = pickTimeKey(r, PROCESS_CREATE_KEYS);
    if (timeKey) fields.add("timestamp", timeKey);
    else undated += 1;
  }
  fields.flush(debug);
  if (undated) debug.observed("empty_timestamp", undated);
}
