// #2891: make an import's end-of-import settle fail at a chosen point, against a real StateStore.
import { vi } from "vitest";
import type { StateStore } from "../../src/analysis/stateStore.js";

/**
 * Fail the settle's first page read of rows that already carry an import stamp — its dual-write,
 * AFTER the stamp and BEFORE the tagger. Returns whether it fired.
 */
export function failSettleAfterStamp(stateStore: StateStore, message = "out of memory"): () => boolean {
  const real = stateStore.forensicRowsById.bind(stateStore);
  let failed = false;
  vi.spyOn(stateStore, "forensicRowsById").mockImplementation(async (caseId, ids) => {
    const rows = await real(caseId, ids);
    if (!failed && rows.length && rows.every((r) => r.event.importBatchId)) {
      failed = true;
      throw new Error(message);
    }
    return rows;
  });
  return () => failed;
}
