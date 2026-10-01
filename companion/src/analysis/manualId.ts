/**
 * The id prefix of every analyst-authored row (analysis/manualEntry.ts mints it, and nothing else
 * does). An id that carries it names a row the analyst typed in — never one an import produced — so
 * the import settle and the import undo can tell a manual event added mid-import from the import's
 * own rows (#1904). A shared leaf so the import layer can read it without importing the workflow one.
 */
export const MANUAL_ID_PREFIX = "manual-";

export function isManualId(id: unknown): boolean {
  return typeof id === "string" && id.startsWith(MANUAL_ID_PREFIX);
}
