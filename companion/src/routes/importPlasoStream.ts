import { stat } from "node:fs/promises";
import type { InvestigationState } from "../analysis/stateTypes.js";
import { formatImportCancelled, formatImportMerged, formatImportStart } from "../logging/importLog.js";
import type { ImportBase, RouteContext } from "./context.js";

/**
 * The streamed Plaso import with its log lines (#1438). `/import-file` and the job resume handler
 * hand a Plaso CSV straight to `pipeline.importPlasoFile` — it never crosses dispatchImport, where
 * every in-memory import writes its start and merged lines — so the lines live here, once, and both
 * callers use this in place of the pipeline call. The size comes from the stored file: the text was
 * never in memory. A cancelled import logs as cancelled and rethrows so the caller's own AbortError
 * handling still runs; a failure rethrows untouched, and recordImportFailure writes the FAILED line.
 */
export async function importPlasoFileLogged(
  ctx: RouteContext,
  caseId: string,
  storedPath: string,
  storedName: string,
  base: ImportBase,
): Promise<InvestigationState> {
  const { serverLogger: log, options } = ctx;
  if (!options.pipeline) throw new Error("pipeline is not configured");
  const bytes = await stat(storedPath)
    .then((s) => s.size)
    .catch(() => undefined);
  log.info(formatImportStart({ caseId, label: storedName, kind: "plaso", bytes }), { caseId });
  const startedAt = Date.now();
  try {
    const state = await options.pipeline.importPlasoFile(caseId, storedPath, base);
    log.info(formatImportMerged(caseId, storedName, Date.now() - startedAt), { caseId });
    return state;
  } catch (err) {
    if ((err as Error).name === "AbortError")
      log.info(formatImportCancelled(caseId, storedName, Date.now() - startedAt), { caseId });
    throw err;
  }
}
