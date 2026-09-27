import { getServerLogger } from "../logging/serverLogger.js";
import {
  formatImportDebugLine,
  type ImportDebugRecorder,
  type ImportOutcome,
} from "../analysis/importDebug.js";

/**
 * Close an import attempt's debug recorder (#1736) and write its one `[import-debug]` line, scoped
 * to the case so it lands in the always-on debug log and the case log. Called at each terminal seam:
 * success (dispatchImport, commitDedicatedImport, the streamed paths), cancellation, and failure
 * (recordImportFailure). A missing recorder is a no-op, so an entry point not yet carrying one costs
 * nothing.
 */
export function emitImportDebug(
  caseId: string,
  debug: ImportDebugRecorder | undefined,
  outcome: ImportOutcome,
): void {
  if (!debug) return;
  debug.finish(outcome);
  getServerLogger().debug(formatImportDebugLine(debug.summary()), { caseId });
}
