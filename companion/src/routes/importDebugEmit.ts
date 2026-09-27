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
  if (!debug || !debug.finish(outcome)) return; // an attempt already closed writes no second line
  getServerLogger().debug(formatImportDebugLine(debug.summary()), { caseId });
}

/**
 * An attempt the route refused after detection (#1736): unknown format, no AI provider, budget, AI
 * off. The reason is a code literal; the refusal closes the recorder so the line is written once.
 */
export function emitImportRefused(
  caseId: string,
  debug: ImportDebugRecorder | undefined,
  reason: string,
): void {
  debug?.observed(reason);
  emitImportDebug(caseId, debug, "refused");
}
