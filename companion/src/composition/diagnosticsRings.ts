/**
 * The Health/Diagnostics page's in-memory state (#118), lifted out of createApp by #416.
 *
 * Three capped records, all reset by a restart on purpose — they answer "what went wrong just now",
 * not "what has ever gone wrong", and the persistent record of that is the session log.
 *
 * WHY THE REDACTION IS ON THE WAY IN. Both rings are served to the client twice — as the
 * /diagnostics JSON report AND as the copy-to-clipboard text blob an analyst pastes into a bug
 * report — so redacting at each read is two chances to forget. Node's fs errors carry the full
 * path, and the cases root is the one thing that must not travel in a pasted diagnostic, so the
 * message is redacted once here, at the only door into the ring.
 *
 * `recordImportFailure` is also where every failed import's log line is written (#1438): the ring
 * and the log carry the SAME redacted message, and the log line names the file by its basename,
 * so an operator's absolute path never lands in the case log — that file travels with a case
 * export. It is the one FAILED line per failure; the import seams log start/merged/cancelled and
 * never FAILED, so a failure is not doubled.
 */
import { basename } from "node:path";
import { ProviderError } from "../providers/provider.js";
import { redactedErrorMessage } from "../analysis/redactPaths.js";
import type { ImporterFailure, AiError, ImporterRunStat } from "../analysis/diagnostics.js";
import { getServerLogger } from "../logging/serverLogger.js";
import { formatImportFailed } from "../logging/importLog.js";

/** How many entries each error ring keeps. Old entries fall off the end. */
const DIAG_RING = 50;

export interface DiagnosticsRings {
  /** When this app instance was constructed — the uptime shown on the Diagnostics page. */
  readonly appStartedAt: number;
  /** Newest-first ring of failed imports. Mutated in place; RouteContext hands out this array. */
  readonly recentImportFailures: ImporterFailure[];
  /** Newest-first ring of AI call failures. Mutated in place, same as above. */
  readonly recentAiErrors: AiError[];
  /**
   * Per-importer health (#84): the LAST run's outcome per custom (declarative) importer, keyed by
   * spec.id. Not a ring — only the latest run matters for a health view, so a later run overwrites.
   */
  readonly importerRunStats: Map<string, ImporterRunStat>;
  /** Redact absolute paths out of an error message. Exposed for callers that record their own text. */
  redactErr(err: unknown): string;
  recordImportFailure(caseId: string, kind: string, filename: string, err: unknown): void;
  recordAiError(caseId: string, phase: string, err: unknown): void;
  recordImporterRun(id: string, patch: Omit<ImporterRunStat, "lastRunAt">): void;
}

export function createDiagnosticsRings(casesRoot: string): DiagnosticsRings {
  const appStartedAt = Date.now();
  const recentImportFailures: ImporterFailure[] = [];
  const recentAiErrors: AiError[] = [];
  const importerRunStats = new Map<string, ImporterRunStat>();
  const redactErr = (err: unknown): string => redactedErrorMessage(err, [casesRoot]);

  return {
    appStartedAt,
    recentImportFailures,
    recentAiErrors,
    importerRunStats,
    redactErr,
    recordImportFailure(caseId, kind, filename, err) {
      const message = redactErr(err);
      recentImportFailures.unshift({
        at: new Date().toISOString(),
        caseId,
        kind,
        filename,
        error: message,
      });
      if (recentImportFailures.length > DIAG_RING) recentImportFailures.length = DIAG_RING;
      getServerLogger().warn(formatImportFailed({ caseId, label: basename(filename), kind, message }), {
        caseId,
      });
    },
    recordAiError(caseId, phase, err) {
      const kind = err instanceof ProviderError ? err.kind : "other";
      recentAiErrors.unshift({ at: new Date().toISOString(), caseId, phase, kind, detail: redactErr(err) });
      if (recentAiErrors.length > DIAG_RING) recentAiErrors.length = DIAG_RING;
    },
    recordImporterRun(id, patch) {
      importerRunStats.set(id, { ...patch, lastRunAt: new Date().toISOString() });
    },
  };
}
