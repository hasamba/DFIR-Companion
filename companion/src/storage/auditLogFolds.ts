/**
 * What CaseStore reads out of its append-only audit logs (imports, custody, captures), through
 * AppendOnlyLogTail (#2584): the next-safe sequence number and the custody chain's tail.
 */
import { basename } from "node:path";
import { AuditLogNeedsRepairError } from "./auditLogNeedsRepairError.js";
import type { AppendOnlyLogTail, LogFold } from "./appendOnlyLogTail.js";
import type { SequenceKind } from "./sequenceAllocator.js";

export interface LogScope {
  caseId: string;
  generation: string;
}

/** Keeps nothing but the line count and last line AppendOnlyLogTail tracks anyway. */
const LINES_ONLY: LogFold<null> = { id: "lines", initial: null, step: () => null };

/**
 * The next-safe recovery number for an append-only .jsonl audit log; 0 when the log does not
 * exist yet. `Math.max(nonEmptyLineCount, highest value of `field` seen)` (#1119, Codex H1/M1):
 *   - a reservation burned by a failed append wrote no line, so a line count alone under-reports
 *     after a restart forgets the in-memory high-water mark — the field's own max recovers past it;
 *   - historical custody rows predate `seq` (#231) and would count as 0 toward the max — the line
 *     count still gives the right floor, exactly the pre-#1119 behavior for a fully legacy log.
 * A NON-EMPTY line that fails to parse is a truncated/corrupted write and THROWS (a burned
 * reservation and a corrupted append are indistinguishable from a count, so this fails closed and
 * asks for repair rather than risk reissuing that row's number). A parsed row lacking `field` is not
 * an error: it counts toward the line floor only. Throws AuditLogNeedsRepairError (#2252).
 * Still checked against the log on every call for imports and custody; since #2584 the last read's
 * answer is reused while the file is exactly as that read, or this process's own appendAuditLines,
 * left it. Any other change — another writer's append included — re-reads the whole file.
 */
export async function readMaxSequence(
  tails: AppendOnlyLogTail,
  scope: LogScope,
  kind: SequenceKind,
  path: string,
  field: "sequenceNumber" | "seq",
): Promise<number> {
  const fold: LogFold<{ count: number; maxField: number }> = {
    id: `max-${field}`,
    initial: { count: 0, maxField: 0 },
    step: (acc, line, index) => {
      let row: Record<string, unknown>;
      try {
        row = JSON.parse(line) as Record<string, unknown>;
      } catch (err) {
        throw new AuditLogNeedsRepairError(
          scope.caseId,
          kind,
          basename(path),
          index + 1,
          (err as Error).message,
        );
      }
      const value = row[field];
      const higher = typeof value === "number" && Number.isFinite(value) && value > acc.maxField;
      return { count: acc.count + 1, maxField: higher ? value : acc.maxField };
    },
  };
  const { state } = await tails.read(scope, path, fold);
  return Math.max(state.count, state.maxField);
}

/**
 * How many non-blank lines an audit log holds, and its last one verbatim (the custody chain links
 * to the last stored line). Served from the last read while the file is exactly as that read (or
 * this process's own append) left it; any other change is read in full.
 */
export async function readLogTail(
  tails: AppendOnlyLogTail,
  scope: LogScope,
  path: string,
): Promise<{ lineCount: number; lastLine: string | null }> {
  const { lineCount, lastLine } = await tails.read(scope, path, LINES_ONLY);
  return { lineCount, lastLine };
}
