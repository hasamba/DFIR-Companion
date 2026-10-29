import type { SequenceKind } from "./sequenceAllocator.js";

/**
 * A case's append-only audit log (captures, imports or custody) has a line that does not parse, so
 * no new sequence number can be allocated past it (#2252).
 *
 * The allocator fails closed on purpose (#1119, Codex H1): a truncated append and a burned
 * reservation look the same from a line count, so skipping the bad line risks handing out that
 * row's own number a second time. This type exists so a route can tell the analyst WHAT is wrong
 * and WHERE — the case, the file and the line — instead of answering a bare 500. Repair stays
 * manual: the analyst fixes or removes the named line, and the next allocation reads the log again.
 */
export class AuditLogNeedsRepairError extends Error {
  /** Machine-readable reason for a JSON body, e.g. "capture-log-needs-repair". */
  readonly code: string;

  constructor(
    readonly caseId: string,
    readonly kind: SequenceKind,
    /** The log's file name inside the case's metadata folder — never an absolute path. */
    readonly logFile: string,
    /** 1-based physical line number, as a text editor shows it. */
    readonly lineNumber: number,
    parseError: string,
  ) {
    super(
      `Case "${caseId}": its ${kind} log (${logFile}) has a corrupted/truncated line at line ${lineNumber}. ` +
        `No new ${kind} can be numbered until that line is repaired or removed by hand ` +
        `(sequence numbers fail closed so no evidence number is ever reused). Parser said: ${parseError}`,
    );
    this.name = "AuditLogNeedsRepairError";
    this.code = `${kind}-log-needs-repair`;
  }
}
