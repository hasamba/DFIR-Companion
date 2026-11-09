import { ZodError } from "zod";
import type { Logger } from "../../logging/logger.js";

/** What the analyst sees when the AI answered, but not in the shape the work needs (#2459). */
export const AI_REPLY_UNREADABLE_MESSAGE =
  "The AI reply could not be read. Try again, or check the AI provider in Settings.";

/**
 * An AI reply that failed its schema after every retry (#2459). The zod issue list is a developer
 * detail: it goes to the server log, and the analyst gets one plain sentence with a next step.
 * The original ZodError stays on `cause` for anything that needs it.
 */
export class AiReplyUnreadableError extends Error {
  constructor(cause: ZodError) {
    super(AI_REPLY_UNREADABLE_MESSAGE, { cause });
    this.name = "AiReplyUnreadableError";
  }
}

/**
 * Turns a schema failure on an AI reply into AiReplyUnreadableError and logs the issue list;
 * every other error is returned unchanged.
 */
export function toReadableAiError(
  err: unknown,
  log: Logger | undefined,
  caseId: string,
  kind: string,
): unknown {
  if (!(err instanceof ZodError)) return err;
  log?.warn(`AI reply for ${kind} (case ${caseId}) failed its schema: ${JSON.stringify(err.issues)}`);
  return new AiReplyUnreadableError(err);
}
