/**
 * The `onAiStatus` seam (#1438): every import path reports progress through one callback, so this
 * is the one place a progress line can reach the server log without touching thirty routes.
 *
 * Two jobs, in order: broadcast the REDACTED event to the case's dashboards exactly as appWiring
 * did inline (#1029 — `detail` may carry a raw err.message with an absolute path), then, when the
 * detail has the "<kind> import — done/total" shape, throttle it per case and log the survivor with
 * `{ caseId }` so it lands in the session log AND the case's own log. Enrichment, screenshot and
 * exposure-check statuses share the "extracting" phase but not the shape, so they never print.
 * Any status other than "analyzing" ends the case's import from the throttle's point of view, so
 * the next import logs its first progress at once.
 */
import type { AiStatusEvent } from "./appOptions.js";
import type { Logger } from "../logging/logger.js";
import {
  createImportProgressThrottle,
  IMPORT_PROGRESS_DETAIL,
  type ImportProgressThrottle,
} from "../logging/importLog.js";

export interface AiStatusHandlerDeps {
  broadcast: (caseId: string, event: AiStatusEvent) => void;
  /** The server logger, or a getter for it (the logger is swapped in after wiring, see serverLogger.ts). */
  logger: Logger | (() => Logger);
  throttle?: ImportProgressThrottle;
  /** Applied once, to the event that is both broadcast and logged. */
  redact: (event: AiStatusEvent) => AiStatusEvent;
}

export function createAiStatusHandler(
  deps: AiStatusHandlerDeps,
): (caseId: string, event: AiStatusEvent) => void {
  const throttle = deps.throttle ?? createImportProgressThrottle();
  const logger = (): Logger => (typeof deps.logger === "function" ? deps.logger() : deps.logger);
  return (caseId, event) => {
    const redacted = deps.redact(event);
    deps.broadcast(caseId, redacted);
    if (redacted.status !== "analyzing") {
      throttle.clear(caseId);
      return;
    }
    if (redacted.phase !== "extracting" || !redacted.detail || !IMPORT_PROGRESS_DETAIL.test(redacted.detail))
      return;
    const line = throttle.note(caseId, redacted.detail);
    if (line) logger().info(line, { caseId });
  };
}
