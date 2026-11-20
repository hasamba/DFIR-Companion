// The server-log line for one failed attempt of an AI call, written by the pipeline's withRetry.
import { ProviderError } from "../../providers/provider.js";
import type { Logger } from "../../logging/logger.js";
import { isAbortError } from "../abortable.js";
import { isAiPreviewCapture } from "./aiPreviewScope.js";

/** Logs one failed attempt. Returns false when the error was not a failure (no retry to count). */
export function logAiCallFailure(
  log: Logger,
  caseId: string,
  label: string,
  err: unknown,
  attempt: number,
  willRetry: boolean,
): boolean {
  if (isAiPreviewCapture(err)) return false; // a preview stopping at the gate is not a failed call (#2491)
  if (isAbortError(err)) {
    // #2779: an analyst Stop is a cancel, not a failure or a timeout.
    log.info(`AI call [${label}] cancelled`, { caseId });
    return false;
  }
  const msg = err instanceof Error ? err.message : String(err);
  const kind = err instanceof ProviderError ? ` kind=${err.kind}` : "";
  log.warn(
    `AI call [${label}] attempt ${attempt + 1} failed${kind}: ${msg}${willRetry ? " — retrying" : " — giving up"}`,
    { caseId },
  );
  return true;
}
