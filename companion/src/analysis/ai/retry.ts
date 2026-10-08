import { ProviderError, type ProviderErrorKind } from "../../providers/provider.js";
import { PresidioApprovalRequired, PresidioScanError } from "../presidio.js";
import { HostMergeDecisionRequired } from "../hostDuplicateGate.js";
import { OcrRedactionError } from "../ocrRedact.js";

/**
 * Retry policy for AI calls (#418).
 *
 * Extracted from pipeline.ts with the rest of the AI machinery. The interesting part is what is NOT
 * retried: the point of the classification below is that some failures are a wall, not a blip, and
 * retrying them only triples how long the analyst waits for the same error.
 */

// Error kinds where the failure is inherent to the call (bad/expired creds, exhausted quota, a hung
// process, a prompt or reply that does not fit) rather than a transient blip — retrying just re-runs
// into the same wall, tripling the wait before the analyst sees the same error.
// "output_limit": the model hit its output-token cap; the identical request hits it again.
// "safety_stop": the model's safety filter stopped the answer (#1734). Never retried HERE: synthesis
// runs its own bounded same-model retry (DFIR_AI_SYNTH_SAFETY_RETRIES, #1740) and then its fallback,
// and every other AI path fails fast rather than resending the same evidence.
const NON_RETRYABLE_KINDS = new Set<ProviderErrorKind>([
  "auth",
  "rate_limit",
  "timeout",
  "context",
  "output_limit",
  "safety_stop",
  "model", // the configured model is unavailable: retrying re-sends to the same refusal (#2042)
]);

function isRetryableError(err: unknown): boolean {
  // A cancelled or superseded run (#1608). Retrying it only calls the provider again for a result
  // nobody will keep.
  if (err instanceof Error && err.name === "AbortError") return false;
  // An approval gate is not a transient failure. Retrying it re-runs the Presidio scan and delays
  // the 409 the analyst is waiting on, so surface it on the first throw.
  if (err instanceof PresidioApprovalRequired) return false;
  // Same reasoning as the approval gate above: a merge decision is a wall, not a blip. Retrying
  // re-derives the identical pending list and delays the 409 the analyst is waiting on.
  if (err instanceof HostMergeDecisionRequired) return false;
  // A Presidio scan that could not run is never retried (#1945). A timeout is actively made WORSE
  // by a retry: aborting the request does not cancel the analyzer's work, so the retry queues
  // behind the scan we just abandoned and is slower than the attempt before it. A refused
  // connection was once retried as a possible blip, but a down analyzer stays down within a backoff
  // window — the analyst sat through four failed attempts and still had no clear answer. The first
  // failure is surfaced, and the analyst decides: start the analyzer, or stand the layer down for
  // the case. The gate fails closed either way; nothing unscanned reaches the model.
  if (err instanceof PresidioScanError) return false;
  // OCR that could not read a screenshot fails the same way on the same bytes (#1952).
  if (err instanceof OcrRedactionError) return false;
  return !(err instanceof ProviderError && NON_RETRYABLE_KINDS.has(err.kind));
}

export async function withRetry<T>(
  fn: () => Promise<T>,
  retries: number,
  backoffMs: number,
  onError?: (err: unknown, attempt: number, willRetry: boolean) => void,
): Promise<T> {
  let attempt = 0;
  for (;;) {
    try {
      return await fn();
    } catch (err) {
      const willRetry = attempt < retries && isRetryableError(err);
      onError?.(err, attempt, willRetry);
      if (!willRetry) throw err;
      await new Promise((r) => setTimeout(r, backoffMs * 2 ** attempt));
      attempt++;
    }
  }
}
