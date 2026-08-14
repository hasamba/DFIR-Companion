import { ProviderError, type ProviderErrorKind } from "../../providers/provider.js";
import { PresidioApprovalRequired, PresidioScanError } from "../presidio.js";

/**
 * Retry policy for AI calls (#418).
 *
 * Extracted from pipeline.ts with the rest of the AI machinery. The interesting part is what is NOT
 * retried: the point of the classification below is that some failures are a wall, not a blip, and
 * retrying them only triples how long the analyst waits for the same error.
 */

// Error kinds where the failure is inherent to the call (bad/expired creds, exhausted quota, a hung
// process) rather than a transient blip — retrying just re-runs into the same wall, tripling the wait
// before the analyst sees the same error.
const NON_RETRYABLE_KINDS = new Set<ProviderErrorKind>(["auth", "rate_limit", "timeout"]);

function isRetryableError(err: unknown): boolean {
  // An approval gate is not a transient failure. Retrying it re-runs the Presidio scan and delays
  // the 409 the analyst is waiting on, so surface it on the first throw.
  if (err instanceof PresidioApprovalRequired) return false;
  // A Presidio scan that ran out of budget is actively made WORSE by retrying, which is why it is
  // singled out from scan failures in general (a refused connection can still be a blip worth one
  // more go). Aborting the request does not cancel the analyzer's work, so the retry queues behind
  // the scan we just abandoned and is slower than the attempt before it — the same compounding
  // stall the timeout fix was written to end. It also multiplies the wait: at four attempts and a
  // 60s budget an analyst sits through ~240s to be told what attempt one already knew.
  if (err instanceof PresidioScanError && err.timedOut) return false;
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
