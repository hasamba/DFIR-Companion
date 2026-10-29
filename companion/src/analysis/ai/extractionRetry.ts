import { ProviderError, type ProviderErrorKind } from "../../providers/provider.js";

/**
 * Extraction's own retry for transient provider errors (#2248).
 *
 * The shared policy in retry.ts treats `rate_limit` and `timeout` as walls, and the other AI paths
 * rely on that: the analyst is waiting on them. A screenshot window is background work, and before
 * this one 429 or one timeout lost the window's screenshots for good. So screenshot extraction, and
 * ONLY screenshot extraction, retries these two kinds a bounded number of times with a backoff.
 *
 * It wraps the shared withRetry rather than changing it, so auth, context, model, output_limit and
 * safety_stop still fail on the first throw. The provider clients do not carry a Retry-After value
 * on ProviderError today, so the backoff is a fixed doubling one.
 */

const TRANSIENT_KINDS: ReadonlySet<ProviderErrorKind> = new Set<ProviderErrorKind>(["rate_limit", "timeout"]);

/** Retries after the first try. Three calls at most, so a lasting outage stays cheap. */
export const EXTRACTION_TRANSIENT_RETRIES = 2;

/** The first wait is this many times the configured AI backoff; it doubles after that. */
const BACKOFF_FACTOR = 4;

export function isTransientExtractionError(err: unknown): boolean {
  return err instanceof ProviderError && TRANSIENT_KINDS.has(err.kind);
}

export async function withTransientRetry<T>(
  fn: () => Promise<T>,
  backoffMs: number,
  onRetry?: (err: unknown, attempt: number) => void,
  retries: number = EXTRACTION_TRANSIENT_RETRIES,
): Promise<T> {
  for (let attempt = 0; ; attempt++) {
    try {
      return await fn();
    } catch (err) {
      if (attempt >= retries || !isTransientExtractionError(err)) throw err;
      onRetry?.(err, attempt);
      await new Promise((r) => setTimeout(r, backoffMs * BACKOFF_FACTOR * 2 ** attempt));
    }
  }
}
