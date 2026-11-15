/**
 * A stop raised right before an AI send (AI switched off, case closed, a cancel). Nothing was sent
 * and asking again would stop again, so `isRetryableError` never retries it. A new stop error
 * extends this class to join the same non-retryable group.
 */
export class SendStopped extends Error {}
