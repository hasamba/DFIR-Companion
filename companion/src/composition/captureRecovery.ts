/**
 * The watermark rule for screenshot analysis, and the hold that keeps failed captures owed (#2248).
 *
 * `lastAnalyzedSeq` means "every capture at or below this sequence number has been dealt with".
 * Before #2248 a successful window simply moved it to its own highest sequence number, so a failed
 * window below it was skipped for good — and backfill, which selects `seq > lastAnalyzedSeq`, could
 * never find it again.
 *
 * Now a failed window opens a HOLD. While a hold exists, the watermark stays below the lowest failed
 * capture, and the hold remembers which captures failed and the highest one analyzed since. The
 * captures still owed are then re-derived from captures.jsonl: the failed ones, plus anything newer
 * than the highest analyzed one. Windows that succeeded in between are not sent again.
 *
 * Recovery is capped and backed off, so a permanent error (bad key, model gone, a missing image)
 * stops after `maxAttempts` tries instead of re-spending a paid call every sweep. A hold that gave
 * up stays on disk, with the failure marker, so the analyst can see it; the AI off→on catch-up
 * still tries it again on request.
 *
 * Pure functions only: the caller reads the control, asks for a patch, and writes it.
 */
import type { AiControl, AnalysisHold } from "../analysis/aiControl.js";
import type { CaptureMetadata } from "../types.js";

export interface RecoveryPolicy {
  maxAttempts: number;
  backoffMs: number;
}

/** Three tries, the first a minute after the failure; the 5-minute sweep is the real cadence. */
export const DEFAULT_RECOVERY_POLICY: RecoveryPolicy = { maxAttempts: 3, backoffMs: 60_000 };

export function recoveryPolicy(opts?: Partial<RecoveryPolicy>): RecoveryPolicy {
  return { ...DEFAULT_RECOVERY_POLICY, ...(opts ?? {}) };
}

/** captures.jsonl, one capture per line. A torn line (crash mid-append) is skipped and counted. */
export function parseCaptureLog(text: string): { captures: CaptureMetadata[]; skipped: number } {
  const captures: CaptureMetadata[] = [];
  let skipped = 0;
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      captures.push(JSON.parse(trimmed) as CaptureMetadata);
    } catch {
      skipped += 1;
    }
  }
  return { captures, skipped };
}

/**
 * The captures still owed, oldest first. `exclude` is what the live buffer already holds — those
 * go out with the next flush, so sending them here too would analyze them twice. `skipHeld` leaves
 * the hold's failed captures out — for a pass that must not spend a recovery attempt (#2249).
 */
export function pendingCaptures(
  captures: readonly CaptureMetadata[],
  control: AiControl,
  exclude: ReadonlySet<number> = new Set(),
  skipHeld = false,
): CaptureMetadata[] {
  const hold = control.analysisHold;
  const failed = new Set(hold?.failedSeqs ?? []);
  const owed = (seq: number) =>
    !hold || seq > hold.analyzedThrough ? !(skipHeld && failed.has(seq)) : failed.has(seq) && !skipHeld;
  return captures
    .filter((c) => !c.isDuplicate && c.sequenceNumber > control.lastAnalyzedSeq)
    .filter((c) => owed(c.sequenceNumber))
    .filter((c) => !exclude.has(c.sequenceNumber))
    .sort((a, b) => a.sequenceNumber - b.sequenceNumber);
}

/** The control patch after a window of `seqs` was analyzed. Never lowers the watermark. */
export function afterWindowSuccess(control: AiControl, seqs: readonly number[]): Partial<AiControl> {
  const maxSeq = Math.max(...seqs);
  const hold = control.analysisHold;
  if (!hold) return maxSeq > control.lastAnalyzedSeq ? { lastAnalyzedSeq: maxSeq } : {};
  const done = new Set(seqs);
  const failedSeqs = hold.failedSeqs.filter((s) => !done.has(s));
  const analyzedThrough = Math.max(hold.analyzedThrough, maxSeq);
  if (failedSeqs.length === 0) {
    return { lastAnalyzedSeq: Math.max(control.lastAnalyzedSeq, analyzedThrough), analysisHold: undefined };
  }
  return {
    lastAnalyzedSeq: Math.max(control.lastAnalyzedSeq, Math.min(...failedSeqs) - 1),
    analysisHold: { ...hold, failedSeqs, analyzedThrough },
  };
}

/** Recovery found nothing owed (e.g. the failed captures are not in the log): release the hold. */
export function releaseHold(control: AiControl): Partial<AiControl> {
  const hold = control.analysisHold;
  if (!hold) return {};
  return {
    lastAnalyzedSeq: Math.max(control.lastAnalyzedSeq, hold.analyzedThrough),
    analysisHold: undefined,
  };
}

/**
 * The control patch after a window of `seqs` failed. `recovery` says whether this was a recovery
 * attempt: only those count against `maxAttempts`, so the cap bounds the EXTRA calls recovery makes.
 */
export function afterWindowFailure(
  control: AiControl,
  seqs: readonly number[],
  error: string,
  recovery: boolean,
  policy: RecoveryPolicy,
  now: number = Date.now(),
): Partial<AiControl> {
  const prior: AnalysisHold = control.analysisHold ?? {
    failedSeqs: [],
    analyzedThrough: control.lastAnalyzedSeq,
    attempts: 0,
  };
  const failedSeqs = [...new Set([...prior.failedSeqs, ...seqs])].sort((a, b) => a - b);
  const attempts = prior.attempts + (recovery ? 1 : 0);
  const delay = policy.backoffMs * 2 ** Math.max(0, attempts - 1);
  const hold: AnalysisHold = {
    failedSeqs,
    analyzedThrough: prior.analyzedThrough,
    attempts,
    nextAttemptAt: new Date(now + delay).toISOString(),
    lastError: error,
    ...(prior.gaveUp || attempts >= policy.maxAttempts ? { gaveUp: true } : {}),
  };
  return {
    lastAnalyzedSeq: Math.min(control.lastAnalyzedSeq, Math.min(...failedSeqs) - 1),
    analysisHold: hold,
  };
}

/** Is an automatic recovery attempt due now? */
export function recoveryDue(control: AiControl, now: number = Date.now()): boolean {
  const hold = control.analysisHold;
  if (!hold || hold.gaveUp) return false;
  return !hold.nextAttemptAt || now >= Date.parse(hold.nextAttemptAt);
}
