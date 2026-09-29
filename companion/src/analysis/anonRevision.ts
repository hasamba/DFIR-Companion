// Per-case anonymization revision (#1840).
//
// An AI call snapshots the case's anonymization settings and entity lists, masks the prompt with
// that snapshot, and only then sends it — after an OCR pass and a Presidio scan that can take
// seconds. A "Hide from AI" that lands inside that window used to be ignored: the call sent the
// value in clear after Hide had already returned. So every analyst-side write of what the
// anonymizer reads bumps this counter, and the call re-checks it right before the provider request.
// On a change it masks again from fresh lists.
//
// Ordering contract, which is what makes the check sound:
//   - a caller reads the revision BEFORE it loads the lists;
//   - a writer bumps AFTER its write (in `finally`, so a failed write still forces a re-check).
// A write that finished before the load is in the snapshot. A write that finished after the load
// bumps before the route answers, so either the pre-send check sees it, or the request left before
// the analyst's click returned — and a request already sent cannot be recalled.
//
// In memory, MODULE-level and keyed by case id: the call and the writer share one process (a
// restart ends every call in flight), and every store instance must share one counter — the
// pipeline and the routes each build their own stores over the same files.
//
// The OCR pass's own auto-discovery write does not bump: it is not an analyst decision, and a bump
// there would make every screenshot call re-run OCR once over its own discoveries.

const revisions = new Map<string, number>();

/** The case's current anonymization revision. Starts at 0; only compared for equality. */
export function anonRevision(caseId: string): number {
  return revisions.get(caseId) ?? 0;
}

/** Record that something the anonymizer reads for this case has changed. */
export function bumpAnonRevision(caseId: string): void {
  revisions.set(caseId, anonRevision(caseId) + 1);
}

/**
 * The anonymization changed under a call, and the call held instead of sending. Nothing was sent;
 * the analyst runs it again. Thrown only after the call already tried to mask again and the
 * settings kept moving, or by a path that cannot mask again (a Jev review mid-run).
 */
export class AnonymizationChangedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AnonymizationChangedError";
  }
}

/** Hold the send when the revision moved since `maskedAt`. Synchronous: call it right before sending. */
export function assertAnonRevision(caseId: string, maskedAt: number, what: string): void {
  if (anonRevision(caseId) === maskedAt) return;
  throw new AnonymizationChangedError(
    `The anonymization settings or hidden values changed while ${what} was running, so the rest ` +
      `of it was not sent to the AI. Run it again.`,
  );
}
