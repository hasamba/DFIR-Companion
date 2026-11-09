/**
 * A case's job slot held in memory, without a job row (#2425).
 *
 * The job slot normally comes from a job row the ledger admitted. Two moments have work on the case
 * and no admitted row:
 * - a dedicated import the analyst cancelled while it runs: cancel() ends its row and frees the slot
 *   at once, but the importer only stops at its next check, and an import that kept earlier batches
 *   still has to settle them (tag → demote) before anything reads the case;
 * - a dedicated import the job ledger refused to record: it runs anyway, so the evidence is processed,
 *   with no row at all.
 * A hold covers both. While a case is held, the job manager admits no new job of that case — a
 * synthesis or another import waits, as it would behind an admitted row. Nothing here touches the
 * ledger, so a hold works when the ledger does not.
 */
export class CaseHolds {
  private readonly counts = new Map<string, number>();
  private waiters: Array<{ caseId: string; resolve: () => void }> = [];

  /**
   * `onRelease` runs when a hold ends, so queued work of the case is admitted again. `isIdle` says
   * whether none of the case's jobs is running.
   */
  constructor(
    private readonly onRelease: () => void,
    private readonly isIdle: (caseId: string) => boolean,
  ) {}

  isHeld(caseId: string | null): boolean {
    return caseId !== null && (this.counts.get(caseId) ?? 0) > 0;
  }

  /** Hold the case now. The returned release is idempotent. */
  hold(caseId: string): () => void {
    this.counts.set(caseId, (this.counts.get(caseId) ?? 0) + 1);
    let released = false;
    return () => {
      if (released) return;
      released = true;
      const left = (this.counts.get(caseId) ?? 1) - 1;
      if (left > 0) this.counts.set(caseId, left);
      else this.counts.delete(caseId);
      this.onRelease();
    };
  }

  /** Resolves once none of the case's jobs is running — checked now and on every `wake`. */
  whenIdle(caseId: string): Promise<void> {
    if (this.isIdle(caseId)) return Promise.resolve();
    return new Promise((resolve) => this.waiters.push({ caseId, resolve }));
  }

  /** Resolve the waiters whose case is idle now. The job manager calls it after each scheduling pass. */
  wake(): void {
    if (!this.waiters.length) return;
    const still: typeof this.waiters = [];
    for (const w of this.waiters) this.isIdle(w.caseId) ? w.resolve() : still.push(w);
    this.waiters = still;
  }
}
