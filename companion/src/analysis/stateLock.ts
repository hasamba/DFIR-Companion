// Per-case async mutex: serializes critical sections that read-modify-write the same case's
// investigation.json (manual event/IOC adds, background enrichment, synthesis). Without it, two
// concurrent read-modify-writes race — the second save clobbers the first (lost update), so an
// analyst's just-added IOC/event can vanish when a background enrichment or re-synthesis save
// lands a moment later. Only the short load->save critical section is held; AI calls and network
// enrichment happen outside the lock so they never block the analyst.
export class StateLock {
  private readonly tails = new Map<string, Promise<unknown>>();

  runExclusive<T>(caseId: string, fn: () => Promise<T>): Promise<T> {
    const tail = this.tails.get(caseId) ?? Promise.resolve();
    const next = tail.then(fn, fn);
    // Keep the chain alive for the next caller, but let it settle so a rejection doesn't poison
    // every subsequent critical section for this case.
    const settled = next.then(
      () => {},
      () => {},
    );
    this.tails.set(caseId, settled);
    // Drop the entry once drained so the map can't grow without bound across cases.
    settled.finally(() => {
      if (this.tails.get(caseId) === settled) this.tails.delete(caseId);
    });
    return next;
  }
}
