/**
 * A memory budget for the heavy whole-case reads (#2846).
 *
 * THE PROBLEM. The heavy-read gate (composition/heavyReadGate.ts) runs HEAVY_READ_CONCURRENCY reads
 * at once. That bounds how MANY run, not how much memory they take, and on a large case each one
 * builds gigabytes. On a synthetic 72,000-event case one dashboard open peaked at 8.6 GB RSS and a
 * second open on top of it at 9.8 GB; a 16 GB machine with 6 GB used by other programs had the server
 * killed by the kernel at 8.4 GB.
 *
 * THE BUDGET. Before a heavy read starts, the gate asks this budget whether its estimated cost fits
 * next to the reads already running. A read that does not fit WAITS — the case opens more slowly.
 * When no heavy read is running and it still does not fit, it waits up to HEAVY_READ_IDLE_HOLD_MS for
 * memory to come back (idle worker isolates hand their heaps back within seconds), and then starts
 * anyway: a case too large for the machine still opens, one read at a time. That one read is the
 * remaining limit — nothing here makes a single read smaller, so a kill is still possible on a
 * machine that cannot hold one read. The count cap stays as a backstop.
 *
 * THE ESTIMATE is linear in the case's forensic event count, like the import memory guard's
 * (analysis/importMemoryGuard.ts), whose count source and reservations it reuses. Measured on a
 * synthetic 72,000-event case, one GET at a time on an idle server (RSS sampled every 200 ms): the
 * costliest read, the cockpit's cold load, added 2.95 GB (41 KB per event); asset-graph and
 * evidence-graph 2.6 GB; geo-map, lateral-paths, attack-mitigations, d3fend, adversary-hints and
 * ioc-risk about 1.9 GB each; most of the rest far less. HEAVY_READ_BYTES_PER_EVENT covers the
 * costliest measured read; cheap reads (a cache hit) are over-charged, which costs only time on a
 * machine short of memory. It is a calibration on synthetic data, not a proven upper bound: a real
 * case with many findings and IOCs costs more per event. The checks below are strict to make up for
 * it. A case whose events cannot be counted is charged as too large to share (it runs alone).
 *
 * WHAT A READ MUST FIT IN: the memory the OS can still give the process (free memory, capped by a
 * container limit), less what other admitted heavy reads and imports have reserved. That is the
 * limit whose crossing gets the server killed. A running read's own growth is counted both in free
 * memory and in its reservation, which makes the check stricter, never looser: on a machine with
 * room to spare reads still run side by side; on one without, they run one by one.
 * Not the V8 heap: the estimate is the whole process's growth (worker isolates and native memory
 * included), far more than a read adds to the main heap, and charging it there held every read of a
 * large case at the default heap limits (Docker, the desktop build) on machines with plenty of
 * memory. Imports do not see the reads' reservations (analysis/importMemoryGuard.ts reads free
 * memory, which a running read has already used): the sharing is one way.
 *
 * The event count is read through the forensic index and kept per case for HEAVY_READ_COUNT_TTL_MS,
 * so a burst of 33 reads asks for it once.
 */
/** Estimated memory one heavy read builds, per forensic event in the case (see the header). */
export const HEAVY_READ_BYTES_PER_EVENT = 42 * 1024;
/** How long a case's event count is reused before it is read again. */
export const HEAVY_READ_COUNT_TTL_MS = 30_000;
/** While a read waits only for memory, how often the gate looks again (memory frees as GC runs). */
export const HEAVY_READ_BUDGET_RECHECK_MS = 1_000;
/** With no heavy read running, the longest a read waits for memory before it starts anyway. */
export const HEAVY_READ_IDLE_HOLD_MS = 30_000;

/** What the process can allocate now. */
export interface HeavyReadMemorySnapshot {
  /** Free memory the OS can still give the process, capped by any container limit. */
  availableBytes: number;
}

export interface HeavyReadBudget {
  /** Estimated bytes a heavy read of this case needs; 0 when it cannot be estimated. */
  estimate(caseId: string): Promise<number>;
  /** Whether a read needing `needBytes` fits next to `reservedBytes` already admitted. */
  fits(needBytes: number, reservedBytes: number): boolean;
}

export interface HeavyReadBudgetDeps {
  countEvents(caseId: string): Promise<number>;
  probe?: () => HeavyReadMemorySnapshot;
  /** Memory admitted imports have reserved (analysis/importMemoryGuard.ts). */
  importReservedBytes?: () => number;
  now?: () => number;
}

export function processHeavyReadSnapshot(): HeavyReadMemorySnapshot {
  return { availableBytes: process.availableMemory() };
}

export function createHeavyReadBudget(deps: HeavyReadBudgetDeps): HeavyReadBudget {
  const probe = deps.probe ?? processHeavyReadSnapshot;
  const now = deps.now ?? Date.now;
  const counts = new Map<string, { events: number; at: number }>();
  const pending = new Map<string, Promise<number>>();

  const countOf = (caseId: string): Promise<number> => {
    const held = counts.get(caseId);
    if (held && now() - held.at < HEAVY_READ_COUNT_TTL_MS) return Promise.resolve(held.events);
    const inFlight = pending.get(caseId);
    if (inFlight) return inFlight;
    const read = deps
      .countEvents(caseId)
      .then((events) => {
        const n = Number.isFinite(events) && events >= 0 ? events : Number.POSITIVE_INFINITY;
        if (Number.isFinite(n)) counts.set(caseId, { events: n, at: now() });
        return n;
      })
      .catch(() => Number.POSITIVE_INFINITY) // unknown size: run it alone, never next to another read
      .finally(() => pending.delete(caseId));
    pending.set(caseId, read);
    return read;
  };

  return {
    async estimate(caseId) {
      return (await countOf(caseId)) * HEAVY_READ_BYTES_PER_EVENT;
    },
    fits(needBytes, reservedBytes) {
      if (needBytes <= 0) return true;
      const imports = deps.importReservedBytes?.() ?? 0;
      return needBytes <= probe().availableBytes - imports - reservedBytes;
    },
  };
}
