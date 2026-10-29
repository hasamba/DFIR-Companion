import { StateLock } from "../analysis/stateLock.js";
import { currentGeneration } from "./caseIncarnation.js";

export type SequenceKind = "capture" | "import" | "custody";

interface HighWaterMark {
  seq: number;
  generation: string;
}

/**
 * Hands out evidence sequence numbers per case+kind for CaseStore (captures, imports, custody).
 *
 * Serialized per case+kind (#214). Reading "audit-log length + 1" is a read-modify-write: two
 * ingestions racing for the same case both read the same length and both got the same number, and
 * when their filenames also matched, one evidence file silently overwrote the other. The lock makes
 * allocation atomic; the high-water mark makes it correct even before the audit line lands.
 */
export class SequenceAllocator {
  private readonly lock = new StateLock();

  // Highest sequence number handed out per `<kind>:<caseId>` in this process. The audit line is
  // appended AFTER the evidence is written, so between reserving a number and recording it the log
  // still has its old length — without this, a second caller arriving in that window would read the
  // same length and reuse the number. Numbers are therefore never reused, only ever skipped (a
  // failed ingestion burns its number, which is the safe direction for provenance). Each mark
  // carries the case incarnation (#1855 generation) it was read for.
  private readonly highWater = new Map<string, HighWaterMark>();

  constructor(private readonly casesRoot: string) {}

  /** Reserve the next never-yet-used sequence number for this case+kind. */
  reserve(kind: SequenceKind, caseId: string, maxOnDisk: () => Promise<number>): Promise<number> {
    const key = `${kind}:${caseId}`;
    return this.lock.runExclusive(key, async () => {
      // Disk is authoritative across restarts (the map starts empty); the map is authoritative
      // for numbers already handed out but not yet appended. The later of the two is correct.
      // `maxOnDisk` must return the HIGHEST recorded sequence number, never a line count (#1119):
      // a reservation burned by a failed append (no line written) still consumed a number, so a
      // line count under-reports how many numbers were actually issued once the process restarts
      // and the map resets — max(sequenceNumber) is correct regardless of any such gaps.
      //
      // The log is read once per case incarnation per process, never per allocation (#2253): every
      // number in it was handed out by this allocator, so after the cold-start read the mark is
      // already at or past the log's highest number. Re-reading it made a capture session O(n²).
      // A mark from another incarnation forces the read again — a delete or reseed clears marks
      // (forget), and a whole-case import publishes a fresh generation by rename, never through
      // the store. A read that throws caches nothing, so a corrupted log keeps failing closed.
      // Captures only: the custody log can hold a line written outside this allocator (a crash
      // between append and pin write, #2150), so imports and custody keep reading the log.
      const generation = currentGeneration(this.casesRoot, caseId);
      const mark = this.highWater.get(key);
      const next =
        kind === "capture" && mark && mark.generation === generation
          ? mark.seq + 1
          : Math.max((await maxOnDisk()) + 1, (mark?.seq ?? 0) + 1);
      this.highWater.set(key, { seq: next, generation });
      return next;
    });
  }

  /** Drop every mark held for a deleted or replaced case (#1866). */
  forget(caseId: string): void {
    for (const key of [...this.highWater.keys()]) {
      if (key.slice(key.indexOf(":") + 1) === caseId) this.highWater.delete(key);
    }
  }
}
