import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { atomicWrite } from "../storage/atomicWrite.js";
import { StateLock } from "./stateLock.js";
import type { CaseStore } from "../storage/caseStore.js";
import { mergeLearnedPattern, type LearnedPattern, type LearnedPatternInput } from "./learnedPatterns.js";

// Disk-backed per-case ledger of learned dismissal patterns (issue #65), in state/learned-patterns.json.
// A stateless wrapper over CaseStore (mirrors FalsePositiveStore) so a fresh instance reads/writes the same
// file. record() is the single mutation: it distils one reasoned dismissal through the pure merge core and
// persists only when something changed.
// Serializes a case's load->modify->save section on learned-patterns.json (follow-up to #682). A
// bulk dismissal calls record() once per finding, so a single analyst action is already a burst of
// read-modify-writes against one file; a second request landing inside that burst loses whatever it
// overlapped. What is lost is not a row but a REASON, and later synthesis is what consumes it — so
// the case silently stops learning from a dismissal the analyst did explain. MODULE-level: the app
// builds this store twice (runtimeStores.ts and aiProviders.ts).
const learnedPatternLock = new StateLock();

export class LearnedPatternStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "learned-patterns.json");
  }

  async load(caseId: string): Promise<LearnedPattern[]> {
    try {
      return JSON.parse(await readFile(this.path(caseId), "utf8")) as LearnedPattern[];
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
  }

  async save(caseId: string, patterns: LearnedPattern[]): Promise<void> {
    await atomicWrite(this.path(caseId), JSON.stringify(patterns, null, 2));
  }

  // Record one reasoned dismissal. Returns the updated ledger (persisted only when it actually changed —
  // an opaque/too-short signature is a no-op). `now` is injectable for deterministic tests.
  record(
    caseId: string,
    input: LearnedPatternInput,
    now: string = new Date().toISOString(),
  ): Promise<LearnedPattern[]> {
    return this.recordMany(caseId, [input], now);
  }

  // Record a whole batch in ONE load->merge->save. Dismissing forty findings used to call record()
  // forty times, so a single analyst action re-read and rewrote the entire ledger forty times over —
  // work that grows with the case, for one click. Folding the batch in memory makes it one write,
  // and it also means a bulk dismissal takes the lock once instead of contending with itself.
  // Persists only when the batch actually changed something (an opaque or too-short signature is a
  // no-op, exactly as it is for a single record).
  recordMany(
    caseId: string,
    inputs: readonly LearnedPatternInput[],
    now: string = new Date().toISOString(),
  ): Promise<LearnedPattern[]> {
    if (inputs.length === 0) return this.load(caseId);
    return learnedPatternLock.runExclusive(caseId, async () => {
      let patterns: LearnedPattern[] = await this.load(caseId);
      let changed = false;
      for (const input of inputs) {
        const merged = mergeLearnedPattern(patterns, input, now);
        patterns = merged.patterns;
        changed = changed || merged.changed;
      }
      if (changed) await this.save(caseId, patterns);
      return patterns;
    });
  }
}
