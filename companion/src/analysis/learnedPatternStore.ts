import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { atomicWrite } from "../storage/atomicWrite.js";
import type { CaseStore } from "../storage/caseStore.js";
import { mergeLearnedPattern, type LearnedPattern, type LearnedPatternInput } from "./learnedPatterns.js";

// Disk-backed per-case ledger of learned dismissal patterns (issue #65), in state/learned-patterns.json.
// A stateless wrapper over CaseStore (mirrors FalsePositiveStore) so a fresh instance reads/writes the same
// file. record() is the single mutation: it distils one reasoned dismissal through the pure merge core and
// persists only when something changed.
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
  async record(caseId: string, input: LearnedPatternInput, now: string = new Date().toISOString()): Promise<LearnedPattern[]> {
    const existing = await this.load(caseId);
    const { patterns, changed } = mergeLearnedPattern(existing, input, now);
    if (changed) await this.save(caseId, patterns);
    return patterns;
  }
}
