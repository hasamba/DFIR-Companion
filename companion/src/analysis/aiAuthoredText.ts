import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import { StateLock } from "./stateLock.js";
import { AUTHORED_MAX_CHARS, AUTHORED_MIN_CHARS, normalizeAuthored } from "./ai/presidioAuthoredText.js";

/** Newest strings kept per case. Enough for many synthesis runs of a large case. */
export const AUTHORED_MAX_STRINGS = 3000;

/**
 * The text the synthesis model wrote for this case — summary, attacker path, finding titles and
 * descriptions — so the Presidio gate can tell it apart from events and analyst notes (see
 * ai/presidioAuthoredText.ts). Persisted so a restart does not bring the approval loop back for
 * text written before it. Model B's 2nd-opinion answer is recorded too: it is never saved to the
 * case state, yet the referee prompt quotes it.
 *
 * Holds real values, like the case state the same text already sits in. A missing or unreadable
 * file reads as empty, which means "skip nothing": the gate then holds every value, as before.
 */
// One lock for every instance: the anonymization route clears the record through its own instance,
// and a clear racing a pipeline instance's read-modify-write would bring the cleared strings back.
const lock = new StateLock();

export class AiAuthoredTextStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "ai-authored-text.json");
  }

  async load(caseId: string): Promise<string[]> {
    try {
      const raw = JSON.parse(await readFile(this.path(caseId), "utf8")) as { strings?: unknown };
      return sanitize(raw?.strings);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
  }

  /** Forget everything recorded for the case — masking or Presidio was switched off. */
  async clear(caseId: string): Promise<void> {
    await lock.runExclusive(caseId, () => atomicWrite(this.path(caseId), JSON.stringify({ strings: [] })));
  }

  /** Add strings, newest last; an already-recorded string moves to the end. Oldest drop past the cap. */
  async record(caseId: string, strings: readonly string[]): Promise<void> {
    const added = sanitize(strings);
    if (added.length === 0) return;
    await lock.runExclusive(caseId, async () => {
      const fresh = new Set(added);
      const kept = (await this.load(caseId)).filter((s) => !fresh.has(s));
      const all = [...kept, ...added].slice(-AUTHORED_MAX_STRINGS);
      await atomicWrite(this.path(caseId), JSON.stringify({ strings: all }));
    });
  }
}

function sanitize(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  const out = new Set<string>();
  for (const s of value) {
    if (typeof s !== "string") continue;
    const n = normalizeAuthored(s).slice(0, AUTHORED_MAX_CHARS);
    if (n.length >= AUTHORED_MIN_CHARS) out.add(n);
  }
  return [...out];
}
