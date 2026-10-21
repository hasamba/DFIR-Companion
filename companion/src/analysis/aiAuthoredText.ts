import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import { StateLock } from "./stateLock.js";
import {
  AUTHORED_MAX_CHARS,
  AUTHORED_MIN_CHARS,
  normalizeAuthored,
  withoutVisible,
} from "./ai/presidioAuthoredText.js";

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

/**
 * One recorded string, and the values the analyst had left visible ("Leave visible") when it was
 * recorded. The model may have learned from a visible value without repeating it whole — "Jane" from
 * "Jane Doe" — so when any of those values changes visibility, the string is forgotten.
 */
export interface AuthoredEntry {
  text: string;
  /** Case-folded suppressed values at record time. */
  visible: string[];
}

export interface RecordOptions {
  /** Asked inside the lock, so a clear or forget that lands first always wins over this write. */
  stillValid?: () => boolean;
  /** The values left visible while the strings were written. */
  visible?: readonly string[];
}

const fold = (v: string): string => v.trim().toLowerCase();

export class AiAuthoredTextStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "ai-authored-text.json");
  }

  /** The recorded strings, oldest first. */
  async load(caseId: string): Promise<string[]> {
    return (await this.loadEntries(caseId)).map((e) => e.text);
  }

  async loadEntries(caseId: string): Promise<AuthoredEntry[]> {
    try {
      const raw = JSON.parse(await readFile(this.path(caseId), "utf8")) as { entries?: unknown };
      return sanitize(raw?.entries);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
  }

  private write(caseId: string, entries: readonly AuthoredEntry[]): Promise<void> {
    return atomicWrite(this.path(caseId), JSON.stringify({ entries }));
  }

  /** Forget everything recorded for the case — masking or Presidio was switched off. */
  async clear(caseId: string): Promise<void> {
    await lock.runExclusive(caseId, () => this.write(caseId, []));
  }

  /**
   * Forget every string that holds `value`, and every string recorded while `value` was left
   * visible — the analyst left it visible, or took that back. The model may have seen the value in
   * clear, so no such string is proof of anything. Only those strings go: clearing the whole record
   * would bring the approval loop back for every other value.
   */
  async forget(caseId: string, value: string): Promise<void> {
    const k = fold(value);
    await lock.runExclusive(caseId, async () => {
      const entries = await this.loadEntries(caseId);
      const clean = new Set(
        withoutVisible(
          entries.map((e) => e.text),
          [value],
        ),
      );
      const kept = entries.filter((e) => clean.has(e.text) && !e.visible.includes(k));
      if (kept.length !== entries.length) await this.write(caseId, kept);
    });
  }

  /**
   * Add strings, newest last; an already-recorded string moves to the end and keeps its old visible
   * values as well as the new ones. Oldest drop past the cap.
   */
  async record(caseId: string, strings: readonly string[], opts: RecordOptions = {}): Promise<void> {
    const visible = [...new Set((opts.visible ?? []).map(fold).filter(Boolean))];
    const added = sanitize(strings.map((text) => ({ text, visible })));
    if (added.length === 0) return;
    await lock.runExclusive(caseId, async () => {
      if (opts.stillValid && !opts.stillValid()) return;
      const before = new Map((await this.loadEntries(caseId)).map((e) => [e.text, e]));
      const merged = added.map((e) => ({
        text: e.text,
        visible: [...new Set([...(before.get(e.text)?.visible ?? []), ...e.visible])],
      }));
      const fresh = new Set(added.map((e) => e.text));
      const kept = [...before.values()].filter((e) => !fresh.has(e.text));
      await this.write(caseId, [...kept, ...merged].slice(-AUTHORED_MAX_STRINGS));
    });
  }
}

function sanitize(value: unknown): AuthoredEntry[] {
  if (!Array.isArray(value)) return [];
  const out = new Map<string, AuthoredEntry>();
  for (const raw of value) {
    const e = (raw ?? {}) as { text?: unknown; visible?: unknown };
    if (typeof e.text !== "string") continue;
    const text = normalizeAuthored(e.text).slice(0, AUTHORED_MAX_CHARS);
    if (text.length < AUTHORED_MIN_CHARS) continue;
    const visible = Array.isArray(e.visible)
      ? e.visible.filter((v): v is string => typeof v === "string")
      : [];
    const prev = out.get(text)?.visible ?? [];
    out.set(text, { text, visible: [...new Set([...prev, ...visible.map(fold)])] });
  }
  return [...out.values()];
}
