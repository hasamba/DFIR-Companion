import type { ForensicEvent } from "./stateTypes.js";

/**
 * The import seam's hook for hunt grading (#2670). Composition registers the grader against the
 * case-state store it built; routes/importSettle.ts calls it after the tagger and the caps, BEFORE
 * demote, on every import path (they all settle through settleForensicImport). Keyed by the store
 * instance so two apps in one process (tests) never grade through each other's stores.
 *
 * A failing grader never fails an import: the evidence is already stored; the error is logged.
 */
export type HuntSettle = (caseId: string, added: readonly ForensicEvent[]) => Promise<number>;

const hooks = new WeakMap<object, HuntSettle>();

export function registerHuntSettle(stateStore: object, fn: HuntSettle): void {
  hooks.set(stateStore, fn);
}

export async function runHuntSettle(
  stateStore: object,
  caseId: string,
  added: readonly ForensicEvent[],
  onError: (err: Error) => void = () => undefined,
): Promise<number> {
  const fn = hooks.get(stateStore);
  if (!fn) return 0;
  try {
    return await fn(caseId, added);
  } catch (err) {
    onError(err instanceof Error ? err : new Error(String(err)));
    return 0;
  }
}
