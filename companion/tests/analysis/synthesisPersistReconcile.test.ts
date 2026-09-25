// #1595: an analyst's "treat as real intrusion" saved while the model was thinking must not be
// overwritten by the run's stale answer. persistSynthesis runs the reconcile pass INSIDE its locked
// write, over the merged state it is about to save.
import { describe, it, expect } from "vitest";
import { persistSynthesis } from "../../src/analysis/ai/synthesisPersist.js";
import { emptyState, type InvestigationState } from "../../src/analysis/stateTypes.js";
import type { StateStore } from "../../src/analysis/stateStore.js";
import { StateLock } from "../../src/analysis/stateLock.js";

function memoryStore(initial: InvestigationState): { store: StateStore; saved: InvestigationState[] } {
  let current = initial;
  const saved: InvestigationState[] = [];
  const store = {
    load: async () => current,
    save: async (s: InvestigationState) => {
      current = s;
      saved.push(s);
    },
  } as unknown as StateStore;
  return { store, saved };
}

describe("persistSynthesis reconcile hook (#1595)", () => {
  it("runs over the merged state under the lock and saves its result", async () => {
    const loaded = emptyState("c1");
    const { store, saved } = memoryStore(loaded);
    const lock = new StateLock();
    const order: string[] = [];
    let other: Promise<unknown> = Promise.resolve();
    const out = await persistSynthesis({ opts: { stateStore: store, stateLock: lock } }, "c1", {
      loaded,
      next: { ...loaded, lastSummary: "from the run" },
      findingsDiff: { added: [], removed: [], severityChanged: [] },
      reconcile: async (merged) => {
        // A second critical section queued now must wait until this write has saved.
        other = lock.runExclusive("c1", async () => order.push(`other after ${saved.length} save`));
        await new Promise((r) => setTimeout(r, 5));
        order.push("reconcile");
        return { ...merged, lastSummary: `${merged.lastSummary} + reconciled` };
      },
    });
    await other;
    expect(order).toEqual(["reconcile", "other after 1 save"]);
    expect(out.lastSummary).toBe("from the run + reconciled");
    expect(saved.at(-1)?.lastSummary).toBe("from the run + reconciled");
  });
});
