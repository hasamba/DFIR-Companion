import type { InvestigationState } from "../analysis/stateTypes.js";

/**
 * "This case's state changed" → a state push to the dashboards watching it (#1874).
 *
 * A writer that changed a few rows (an import's settle) no longer holds the whole case, so it cannot
 * hand the hub a state to push. This loads the case for it — but only when a dashboard is subscribed
 * to that case, since a push to nobody is dropped anyway, and it coalesces: a change announced while
 * a load for the same case is in flight produces one more load when that one ends, not one each.
 */
export interface StateBroadcastDeps {
  load(caseId: string): Promise<InvestigationState>;
  broadcast(state: InvestigationState): void;
  hasSubscribers(caseId: string): boolean;
}

export function createStateBroadcaster(deps: StateBroadcastDeps): (caseId: string) => void {
  const running = new Map<string, { again: boolean }>();
  const run = async (caseId: string): Promise<void> => {
    const slot = { again: false };
    running.set(caseId, slot);
    try {
      do {
        slot.again = false;
        if (!deps.hasSubscribers(caseId)) break;
        try {
          deps.broadcast(await deps.load(caseId));
        } catch {
          // A failed load skips this push; the next change announces again.
        }
      } while (slot.again);
    } finally {
      running.delete(caseId);
    }
  };
  return (caseId) => {
    const slot = running.get(caseId);
    if (slot) slot.again = true;
    else void run(caseId);
  };
}
