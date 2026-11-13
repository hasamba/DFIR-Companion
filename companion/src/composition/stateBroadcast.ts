/**
 * "This case's state changed" → a state-changed notice to the dashboards watching it (#1874, #2615).
 *
 * A writer that changed a few rows (an import's settle) no longer holds the whole case. It used to
 * load the whole case just to push it to the hub; the push is now a small notice that the dashboard
 * answers with the paged GET /cases/:id/state, so nothing is loaded here. Still skipped when nobody
 * is subscribed, since a notice to nobody is dropped anyway.
 */
export interface StateBroadcastDeps {
  notify(caseId: string): void;
  hasSubscribers(caseId: string): boolean;
}

export function createStateBroadcaster(deps: StateBroadcastDeps): (caseId: string) => void {
  return (caseId) => {
    try {
      if (deps.hasSubscribers(caseId)) deps.notify(caseId);
    } catch {
      // A failed announce skips this notice; the next change announces again.
    }
  };
}
