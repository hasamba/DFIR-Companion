// In-flight guard for outbound pushes (#2775).
//
// Every push does find-then-create against the remote (MISP event by tag, IRIS case by name, the
// Jira/ServiceNow ticket remembered per finding). That pair is not atomic, so two overlapping
// requests for the same target both miss and both create — a duplicate event, case or ticket the
// Companion never cleans up. The guard refuses the second request instead of letting it race:
// the route answers 409 and the analyst pushes again once the first one finishes.
//
// In memory only: a push is a single request on a single process, so a restart cannot leave a
// push half-held. One guard per registered app, so tests (and two apps in one process) never
// share busy keys.

export interface PushGuard {
  /**
   * Take every key at once, or none. Returns a release function, or null when any key is already
   * held by a push in flight. Duplicate keys in one call are treated as one.
   */
  tryAcquire(keys: readonly string[]): (() => void) | null;
}

export function createPushGuard(): PushGuard {
  const busy = new Set<string>();
  return {
    tryAcquire(keys) {
      const unique = [...new Set(keys)];
      // Synchronous check-and-set: no await between the check and the add, so two requests can
      // never both see a key free.
      if (unique.some((k) => busy.has(k))) return null;
      unique.forEach((k) => busy.add(k));
      let released = false;
      return () => {
        if (released) return;
        released = true;
        unique.forEach((k) => busy.delete(k));
      };
    },
  };
}

/** The 409 body a refused push answers with. */
export function pushBusyError(target: string): { error: string } {
  return {
    error: `a ${target} push for this case is already running — wait for it to finish, then push again`,
  };
}
