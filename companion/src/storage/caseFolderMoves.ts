/**
 * Counts case-folder moves between the active root and `_archived/` (#2945). Archive and restore hold
 * a per-case lock private to the case store, so a reader that must not miss a moving case (the client
 * delete check, analysis/clientProfileLinks.ts) cannot take it. Instead it reads `state()` before and
 * after it looks: when no move started and none was in flight at either end, nothing moved while it
 * looked — even a case moved twice and back shows as a change in `started`.
 *
 * Only moves the case store makes through `track` are counted; one case store serves one cases root
 * in one process (composition/runtimeStores.ts). A folder moved by hand outside the server is not.
 */
export interface FolderMoveState {
  readonly started: number;
  readonly inFlight: number;
}

export class FolderMoveCounter {
  private started = 0;
  private inFlight = 0;

  /** A fresh snapshot, never a live view, so two reads can be compared. */
  state(): FolderMoveState {
    return { started: this.started, inFlight: this.inFlight };
  }

  /** Run one move. Counted as started before it runs; in flight until it settles, however it ends. */
  async track<T>(move: () => Promise<T>): Promise<T> {
    this.started += 1;
    this.inFlight += 1;
    try {
      return await move();
    } finally {
      this.inFlight -= 1;
    }
  }
}

/** True when nothing moved between the two reads: no move started, none in flight at either end. */
export function heldStill(before: FolderMoveState, after: FolderMoveState): boolean {
  return before.inFlight === 0 && after.inFlight === 0 && before.started === after.started;
}
