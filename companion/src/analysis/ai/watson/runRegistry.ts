import { WatsonCancelled } from "./roundContext.js";

// The Watson rounds running on each case, held in memory only. A restarted server knows no run, and
// the chat file never holds a "running" flag. Each run owns an AbortController: cancel aborts every
// active run of a case (the running one and the queued ones) with a WatsonCancelled reason.

export interface WatsonRunStatus {
  /** When the oldest active run began (ISO). */
  since: string;
  kind: "analyst" | "reaction";
  actor?: string;
  /** Active runs behind the oldest one. */
  queued: number;
}

export interface WatsonRunHandle {
  readonly signal: AbortSignal;
  /** Removes the run from the registry. Idempotent. */
  end(): void;
}

interface ActiveRun {
  readonly since: string;
  readonly kind: "analyst" | "reaction";
  readonly actor?: string;
  readonly controller: AbortController;
}

export class WatsonRunRegistry {
  private readonly runs = new Map<string, readonly ActiveRun[]>();

  constructor(private readonly now: () => Date = () => new Date()) {}

  begin(caseId: string, run: { kind: "analyst" | "reaction"; actor?: string }): WatsonRunHandle {
    const entry: ActiveRun = {
      since: this.now().toISOString(),
      kind: run.kind,
      ...(run.actor ? { actor: run.actor } : {}),
      controller: new AbortController(),
    };
    this.runs.set(caseId, [...(this.runs.get(caseId) ?? []), entry]);
    let ended = false;
    return {
      signal: entry.controller.signal,
      end: () => {
        if (ended) return;
        ended = true;
        this.remove(caseId, entry);
      },
    };
  }

  /** The oldest active run of the case, with the count queued behind it; null when none runs. */
  status(caseId: string): WatsonRunStatus | null {
    const list = this.runs.get(caseId);
    const first = list?.[0];
    if (!list || !first) return null;
    return {
      since: first.since,
      kind: first.kind,
      ...(first.actor ? { actor: first.actor } : {}),
      queued: list.length - 1,
    };
  }

  /** Aborts every active run of the case with a WatsonCancelled reason; returns how many. */
  cancel(caseId: string): number {
    const list = this.runs.get(caseId) ?? [];
    for (const run of list) {
      if (!run.controller.signal.aborted) run.controller.abort(new WatsonCancelled());
    }
    return list.length;
  }

  private remove(caseId: string, entry: ActiveRun): void {
    const left = (this.runs.get(caseId) ?? []).filter((r) => r !== entry);
    if (left.length) this.runs.set(caseId, left);
    else this.runs.delete(caseId);
  }
}

/** The one process-wide registry. */
export const watsonRuns = new WatsonRunRegistry();
