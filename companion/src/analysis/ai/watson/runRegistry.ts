import { WatsonCancelled } from "./roundContext.js";

// The Watson rounds running on each case, held in memory only. A restarted server knows no run, and
// the chat file never holds a "running" flag. Each run owns an AbortController: cancel aborts every
// active run of a case (the running one and the queued ones) with a WatsonCancelled reason.
//
// Final review F6: a message also counts from its admission (routes/watsonMessage.ts), while its
// checks run and before its round begins. Cancel aborts those admissions too, and a round that
// begins from an aborted admission starts aborted, so it stops before any provider call.

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
  /** Aborts this run with `reason` (the round's time limit, #2639). No-op once stopped or ended. */
  expire(reason: WatsonCancelled): void;
}

/** A message admitted on a case whose round has not begun yet. */
export interface WatsonAdmissionTicket {
  /** Aborted when a cancel lands before the round begins. Pass it to begin() as `admitted`. */
  readonly signal: AbortSignal;
  /** Removes the admission. Idempotent. */
  leave(): void;
}

interface ActiveRun {
  readonly since: string;
  readonly kind: "analyst" | "reaction";
  readonly actor?: string;
  readonly controller: AbortController;
}

export class WatsonRunRegistry {
  private readonly runs = new Map<string, readonly ActiveRun[]>();
  private readonly admissions = new Map<string, readonly AbortController[]>();

  constructor(private readonly now: () => Date = () => new Date()) {}

  begin(
    caseId: string,
    run: { kind: "analyst" | "reaction"; actor?: string; admitted?: AbortSignal },
  ): WatsonRunHandle {
    const entry: ActiveRun = {
      since: this.now().toISOString(),
      kind: run.kind,
      ...(run.actor ? { actor: run.actor } : {}),
      controller: new AbortController(),
    };
    // A stop that landed while the message was admitted carries over: the round starts stopped.
    if (run.admitted?.aborted) entry.controller.abort(new WatsonCancelled());
    this.runs.set(caseId, [...(this.runs.get(caseId) ?? []), entry]);
    let ended = false;
    return {
      signal: entry.controller.signal,
      end: () => {
        if (ended) return;
        ended = true;
        this.remove(caseId, entry);
      },
      expire: (reason) => {
        if (!ended && !entry.controller.signal.aborted) entry.controller.abort(reason);
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

  /** Admits a message on the case until its round begins (or its checks refuse it). */
  admit(caseId: string): WatsonAdmissionTicket {
    const controller = new AbortController();
    this.admissions.set(caseId, [...(this.admissions.get(caseId) ?? []), controller]);
    let left = false;
    return {
      signal: controller.signal,
      leave: () => {
        if (left) return;
        left = true;
        const rest = (this.admissions.get(caseId) ?? []).filter((c) => c !== controller);
        if (rest.length) this.admissions.set(caseId, rest);
        else this.admissions.delete(caseId);
      },
    };
  }

  /** How many messages are admitted on the case and have not begun their round yet. */
  admitting(caseId: string): number {
    return this.admissions.get(caseId)?.length ?? 0;
  }

  /**
   * Aborts every active run and every admitted message of the case with a WatsonCancelled reason;
   * returns how many it newly aborted.
   */
  cancel(caseId: string): number {
    const live = [
      ...(this.runs.get(caseId) ?? []).map((r) => r.controller),
      ...(this.admissions.get(caseId) ?? []),
    ].filter((c) => !c.signal.aborted);
    for (const c of live) c.abort(new WatsonCancelled());
    return live.length;
  }

  private remove(caseId: string, entry: ActiveRun): void {
    const left = (this.runs.get(caseId) ?? []).filter((r) => r !== entry);
    if (left.length) this.runs.set(caseId, left);
    else this.runs.delete(caseId);
  }
}

/** The one process-wide registry. */
export const watsonRuns = new WatsonRunRegistry();
