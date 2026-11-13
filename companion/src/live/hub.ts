import { CaseForgetter } from "../storage/caseKeyedState.js";
import type { InvestigationState } from "../analysis/stateTypes.js";

export interface SocketLike {
  readyState: number;
  OPEN: number;
  send(data: string): void;
  /** Optional ping/pong/terminate — present on real `ws.WebSocket`s, absent on test fakes. */
  ping?(data?: unknown): void;
  pong?(data?: unknown): void;
  terminate?(): void;
  on?(event: "pong", listener: () => void): unknown;
  isAlive?: boolean;
}

/** The `job_changed` push, with the case's job list on board (#1453). */
export function jobsChangedMessage(jobs: readonly unknown[]): {
  type: "job_changed";
  jobs: readonly unknown[];
} {
  return { type: "job_changed", jobs };
}

function passes(guard: () => boolean): boolean {
  try {
    return guard();
  } catch {
    return false;
  }
}

export class LiveHub {
  private subs = new Map<string, Set<SocketLike>>();
  // #1866: with a cases root, a deleted (or reseeded) case's sockets are closed, so a dashboard
  // left open on it never receives a same-id successor's pushes. The client reconnects and is
  // re-checked against the new case.
  private readonly forgetter?: CaseForgetter;

  constructor(casesRoot?: string) {
    if (casesRoot !== undefined)
      this.forgetter = new CaseForgetter(casesRoot, (caseId) => this.dropCase(caseId));
  }

  // #2441: bumped by every dropCase. An upgrade reads it before it authorizes and refuses itself if
  // it moved, so a socket authorized against the case as it was before a drop (a password change,
  // a delete) can never subscribe after it. Kept for the process's life: the compare needs the old value.
  private readonly epochs = new Map<string, number>();

  // #2615: the last notice number sent per case. A counter per process, not a clock: it only has to
  // order notices on one socket, and a restart drops every socket (the dashboard resets on reconnect).
  private readonly stateVersions = new Map<string, number>();

  /** The case's authorization epoch: changes whenever its sockets are dropped (#2441). */
  authEpoch(caseId: string): number {
    return this.epochs.get(caseId) ?? 0;
  }

  /** Close and forget every socket subscribed to the case. */
  dropCase(caseId: string): void {
    this.epochs.set(caseId, this.authEpoch(caseId) + 1);
    const set = this.subs.get(caseId);
    this.subs.delete(caseId);
    for (const socket of set ?? []) socket.terminate?.();
  }

  // #2449: team mode authorizes a socket only at upgrade. The upgrade hands over a re-check closure
  // (the same check, same cookie, same case) so revalidate() can close a socket whose user was
  // disabled, signed out, or lost the case. A WeakMap, so every removal path needs no cleanup.
  private readonly guards = new WeakMap<SocketLike, () => boolean>();

  /**
   * Subscribe the socket; returns false (and closes it) when its re-check already fails. A
   * revocation that landed after the upgrade check but before this call ran its revalidate()
   * without this socket. Revocations change the store before they signal, so one check here,
   * after the socket joins the set, leaves no window: later revocations reach it via revalidate().
   */
  subscribe(caseId: string, socket: SocketLike, stillAllowed?: () => boolean): boolean {
    const set = this.subs.get(caseId) ?? new Set<SocketLike>();
    set.add(socket);
    this.subs.set(caseId, set);
    if (!stillAllowed) return true;
    this.guards.set(socket, stillAllowed);
    if (passes(stillAllowed)) return true;
    this.unsubscribe(caseId, socket);
    socket.terminate?.();
    return false;
  }

  /**
   * Re-run every socket's upgrade check and close the ones that no longer pass (#2449). A guard
   * that throws fails CLOSED. Sockets without a guard (single-user mode) are never touched.
   * Failures are collected first and closed after: `terminate` fires ws's `close` handler, which
   * calls `unsubscribe` re-entrantly. Returns how many sockets were closed.
   */
  revalidate(): number {
    const revoked: Array<[string, SocketLike]> = [];
    for (const [caseId, set] of this.subs) {
      for (const socket of set) {
        const guard = this.guards.get(socket);
        if (guard && !passes(guard)) revoked.push([caseId, socket]);
      }
    }
    for (const [caseId, socket] of revoked) {
      this.unsubscribe(caseId, socket);
      socket.terminate?.();
    }
    return revoked.length;
  }

  /** True when at least one socket is subscribed to the case (composition/stateBroadcast.ts). */
  hasSubscribers(caseId: string): boolean {
    return (this.subs.get(caseId)?.size ?? 0) > 0;
  }

  unsubscribe(caseId: string, socket: SocketLike): void {
    this.subs.get(caseId)?.delete(socket);
    if (this.subs.get(caseId)?.size === 0) this.subs.delete(caseId);
  }

  /** For the ping/reaper: every socket that has not ponged since the last sweep is dead. */
  sweepReaper(): number {
    let reaped = 0;
    for (const [caseId, set] of this.subs) {
      for (const socket of set) {
        if (socket.isAlive === false) {
          socket.terminate?.();
          set.delete(socket);
          reaped++;
          continue;
        }
        socket.isAlive = false;
        // A ping to an already-dead peer throws; that socket is gone, so close it out the same
        // way the broadcast paths do rather than dropping the reference and leaking the handle.
        try {
          socket.ping?.();
        } catch {
          set.delete(socket);
          socket.terminate?.();
          reaped++;
        }
      }
      if (set.size === 0) this.subs.delete(caseId);
    }
    return reaped;
  }

  connectionCount(): number {
    let count = 0;
    for (const sockets of this.subs.values()) count += sockets.size;
    return count;
  }

  // "This case's state changed" (#2615). The push used to carry the whole InvestigationState — every
  // forensic-timeline row — and `ws` copies a string frame into a fresh Buffer per socket, so a 20k-row
  // case cost hundreds of MB per client per change. Now it is a notice: the dashboard answers it with
  // GET /cases/:id/state, which pages the timeline and attaches the ATT&CK name map, the rejected-
  // technique filter and the rest of the wire view (routes/caseState.ts). The hub only names the case
  // and numbers the notice so a dashboard can tell a duplicate or reordered one.
  //
  // Kept under its old name because ~120 `onState` call sites funnel into it; it only reads `caseId`,
  // so a partial state (the socket-gate tests hand over one) cannot throw inside a route that saved.
  broadcast(saved: InvestigationState): void {
    this.notifyStateChanged(saved.caseId);
  }

  /** Announce a change for a case the writer holds no state for (the import settle, #1874). */
  notifyStateChanged(caseId: string): void {
    if (!this.subs.has(caseId)) return;
    const version = (this.stateVersions.get(caseId) ?? 0) + 1;
    this.stateVersions.set(caseId, version);
    this.broadcastTo(caseId, { type: "state_changed", caseId, version });
  }

  // The jobs push carries the case's job list (#1453). It used to be a bare nudge that sent the
  // dashboard back over HTTP for the list — and during a big import every HTTP lane is held by a
  // panel read waiting on the case worker, so that fetch never left the browser and the jobs chip
  // stayed hidden for the whole import. The socket is its own connection; a push that carries the
  // list needs no lane. `jobsChangedMessage` is shared with the subscribe-time snapshot (wsGate).
  broadcastJobs(caseId: string, jobs: readonly unknown[]): void {
    this.broadcastTo(caseId, jobsChangedMessage(jobs));
  }

  // Send an arbitrary JSON message to all live subscribers of a case.
  broadcastTo(caseId: string, message: unknown): void {
    const set = this.subs.get(caseId);
    if (!set) return;
    const data = JSON.stringify(message);
    for (const socket of set) {
      if (socket.readyState !== socket.OPEN) {
        set.delete(socket);
        continue;
      }
      try {
        socket.send(data);
      } catch {
        // send to a just-dead peer throws on ws; contain it instead of crashing the process.
        set.delete(socket);
        socket.terminate?.();
      }
    }
  }

  // Send a message to EVERY live subscriber, regardless of which case they're viewing. Used for
  // cross-case signals — e.g. warning a dashboard that captures are arriving for a different case
  // than the one it's connected to. A socket subscribed to one case receives it once.
  broadcastAll(message: unknown): void {
    const data = JSON.stringify(message);
    for (const set of this.subs.values()) {
      for (const socket of set) {
        if (socket.readyState !== socket.OPEN) {
          set.delete(socket);
          continue;
        }
        try {
          socket.send(data);
        } catch {
          set.delete(socket);
          socket.terminate?.();
        }
      }
    }
  }
}
