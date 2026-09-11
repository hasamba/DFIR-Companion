import { techniqueNamesFor } from "../analysis/attackTechniqueNames.js";
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

export class LiveHub {
  private subs = new Map<string, Set<SocketLike>>();

  subscribe(caseId: string, socket: SocketLike): void {
    const set = this.subs.get(caseId) ?? new Set<SocketLike>();
    set.add(socket);
    this.subs.set(caseId, set);
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

  // A state push carries the same ATT&CK name map GET /cases/:id/state attaches
  // (routes/caseState.ts). The dashboard's MITRE derivation reads that map off whichever state
  // object it was last handed, and a push REPLACES the fetched one wholesale — so a push without
  // it sent every event-only technique back to its bare id on the first import, synthesis or edit
  // after the page loaded, until the next reload. Built here rather than at the onState call
  // sites because every one of them funnels into this method; there is nowhere else to miss.
  //
  // `?? []` because this is transport, not the route: a caller may hand over a partial state (the
  // socket-gate tests do), and a throw here would surface inside a route that has already saved.
  broadcast(state: InvestigationState): void {
    const techniqueNames = techniqueNamesFor(state.mitreTechniques ?? [], state.forensicTimeline ?? []);
    this.broadcastTo(state.caseId, { type: "state", state: { ...state, techniqueNames } });
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
