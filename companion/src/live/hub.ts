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
  sweepReaper(): void {
    for (const set of this.subs.values()) {
      for (const socket of set) {
        if (socket.isAlive === false) {
          socket.terminate?.();
          set.delete(socket);
          continue;
        }
        socket.isAlive = false;
        try { socket.ping?.(); } catch { set.delete(socket); }
      }
      if (set.size === 0) {
        const caseId = [...this.subs.entries()].find(([, s]) => s === set)?.[0];
        if (caseId) this.subs.delete(caseId);
      }
    }
  }

  broadcast(state: InvestigationState): void {
    this.broadcastTo(state.caseId, { type: "state", state });
  }

  // Send an arbitrary JSON message to all live subscribers of a case.
  broadcastTo(caseId: string, message: unknown): void {
    const set = this.subs.get(caseId);
    if (!set) return;
    const data = JSON.stringify(message);
    for (const socket of set) {
      if (socket.readyState !== socket.OPEN) { set.delete(socket); continue; }
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
        if (socket.readyState !== socket.OPEN) { set.delete(socket); continue; }
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
