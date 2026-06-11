import type { InvestigationState } from "../analysis/stateTypes.js";

export interface SocketLike {
  readyState: number;
  OPEN: number;
  send(data: string): void;
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
      if (socket.readyState === socket.OPEN) socket.send(data);
      else set.delete(socket);
    }
  }

  // Send a message to EVERY live subscriber, regardless of which case they're viewing. Used for
  // cross-case signals — e.g. warning a dashboard that captures are arriving for a different case
  // than the one it's connected to. A socket subscribed to one case receives it once.
  broadcastAll(message: unknown): void {
    const data = JSON.stringify(message);
    for (const set of this.subs.values()) {
      for (const socket of set) {
        if (socket.readyState === socket.OPEN) socket.send(data);
        else set.delete(socket);
      }
    }
  }
}
