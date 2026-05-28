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
    const set = this.subs.get(state.caseId);
    if (!set) return;
    const message = JSON.stringify({ type: "state", state });
    for (const socket of set) {
      if (socket.readyState === socket.OPEN) socket.send(message);
      else set.delete(socket);
    }
  }
}
