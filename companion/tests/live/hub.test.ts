import { describe, it, expect } from "vitest";
import { LiveHub, type SocketLike } from "../../src/live/hub.js";
import { techniqueNamesFor } from "../../src/analysis/attackTechniqueNames.js";
import { emptyState, type InvestigationState } from "../../src/analysis/stateTypes.js";

function fakeSocket(): SocketLike & { sent: string[] } {
  const sent: string[] = [];
  return { sent, readyState: 1, OPEN: 1, send: (d: string) => sent.push(d) };
}

describe("LiveHub", () => {
  it("broadcasts state only to subscribers of that case", () => {
    const hub = new LiveHub();
    const a = fakeSocket();
    const b = fakeSocket();
    hub.subscribe("c1", a);
    hub.subscribe("c2", b);

    hub.broadcast(emptyState("c1"));
    expect(a.sent).toHaveLength(1);
    expect(b.sent).toHaveLength(0);
    expect(JSON.parse(a.sent[0]).type).toBe("state");
  });

  // THE LIVE HALF OF THE MITRE NAME FIX. GET /cases/:id/state attaches an id -> name map so the
  // dashboard can name a technique row it appends from an event; the dashboard reads that map off
  // whichever state it was last handed, and a live push replaces the fetched state wholesale. So
  // the push has to carry the same map, built by the same function, or the first import after
  // page load sends "Inhibit System Recovery" back to "T1490" until a reload.
  it("carries the ATT&CK name map the state route sends, built by the same function", () => {
    const hub = new LiveHub();
    const s = fakeSocket();
    hub.subscribe("c1", s);
    const state = emptyState("c1");
    state.forensicTimeline = [
      {
        id: "e1",
        timestamp: "2026-05-18T02:10:00Z",
        description: "vssadmin delete shadows",
        severity: "High",
        mitreTechniques: ["T1490", "T9999"],
        relatedFindingIds: [],
        sourceScreenshots: [],
      },
    ];
    hub.broadcast(state);
    const msg = JSON.parse(s.sent[0]);
    // The literal, so a map that silently went empty on both paths cannot agree its way past.
    expect(msg.state.techniqueNames).toEqual({ T1490: "Inhibit System Recovery" });
    // And the route's own builder over the same inputs, so the two paths cannot drift apart.
    expect(msg.state.techniqueNames).toEqual(
      techniqueNamesFor(state.mitreTechniques, state.forensicTimeline),
    );
    // The stored state is untouched: the map is a view on the wire, never written back.
    expect(state).not.toHaveProperty("techniqueNames");
  });

  // The hub is transport, and its callers include tests that hand it a partial state. A throw
  // here would surface inside a route that has already saved — the worst place for one.
  it("tolerates a partial state rather than throwing inside the caller", () => {
    const hub = new LiveHub();
    const s = fakeSocket();
    hub.subscribe("c1", s);
    expect(() => hub.broadcast({ caseId: "c1" } as InvestigationState)).not.toThrow();
    expect(JSON.parse(s.sent[0]).state.techniqueNames).toEqual({});
  });

  it("drops closed sockets", () => {
    const hub = new LiveHub();
    const s = fakeSocket();
    hub.subscribe("c1", s);
    s.readyState = 3; // CLOSED
    hub.broadcast(emptyState("c1"));
    expect(s.sent).toHaveLength(0);
  });

  it("broadcastTo sends an arbitrary message only to that case's subscribers", () => {
    const hub = new LiveHub();
    const a = fakeSocket();
    const b = fakeSocket();
    hub.subscribe("c1", a);
    hub.subscribe("c2", b);

    hub.broadcastTo("c1", { type: "ai_status", status: "analyzing" });
    expect(a.sent).toHaveLength(1);
    expect(b.sent).toHaveLength(0);
    const msg = JSON.parse(a.sent[0]);
    expect(msg.type).toBe("ai_status");
    expect(msg.status).toBe("analyzing");
  });

  it("broadcastAll reaches every subscriber regardless of case (skips closed sockets)", () => {
    const hub = new LiveHub();
    const a = fakeSocket();
    const b = fakeSocket();
    const closed = fakeSocket();
    hub.subscribe("c1", a);
    hub.subscribe("c2", b);
    hub.subscribe("c3", closed);
    closed.readyState = 3;

    hub.broadcastAll({ type: "capture_ingest", caseId: "c1" });
    expect(JSON.parse(a.sent[0]).type).toBe("capture_ingest");
    expect(JSON.parse(b.sent[0]).caseId).toBe("c1");
    expect(closed.sent).toHaveLength(0);
  });

  it("broadcastTo contains a send() that throws (half-open peer) instead of crashing", () => {
    const hub = new LiveHub();
    const dead = fakeSocket();
    dead.send = () => {
      throw new Error("not open");
    };
    const alive = fakeSocket();
    let terminated = false;
    dead.terminate = () => {
      terminated = true;
    };
    hub.subscribe("c1", dead);
    hub.subscribe("c1", alive);
    expect(() => hub.broadcastTo("c1", { type: "state" })).not.toThrow();
    expect(alive.sent).toHaveLength(1);
    expect(terminated).toBe(true);
  });

  it("sweepReaper terminates sockets that never ponged since the last sweep", () => {
    const hub = new LiveHub();
    let terminated = false;
    let pinged = false;
    const s = fakeSocket();
    s.isAlive = true;
    s.ping = () => {
      pinged = true;
    };
    s.terminate = () => {
      terminated = true;
    };
    hub.subscribe("c1", s);
    // First sweep: flip isAlive=false and ping.
    hub.sweepReaper();
    expect(pinged).toBe(true);
    expect(terminated).toBe(false);
    // Second sweep (no pong happened in between): isAlive still false → terminate + drop.
    const reaped = hub.sweepReaper();
    expect(terminated).toBe(true);
    expect(reaped).toBe(1);
    // The dead socket is dropped from the hub; a subsequent broadcast is a no-op.
    expect(() => hub.broadcastTo("c1", { type: "state" })).not.toThrow();
    expect(s.sent).toHaveLength(0);
  });

  it("sweepReaper keeps a socket that ponged between sweeps", () => {
    const hub = new LiveHub();
    let terminated = false;
    const s = fakeSocket();
    s.isAlive = true;
    s.ping = () => {};
    s.terminate = () => {
      terminated = true;
    };
    hub.subscribe("c1", s);
    hub.sweepReaper(); // isAlive=false, ping sent
    s.isAlive = true; // pong handler fired
    hub.sweepReaper(); // still alive → ping again, no terminate
    expect(terminated).toBe(false);
    expect(hub.connectionCount()).toBe(1);
  });
});
