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

// #1453: the jobs chip used to learn about jobs over HTTP after a bare `job_changed` nudge. During
// a big import every HTTP lane is held by a panel read waiting on the case worker, so that fetch
// never left the browser and the chip stayed hidden while the header pill said "importing". The
// socket is its own connection: the push carries the case's job list, so the chip needs no lane.
describe("LiveHub.broadcastJobs (#1453)", () => {
  it("sends a job_changed message that carries the job list, to that case only", () => {
    const hub = new LiveHub();
    const a = fakeSocket();
    const b = fakeSocket();
    hub.subscribe("c1", a);
    hub.subscribe("c2", b);
    hub.broadcastJobs("c1", [{ id: "job_1", status: "running", kind: "import" }]);
    expect(b.sent).toHaveLength(0);
    expect(a.sent).toHaveLength(1);
    expect(JSON.parse(a.sent[0])).toEqual({
      type: "job_changed",
      jobs: [{ id: "job_1", status: "running", kind: "import" }],
    });
  });
});

// #2449: team mode authorizes a live socket only at upgrade. A socket subscribed with a re-check
// guard is closed by revalidate() once that guard says no (or throws — fail closed). A socket with
// no guard (single-user mode) is never touched.
describe("LiveHub.revalidate (#2449)", () => {
  function closableSocket(): SocketLike & { sent: string[]; terminated: number } {
    const socket = {
      sent: [] as string[],
      terminated: 0,
      readyState: 1,
      OPEN: 1,
      send(d: string) {
        socket.sent.push(d);
      },
      terminate() {
        socket.terminated++;
      },
    };
    return socket;
  }

  it("closes sockets whose guard refuses or throws and keeps allowed and guardless ones", () => {
    const hub = new LiveHub();
    const refused = closableSocket();
    const throwing = closableSocket();
    const allowed = closableSocket();
    const guardless = closableSocket();
    // Access is revoked AFTER subscribe; revalidate() is what has to notice.
    let revoked = false;
    hub.subscribe("c1", refused, () => !revoked);
    hub.subscribe("c1", throwing, () => {
      if (revoked) throw new Error("auth store gone");
      return true;
    });
    hub.subscribe("c1", allowed, () => true);
    hub.subscribe("c2", guardless);
    revoked = true;

    expect(hub.revalidate()).toBe(2);
    expect(refused.terminated).toBe(1);
    expect(throwing.terminated).toBe(1);
    expect(allowed.terminated).toBe(0);
    expect(guardless.terminated).toBe(0);
    expect(hub.connectionCount()).toBe(2);

    hub.broadcastTo("c1", { type: "ping" });
    expect(refused.sent).toHaveLength(0);
    expect(throwing.sent).toHaveLength(0);
    expect(allowed.sent).toHaveLength(1);
  });

  it("forgets a case whose last socket is revoked", () => {
    const hub = new LiveHub();
    let revoked = false;
    hub.subscribe("c1", closableSocket(), () => !revoked);
    revoked = true;
    expect(hub.revalidate()).toBe(1);
    expect(hub.hasSubscribers("c1")).toBe(false);
    expect(hub.connectionCount()).toBe(0);
  });

  it("survives a terminate that unsubscribes the socket re-entrantly, as ws's close handler does", () => {
    const hub = new LiveHub();
    const sockets = [closableSocket(), closableSocket(), closableSocket()];
    let revoked = false;
    for (const socket of sockets) {
      socket.terminate = () => {
        socket.terminated++;
        hub.unsubscribe("c1", socket);
      };
      hub.subscribe("c1", socket, () => !revoked);
    }
    revoked = true;
    expect(hub.revalidate()).toBe(3);
    expect(sockets.map((s) => s.terminated)).toEqual([1, 1, 1]);
    expect(hub.connectionCount()).toBe(0);
  });

  it("refuses and closes a socket whose guard already fails at subscribe (revoked mid-upgrade)", () => {
    const hub = new LiveHub();
    const refused = closableSocket();
    const throwing = closableSocket();
    expect(hub.subscribe("c1", refused, () => false)).toBe(false);
    expect(
      hub.subscribe("c1", throwing, () => {
        throw new Error("auth store gone");
      }),
    ).toBe(false);
    expect(refused.terminated).toBe(1);
    expect(throwing.terminated).toBe(1);
    expect(hub.hasSubscribers("c1")).toBe(false);
    expect(hub.subscribe("c1", closableSocket(), () => true)).toBe(true);
    expect(hub.subscribe("c1", closableSocket())).toBe(true);
  });

  it("returns 0 and closes nothing when no socket carries a guard (single-user mode)", () => {
    const hub = new LiveHub();
    const socket = closableSocket();
    hub.subscribe("c1", socket);
    expect(hub.revalidate()).toBe(0);
    expect(socket.terminated).toBe(0);
    expect(hub.hasSubscribers("c1")).toBe(true);
  });
});

describe("LiveHub.authEpoch (#2441)", () => {
  it("starts at 0 and moves on every dropCase of that case only", () => {
    const hub = new LiveHub();
    expect(hub.authEpoch("c1")).toBe(0);
    hub.dropCase("c1");
    expect(hub.authEpoch("c1")).toBe(1);
    hub.dropCase("c1");
    expect(hub.authEpoch("c1")).toBe(2);
    expect(hub.authEpoch("c2")).toBe(0);
  });
});
