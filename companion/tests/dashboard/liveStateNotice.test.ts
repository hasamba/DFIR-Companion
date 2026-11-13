// #2615: the live socket pushes a small state-changed notice, not the whole case. The page answers
// it with the paged GET /cases/:id/state it already uses, bounded and debounced, and feeds the reply
// to the same `state` handler a full push used to reach. A legacy full `state` frame still renders.
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

class FakeSocket {
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSING = 2;
  static CLOSED = 3;
  static made: FakeSocket[] = [];
  readyState = FakeSocket.CONNECTING;
  onopen: (() => void) | null = null;
  onclose: (() => void) | null = null;
  onmessage: ((ev: { data: string }) => void) | null = null;
  constructor(public url: string) {
    FakeSocket.made.push(this);
  }
  close() {
    this.readyState = FakeSocket.CLOSED;
  }
  open() {
    this.readyState = FakeSocket.OPEN;
    this.onopen?.();
  }
  push(msg: unknown) {
    this.onmessage?.({ data: JSON.stringify(msg) });
  }
}

type LiveMsg = { type: string; state?: { caseId?: string; v?: string } };
interface LiveApi {
  openCaseSocket: (caseId: string, onMessage: (msg: LiveMsg) => void) => void;
  closeCaseSocket: () => void;
}
interface Pending {
  url: string;
  resolve: (body: unknown) => void;
  fail: (status: number) => void;
}

const DEBOUNCE_MS = 250;

function harness() {
  FakeSocket.made = [];
  const requests: Pending[] = [];
  const messages: LiveMsg[] = [];
  const api = loadDashboardModule<LiveApi>("dashboard-live-socket.js", [], {
    document: { visibilityState: "visible", getElementById: () => null, addEventListener: () => {} },
    location: { protocol: "http:", host: "127.0.0.1:4773" },
    WebSocket: FakeSocket,
    ws: null,
    activeCaseId: "INC-1",
    refreshAiState: () => {},
    loadJobs: () => {},
    fetch: (url: string) =>
      new Promise((res) => {
        requests.push({
          url,
          resolve: (body) => res({ ok: true, json: () => Promise.resolve(body) }),
          fail: (status) => res({ ok: false, status, json: () => Promise.reject(new Error("no")) }),
        });
      }),
    setTimeout: (fn: () => void, ms: number) => globalThis.setTimeout(fn, ms),
    clearTimeout: (id: unknown) => globalThis.clearTimeout(id as number),
    setInterval: (fn: () => void, ms: number) => globalThis.setInterval(fn, ms),
    clearInterval: (id: unknown) => globalThis.clearInterval(id as number),
    AbortController,
  });
  api.openCaseSocket("INC-1", (m) => messages.push(m));
  const sock = FakeSocket.made[0];
  sock.open();
  return { api, sock, requests, messages };
}

const notice = (version: number, caseId = "INC-1") => ({ type: "state_changed", caseId, version });
const stateReads = (r: Pending[]) => r.filter((p) => p.url === "/cases/INC-1/state");

beforeEach(() => vi.useFakeTimers());
afterEach(() => vi.useRealTimers());

describe("a state-changed notice (#2615)", () => {
  it("makes one state read and hands the reply to the state handler", async () => {
    const h = harness();
    h.sock.push(notice(1));
    expect(h.requests).toHaveLength(0); // debounced, not instant
    await vi.advanceTimersByTimeAsync(DEBOUNCE_MS);
    expect(stateReads(h.requests)).toHaveLength(1);
    h.requests[0].resolve({ caseId: "INC-1", v: "one" });
    await vi.advanceTimersByTimeAsync(0);
    expect(h.messages).toEqual([{ type: "state", state: { caseId: "INC-1", v: "one" } }]);
  });

  it("does not forward the notice itself to the handler", async () => {
    const h = harness();
    h.sock.push(notice(1));
    await vi.advanceTimersByTimeAsync(DEBOUNCE_MS);
    expect(h.messages.some((m) => m.type === "state_changed")).toBe(false);
  });

  it("bounds a burst: one read in flight, one pending, never a stack", async () => {
    const h = harness();
    for (let i = 1; i <= 5; i++) h.sock.push(notice(i));
    await vi.advanceTimersByTimeAsync(DEBOUNCE_MS);
    expect(stateReads(h.requests)).toHaveLength(1);
    // More notices while that read is out: debounce fires, but the read waits for the first.
    for (let i = 6; i <= 20; i++) h.sock.push(notice(i));
    await vi.advanceTimersByTimeAsync(DEBOUNCE_MS * 4);
    expect(stateReads(h.requests)).toHaveLength(1);
    h.requests[0].resolve({ caseId: "INC-1", v: "a" });
    await vi.advanceTimersByTimeAsync(0);
    expect(stateReads(h.requests)).toHaveLength(2); // exactly one catch-up read, not fifteen
    h.requests[1].resolve({ caseId: "INC-1", v: "b" });
    await vi.advanceTimersByTimeAsync(DEBOUNCE_MS * 4);
    expect(stateReads(h.requests)).toHaveLength(2);
    expect(h.messages.map((m) => m.state?.v)).toEqual(["a", "b"]);
  });

  it("drops a reply for another case", async () => {
    const h = harness();
    h.sock.push(notice(1));
    await vi.advanceTimersByTimeAsync(DEBOUNCE_MS);
    h.requests[0].resolve({ caseId: "INC-2", v: "wrong" });
    await vi.advanceTimersByTimeAsync(0);
    expect(h.messages).toEqual([]);
  });

  it("ignores a notice for another case and a version already covered", async () => {
    const h = harness();
    h.sock.push(notice(1, "INC-2"));
    await vi.advanceTimersByTimeAsync(DEBOUNCE_MS);
    expect(h.requests).toHaveLength(0);
    h.sock.push(notice(3));
    await vi.advanceTimersByTimeAsync(DEBOUNCE_MS);
    h.requests[0].resolve({ caseId: "INC-1", v: "x" });
    await vi.advanceTimersByTimeAsync(0);
    h.sock.push(notice(2)); // reordered: the read above already covered it
    await vi.advanceTimersByTimeAsync(DEBOUNCE_MS);
    expect(stateReads(h.requests)).toHaveLength(1);
  });

  it("drops a reply that lands after a newer full push", async () => {
    const h = harness();
    h.sock.push(notice(1));
    await vi.advanceTimersByTimeAsync(DEBOUNCE_MS);
    h.sock.push({ type: "state", state: { caseId: "INC-1", v: "newer" } });
    h.requests[0].resolve({ caseId: "INC-1", v: "older" });
    await vi.advanceTimersByTimeAsync(0);
    expect(h.messages.map((m) => m.state?.v)).toEqual(["newer"]);
  });

  it("drops a reply that lands after a case switch", async () => {
    const h = harness();
    h.sock.push(notice(1));
    await vi.advanceTimersByTimeAsync(DEBOUNCE_MS);
    h.api.closeCaseSocket();
    h.requests[0].resolve({ caseId: "INC-1", v: "late" });
    await vi.advanceTimersByTimeAsync(0);
    expect(h.messages).toEqual([]);
  });

  it("still renders a legacy full state frame", () => {
    const h = harness();
    h.sock.push({ type: "state", state: { caseId: "INC-1", v: "legacy" } });
    expect(h.messages).toEqual([{ type: "state", state: { caseId: "INC-1", v: "legacy" } }]);
    expect(h.requests).toHaveLength(0);
  });

  it("retries a failed read with backoff until the notice is covered", async () => {
    const h = harness();
    h.sock.push(notice(1));
    await vi.advanceTimersByTimeAsync(DEBOUNCE_MS);
    h.requests[0].fail(500);
    await vi.advanceTimersByTimeAsync(0);
    expect(h.messages).toEqual([]);
    expect(stateReads(h.requests)).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(1000); // first backoff step
    expect(stateReads(h.requests)).toHaveLength(2);
    h.requests[1].resolve({ caseId: "INC-1", v: "recovered" });
    await vi.advanceTimersByTimeAsync(0);
    expect(h.messages.map((m) => m.state?.v)).toEqual(["recovered"]);
    await vi.advanceTimersByTimeAsync(60000);
    expect(stateReads(h.requests)).toHaveLength(2); // covered: no more retries
  });

  it("gives up after bounded retries but a later notice still reads", async () => {
    const h = harness();
    h.sock.push(notice(1));
    await vi.advanceTimersByTimeAsync(DEBOUNCE_MS);
    for (let i = 0; i < 5; i++) {
      h.requests[i].fail(500);
      await vi.advanceTimersByTimeAsync(40000);
    }
    expect(stateReads(h.requests)).toHaveLength(5);
    h.sock.push(notice(2));
    await vi.advanceTimersByTimeAsync(DEBOUNCE_MS);
    expect(stateReads(h.requests)).toHaveLength(6);
  });

  it("a read left pending across a socket replacement does not block the new session", async () => {
    const h = harness();
    h.sock.push(notice(1));
    await vi.advanceTimersByTimeAsync(DEBOUNCE_MS);
    expect(stateReads(h.requests)).toHaveLength(1);
    h.api.openCaseSocket("INC-1", (m) => h.messages.push(m));
    const sock2 = FakeSocket.made[1];
    sock2.open();
    sock2.push(notice(1));
    await vi.advanceTimersByTimeAsync(DEBOUNCE_MS);
    expect(stateReads(h.requests)).toHaveLength(2);
    h.requests[1].resolve({ caseId: "INC-1", v: "new" });
    await vi.advanceTimersByTimeAsync(0);
    h.requests[0].resolve({ caseId: "INC-1", v: "old" }); // the retired read finishing late
    await vi.advanceTimersByTimeAsync(0);
    expect(h.messages.map((m) => m.state?.v)).toEqual(["new"]);
    sock2.push(notice(2)); // the old completion must not have left in-flight state behind
    await vi.advanceTimersByTimeAsync(DEBOUNCE_MS);
    expect(stateReads(h.requests)).toHaveLength(3);
  });

  it("times out a read that never settles and a later notice still refreshes", async () => {
    const h = harness();
    h.sock.push(notice(1));
    await vi.advanceTimersByTimeAsync(DEBOUNCE_MS);
    await vi.advanceTimersByTimeAsync(20000); // timeout: counted as a failure, retry follows
    await vi.advanceTimersByTimeAsync(1000);
    expect(stateReads(h.requests)).toHaveLength(2);
    h.requests[1].resolve({ caseId: "INC-1", v: "after-timeout" });
    await vi.advanceTimersByTimeAsync(0);
    expect(h.messages.map((m) => m.state?.v)).toEqual(["after-timeout"]);
    h.requests[0].resolve({ caseId: "INC-1", v: "very-late" }); // the timed-out read answering
    await vi.advanceTimersByTimeAsync(0);
    expect(h.messages).toHaveLength(1);
  });
});
