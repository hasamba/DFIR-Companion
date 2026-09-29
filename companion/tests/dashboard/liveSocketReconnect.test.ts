// #1675: after a sleep the case WebSocket was dead and never came back.
//
// The analyst pressed AI Re-synthesize, the server ran the synthesis, and the pill kept reading
// "conclusions out of date" until a reload. The log proved the socket was dead: every idle push
// after the wake should have made the page GET /ai-state, and none did. Three gaps, three suites:
//
//  1. js/dashboard-live-socket.js reconnects the case socket with capped backoff, only while the
//     SAME case is still connected, and catches up on what the gap missed.
//  2. A tab that becomes visible again re-derives the pill, and reopens a socket that is closed —
//     or one that sat through a long sleep, because a half-open socket reads OPEN and never closes.
//  3. The Re-synthesize click paints the pill at once and re-derives it when the POST ends, so it
//     never depends on a push arriving.
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { readFileSync } from "node:fs";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// ── A fake WebSocket the tests drive by hand ────────────────────────────────────────────────────
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
  closeCalls = 0;
  constructor(public url: string) {
    FakeSocket.made.push(this);
  }
  close() {
    this.closeCalls++;
    this.readyState = FakeSocket.CLOSED;
  }
  /** The server accepted the handshake. */
  open() {
    this.readyState = FakeSocket.OPEN;
    this.onopen?.();
  }
  /** The connection dropped (sleep, network, server restart). */
  drop() {
    this.readyState = FakeSocket.CLOSED;
    this.onclose?.();
  }
  push(msg: unknown) {
    this.onmessage?.({ data: JSON.stringify(msg) });
  }
}

type CatchUpCtx = { source: string; ran: Set<string> };
type LiveMsg = { type: string; state?: unknown; start?: unknown; end?: unknown };
type PanelRunner = (
  entries: Array<[string, () => void]>,
  onProgress: unknown,
  options: { concurrency?: number; signal?: AbortSignal },
) => unknown;

// How long a reopened socket must stay up before its catch-up runs (#1709).
const CATCH_UP_SETTLE_MS = 2000;

interface LiveApi {
  openCaseSocket: (caseId: string, onMessage: (msg: LiveMsg, ctx?: CatchUpCtx) => void) => void;
  closeCaseSocket: () => void;
  ws: FakeSocket | null;
  activeCaseId: string | null;
  fetch: (url: string) => Promise<unknown>;
}

function harness(opts: { runner?: PanelRunner } = {}) {
  FakeSocket.made = [];
  const status = { textContent: "" };
  const listeners = new Map<string, Array<() => void>>();
  const doc = {
    visibilityState: "visible",
    getElementById: (id: string) => (id === "status" ? status : null),
    addEventListener: (type: string, fn: () => void) => {
      listeners.set(type, [...(listeners.get(type) ?? []), fn]);
    },
  };
  const aiRefreshed: string[] = [];
  const jobsLoaded: number[] = [];
  const fetched: string[] = [];
  const messages: LiveMsg[] = [];
  const contexts: Array<CatchUpCtx | undefined> = [];
  const api = loadDashboardModule<LiveApi>("dashboard-live-socket.js", [], {
    document: doc,
    location: { protocol: "http:", host: "127.0.0.1:4773" },
    WebSocket: FakeSocket,
    ws: null,
    activeCaseId: "INC-1",
    refreshAiState: (id: string) => aiRefreshed.push(id),
    loadJobs: () => jobsLoaded.push(1),
    fetch: (url: string) => {
      fetched.push(url);
      const body = url.endsWith("/scope")
        ? { start: "2026-01-01T00:00:00Z", end: null }
        : { caseId: "INC-1", forensicTimeline: [] };
      return Promise.resolve({ ok: true, json: () => Promise.resolve(body) });
    },
    setTimeout: (fn: () => void, ms: number) => globalThis.setTimeout(fn, ms),
    clearTimeout: (id: unknown) => globalThis.clearTimeout(id as number),
    setInterval: (fn: () => void, ms: number) => globalThis.setInterval(fn, ms),
    clearInterval: (id: unknown) => globalThis.clearInterval(id as number),
    AbortController,
    ...(opts.runner ? { DfirCaseLoadProgress: { runPanelLoaders: opts.runner } } : {}),
  });
  const onMessage = (msg: LiveMsg, ctx?: CatchUpCtx) => {
    messages.push(msg);
    contexts.push(ctx);
  };
  const setVisibility = (v: "visible" | "hidden") => {
    doc.visibilityState = v;
    for (const fn of listeners.get("visibilitychange") ?? []) fn();
  };
  return { api, status, aiRefreshed, jobsLoaded, fetched, messages, contexts, onMessage, setVisibility };
}

beforeEach(() => vi.useFakeTimers());
afterEach(() => vi.useRealTimers());

describe("the case socket reconnects after it drops (#1675)", () => {
  it("schedules a reconnect to the same case when the current socket closes", async () => {
    const h = harness();
    h.api.openCaseSocket("INC-1", h.onMessage);
    const first = FakeSocket.made[0];
    first.open();
    expect(h.status.textContent).toBe("connected (live)");
    first.drop();
    expect(h.status.textContent).toBe("disconnected — reconnecting…");
    expect(FakeSocket.made).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(1000);
    expect(FakeSocket.made).toHaveLength(2);
    expect(FakeSocket.made[1].url).toBe("ws://127.0.0.1:4773/ws?caseId=INC-1");
    expect(h.api.ws).toBe(FakeSocket.made[1]);
    FakeSocket.made[1].open();
    expect(h.status.textContent).toBe("connected (live)");
  });

  it("backs off 1 s, 2 s, 4 s … and caps at 30 s", async () => {
    const h = harness();
    h.api.openCaseSocket("INC-1", h.onMessage);
    const waits: number[] = [];
    for (let i = 0; i < 7; i++) {
      FakeSocket.made.at(-1)!.drop();
      const before = FakeSocket.made.length;
      let waited = 0;
      while (FakeSocket.made.length === before && waited < 60_000) {
        await vi.advanceTimersByTimeAsync(500);
        waited += 500;
      }
      waits.push(waited);
    }
    expect(waits).toEqual([1000, 2000, 4000, 8000, 16000, 30000, 30000]);
  });

  it("does not reset the backoff on a socket that opens and drops at once", async () => {
    const h = harness();
    h.api.openCaseSocket("INC-1", h.onMessage);
    FakeSocket.made[0].drop();
    await vi.advanceTimersByTimeAsync(1000);
    FakeSocket.made[1].open();
    FakeSocket.made[1].drop(); // a flapping server: accepted, then gone
    await vi.advanceTimersByTimeAsync(1000);
    expect(FakeSocket.made, "a flap must not retry at the base delay again").toHaveLength(2);
    await vi.advanceTimersByTimeAsync(1000);
    expect(FakeSocket.made).toHaveLength(3);
  });

  it("does not reconnect a socket a case switch replaced", async () => {
    const h = harness();
    h.api.openCaseSocket("INC-1", h.onMessage);
    const old = FakeSocket.made[0];
    old.open();
    h.api.activeCaseId = "INC-2";
    h.api.openCaseSocket("INC-2", h.onMessage);
    FakeSocket.made[1].open();
    // A late close event on the replaced socket.
    old.drop();
    await vi.advanceTimersByTimeAsync(60_000);
    expect(FakeSocket.made.map((s) => s.url)).toEqual([
      "ws://127.0.0.1:4773/ws?caseId=INC-1",
      "ws://127.0.0.1:4773/ws?caseId=INC-2",
    ]);
    expect(old.closeCalls).toBe(1);
  });

  it("does not reconnect after a cancelled case load", async () => {
    const h = harness();
    h.api.openCaseSocket("INC-1", h.onMessage);
    const sock = FakeSocket.made[0];
    sock.open();
    h.api.closeCaseSocket();
    h.api.activeCaseId = null;
    sock.drop();
    await vi.advanceTimersByTimeAsync(60_000);
    expect(FakeSocket.made).toHaveLength(1);
    expect(h.api.ws).toBeNull();
    expect(h.status.textContent, "the cancel message must survive the close").toBe("connected (live)");
  });

  it("drops a reconnect that was already scheduled when the case is cancelled", async () => {
    const h = harness();
    h.api.openCaseSocket("INC-1", h.onMessage);
    FakeSocket.made[0].drop(); // reconnect pending
    h.api.closeCaseSocket();
    await vi.advanceTimersByTimeAsync(60_000);
    expect(FakeSocket.made).toHaveLength(1);
  });

  it("catches up on a reconnect: AI state, jobs, and the case state through the same handler", async () => {
    const h = harness();
    h.api.openCaseSocket("INC-1", h.onMessage);
    FakeSocket.made[0].open();
    // The first open re-derives the pill (as before) but does not refetch the state the connect
    // itself is already loading.
    expect(h.aiRefreshed).toEqual(["INC-1"]);
    expect(h.fetched).toEqual([]);
    expect(h.jobsLoaded).toEqual([]);
    FakeSocket.made[0].drop();
    await vi.advanceTimersByTimeAsync(1000);
    FakeSocket.made[1].open();
    await vi.advanceTimersByTimeAsync(CATCH_UP_SETTLE_MS);
    expect(h.aiRefreshed).toEqual(["INC-1", "INC-1"]);
    expect(h.jobsLoaded).toEqual([1]);
    expect(h.fetched).toEqual(["/cases/INC-1/state", "/cases/INC-1/scope"]);
    expect(h.messages).toContainEqual({ type: "state", state: { caseId: "INC-1", forensicTimeline: [] } });
  });

  it("drops a catch-up snapshot that lands after a newer state push", async () => {
    const h = harness();
    let answer: (v: unknown) => void = () => {};
    h.api.fetch = (url: string) =>
      url.endsWith("/state")
        ? Promise.resolve({ ok: true, json: () => new Promise((resolve) => (answer = resolve)) })
        : Promise.resolve({ ok: false });
    h.api.openCaseSocket("INC-1", h.onMessage);
    FakeSocket.made[0].open();
    FakeSocket.made[0].drop();
    await vi.advanceTimersByTimeAsync(1000);
    FakeSocket.made[1].open();
    await vi.advanceTimersByTimeAsync(CATCH_UP_SETTLE_MS); // catch-up GET now in flight
    FakeSocket.made[1].push({ type: "state", state: { caseId: "INC-1", v: "newer" } });
    answer({ caseId: "INC-1", v: "older" });
    await vi.advanceTimersByTimeAsync(0);
    expect(h.messages.filter((m) => m.type === "state")).toEqual([
      { type: "state", state: { caseId: "INC-1", v: "newer" } },
    ]);
  });

  it("delivers pushes from the current socket only", () => {
    const h = harness();
    h.api.openCaseSocket("INC-1", h.onMessage);
    const old = FakeSocket.made[0];
    const oldHandler = old.onmessage;
    h.api.openCaseSocket("INC-1", h.onMessage);
    FakeSocket.made[1].push({ type: "ai_status", status: "idle" });
    oldHandler?.({ data: JSON.stringify({ type: "state", state: {} }) });
    expect(h.messages).toEqual([{ type: "ai_status", status: "idle" }]);
  });

  it("gives up on a handshake that hangs and tries again", async () => {
    const h = harness();
    h.api.openCaseSocket("INC-1", h.onMessage);
    await vi.advanceTimersByTimeAsync(10_000);
    expect(FakeSocket.made[0].closeCalls).toBe(1);
    await vi.advanceTimersByTimeAsync(1000);
    expect(FakeSocket.made).toHaveLength(2);
  });

  it("does not overwrite an unrelated status message when the socket drops", () => {
    const h = harness();
    h.api.openCaseSocket("INC-1", h.onMessage);
    FakeSocket.made[0].open();
    h.status.textContent = "report written: case.md";
    FakeSocket.made[0].drop();
    expect(h.status.textContent).toBe("report written: case.md");
  });
});

// #1707: onmessage parsed every frame with a bare JSON.parse and handed the result straight on. A
// frame that is not JSON threw inside the handler; one that parses to null, an array or a primitive
// reached handleCaseMessage, which reads msg.type and renders msg.state. The hub accepts `unknown`,
// so nothing upstream enforces the shape. A bad frame is now skipped, with one fixed warning per
// socket that never echoes the frame, and it is skipped before it can count as a state push.
describe("a frame that is not a live message is skipped (#1707)", () => {
  const BAD_FRAMES = [
    "<html>502 Bad Gateway</html>",
    '{"type":"state",',
    "null",
    "[1,2]",
    '"state"',
    "42",
    "true",
    "{}",
    '{"type":42}',
    '{"type":"state"}',
    '{"type":"state","state":null}',
    '{"type":"state","state":[]}',
  ];

  function raw(sock: FakeSocket, data: string) {
    sock.onmessage?.({ data });
  }

  afterEach(() => vi.restoreAllMocks());

  it("skips each bad frame without throwing and still delivers the next good one", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const h = harness();
    h.api.openCaseSocket("INC-1", h.onMessage);
    const sock = FakeSocket.made[0];
    sock.open();
    for (const data of BAD_FRAMES) expect(() => raw(sock, data)).not.toThrow();
    expect(h.messages).toEqual([]);
    sock.push({ type: "ai_status", status: "idle" });
    expect(h.messages).toEqual([{ type: "ai_status", status: "idle" }]);
    expect(warn).toHaveBeenCalledTimes(1);
  });

  it("warns once per socket with a fixed message that never echoes the frame", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const h = harness();
    h.api.openCaseSocket("INC-1", h.onMessage);
    FakeSocket.made[0].open();
    raw(FakeSocket.made[0], "secret-looking-frame");
    raw(FakeSocket.made[0], "null");
    expect(warn.mock.calls).toEqual([["live update skipped: a frame was not a live message"]]);
    FakeSocket.made[0].drop();
    await vi.advanceTimersByTimeAsync(1000);
    FakeSocket.made[1].open();
    raw(FakeSocket.made[1], "{}");
    expect(warn).toHaveBeenCalledTimes(2);
  });

  it("does not let a bad frame make an in-flight catch-up snapshot look stale", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const h = harness();
    let answer: (v: unknown) => void = () => {};
    h.api.fetch = (url: string) =>
      url.endsWith("/state")
        ? Promise.resolve({ ok: true, json: () => new Promise((resolve) => (answer = resolve)) })
        : Promise.resolve({ ok: false });
    h.api.openCaseSocket("INC-1", h.onMessage);
    FakeSocket.made[0].open();
    FakeSocket.made[0].drop();
    await vi.advanceTimersByTimeAsync(1000);
    FakeSocket.made[1].open();
    await vi.advanceTimersByTimeAsync(CATCH_UP_SETTLE_MS); // catch-up GET now in flight
    raw(FakeSocket.made[1], '{"type":"state"}');
    raw(FakeSocket.made[1], '{"type":"state","state":null}');
    raw(FakeSocket.made[1], '{"type":"state","state":[]}');
    answer({ caseId: "INC-1", v: "snapshot" });
    await vi.advanceTimersByTimeAsync(0);
    expect(h.messages.filter((m) => m.type === "state")).toEqual([
      { type: "state", state: { caseId: "INC-1", v: "snapshot" } },
    ]);
  });
});

// #1681: the state replay refreshes only the panels the `state` branch reloads. Every other
// push-driven panel (comments, tags, pins, notebook, imports, hunts, scope …) stayed stale after a
// reconnect until its next push or a reload.
const MISSED_TYPES = [
  "comments_changed",
  "activity_changed",
  "tags_changed",
  "pins_changed",
  "finding_workflow_changed",
  "finding_outcome_changed",
  "notebook_changed",
  "dwell_window_changed",
  "super_timeline_changed",
  "asset_overrides_changed",
  "import_meta_changed",
  "drop_status_changed",
  "import_undo_changed",
  "velo_hunt_changed",
  "velo_monitor_changed",
  "push_token_changed",
  "importers_changed",
  "false_positive_changed",
  "learned_patterns_changed",
  "source_trust_changed",
  "clock_skew_changed",
  // #1691: the two case settings a dashboard control shows.
  "confidence_control_changed",
  "report_template_changed",
];

describe("a reconnect re-reads every push-driven panel the gap missed (#1681)", () => {
  async function reconnect(h: ReturnType<typeof harness>) {
    h.api.openCaseSocket("INC-1", h.onMessage);
    FakeSocket.made[0].open();
    FakeSocket.made[0].drop();
    await vi.advanceTimersByTimeAsync(1000);
  }

  it("dispatches one catch-up message per missed type, plus the scope, through the same handler", async () => {
    const h = harness();
    await reconnect(h);
    FakeSocket.made[1].open();
    await vi.advanceTimersByTimeAsync(CATCH_UP_SETTLE_MS);
    const types = h.messages.map((m) => m.type);
    for (const t of MISSED_TYPES)
      expect(
        types.filter((x) => x === t),
        t,
      ).toHaveLength(1);
    expect(h.messages).toContainEqual({
      type: "scope_changed",
      start: "2026-01-01T00:00:00Z",
      end: null,
    });
    // Transient pushes are events, not state: replaying them would raise false case-mismatch banners.
    expect(types).not.toContain("capture_ingest");
    expect(types).not.toContain("import_ingest");
  });

  it("sends nothing on the first open, which the case load already covers", () => {
    const h = harness();
    h.api.openCaseSocket("INC-1", h.onMessage);
    FakeSocket.made[0].open();
    expect(h.messages).toEqual([]);
  });

  it("sends nothing when the reopened socket was already replaced by a case switch", async () => {
    const h = harness();
    await reconnect(h);
    const reopened = FakeSocket.made[1];
    const onopen = reopened.onopen;
    h.api.activeCaseId = "INC-2";
    h.api.openCaseSocket("INC-2", h.onMessage);
    onopen?.(); // a late open on the retired socket
    await vi.advanceTimersByTimeAsync(CATCH_UP_SETTLE_MS);
    expect(h.messages).toEqual([]);
  });

  it("drops a scope answer that lands after the case was switched", async () => {
    const h = harness();
    let answerScope: (v: unknown) => void = () => {};
    h.api.fetch = (url: string) =>
      url.endsWith("/scope")
        ? Promise.resolve({ ok: true, json: () => new Promise((resolve) => (answerScope = resolve)) })
        : Promise.resolve({ ok: false });
    await reconnect(h);
    FakeSocket.made[1].open();
    await vi.advanceTimersByTimeAsync(CATCH_UP_SETTLE_MS);
    h.messages.length = 0;
    h.api.activeCaseId = "INC-2";
    h.api.openCaseSocket("INC-2", h.onMessage);
    answerScope({ start: "x", end: "y" });
    await vi.advanceTimersByTimeAsync(0);
    expect(h.messages).toEqual([]);
  });
});

// Every catch-up type must be one handleCaseMessage handles with a bare { type } — no field read —
// or the replay would call a loader with undefined. scope_changed reads msg.start/msg.end, so it is
// fetched and sent with them instead of from the list.
describe("handleCaseMessage reloads each catch-up type's panel from a bare message (#1681)", () => {
  const live = readFileSync(
    new URL("../../../public/js/dashboard-live-socket.js", import.meta.url),
    "utf8",
  ).replace(/\r\n/g, "\n");
  const connect = readFileSync(
    new URL("../../../public/js/dashboard-case-connect.js", import.meta.url),
    "utf8",
  ).replace(/\r\n/g, "\n");

  it("lists exactly the missed types in CATCH_UP_TYPES", () => {
    const m = live.match(/const CATCH_UP_TYPES = \[([\s\S]*?)\];/);
    expect(m).not.toBeNull();
    const listed = [...m![1].matchAll(/"([a-z_]+)"/g)].map((x) => x[1]);
    expect([...listed].sort()).toEqual([...MISSED_TYPES].sort());
  });

  it("handles every listed type without reading any other field of the message", () => {
    const handler = connect.slice(
      connect.indexOf("function handleCaseMessage("),
      connect.indexOf("// Case templates and incident types moved"),
    );
    for (const t of MISSED_TYPES) {
      const at = handler.indexOf(`msg.type === "${t}"`);
      expect(at, t).toBeGreaterThan(-1);
      const next = handler.indexOf("msg.type ===", at + 1);
      const branch = handler.slice(at, next === -1 ? undefined : next);
      expect(branch.replace(`msg.type === "${t}"`, ""), t).not.toMatch(/msg\./);
    }
  });

  it("runs the panel's loader for the connected case on every bare catch-up message", () => {
    const src = connect.slice(
      connect.indexOf("function handleCaseMessage("),
      connect.indexOf("// Case templates and incident types moved"),
    );
    const calls: Array<{ name: string; args: unknown[] }> = [];
    // Every free name the handler touches resolves to a recording stub; document answers "the
    // Importers tab exists", so the gated branch is exercised too.
    const env = new Proxy(
      {},
      {
        has: (_t, k) => k !== "handleCaseMessage" && k !== "caseId" && k !== "msg",
        get: (_t, k) => {
          if (k === Symbol.unscopables) return undefined;
          if (k === "document") return { getElementById: () => ({}) };
          return (...args: unknown[]) => calls.push({ name: String(k), args });
        },
      },
    );
    // Runs the REAL handler source against recording stubs, so the test cannot drift from it.
    // eslint-disable-next-line @typescript-eslint/no-implied-eval
    const handle = new Function("env", `with (env) { ${src}; return handleCaseMessage; }`)(env) as (
      caseId: string,
      msg: { type: string },
    ) => void;
    for (const t of MISSED_TYPES) {
      calls.length = 0;
      handle("INC-1", { type: t });
      const loaders = calls.filter((c) => /^load[A-Z]/.test(c.name));
      expect(loaders.length, t).toBeGreaterThan(0);
      for (const c of loaders) {
        if (c.name !== "loadImporters") expect(c.args, `${t} → ${c.name}`).toEqual(["INC-1"]);
      }
    }
  });
});

// #1709: every reconnect fired the whole catch-up at once — ~35 requests, /cockpit five times — and a
// flapping server re-fired it on every open. The catch-up now waits until a reopened socket has
// stayed up, collapses a flap into one run (bounded, so a flap cannot starve it), sends each
// loader once per run, and goes through the case load's four-lane request cap.
const CONNECT_SRC = readFileSync(
  new URL("../../../public/js/dashboard-case-connect.js", import.meta.url),
  "utf8",
).replace(/\r\n/g, "\n");

/** The REAL handleCaseMessage, with every free name it touches recorded instead of run. */
function realCaseHandler(calls: string[]) {
  const src = CONNECT_SRC.slice(
    CONNECT_SRC.indexOf("function handleCaseMessage("),
    CONNECT_SRC.indexOf("// Case templates and incident types moved"),
  );
  const env = new Proxy(
    {},
    {
      has: (_t, k) => k !== "handleCaseMessage" && k !== "caseId" && k !== "msg" && k !== "ctx",
      get: (_t, k) => {
        if (k === Symbol.unscopables) return undefined;
        if (k === "document") return { getElementById: () => null };
        return () => calls.push(String(k));
      },
    },
  );
  // eslint-disable-next-line @typescript-eslint/no-implied-eval
  return new Function("env", `with (env) { ${src}; return handleCaseMessage; }`)(env) as (
    caseId: string,
    msg: LiveMsg,
    ctx?: CatchUpCtx,
  ) => void;
}

describe("the reconnect catch-up is one bounded, deduplicated run (#1709)", () => {
  const stateFetches = (h: ReturnType<typeof harness>) =>
    h.fetched.filter((u) => u.endsWith("/state")).length;
  /** Open the first socket, drop it, and let the 1 s retry open the second. */
  async function firstRetry(h: ReturnType<typeof harness>) {
    h.api.openCaseSocket("INC-1", h.onMessage);
    FakeSocket.made[0].open();
    FakeSocket.made[0].drop();
    await vi.advanceTimersByTimeAsync(1000);
  }

  it("waits until the reopened socket has stayed up before catching up", async () => {
    const h = harness();
    await firstRetry(h);
    FakeSocket.made[1].open();
    expect(h.aiRefreshed, "the pill is still re-derived at once").toEqual(["INC-1", "INC-1"]);
    await vi.advanceTimersByTimeAsync(CATCH_UP_SETTLE_MS - 1);
    expect(h.fetched).toEqual([]);
    expect(h.messages).toEqual([]);
    await vi.advanceTimersByTimeAsync(1);
    expect(stateFetches(h)).toBe(1);
  });

  it("collapses a flapping server into one catch-up once a socket stays up", async () => {
    const h = harness();
    await firstRetry(h);
    FakeSocket.made[1].open();
    await vi.advanceTimersByTimeAsync(1000);
    FakeSocket.made[1].drop(); // up 1 s, gone — retry in 2 s
    await vi.advanceTimersByTimeAsync(2000);
    FakeSocket.made[2].open();
    await vi.advanceTimersByTimeAsync(1000);
    FakeSocket.made[2].drop(); // again — retry in 4 s
    await vi.advanceTimersByTimeAsync(4000);
    expect(stateFetches(h), "no catch-up while the server flaps").toBe(0);
    FakeSocket.made[3].open();
    await vi.advanceTimersByTimeAsync(60_000);
    expect(stateFetches(h)).toBe(1);
    expect(h.messages.filter((m) => m.type === "comments_changed")).toHaveLength(1);
  });

  it("still catches up during a long flap, within the 10 s bound", async () => {
    const h = harness();
    await firstRetry(h);
    const t0 = Date.now();
    // Every socket stays up 1.9 s — never long enough to settle — and the flap never ends.
    for (let i = 1; stateFetches(h) === 0 && i < 12; i++) {
      FakeSocket.made[i].open();
      await vi.advanceTimersByTimeAsync(1900);
      if (stateFetches(h) > 0) break;
      FakeSocket.made[i].drop();
      while (FakeSocket.made.length === i + 1) await vi.advanceTimersByTimeAsync(100);
    }
    expect(stateFetches(h)).toBe(1);
    expect(Date.now() - t0).toBeLessThanOrEqual(10_000 + 1900);
  });

  it("runs one catch-up when the tab wakes during the settle wait", async () => {
    const h = harness();
    await firstRetry(h);
    FakeSocket.made[1].open(); // catch-up now waiting
    h.setVisibility("hidden");
    vi.setSystemTime(Date.now() + 13 * 60_000);
    h.setVisibility("visible"); // a sleep: the socket is replaced
    expect(FakeSocket.made).toHaveLength(3);
    FakeSocket.made[2].open();
    await vi.advanceTimersByTimeAsync(60_000);
    expect(stateFetches(h)).toBe(1);
  });

  it("drops a pending catch-up on a case switch and on a cancel", async () => {
    const h = harness();
    await firstRetry(h);
    FakeSocket.made[1].open();
    h.api.activeCaseId = "INC-2";
    h.api.openCaseSocket("INC-2", h.onMessage);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(h.fetched).toEqual([]);

    const c = harness();
    await firstRetry(c);
    FakeSocket.made[1].open();
    c.api.closeCaseSocket();
    await vi.advanceTimersByTimeAsync(60_000);
    expect(c.fetched).toEqual([]);
    expect(c.messages).toEqual([]);
  });

  it("marks every catch-up message with one shared context, and a real push with none", async () => {
    const h = harness();
    await firstRetry(h);
    FakeSocket.made[1].open();
    await vi.advanceTimersByTimeAsync(CATCH_UP_SETTLE_MS);
    const ctx = h.contexts[0];
    expect(ctx?.source).toBe("catch-up");
    expect(h.contexts.every((c) => c === ctx)).toBe(true);
    expect(h.messages.map((m) => m.type)).toContain("state");
    expect(h.messages.map((m) => m.type)).toContain("scope_changed");
    FakeSocket.made[1].push({ type: "pins_changed" });
    expect(h.contexts.at(-1)).toBeUndefined();
  });

  it("puts the catch-up through the case load's request cap of four", async () => {
    const runs: Array<{ names: string[]; concurrency?: number }> = [];
    const h = harness({
      runner: (entries, _onProgress, options) => {
        runs.push({ names: entries.map(([n]) => n), concurrency: options.concurrency });
        for (const [, run] of entries) run();
        return {};
      },
    });
    await firstRetry(h);
    FakeSocket.made[1].open();
    await vi.advanceTimersByTimeAsync(CATCH_UP_SETTLE_MS);
    expect(runs).toHaveLength(1);
    expect(runs[0].concurrency).toBe(4);
    expect(runs[0].names).toEqual(expect.arrayContaining(["jobs", "state", "scope", ...MISSED_TYPES]));
    expect(h.jobsLoaded).toEqual([1]);
    expect(stateFetches(h)).toBe(1);
    for (const t of MISSED_TYPES)
      expect(
        h.messages.filter((m) => m.type === t),
        t,
      ).toHaveLength(1);
  });

  it("abandons a catch-up already running on a drop, a case switch and a cancel", async () => {
    const signals: AbortSignal[] = [];
    const runner: PanelRunner = (_entries, _p, options) => {
      signals.push(options.signal!);
      return {}; // requests stay queued: nothing runs
    };
    const started = async (h: ReturnType<typeof harness>) => {
      await firstRetry(h);
      FakeSocket.made[1].open();
      await vi.advanceTimersByTimeAsync(CATCH_UP_SETTLE_MS);
      expect(signals.at(-1)?.aborted).toBe(false);
    };

    const drop = harness({ runner });
    await started(drop);
    FakeSocket.made[1].drop();
    expect(signals.at(-1)?.aborted, "drop").toBe(true);
    // The next socket that stays up owes, and runs, a fresh catch-up.
    await vi.advanceTimersByTimeAsync(2000);
    FakeSocket.made[2].open();
    await vi.advanceTimersByTimeAsync(CATCH_UP_SETTLE_MS);
    expect(signals).toHaveLength(2);
    expect(signals[1].aborted).toBe(false);

    const sw = harness({ runner });
    await started(sw);
    sw.api.activeCaseId = "INC-2";
    sw.api.openCaseSocket("INC-2", sw.onMessage);
    expect(signals.at(-1)?.aborted, "case switch").toBe(true);

    const cancel = harness({ runner });
    await started(cancel);
    cancel.api.closeCaseSocket();
    expect(signals.at(-1)?.aborted, "cancel").toBe(true);
  });

  it("runs each shared loader once per catch-up with the real handler, and again on a real push", async () => {
    const calls: string[] = [];
    const handle = realCaseHandler(calls);
    const h = harness();
    h.api.openCaseSocket("INC-1", (msg, ctx) => handle("INC-1", msg, ctx));
    FakeSocket.made[0].open();
    FakeSocket.made[0].drop();
    await vi.advanceTimersByTimeAsync(1000);
    FakeSocket.made[1].open();
    await vi.advanceTimersByTimeAsync(CATCH_UP_SETTLE_MS);
    const n = (name: string) => calls.filter((c) => c === name).length;
    expect(calls, "the state replay ran").toContain("render");
    expect(n("loadCockpit")).toBe(1);
    expect(n("loadSuperTimeline")).toBe(1);
    expect(n("loadAssetGraph") + n("scheduleAssetGraphReload")).toBe(1);
    // Loaders only one branch runs are untouched.
    expect(n("loadPins")).toBe(1);
    expect(n("loadHypotheses")).toBe(1);
    // A real push is a real change: the catch-up's bookkeeping must not swallow it.
    FakeSocket.made[1].push({ type: "activity_changed" });
    expect(n("loadCockpit")).toBe(2);
    FakeSocket.made[1].push({ type: "activity_changed" });
    expect(n("loadCockpit")).toBe(3);
  });
});

describe("a tab that becomes visible again (#1675)", () => {
  it("re-derives the pill and reconnects a closed socket at once, without waiting for the backoff", async () => {
    const h = harness();
    h.api.openCaseSocket("INC-1", h.onMessage);
    FakeSocket.made[0].open();
    FakeSocket.made[0].drop(); // a retry is now pending
    h.aiRefreshed.length = 0;
    h.setVisibility("hidden");
    h.setVisibility("visible");
    expect(h.aiRefreshed).toEqual(["INC-1"]);
    expect(FakeSocket.made, "reconnected synchronously, not after the timer").toHaveLength(2);
    // The pending retry was cancelled, so it does not open a third socket.
    await vi.advanceTimersByTimeAsync(5000);
    expect(FakeSocket.made).toHaveLength(2);
  });

  it("recycles an OPEN socket after a long sleep, since a half-open one never closes", async () => {
    const h = harness();
    h.api.openCaseSocket("INC-1", h.onMessage);
    const halfOpen = FakeSocket.made[0];
    halfOpen.open();
    h.setVisibility("hidden");
    vi.setSystemTime(Date.now() + 13 * 60_000);
    h.setVisibility("visible");
    expect(halfOpen.closeCalls).toBe(1);
    expect(FakeSocket.made).toHaveLength(2);
    expect(h.api.ws).toBe(FakeSocket.made[1]);
  });

  it("recycles the socket after a sleep in a tab that stayed visible", async () => {
    const h = harness();
    h.api.openCaseSocket("INC-1", h.onMessage);
    const halfOpen = FakeSocket.made[0];
    halfOpen.open();
    h.aiRefreshed.length = 0;
    // The machine sleeps: no timer runs, the wall clock jumps, no visibilitychange fires.
    vi.setSystemTime(Date.now() + 13 * 60_000);
    await vi.advanceTimersByTimeAsync(5000);
    expect(h.aiRefreshed).toEqual(["INC-1"]);
    expect(halfOpen.closeCalls).toBe(1);
    expect(h.api.ws).toBe(FakeSocket.made[1]);
  });

  it("leaves an OPEN socket alone after a short tab switch", () => {
    const h = harness();
    h.api.openCaseSocket("INC-1", h.onMessage);
    FakeSocket.made[0].open();
    h.setVisibility("hidden");
    h.setVisibility("visible");
    expect(FakeSocket.made).toHaveLength(1);
  });

  it("does nothing when no case is connected", () => {
    const h = harness();
    h.api.openCaseSocket("INC-1", h.onMessage);
    h.api.closeCaseSocket();
    h.aiRefreshed.length = 0;
    h.setVisibility("visible");
    expect(h.aiRefreshed).toEqual([]);
    expect(FakeSocket.made).toHaveLength(1);
  });
});

// ── The pill's own guard ────────────────────────────────────────────────────────────────────────
interface AiStatusApi {
  refreshAiState: (caseId: string) => Promise<void>;
  applyAiStatus: (evt: Record<string, unknown>) => void;
  activeCaseId: string | null;
}

describe("refreshAiState paints only the case on screen, newest answer wins (#1675)", () => {
  function pill() {
    const el = { className: "", textContent: "", title: "" };
    const pending: Array<(v: unknown) => void> = [];
    const api = loadDashboardModule<AiStatusApi>("dashboard-ai-status.js", [], {
      document: { getElementById: (id: string) => (id === "aiStatus" ? el : null) },
      fetch: () => Promise.resolve({ ok: true, json: () => new Promise((resolve) => pending.push(resolve)) }),
      setAi: (kind: string, text: string) => {
        el.className = "ai-" + kind;
        el.textContent = "AI: " + text;
      },
      activeCaseId: "INC-1",
      aiEnabled: true,
      ws: null,
    });
    return { el, api, pending };
  }

  it("drops an answer for a case the analyst has left", async () => {
    const { el, api, pending } = pill();
    const done = api.refreshAiState("INC-1");
    await vi.advanceTimersByTimeAsync(0);
    api.activeCaseId = "INC-2";
    pending[0]({ state: "idle", outOfDate: true, detail: "conclusions out of date" });
    await done;
    expect(el.textContent).toBe("");
  });

  it("does not let a call for a case the analyst left cancel the current case's correction", async () => {
    const { el, api, pending } = pill();
    api.activeCaseId = "INC-2";
    const current = api.refreshAiState("INC-2");
    await vi.advanceTimersByTimeAsync(0);
    await api.refreshAiState("INC-1"); // the old case's Re-synthesize finally, landing late
    pending[0]({ state: "analyzing", detail: "synthesizing findings…" });
    await current;
    expect(el.textContent).toBe("AI: synthesizing findings…");
  });

  it("drops a correction that lands after a newer pushed status", async () => {
    const { el, api, pending } = pill();
    const late = api.refreshAiState("INC-1");
    await vi.advanceTimersByTimeAsync(0);
    api.applyAiStatus({ status: "analyzing", phase: "synthesizing", detail: "" });
    const pushed = el.textContent;
    pending[0]({ state: "idle", outOfDate: true, detail: "conclusions out of date" });
    await late;
    expect(el.textContent).toBe(pushed);
  });

  it("drops an older answer that lands after a newer one", async () => {
    const { el, api, pending } = pill();
    const a = api.refreshAiState("INC-1");
    const b = api.refreshAiState("INC-1");
    await vi.advanceTimersByTimeAsync(0);
    pending[1]({ state: "analyzing", detail: "synthesizing findings…" });
    await b;
    pending[0]({ state: "idle", outOfDate: true, detail: "conclusions out of date" });
    await a;
    expect(el.textContent).toBe("AI: synthesizing findings…");
  });
});

// ── The Re-synthesize button ────────────────────────────────────────────────────────────────────
interface ScopeApi {
  resynthesize: () => void;
  resynthesizeInFlight: () => boolean;
}

describe("the Re-synthesize click (#1675)", () => {
  function click(opts: { deep?: boolean; answer: () => Promise<unknown> }) {
    const events: string[] = [];
    const synthesize = { disabled: false };
    const els: Record<string, unknown> = {
      caseId: { value: "INC-1" },
      status: { textContent: "" },
      deepReasoning: { checked: !!opts.deep },
      synthesize,
    };
    const api = loadDashboardModule<ScopeApi>("dashboard-search-scope.js", [], {
      document: { getElementById: (id: string) => els[id] ?? null },
      setAi: (kind: string, text: string) => events.push(`pill ${kind}: ${text}`),
      refreshAiState: (id: string) => events.push(`refresh ${id}`),
      fetch: (url: string) => {
        events.push(`fetch ${url}`);
        return url.endsWith("/synthesize") ? opts.answer() : Promise.reject(new Error("no"));
      },
      render: () => {},
      loadSynthMeta: () => {},
    });
    api.resynthesize();
    return Object.assign(events, { status: els.status as { textContent: string }, synthesize, api });
  }

  // Found in the #1800 triage: the button stayed live mid-run, and a second press superseded the
  // first run, whose 499 then read "synthesis failed: synthesis cancelled".
  it("disables the button until the POST settles", async () => {
    let answer: (v: unknown) => void = () => {};
    const events = click({ answer: () => new Promise((resolve) => (answer = resolve)) });
    expect(events.synthesize.disabled).toBe(true);
    expect(events.api.resynthesizeInFlight()).toBe(true);
    answer({ status: 200, json: () => Promise.resolve({ findings: 1, mitreTechniques: 0 }) });
    await vi.advanceTimersByTimeAsync(0);
    expect(events.synthesize.disabled).toBe(false);
    expect(events.api.resynthesizeInFlight()).toBe(false);
  });

  it("reads a superseded run's 499 as stopped, not failed", async () => {
    const events = click({
      answer: () =>
        Promise.resolve({ status: 499, json: () => Promise.resolve({ error: "synthesis cancelled" }) }),
    });
    await vi.advanceTimersByTimeAsync(0);
    expect(events.status.textContent).toBe("synthesis stopped — superseded by a newer run or cancelled");
    expect(events.at(-1)).toBe("refresh INC-1");
  });

  it("paints the pill before the POST is sent, and re-derives it when the POST ends", async () => {
    const events = click({
      answer: () =>
        Promise.resolve({ status: 200, json: () => Promise.resolve({ findings: 3, mitreTechniques: 2 }) }),
    });
    expect(events[0]).toBe("pill analyzing: synthesizing findings…");
    expect(events[1]).toBe("fetch /cases/INC-1/synthesize");
    await vi.advanceTimersByTimeAsync(0);
    expect(events).toContain("refresh INC-1");
  });

  it("says nothing was synthesized when the forensic timeline is empty (#1676)", async () => {
    const message = "nothing to synthesize — the forensic timeline is empty";
    const events = click({
      answer: () =>
        Promise.resolve({
          status: 200,
          json: () =>
            Promise.resolve({ skipped: "empty-timeline", message, findings: 0, mitreTechniques: 0 }),
        }),
    });
    await vi.advanceTimersByTimeAsync(0);
    expect(events.status.textContent).toBe(message);
    expect(events.at(-1)).toBe("refresh INC-1");
  });

  it("names deep reasoning on the pill", () => {
    const events = click({ deep: true, answer: () => new Promise(() => {}) });
    expect(events[0]).toBe("pill analyzing: synthesizing findings (deep reasoning)…");
  });

  it("re-derives the pill when the POST fails", async () => {
    const events = click({ answer: () => Promise.reject(new Error("network")) });
    await vi.advanceTimersByTimeAsync(0);
    expect(events.at(-1)).toBe("refresh INC-1");
  });

  it("re-derives the pill after a Presidio hold, so it reads on hold rather than synthesizing", async () => {
    const events = click({
      answer: () =>
        Promise.resolve({
          status: 409,
          json: () => Promise.resolve({ error: "presidio_approval_required", findings: [] }),
        }),
    });
    await vi.advanceTimersByTimeAsync(0);
    expect(events.at(-1)).toBe("refresh INC-1");
  });
});

// ── Wiring: the case-load path uses the socket module ───────────────────────────────────────────
describe("the case-load path hands its socket to js/dashboard-live-socket.js (#1675)", () => {
  const connect = readFileSync(
    new URL("../../../public/js/dashboard-case-connect.js", import.meta.url),
    "utf8",
  ).replace(/\r\n/g, "\n");
  const body = (name: string, next: string) => connect.slice(connect.indexOf(name), connect.indexOf(next));

  it("opens the socket through openCaseSocket with the named message handler", () => {
    expect(body("function proceedConnect(", "function restoreCaseFromUrl(")).toMatch(
      /openCaseSocket\(caseId, \(msg, ctx\) =>\s*handleCaseMessage\(caseId, msg, ctx\),?\s*\)/,
    );
    expect(connect).not.toMatch(/new WebSocket\(/);
  });

  it("closes the old socket through closeCaseSocket on a switch and on a cancel", () => {
    expect(body("function proceedConnect(", "function restoreCaseFromUrl(")).toContain("closeCaseSocket()");
    expect(body("function dismissCaseLoading(", "function proceedConnect(")).toContain("closeCaseSocket()");
  });
});
