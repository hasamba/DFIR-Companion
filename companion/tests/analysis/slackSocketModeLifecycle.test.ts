import { describe, it, expect, vi } from "vitest";
import {
  SlackSocketMode,
  type SocketLike,
  type SlackCommandPayload,
} from "../../src/analysis/slackSocketMode.js";
import type { Logger } from "../../src/logging/logger.js";

// Issue #2411: reconnects always back off unless the connection was healthy, a redelivered envelope
// never runs its command twice, stop() is prompt in every phase, and start() after stop() works.

function fakeLog(): Logger & { lines: string[] } {
  const lines: string[] = [];
  const push = (level: string) => (m: string) => {
    lines.push(`${level} ${m}`);
  };
  return {
    lines,
    debug: push("debug"),
    info: push("info"),
    warn: push("warn"),
    error: push("error"),
    getLevel: () => "info",
    setLevel: () => {},
    close: async () => {},
  } as unknown as Logger & { lines: string[] };
}

class FakeSocket implements SocketLike {
  readonly sent: string[] = [];
  closed = false;
  private handlers = new Map<string, (arg?: unknown) => void>();
  on(event: string, cb: (arg?: unknown) => void): void {
    this.handlers.set(event, cb);
  }
  send(data: string): void {
    if (this.closed) throw new Error("socket closed");
    this.sent.push(data);
  }
  close(): void {
    this.closed = true;
  }
  emit(event: string, arg?: unknown): void {
    this.handlers.get(event)?.(arg);
  }
  deliver(frame: unknown): void {
    this.emit("message", JSON.stringify(frame));
  }
  acks(): Array<Record<string, unknown>> {
    return this.sent.map((s) => JSON.parse(s));
  }
}

interface HarnessOpts {
  onCommand?: (p: SlackCommandPayload) => Promise<unknown>;
  sleepFn?: (ms: number) => Promise<void>;
  nowFn?: () => number;
  fetchFn?: typeof fetch;
}

function harness(opts: HarnessOpts = {}) {
  const sockets: FakeSocket[] = [];
  const slept: number[] = [];
  const log = fakeLog();
  let opens = 0;
  const fetchFn =
    opts.fetchFn ??
    (async () => {
      opens++;
      return new Response(JSON.stringify({ ok: true, url: "wss://slack.test/link" }), { status: 200 });
    });
  const mode = new SlackSocketMode({
    appToken: "xapp-1",
    fetchFn,
    log,
    nowFn: opts.nowFn,
    sleepFn:
      opts.sleepFn ??
      (async (ms) => {
        slept.push(ms);
        await new Promise((r) => setTimeout(r, 1));
      }),
    socketFactory: () => {
      const s = new FakeSocket();
      sockets.push(s);
      return s;
    },
    onCommand: opts.onCommand ?? (async () => ({ text: "ok" })),
  });
  return { mode, sockets, slept, log, opens: () => opens };
}

const envelope = (id: string, retry = 0) => ({
  envelope_id: id,
  type: "slash_commands",
  accepts_response_payload: true,
  retry_attempt: retry,
  payload: { command: "/dfir", text: "status", channel_id: "C1", user_id: "U1" },
});

function deferred<T>() {
  let resolve!: (v: T) => void;
  const promise = new Promise<T>((r) => (resolve = r));
  return { promise, resolve };
}

describe("SlackSocketMode reconnect backoff (#2411)", () => {
  it("backs off when a socket closes right after opening, instead of a hot loop", async () => {
    const { mode, sockets, slept } = harness();
    mode.start();
    for (let i = 0; i < 3; i++) {
      await vi.waitFor(() => expect(sockets.length).toBeGreaterThan(i));
      sockets[i].emit("open");
      sockets[i].deliver({ type: "hello" });
      sockets[i].emit("close");
    }
    await vi.waitFor(() => expect(slept.length).toBeGreaterThanOrEqual(3));
    await mode.stop();
    expect(slept.slice(0, 3)).toEqual([1000, 2000, 4000]);
  });

  it("reconnects at once after Slack rotates a long-lived connection", async () => {
    let now = 0;
    const { mode, sockets, slept, log } = harness({ nowFn: () => now });
    mode.start();
    await vi.waitFor(() => expect(sockets).toHaveLength(1));
    sockets[0].emit("open");
    now += 60 * 60_000;
    sockets[0].deliver({ type: "disconnect", reason: "refresh_requested" });
    await vi.waitFor(() => expect(sockets).toHaveLength(2));
    await mode.stop();
    expect(slept).toEqual([]);
    expect(log.lines.some((l) => l.startsWith("warn"))).toBe(false);
  });

  it("resets the backoff after a healthy connection", async () => {
    let now = 0;
    const { mode, sockets, slept } = harness({ nowFn: () => now });
    mode.start();
    for (let i = 0; i < 2; i++) {
      await vi.waitFor(() => expect(sockets.length).toBeGreaterThan(i));
      sockets[i].emit("close"); // never opened: unhealthy
    }
    await vi.waitFor(() => expect(sockets).toHaveLength(3));
    sockets[2].emit("open");
    now += 60_000;
    sockets[2].emit("close"); // healthy: reconnect immediately, backoff reset
    await vi.waitFor(() => expect(sockets).toHaveLength(4));
    sockets[3].emit("close");
    await vi.waitFor(() => expect(slept).toHaveLength(3));
    await mode.stop();
    expect(slept).toEqual([1000, 2000, 1000]);
  });
});

describe("SlackSocketMode envelope dedupe (#2411)", () => {
  it("runs a command once when Slack redelivers it while it is still running", async () => {
    const gate = deferred<unknown>();
    const onCommand = vi.fn(() => gate.promise);
    const { mode, sockets } = harness({ onCommand });
    mode.start();
    await vi.waitFor(() => expect(sockets).toHaveLength(1));
    sockets[0].deliver(envelope("env-1"));
    sockets[0].deliver(envelope("env-1", 1));
    await new Promise((r) => setTimeout(r, 5));
    expect(onCommand).toHaveBeenCalledTimes(1);
    gate.resolve({ text: "done" });
    await vi.waitFor(() => expect(sockets[0].sent.length).toBeGreaterThanOrEqual(1));
    // A late retry after completion is answered from the cache.
    sockets[0].deliver(envelope("env-1", 2));
    await vi.waitFor(() => expect(sockets[0].sent.length).toBeGreaterThanOrEqual(3));
    await mode.stop();
    expect(onCommand).toHaveBeenCalledTimes(1);
    for (const ack of sockets[0].acks())
      expect(ack).toEqual({ envelope_id: "env-1", payload: { text: "done" } });
  });

  it("acks a retry on the new connection when the original socket dropped mid-command", async () => {
    const gate = deferred<unknown>();
    const onCommand = vi.fn(() => gate.promise);
    const { mode, sockets } = harness({ onCommand });
    mode.start();
    await vi.waitFor(() => expect(sockets).toHaveLength(1));
    sockets[0].deliver(envelope("env-2"));
    sockets[0].emit("close");
    await vi.waitFor(() => expect(sockets).toHaveLength(2));
    sockets[1].deliver(envelope("env-2", 1));
    gate.resolve({ text: "late" });
    await vi.waitFor(() => expect(sockets[1].sent).toHaveLength(1));
    await mode.stop();
    expect(onCommand).toHaveBeenCalledTimes(1);
    expect(sockets[1].acks()[0]).toEqual({ envelope_id: "env-2", payload: { text: "late" } });
  });

  it("does not re-run a command whose handler threw when it is redelivered", async () => {
    const onCommand = vi.fn(async () => {
      throw new Error("boom");
    });
    const { mode, sockets } = harness({ onCommand });
    mode.start();
    await vi.waitFor(() => expect(sockets).toHaveLength(1));
    sockets[0].deliver(envelope("env-3"));
    await vi.waitFor(() => expect(sockets[0].sent).toHaveLength(1));
    sockets[0].deliver(envelope("env-3", 1));
    await vi.waitFor(() => expect(sockets[0].sent).toHaveLength(2));
    await mode.stop();
    expect(onCommand).toHaveBeenCalledTimes(1);
    expect(sockets[0].acks()[1]).toEqual({ envelope_id: "env-3" });
  });
});

describe("SlackSocketMode stop/start (#2411)", () => {
  it("stop() interrupts a long backoff sleep", async () => {
    const { mode, sockets } = harness({ sleepFn: () => new Promise(() => {}) });
    mode.start();
    await vi.waitFor(() => expect(sockets).toHaveLength(1));
    sockets[0].emit("close"); // unhealthy → parks in the never-ending sleep
    await new Promise((r) => setTimeout(r, 5));
    await expect(
      Promise.race([
        mode.stop().then(() => "stopped"),
        new Promise((r) => setTimeout(() => r("hung"), 1000)),
      ]),
    ).resolves.toBe("stopped");
  });

  it("stop() during connections.open neither hangs nor opens a socket afterwards", async () => {
    const gate = deferred<Response>();
    let sawAbort = false;
    const fetchFn = ((_url: string, init?: { signal?: AbortSignal }) => {
      init?.signal?.addEventListener("abort", () => (sawAbort = true));
      return gate.promise;
    }) as unknown as typeof fetch;
    const { mode, sockets } = harness({ fetchFn });
    mode.start();
    await new Promise((r) => setTimeout(r, 5));
    const stopping = mode.stop();
    gate.resolve(new Response(JSON.stringify({ ok: true, url: "wss://slack.test/x" }), { status: 200 }));
    await expect(
      Promise.race([stopping.then(() => "stopped"), new Promise((r) => setTimeout(() => r("hung"), 1000))]),
    ).resolves.toBe("stopped");
    expect(sawAbort).toBe(true);
    expect(sockets).toHaveLength(0);
  });

  it("start() after stop() connects again", async () => {
    const { mode, sockets } = harness();
    mode.start();
    await vi.waitFor(() => expect(sockets).toHaveLength(1));
    await mode.stop();
    mode.start();
    await vi.waitFor(() => expect(sockets).toHaveLength(2));
    await mode.stop();
  });

  it("concurrent stop() calls share one shutdown", async () => {
    const { mode, sockets } = harness();
    mode.start();
    await vi.waitFor(() => expect(sockets).toHaveLength(1));
    await Promise.all([mode.stop(), mode.stop()]);
    expect(sockets[0].closed).toBe(true);
  });
});
