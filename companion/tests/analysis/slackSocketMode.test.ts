import { describe, it, expect, vi } from "vitest";
import {
  SlackSocketMode,
  type SocketLike,
  type SlackCommandPayload,
} from "../../src/analysis/slackSocketMode.js";
import type { Logger } from "../../src/logging/logger.js";

// Slack Socket Mode (#235): an outbound WebSocket instead of a Request URL, so Slack commands need
// no tunnel and no public hostname. Slack pushes an envelope per command; each must be acked, and
// the ack payload is what the analyst sees.

const yieldingSleep = (record?: number[]) => async (ms: number) => {
  record?.push(ms);
  await new Promise((r) => setTimeout(r, 1));
};

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

/** A controllable stand-in for the WebSocket, so a test can push frames at the transport. */
class FakeSocket implements SocketLike {
  readonly sent: string[] = [];
  closed = false;
  private handlers = new Map<string, (arg?: unknown) => void>();
  on(event: string, cb: (arg?: unknown) => void): void {
    this.handlers.set(event, cb);
  }
  send(data: string): void {
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

/** connections.open always succeeds; every socket it hands out is captured for the test. */
function harness(
  opts: { onCommand?: (p: SlackCommandPayload) => Promise<unknown>; openBody?: unknown } = {},
) {
  const sockets: FakeSocket[] = [];
  const log = fakeLog();
  const opened: string[] = [];
  const fetchFn = (async (url: string) => {
    opened.push(String(url));
    return new Response(JSON.stringify(opts.openBody ?? { ok: true, url: "wss://slack.test/link" }), {
      status: 200,
    });
  }) as unknown as typeof fetch;

  const mode = new SlackSocketMode({
    appToken: "xapp-1",
    fetchFn,
    log,
    sleepFn: yieldingSleep(),
    socketFactory: () => {
      const s = new FakeSocket();
      sockets.push(s);
      return s;
    },
    onCommand: opts.onCommand ?? (async () => ({ response_type: "in_channel", text: "ok" })),
  });
  return { mode, sockets, log, opened };
}

const commandEnvelope = (id: string, text: string) => ({
  envelope_id: id,
  type: "slash_commands",
  accepts_response_payload: true,
  payload: {
    command: "/dfir",
    text,
    channel_id: "C1",
    user_id: "U1",
    response_url: "https://hooks.slack.com/x",
  },
});

describe("SlackSocketMode", () => {
  it("trades the app token for a socket URL", async () => {
    const { mode, sockets, opened } = harness();
    mode.start();
    await vi.waitFor(() => expect(sockets).toHaveLength(1));
    await mode.stop();
    expect(opened[0]).toBe("https://slack.com/api/apps.connections.open");
  });

  it("dispatches a slash command and acks with the reply", async () => {
    const seen: string[] = [];
    const { mode, sockets } = harness({
      onCommand: async (p) => {
        seen.push(p.text ?? "");
        return { response_type: "in_channel", text: "Top 5 findings" };
      },
    });
    mode.start();
    await vi.waitFor(() => expect(sockets).toHaveLength(1));
    sockets[0].deliver(commandEnvelope("env-1", "findings demo"));

    await vi.waitFor(() => expect(sockets[0].sent).toHaveLength(1));
    await mode.stop();
    expect(seen).toEqual(["findings demo"]);
    expect(sockets[0].acks()[0]).toEqual({
      envelope_id: "env-1",
      payload: { response_type: "in_channel", text: "Top 5 findings" },
    });
  });

  // An unacked envelope is redelivered, so kinds we ignore still have to be acked.
  it("acks an envelope it does not act on, with no payload", async () => {
    const { mode, sockets } = harness();
    mode.start();
    await vi.waitFor(() => expect(sockets).toHaveLength(1));
    sockets[0].deliver({ envelope_id: "env-2", type: "events_api", payload: { event: {} } });

    await vi.waitFor(() => expect(sockets[0].sent).toHaveLength(1));
    await mode.stop();
    expect(sockets[0].acks()[0]).toEqual({ envelope_id: "env-2" });
  });

  it("still acks when the command handler throws, so Slack does not redeliver it", async () => {
    const { mode, sockets, log } = harness({
      onCommand: async () => {
        throw new Error("dispatch exploded");
      },
    });
    mode.start();
    await vi.waitFor(() => expect(sockets).toHaveLength(1));
    sockets[0].deliver(commandEnvelope("env-3", "status"));

    await vi.waitFor(() => expect(sockets[0].sent).toHaveLength(1));
    await mode.stop();
    expect(sockets[0].acks()[0]).toEqual({ envelope_id: "env-3" });
    expect(log.lines.some((l) => l.includes("dispatch exploded"))).toBe(true);
  });

  // Slack rotates connections and warns first. Routine, not an error.
  it("opens a fresh connection when Slack asks it to reconnect", async () => {
    const { mode, sockets, opened, log } = harness();
    mode.start();
    await vi.waitFor(() => expect(sockets).toHaveLength(1));
    sockets[0].deliver({ type: "disconnect", reason: "refresh_requested" });

    await vi.waitFor(() => expect(sockets.length).toBeGreaterThanOrEqual(2));
    await mode.stop();
    expect(opened.length).toBeGreaterThanOrEqual(2);
    expect(log.lines.some((l) => l.includes("reconnecting"))).toBe(true);
    expect(log.lines.some((l) => l.startsWith("warn"))).toBe(false); // a rotation is not a warning
  });

  it("reconnects after the socket drops", async () => {
    const { mode, sockets } = harness();
    mode.start();
    await vi.waitFor(() => expect(sockets).toHaveLength(1));
    sockets[0].emit("close");
    await vi.waitFor(() => expect(sockets.length).toBeGreaterThanOrEqual(2));
    await mode.stop();
  });

  it("backs off when connections.open keeps failing", async () => {
    const slept: number[] = [];
    const log = fakeLog();
    const fetchFn = (async () =>
      new Response(JSON.stringify({ ok: false, error: "ratelimited" }), {
        status: 200,
      })) as unknown as typeof fetch;
    const mode = new SlackSocketMode({
      appToken: "xapp-1",
      fetchFn,
      log,
      sleepFn: yieldingSleep(slept),
      socketFactory: () => new FakeSocket(),
      onCommand: async () => undefined,
    });
    mode.start();
    await vi.waitFor(() => expect(slept.length).toBeGreaterThanOrEqual(3));
    await mode.stop();
    expect(slept.slice(0, 3)).toEqual([1000, 2000, 4000]);
  });

  it("explains a bad app token rather than retrying quietly", async () => {
    const log = fakeLog();
    const fetchFn = (async () =>
      new Response(JSON.stringify({ ok: false, error: "invalid_auth" }), {
        status: 200,
      })) as unknown as typeof fetch;
    const mode = new SlackSocketMode({
      appToken: "xoxb-wrong-kind",
      fetchFn,
      log,
      sleepFn: yieldingSleep(),
      socketFactory: () => new FakeSocket(),
      onCommand: async () => undefined,
    });
    mode.start();
    await vi.waitFor(() => expect(log.lines.some((l) => l.startsWith("error"))).toBe(true));
    await mode.stop();
    const line = log.lines.find((l) => l.startsWith("error"))!;
    expect(line).toMatch(/DFIR_SLACK_APP_TOKEN/);
    expect(line).toMatch(/xapp-/);
    expect(line).toMatch(/connections:write/);
  });

  it("ignores a frame that isn't JSON instead of dropping the connection", async () => {
    const { mode, sockets } = harness();
    mode.start();
    await vi.waitFor(() => expect(sockets).toHaveLength(1));
    sockets[0].emit("message", "<not json>");
    sockets[0].deliver(commandEnvelope("env-4", "status"));
    await vi.waitFor(() => expect(sockets[0].sent).toHaveLength(1));
    await mode.stop();
    expect(sockets[0].acks()[0].envelope_id).toBe("env-4");
  });

  it("stop() closes the socket and stops reconnecting", async () => {
    const { mode, sockets, opened } = harness();
    mode.start();
    await vi.waitFor(() => expect(sockets).toHaveLength(1));
    await mode.stop();
    const openCount = opened.length;
    sockets[0].emit("close");
    await new Promise((r) => setTimeout(r, 20));
    expect(opened.length).toBe(openCount);
    expect(sockets[0].closed).toBe(true);
  });

  // stop() must not wait on a "close" event: a half-open or wedged socket never emits one, and
  // shutdown would hang forever. FakeSocket.close() deliberately stays silent to prove it.
  it("stop() returns even when the socket never emits close", async () => {
    const { mode, sockets } = harness();
    mode.start();
    await vi.waitFor(() => expect(sockets).toHaveLength(1));
    await expect(
      Promise.race([
        mode.stop().then(() => "stopped"),
        new Promise((r) => setTimeout(() => r("hung"), 2_000)),
      ]),
    ).resolves.toBe("stopped");
  });

  it("start() twice does not open two connections", async () => {
    const { mode, sockets } = harness();
    mode.start();
    mode.start();
    await vi.waitFor(() => expect(sockets).toHaveLength(1));
    await mode.stop();
    expect(sockets).toHaveLength(1);
  });
});
