import { EventEmitter } from "node:events";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  installGracefulShutdown,
  SHUTDOWN_DEADLINE_MS,
  type ShutdownDeps,
} from "../../src/composition/gracefulShutdown.js";
import { createChildRegistry, type TreeChild } from "../../src/providers/processTree.js";

// #2142: a stop signal must drain the server (close it, stop the outbound transports, flush the
// loggers) and exit within a bounded deadline. In a container Node is PID 1, and PID 1 ignores a
// signal that has no handler, so without this every `docker stop` ended in a SIGKILL.
//
// Everything runs against a fake process object: signalling the vitest worker for real would end
// the test run.

class FakeProc extends EventEmitter {
  pid = 777;
  kill = vi.fn(() => true);
}

interface FakeServer {
  close: ReturnType<typeof vi.fn>;
  closeIdleConnections: ReturnType<typeof vi.fn>;
  closeAllConnections: ReturnType<typeof vi.fn>;
}

const fakeServer = (closesCleanly = true): FakeServer => ({
  close: vi.fn((cb?: (err?: Error) => void) => {
    if (closesCleanly) queueMicrotask(() => cb?.());
  }),
  closeIdleConnections: vi.fn(),
  closeAllConnections: vi.fn(),
});

const setup = (over: Partial<ShutdownDeps> = {}, closesCleanly = true) => {
  const proc = new FakeProc();
  const order: string[] = [];
  const server = fakeServer(closesCleanly);
  server.close.mockImplementation((cb?: (err?: Error) => void) => {
    order.push("close");
    if (closesCleanly) queueMicrotask(() => cb?.());
  });
  const lines: string[] = [];
  const exit = vi.fn<(code: number) => void>((code) => {
    order.push(`exit:${code}`);
  });
  const deps: ShutdownDeps = {
    server,
    stopTransports: vi.fn(async () => {
      order.push("transports");
    }),
    closeLogger: vi.fn(async () => {
      order.push("logger");
    }),
    log: (m) => lines.push(m),
    proc,
    exit,
    platform: "linux",
    ...over,
  };
  const uninstall = installGracefulShutdown(deps);
  return { proc, server, order, lines, exit, deps, uninstall };
};

let cleanups: Array<() => void> = [];
const track = <T extends { uninstall: () => void }>(s: T): T => {
  cleanups.push(s.uninstall);
  return s;
};

beforeEach(() => {
  vi.useFakeTimers();
  cleanups = [];
});
afterEach(() => {
  for (const c of cleanups) c();
  vi.useRealTimers();
});

describe("installGracefulShutdown", () => {
  it("drains in order on SIGTERM: close server, stop transports, close logger, exit 0", async () => {
    const s = track(setup());
    s.proc.emit("SIGTERM");
    await vi.runAllTimersAsync();
    expect(s.order).toEqual(["close", "transports", "logger", "exit:0"]);
    expect(s.server.closeIdleConnections).toHaveBeenCalled();
    expect(s.server.closeAllConnections).not.toHaveBeenCalled();
    expect(s.lines.some((l) => l.includes("SIGTERM received"))).toBe(true);
    expect(s.lines.some((l) => l.includes("[shutdown] complete"))).toBe(true);
  });

  it("logs the complete line BEFORE the logger is closed, so it reaches the file", async () => {
    let seenAtClose: string[] = [];
    const lines: string[] = [];
    const s = track(
      setup({
        log: (m) => lines.push(m),
        closeLogger: async () => {
          seenAtClose = [...lines];
        },
      }),
    );
    s.proc.emit("SIGINT");
    await vi.runAllTimersAsync();
    expect(seenAtClose.at(-1)).toContain("[shutdown] complete");
    expect(s.exit).toHaveBeenCalledWith(0);
  });

  it("drops lingering connections when the server never finishes closing, then still drains", async () => {
    const s = track(setup({}, false));
    s.proc.emit("SIGTERM");
    await vi.advanceTimersByTimeAsync(SHUTDOWN_DEADLINE_MS - 1001);
    expect(s.server.closeAllConnections).not.toHaveBeenCalled();
    expect(s.exit).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    expect(s.server.closeAllConnections).toHaveBeenCalled();
    await vi.runAllTimersAsync();
    expect(s.order).toEqual(["close", "transports", "logger", "exit:0"]);
  });

  it("forces exit(1) at the deadline when a drain step hangs", async () => {
    const s = track(setup({ closeLogger: () => new Promise<void>(() => {}) }));
    s.proc.emit("SIGTERM");
    await vi.advanceTimersByTimeAsync(SHUTDOWN_DEADLINE_MS - 1);
    expect(s.exit).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    expect(s.exit).toHaveBeenCalledWith(1);
    expect(s.lines.some((l) => l.includes("deadline reached"))).toBe(true);
  });

  it("keeps draining when stopping the transports throws", async () => {
    const s = track(
      setup({
        stopTransports: async () => {
          throw new Error("telegram down");
        },
      }),
    );
    s.proc.emit("SIGTERM");
    await vi.runAllTimersAsync();
    expect(s.lines.some((l) => l.includes("telegram down"))).toBe(true);
    expect(s.deps.closeLogger).toHaveBeenCalled();
    expect(s.exit).toHaveBeenCalledWith(0);
  });

  it("exits at once with a non-zero code on a second signal during the drain", async () => {
    const s = track(setup({}, false));
    s.proc.emit("SIGTERM");
    await vi.advanceTimersByTimeAsync(10);
    s.proc.emit("SIGINT");
    expect(s.exit).toHaveBeenCalledTimes(1);
    expect(s.exit).toHaveBeenCalledWith(130);
  });

  it("is idempotent per process: installing twice leaves one listener per signal", () => {
    const s = track(setup());
    const again = installGracefulShutdown(s.deps);
    cleanups.push(again);
    expect(s.proc.listenerCount("SIGTERM")).toBe(1);
    expect(s.proc.listenerCount("SIGINT")).toBe(1);
    expect(s.proc.listenerCount("SIGHUP")).toBe(1);
  });

  it("does not listen for SIGHUP on Windows", () => {
    const s = track(setup({ platform: "win32" }));
    expect(s.proc.listenerCount("SIGHUP")).toBe(0);
    expect(s.proc.listenerCount("SIGTERM")).toBe(1);
  });

  it("uninstall removes every listener", () => {
    const s = setup();
    s.uninstall();
    expect(s.proc.listenerCount("SIGTERM")).toBe(0);
    expect(s.proc.listenerCount("SIGINT")).toBe(0);
    expect(s.proc.listenerCount("SIGHUP")).toBe(0);
  });

  it("coexists with the provider child registry: children are killed and the signal is not re-raised", async () => {
    const s = track(setup());
    const killSync = vi.fn<(c: TreeChild) => void>();
    const registry = createChildRegistry({ proc: s.proc, platform: "linux", killSync });
    registry.track({ pid: 4242, kill: vi.fn(() => true) });
    s.proc.emit("SIGTERM");
    await vi.runAllTimersAsync();
    expect(killSync).toHaveBeenCalledTimes(1);
    expect(s.proc.kill).not.toHaveBeenCalled();
    expect(s.exit).toHaveBeenCalledWith(0);
  });
});
