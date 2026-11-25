import { describe, expect, it } from "vitest";
import {
  FORWARDED_SIGNALS,
  FORWARD_GRACE_MS,
  createSignalForwarder,
  HEAP_CEILING_MB,
  HEAP_FLOOR_MB,
  computeHeapMb,
  existingHeapFlag,
  heapLogLine,
} from "../../scripts/dev-launch.mjs";

// `npm run dev` sizes the server's V8 heap from the machine instead of a fixed 8 GB (#2855).
// The sizing is pure, so it is tested here; importing the launcher must never spawn a server.

const GB = 1024 ** 3;

describe("computeHeapMb (#2855)", () => {
  it("keeps 8192 MB on a 16 GB host, exactly as the old fixed flag did", () => {
    expect(computeHeapMb({ totalMemBytes: 16 * GB })).toEqual({
      heapMb: 8192,
      memMb: 16384,
      source: "machine",
    });
  });

  it("caps at 8192 MB on a bigger host", () => {
    expect(computeHeapMb({ totalMemBytes: 64 * GB }).heapMb).toBe(HEAP_CEILING_MB);
  });

  it("gives half of an 8 GB machine", () => {
    expect(computeHeapMb({ totalMemBytes: 8 * GB }).heapMb).toBe(4096);
  });

  it("never goes below the 2048 MB floor", () => {
    expect(computeHeapMb({ totalMemBytes: 2 * GB }).heapMb).toBe(HEAP_FLOOR_MB);
  });

  it("floors a fractional half", () => {
    expect(computeHeapMb({ totalMemBytes: 6001 * 1024 * 1024 }).heapMb).toBe(3000);
  });

  it("lets a container cap below the machine total win", () => {
    expect(computeHeapMb({ totalMemBytes: 32 * GB, constrainedMemBytes: 6 * GB })).toEqual({
      heapMb: 3072,
      memMb: 6144,
      source: "container",
    });
  });

  it.each([
    ["undefined", undefined],
    ["0", 0],
    ["negative", -1],
    ["NaN", Number.NaN],
    ["at or above the machine total (no real cap)", 64 * GB],
    ["the 'unlimited' sentinel", Number.MAX_SAFE_INTEGER],
  ])("ignores a constrainedMemory of %s", (_label, constrained) => {
    expect(computeHeapMb({ totalMemBytes: 8 * GB, constrainedMemBytes: constrained })).toEqual({
      heapMb: 4096,
      memMb: 8192,
      source: "machine",
    });
  });
});

describe("existingHeapFlag (#2855)", () => {
  it("returns null when no flag is set anywhere", () => {
    expect(existingHeapFlag({ nodeOptions: "--enable-source-maps", execArgv: [], args: [] })).toBeNull();
    expect(existingHeapFlag({})).toBeNull();
  });

  it("finds a flag in NODE_OPTIONS and passes nothing extra (the child inherits it)", () => {
    expect(
      existingHeapFlag({
        nodeOptions: "--enable-source-maps --max-old-space-size=3000",
        execArgv: [],
        args: [],
      }),
    ).toEqual({ where: "NODE_OPTIONS", flags: [] });
  });

  it("forwards a flag given to the launcher's own node (execArgv is not inherited)", () => {
    expect(existingHeapFlag({ execArgv: ["--max-old-space-size=4096"], args: [] })).toEqual({
      where: "launcher arguments",
      flags: ["--max-old-space-size=4096"],
    });
  });

  it("forwards a flag passed after `npm run dev --`", () => {
    expect(existingHeapFlag({ execArgv: [], args: ["--max-old-space-size=12000"] })).toEqual({
      where: "launcher arguments",
      flags: ["--max-old-space-size=12000"],
    });
  });

  it("accepts the underscore spelling node also accepts", () => {
    expect(existingHeapFlag({ nodeOptions: "--max_old_space_size=2500" })).toEqual({
      where: "NODE_OPTIONS",
      flags: [],
    });
  });
});

describe("createSignalForwarder (#2855)", () => {
  function setup(alive = true) {
    const kills: string[] = [];
    const child = {
      exitCode: alive ? null : 0,
      signalCode: null,
      kill: (s: string) => kills.push(s),
    };
    const timers: { fn: () => void; ms: number }[] = [];
    const cleared: unknown[] = [];
    const fwd = createSignalForwarder(child, {
      setTimer: (fn, ms) => timers.push({ fn, ms }),
      clearTimer: (t) => cleared.push(t),
    });
    return { child, kills, timers, cleared, fwd };
  }

  it("does not forward at once, so a Ctrl+C the server already got is not doubled", () => {
    const { kills, timers, fwd } = setup();
    fwd.onSignal("SIGINT");
    expect(kills).toEqual([]);
    expect(timers).toHaveLength(1);
    expect(timers[0]?.ms).toBe(FORWARD_GRACE_MS);
    expect(FORWARD_GRACE_MS).toBeGreaterThan(5000);
  });

  it("forwards after the grace when the server is still running (a signal sent to the launcher alone)", () => {
    const { kills, timers, fwd } = setup();
    fwd.onSignal("SIGTERM");
    timers[0]?.fn();
    expect(kills).toEqual(["SIGTERM"]);
  });

  it("does not forward when the server already exited", () => {
    const { kills, timers, fwd } = setup(false);
    fwd.onSignal("SIGINT");
    timers[0]?.fn();
    expect(kills).toEqual([]);
  });

  it("arms only one timer for repeated signals and cancels it", () => {
    const { timers, cleared, fwd } = setup();
    fwd.onSignal("SIGINT");
    fwd.onSignal("SIGINT");
    fwd.onSignal("SIGTERM");
    expect(timers).toHaveLength(1);
    fwd.cancel();
    expect(cleared).toHaveLength(1);
  });

  it("covers SIGINT and SIGTERM", () => {
    expect([...FORWARDED_SIGNALS]).toEqual(["SIGINT", "SIGTERM"]);
  });
});

describe("heapLogLine (#2855)", () => {
  it("names the heap and the machine memory", () => {
    const line = heapLogLine(computeHeapMb({ totalMemBytes: 16 * GB }));
    expect(line).toContain("8192 MB");
    expect(line).toContain("machine memory");
  });

  it("names the container cap when it won", () => {
    const line = heapLogLine(computeHeapMb({ totalMemBytes: 32 * GB, constrainedMemBytes: 6 * GB }));
    expect(line).toContain("3072 MB");
    expect(line).toContain("container memory cap");
  });

  it("says when an existing flag was respected", () => {
    expect(heapLogLine(null, { where: "NODE_OPTIONS", flags: [] })).toContain("NODE_OPTIONS");
  });
});
