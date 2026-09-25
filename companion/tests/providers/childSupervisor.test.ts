import { EventEmitter } from "node:events";
import type { ChildProcess } from "node:child_process";
import { describe, it, expect, vi } from "vitest";
import { superviseChild } from "../../src/providers/childSupervisor.js";
import { createChildRegistry } from "../../src/providers/processTree.js";

// #1627: settlement rules for a killed CLI call, against a fake child so timing is deterministic.

const fakeChild = () => {
  const c = new EventEmitter() as EventEmitter & Partial<ChildProcess>;
  Object.assign(c, { pid: 99, kill: vi.fn(() => true), stdin: null, stdout: null, stderr: null });
  return c as unknown as ChildProcess;
};

const registry = () =>
  createChildRegistry({
    proc: Object.assign(new EventEmitter(), { pid: 1, kill: vi.fn() }),
    platform: "linux",
    killSync: vi.fn(),
  });

describe("superviseChild", () => {
  it("settles a normal exit with its exit code", async () => {
    const child = fakeChild();
    const p = superviseChild(child, { timeoutMs: 10_000, label: "t", registry: registry() });
    child.emit("close", 3);
    expect(await p).toEqual({ kind: "close", code: 3, timedOut: false });
  });

  it("settles a spawn error", async () => {
    const child = fakeChild();
    const p = superviseChild(child, { timeoutMs: 10_000, label: "t", registry: registry() });
    const error = Object.assign(new Error("nope"), { code: "ENOENT" });
    child.emit("error", error);
    expect(await p).toEqual({ kind: "error", error });
  });

  it("starts one tree kill when abort and timeout both fire", async () => {
    vi.useFakeTimers();
    try {
      const child = fakeChild();
      const killTree = vi.fn(async () => {});
      const ac = new AbortController();
      const p = superviseChild(child, {
        timeoutMs: 100,
        signal: ac.signal,
        label: "t",
        registry: registry(),
        killTree,
      });
      ac.abort();
      await vi.advanceTimersByTimeAsync(150);
      expect(killTree).toHaveBeenCalledTimes(1);
      child.emit("close", 1);
      await vi.advanceTimersByTimeAsync(0);
      expect(await p).toEqual({ kind: "close", code: null, timedOut: true });
    } finally {
      vi.useRealTimers();
    }
  });

  it("waits for the tree kill to finish even when the direct child closes first", async () => {
    const child = fakeChild();
    let finishKill: () => void = () => {};
    const killTree = vi.fn(() => new Promise<void>((r) => (finishKill = r)));
    const ac = new AbortController();
    let settled = false;
    const p = superviseChild(child, {
      timeoutMs: 10_000,
      signal: ac.signal,
      label: "t",
      registry: registry(),
      killTree,
    }).then((o) => ((settled = true), o));
    ac.abort();
    // taskkill has killed cmd.exe (exit code 1) but is still walking the tree.
    child.emit("close", 1);
    await new Promise((r) => setTimeout(r, 20));
    expect(settled).toBe(false);
    finishKill();
    // A killed call reports code null on every platform.
    expect(await p).toEqual({ kind: "close", code: null, timedOut: true });
  });

  it("forces settlement when the pipes stay open after the tree kill finished", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      const child = fakeChild();
      const ac = new AbortController();
      const reg = registry();
      const p = superviseChild(child, {
        timeoutMs: 10_000,
        signal: ac.signal,
        label: "t",
        registry: reg,
        graceMs: 30,
        killTree: async () => {},
      });
      expect(reg.size()).toBe(1);
      ac.abort();
      expect(await p).toEqual({ kind: "close", code: null, timedOut: true });
      expect(warn).toHaveBeenCalledTimes(1);
      expect(reg.size()).toBe(0);
    } finally {
      warn.mockRestore();
    }
  });

  it("does not start the grace until a slow tree kill has finished", async () => {
    vi.useFakeTimers();
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      const child = fakeChild();
      let finishKill: () => void = () => {};
      const ac = new AbortController();
      let settled = false;
      void superviseChild(child, {
        timeoutMs: 60_000,
        signal: ac.signal,
        label: "t",
        registry: registry(),
        graceMs: 100,
        killTree: () => new Promise<void>((r) => (finishKill = r)),
      }).then(() => (settled = true));
      ac.abort();
      await vi.advanceTimersByTimeAsync(4_000); // taskkill still walking the tree
      expect(settled).toBe(false);
      finishKill();
      await vi.advanceTimersByTimeAsync(150);
      expect(settled).toBe(true);
    } finally {
      warn.mockRestore();
      vi.useRealTimers();
    }
  });

  it("treats an error raised while killing as a failed kill, not a spawn error", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      const child = fakeChild();
      const ac = new AbortController();
      const p = superviseChild(child, {
        timeoutMs: 10_000,
        signal: ac.signal,
        label: "t",
        registry: registry(),
        killTree: async () => {
          child.emit("error", new Error("kill EPERM"));
        },
      });
      ac.abort();
      child.emit("close", null);
      expect(await p).toEqual({ kind: "close", code: null, timedOut: true });
      expect(warn).toHaveBeenCalledTimes(1);
    } finally {
      warn.mockRestore();
    }
  });
});
