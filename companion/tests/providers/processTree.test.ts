import { EventEmitter } from "node:events";
import { afterEach, beforeEach, describe, it, expect, vi } from "vitest";
import {
  createChildRegistry,
  killProcessTree,
  killProcessTreeSync,
  treeSpawnOptions,
  type RegistryProcess,
  type TreeChild,
  type TreeKillDeps,
} from "../../src/providers/processTree.js";

// #1627: a cancelled CLI call must kill the CLI's whole process tree, not only the direct child.

// `null` stands for a child that never got a pid (a failed spawn).
const fakeChild = (pid: number | null = 4242) => ({
  pid: pid ?? undefined,
  kill: vi.fn(() => true),
});

const deps = (over: Partial<TreeKillDeps> = {}): TreeKillDeps => ({
  platform: "linux",
  killPid: vi.fn(),
  runTaskkill: vi.fn(async () => true),
  runTaskkillSync: vi.fn(() => true),
  ...over,
});

let warn: ReturnType<typeof vi.spyOn>;
beforeEach(() => {
  warn = vi.spyOn(console, "warn").mockImplementation(() => {});
});
afterEach(() => vi.restoreAllMocks());

describe("treeSpawnOptions", () => {
  it("detaches on POSIX so the child leads its own process group", () => {
    expect(treeSpawnOptions("linux")).toEqual({ detached: true });
    expect(treeSpawnOptions("darwin")).toEqual({ detached: true });
  });
  it("does not detach on Windows, where detached opens a new console", () => {
    expect(treeSpawnOptions("win32")).toEqual({});
  });
});

describe("killProcessTree", () => {
  it("SIGKILLs the whole process group on POSIX", async () => {
    const d = deps();
    const child = fakeChild();
    await killProcessTree(child, d);
    expect(d.killPid).toHaveBeenCalledWith(-4242, "SIGKILL");
    expect(child.kill).not.toHaveBeenCalled();
  });

  it("falls back to a direct kill when the group cannot be signalled", async () => {
    const d = deps({
      killPid: vi.fn(() => {
        throw Object.assign(new Error("EPERM"), { code: "EPERM" });
      }),
    });
    const child = fakeChild();
    await killProcessTree(child, d);
    expect(child.kill).toHaveBeenCalledWith("SIGKILL");
    // A direct kill cannot reach the helpers, so the failure is logged.
    expect(warn).toHaveBeenCalledTimes(1);
  });

  it("runs taskkill /T /F on Windows and waits for it", async () => {
    let finish: (ok: boolean) => void = () => {};
    const d = deps({
      platform: "win32",
      runTaskkill: vi.fn(() => new Promise<boolean>((r) => (finish = r))),
    });
    const child = fakeChild();
    let done = false;
    const p = killProcessTree(child, d).then(() => (done = true));
    await Promise.resolve();
    expect(d.runTaskkill).toHaveBeenCalledWith(4242);
    expect(d.killPid).not.toHaveBeenCalled();
    expect(done).toBe(false); // settlement waits for taskkill
    finish(true);
    await p;
    expect(child.kill).not.toHaveBeenCalled();
  });

  it("falls back to a direct kill when taskkill fails", async () => {
    const d = deps({ platform: "win32", runTaskkill: vi.fn(async () => false) });
    const child = fakeChild();
    await killProcessTree(child, d);
    expect(child.kill).toHaveBeenCalledWith("SIGKILL");
  });

  it("never signals a group for a child with no pid (a failed spawn)", async () => {
    const d = deps();
    const child = fakeChild(null);
    await killProcessTree(child, d);
    expect(d.killPid).not.toHaveBeenCalled();
    expect(child.kill).toHaveBeenCalledWith("SIGKILL");
  });
});

describe("killProcessTreeSync", () => {
  it("uses the synchronous taskkill on Windows", () => {
    const d = deps({ platform: "win32" });
    killProcessTreeSync(fakeChild(), d);
    expect(d.runTaskkillSync).toHaveBeenCalledWith(4242);
  });
  it("group-kills on POSIX", () => {
    const d = deps();
    killProcessTreeSync(fakeChild(), d);
    expect(d.killPid).toHaveBeenCalledWith(-4242, "SIGKILL");
  });
  it("falls back to a direct kill when the synchronous taskkill fails", () => {
    const d = deps({ platform: "win32", runTaskkillSync: vi.fn(() => false) });
    const child = fakeChild();
    killProcessTreeSync(child, d);
    expect(child.kill).toHaveBeenCalledWith("SIGKILL");
  });
});

// The registry is tested against a fake process object. Signalling the vitest worker for real
// would terminate the test run.
class FakeProc extends EventEmitter implements RegistryProcess {
  pid = 777;
  kill = vi.fn(() => true);
}

const setup = (platform: NodeJS.Platform = "linux") => {
  const proc = new FakeProc();
  const killSync = vi.fn<(c: TreeChild) => void>();
  const registry = createChildRegistry({ proc, platform, killSync });
  return { proc, killSync, registry };
};

describe("createChildRegistry", () => {
  it("installs listeners only while a child is live", () => {
    const { proc, registry } = setup();
    expect(proc.listenerCount("SIGINT")).toBe(0);
    const untrackA = registry.track(fakeChild(1));
    const untrackB = registry.track(fakeChild(2));
    expect(proc.listenerCount("SIGINT")).toBe(1);
    expect(proc.listenerCount("SIGTERM")).toBe(1);
    expect(proc.listenerCount("SIGHUP")).toBe(1);
    expect(proc.listenerCount("exit")).toBe(1);
    untrackA();
    expect(proc.listenerCount("SIGINT")).toBe(1);
    untrackB();
    expect(proc.listenerCount("SIGINT")).toBe(0);
    expect(proc.listenerCount("exit")).toBe(0);
  });

  it("does not track a child with no pid", () => {
    const { proc, registry } = setup();
    registry.track(fakeChild(null));
    expect(registry.size()).toBe(0);
    expect(proc.listenerCount("exit")).toBe(0);
  });

  it("kills every live tree on process exit", () => {
    const { proc, killSync, registry } = setup();
    const a = fakeChild(1);
    const b = fakeChild(2);
    registry.track(a);
    registry.track(b);
    proc.emit("exit");
    expect(killSync).toHaveBeenCalledWith(a);
    expect(killSync).toHaveBeenCalledWith(b);
  });

  it("on Ctrl-C with no other listener: kills the trees, then re-raises for the default exit", () => {
    const { proc, killSync, registry } = setup();
    const a = fakeChild(1);
    registry.track(a);
    proc.emit("SIGINT");
    expect(killSync).toHaveBeenCalledWith(a);
    expect(proc.kill).toHaveBeenCalledWith(777, "SIGINT");
    // Removed before re-raising, so the default action applies.
    expect(proc.listenerCount("SIGINT")).toBe(0);
    expect(proc.listenerCount("exit")).toBe(0);
  });

  it("leaves shutdown to an existing listener instead of re-raising", () => {
    const { proc, killSync, registry } = setup();
    const own = vi.fn();
    proc.on("SIGTERM", own);
    registry.track(fakeChild(1));
    proc.emit("SIGTERM");
    expect(killSync).toHaveBeenCalled();
    expect(own).toHaveBeenCalled();
    expect(proc.kill).not.toHaveBeenCalled();
  });

  it("counts a once listener as present, even one registered after the first child", () => {
    const { proc, registry } = setup();
    registry.track(fakeChild(1));
    const own = vi.fn();
    proc.once("SIGINT", own);
    proc.emit("SIGINT");
    expect(own).toHaveBeenCalled();
    expect(proc.kill).not.toHaveBeenCalled();
  });

  it("re-installs after a signal handled by another listener when a new child starts", () => {
    const { proc, registry } = setup();
    proc.on("SIGINT", () => {});
    registry.track(fakeChild(1));
    proc.emit("SIGINT");
    expect(registry.size()).toBe(0);
    registry.track(fakeChild(2));
    expect(proc.listenerCount("SIGINT")).toBe(2);
  });

  it("installs no signal listeners on Windows, only the exit listener", () => {
    const { proc, registry } = setup("win32");
    registry.track(fakeChild(1));
    expect(proc.listenerCount("SIGINT")).toBe(0);
    expect(proc.listenerCount("exit")).toBe(1);
  });
});
