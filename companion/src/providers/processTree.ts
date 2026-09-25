import { spawn, spawnSync, type ChildProcess } from "node:child_process";

// Kill a CLI provider call's WHOLE process tree, not only the direct child (#1627).
//
// `child.kill()` stops the process we spawned and nothing below it. The claude and codex CLIs start
// helpers (MCP servers, tool processes) that inherit stdout/stderr; on Windows the child is even the
// cmd.exe behind cross-spawn's `.cmd` shim, with the real CLI one level down. Those survive a direct
// kill, keep the pipes open, and keep a cancelled call running and billed until they exit.
//
// POSIX: the child is spawned `detached`, so it leads its own process group, and the whole group is
// SIGKILLed with `process.kill(-pid)`. A detached group no longer receives the terminal's Ctrl-C, so
// the live-child registry below kills every group itself when the server exits or is signalled.
// Windows: `taskkill /PID <pid> /T /F` walks the tree. Children are not detached there — a detached
// Windows child gets a new console — so a console Ctrl-C still reaches them as it always has.
// A Windows Job Object would also cover a hard kill of the server itself; that is out of scope here.

/** Upper bound on one taskkill run, so a hung taskkill can never hold a cancelled call open. */
export const TASKKILL_TIMEOUT_MS = 5_000;

export type TreeChild = Pick<ChildProcess, "pid" | "kill">;

export interface TreeKillDeps {
  platform: NodeJS.Platform;
  killPid: (pid: number, signal: NodeJS.Signals) => void;
  /** Resolves true when taskkill exited 0. Must never reject. */
  runTaskkill: (pid: number) => Promise<boolean>;
  runTaskkillSync: (pid: number) => boolean;
}

const TASKKILL_ARGS = (pid: number): string[] => ["/PID", String(pid), "/T", "/F"];

const runTaskkill = (pid: number): Promise<boolean> =>
  new Promise((resolve) => {
    let finished = false;
    const finish = (ok: boolean) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      resolve(ok);
    };
    const tk = spawn("taskkill", TASKKILL_ARGS(pid), { stdio: "ignore", windowsHide: true });
    const timer = setTimeout(() => {
      tk.kill();
      finish(false);
    }, TASKKILL_TIMEOUT_MS);
    tk.on("error", () => finish(false));
    tk.on("exit", (code) => finish(code === 0));
  });

const runTaskkillSync = (pid: number): boolean => {
  const r = spawnSync("taskkill", TASKKILL_ARGS(pid), {
    stdio: "ignore",
    windowsHide: true,
    timeout: TASKKILL_TIMEOUT_MS,
  });
  return r.status === 0;
};

export const defaultTreeKillDeps: TreeKillDeps = {
  platform: process.platform,
  killPid: (pid, signal) => {
    process.kill(pid, signal);
  },
  runTaskkill,
  runTaskkillSync,
};

/** Spawn options that make the child killable as a tree on this platform. */
export function treeSpawnOptions(platform: NodeJS.Platform = process.platform): { detached?: true } {
  return platform === "win32" ? {} : { detached: true };
}

const hasPid = (child: TreeChild): child is TreeChild & { pid: number } =>
  typeof child.pid === "number" && child.pid > 0;

const killDirect = (child: TreeChild): void => {
  try {
    child.kill("SIGKILL");
  } catch {
    /* already gone */
  }
};

/** POSIX group kill. Returns false when the group could not be signalled. */
const killGroup = (pid: number, deps: TreeKillDeps): boolean => {
  try {
    deps.killPid(-pid, "SIGKILL");
    return true;
  } catch {
    return false;
  }
};

/**
 * Kill the child and every process under it. Resolves once the kill attempt has finished (taskkill
 * exited, or timed out); never rejects. Falls back to a direct kill when the tree kill fails or the
 * child never got a pid (a failed spawn).
 */
export async function killProcessTree(
  child: TreeChild,
  deps: TreeKillDeps = defaultTreeKillDeps,
): Promise<void> {
  if (!hasPid(child)) return killDirect(child);
  const ok = deps.platform === "win32" ? await deps.runTaskkill(child.pid) : killGroup(child.pid, deps);
  if (!ok) treeKillFailed(child);
}

// A direct kill cannot reach the processes below the child, so a failed tree kill is logged: it is
// the one case where a cancelled call's helpers can outlive it. Node has no Windows Job Object API,
// which is what a guaranteed tree kill would need there.
const treeKillFailed = (child: TreeChild & { pid: number }): void => {
  console.warn(
    `[providers] could not kill the process tree of CLI pid ${child.pid}; killed the CLI only — ` +
      `a process it started may still be running (#1627)`,
  );
  killDirect(child);
};

/** Synchronous variant for process `exit`, where no asynchronous work can run. */
export function killProcessTreeSync(child: TreeChild, deps: TreeKillDeps = defaultTreeKillDeps): void {
  if (!hasPid(child)) return killDirect(child);
  const ok = deps.platform === "win32" ? deps.runTaskkillSync(child.pid) : killGroup(child.pid, deps);
  if (!ok) treeKillFailed(child);
}

/** The slice of `process` the registry uses — injectable so tests never signal the test worker. */
export interface RegistryProcess {
  pid: number;
  kill(pid: number, signal: NodeJS.Signals): boolean | void;
  on(event: "exit", listener: () => void): unknown;
  prependListener(event: NodeJS.Signals, listener: () => void): unknown;
  removeListener(event: string, listener: (...args: unknown[]) => void): unknown;
  listenerCount(event: string): number;
}

export interface ChildRegistry {
  /** Track a live child; returns the function that untracks it. A pid-less child is not tracked. */
  track(child: TreeChild): () => void;
  size(): number;
}

// The signals that stop a server from a terminal or a service manager. SIGKILL cannot be caught.
const SHUTDOWN_SIGNALS: readonly NodeJS.Signals[] = ["SIGINT", "SIGTERM", "SIGHUP"];

/**
 * Tracks live provider children so a server shutdown kills their trees too. Listeners exist only
 * while at least one child is live, so an idle server's signal behavior is untouched.
 *
 * The signal listener is PREPENDED, so it runs before any other listener, including `once`
 * wrappers that are still registered at that moment. It re-raises the signal only when it is the
 * sole listener — the case where Node would have terminated by default — and does so after removing
 * itself, so the default action applies. With another listener present, that listener owns
 * shutdown, exactly as before.
 */
export function createChildRegistry(opts: {
  proc: RegistryProcess;
  platform: NodeJS.Platform;
  killSync: (child: TreeChild) => void;
}): ChildRegistry {
  const { proc, platform, killSync } = opts;
  const live = new Set<TreeChild>();
  const signals = platform === "win32" ? [] : SHUTDOWN_SIGNALS;
  const signalListeners = new Map<NodeJS.Signals, () => void>();

  const killAll = () => {
    for (const child of live) killSync(child);
  };
  const onExit = () => killAll();

  const uninstall = () => {
    proc.removeListener("exit", onExit);
    for (const [sig, fn] of signalListeners) proc.removeListener(sig, fn);
    signalListeners.clear();
  };

  const onSignal = (sig: NodeJS.Signals) => {
    const alone = proc.listenerCount(sig) === 1;
    killAll();
    live.clear();
    uninstall();
    if (alone) proc.kill(proc.pid, sig);
  };

  const install = () => {
    proc.on("exit", onExit);
    for (const sig of signals) {
      const fn = () => onSignal(sig);
      signalListeners.set(sig, fn);
      proc.prependListener(sig, fn);
    }
  };

  return {
    track(child) {
      if (!hasPid(child)) return () => {};
      if (live.size === 0) install();
      live.add(child);
      return () => {
        if (live.delete(child) && live.size === 0) uninstall();
      };
    },
    size: () => live.size,
  };
}

/** The server-wide registry every provider runner tracks its child in. */
export const liveProviderChildren: ChildRegistry = createChildRegistry({
  proc: process,
  platform: process.platform,
  killSync: (child) => killProcessTreeSync(child),
});
