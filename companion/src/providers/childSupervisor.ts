import type { ChildProcess } from "node:child_process";
import { killProcessTree, liveProviderChildren, type ChildRegistry } from "./processTree.js";

/**
 * How long a killed call may wait for its pipes to close before the runner stops waiting (#1627).
 * Counted from the end of the tree-kill attempt. A process that escaped the tree kill (it started its own session,
 * or taskkill failed) can hold the pipes open for as long as it lives; past this point the runner
 * closes its ends and settles, and logs that the kill was not confirmed.
 */
export const KILL_SETTLE_GRACE_MS = 3_000;

export type SupervisedOutcome =
  { kind: "error"; error: NodeJS.ErrnoException } | { kind: "close"; code: number | null; timedOut: boolean };

export interface SuperviseOptions {
  timeoutMs: number;
  signal?: AbortSignal;
  /** Names the CLI in the warning logged when a kill is not confirmed. */
  label: string;
  graceMs?: number;
  registry?: ChildRegistry;
  killTree?: (child: ChildProcess) => Promise<void>;
}

/**
 * Own a spawned CLI child's lifecycle: the timeout, external cancellation, the whole-tree kill, the
 * server-shutdown registry, and settlement. Resolves exactly once and never rejects.
 *
 * A killed call settles only when BOTH its pipes have closed AND the tree kill has finished, so a
 * Windows taskkill still walking the tree is never reported as done. A killed call always reports
 * `code: null` — taskkill leaves exit code 1 on Windows, where POSIX reports a signal.
 */
export function superviseChild(child: ChildProcess, opts: SuperviseOptions): Promise<SupervisedOutcome> {
  const registry = opts.registry ?? liveProviderChildren;
  const killTree = opts.killTree ?? killProcessTree;
  const graceMs = opts.graceMs ?? KILL_SETTLE_GRACE_MS;

  return new Promise((resolve) => {
    let settled = false;
    // Set BEFORE the kill starts: a fallback child.kill() can emit "error" synchronously.
    let killing = false;
    let killed: Promise<void> | undefined;
    let graceTimer: NodeJS.Timeout | undefined;
    const untrack = registry.track(child);

    const settle = (outcome: SupervisedOutcome) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      clearTimeout(graceTimer);
      opts.signal?.removeEventListener("abort", kill);
      untrack();
      resolve(outcome);
    };

    const forceSettle = () => {
      console.warn(
        `[${opts.label}] killed CLI call still held its output open after ${graceMs} ms; ` +
          `a process it started may still be running (#1627)`,
      );
      child.stdin?.destroy();
      child.stdout?.destroy();
      child.stderr?.destroy();
      settle({ kind: "close", code: null, timedOut: true });
    };

    // The grace starts once the tree kill has finished (taskkill is bounded by its own timeout), so
    // the runner never stops waiting while taskkill is still walking the tree.
    function kill() {
      if (killing || settled) return;
      killing = true;
      killed = killTree(child)
        .catch(() => {})
        .then(() => {
          if (!settled) graceTimer = setTimeout(forceSettle, graceMs);
        });
    }

    const timer = setTimeout(kill, opts.timeoutMs);
    if (opts.signal) {
      if (opts.signal.aborted) kill();
      else opts.signal.addEventListener("abort", kill, { once: true });
    }

    child.on("error", (error: NodeJS.ErrnoException) => {
      // Once a kill has started, an error is a failed signal delivery, not a failed spawn: keep
      // waiting for close or the forced settle rather than reporting a spawn error.
      if (killing) return console.warn(`[${opts.label}] error while killing CLI call: ${error.message}`);
      settle({ kind: "error", error });
    });
    child.on("close", (code: number | null) => {
      if (!killing) return settle({ kind: "close", code, timedOut: false });
      void killed?.then(() => settle({ kind: "close", code: null, timedOut: true }));
    });
  });
}
