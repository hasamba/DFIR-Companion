/**
 * Stop-signal drain for the real server (#2142).
 *
 * Without a handler a stop signal ends the process with nothing flushed: the last session and case
 * log lines and the server's close hooks (team-auth store, writer guard) are lost. In a container
 * it is worse: Node runs as PID 1, and PID 1 IGNORES a signal it has no handler for, so every
 * `docker stop` waited out the grace period and ended in a SIGKILL.
 *
 * On the first SIGTERM / SIGINT (/ SIGHUP off Windows) this closes the HTTP server, stops the
 * outbound transports, writes a final line, closes the loggers and exits 0, all inside a bounded
 * deadline that sits safely under Docker's default 10 s grace period. It deliberately does NOT
 * wait for imports or AI runs: the job manager already turns those into recoverable interrupted
 * jobs at the next start, and an AI run can take minutes. A second signal during the drain exits
 * at once (the "press Ctrl+C twice" escape).
 *
 * It coexists with the provider child registry (providers/processTree.ts): that listener is
 * prepended, kills the provider process trees, and does not re-raise when another listener (this
 * one) is present, so this handler owns shutdown.
 */

/** Hard ceiling for the whole drain. Under Docker's default 10 s stop grace period. */
export const SHUTDOWN_DEADLINE_MS = 5000;

/** How long before the deadline lingering connections (keep-alive, live sockets) are dropped. */
const CLOSE_ALL_LEAD_MS = 1000;

const SIGNAL_EXIT_CODES: Readonly<Record<string, number>> = { SIGHUP: 129, SIGINT: 130, SIGTERM: 143 };

export interface ShutdownServer {
  close(cb?: (err?: Error) => void): unknown;
  closeIdleConnections?(): void;
  closeAllConnections?(): void;
}

export interface ShutdownProcess {
  on(event: NodeJS.Signals, listener: () => void): unknown;
  removeListener(event: NodeJS.Signals, listener: () => void): unknown;
}

export interface ShutdownDeps {
  server: ShutdownServer;
  stopTransports: () => Promise<void>;
  closeLogger: () => Promise<void>;
  log: (msg: string) => void;
  /** Injectable so tests never signal the vitest worker. Defaults to `process`. */
  proc?: ShutdownProcess;
  /** Injectable so tests observe the exit. Defaults to `process.exit`. */
  exit?: (code: number) => void;
  deadlineMs?: number;
  platform?: NodeJS.Platform;
}

// One handler set per process object, so a second startServer in one process (tests, the SEA
// entry) does not double-register.
const installedOn = new WeakMap<object, () => void>();

const errText = (e: unknown): string => (e instanceof Error ? e.message : String(e));

function closeServer(server: ShutdownServer, waitMs: number, log: (m: string) => void): Promise<void> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve();
    };
    // Drop lingering connections (keep-alive, upgraded live sockets) shortly before the deadline
    // and carry on: the remaining steps must still get their chance to flush.
    const timer = setTimeout(() => {
      log("[shutdown] connections still open — closing them");
      try {
        server.closeAllConnections?.();
      } catch (e) {
        log(`[shutdown] closing connections failed: ${errText(e)}`);
      }
      finish();
    }, waitMs);
    timer.unref?.();
    try {
      server.close((err) => {
        if (err) log(`[shutdown] server close reported: ${err.message}`);
        finish();
      });
      server.closeIdleConnections?.();
    } catch (e) {
      log(`[shutdown] server close failed: ${errText(e)}`);
      finish();
    }
  });
}

async function step(name: string, fn: () => Promise<void>, log: (m: string) => void): Promise<void> {
  try {
    await fn();
  } catch (e) {
    log(`[shutdown] ${name} failed: ${errText(e)}`);
  }
}

/**
 * Arm the drain. Call it ONLY from the real server entry (startServer), never from createApp, so
 * unit tests keep Node's default signal behavior. Returns an uninstall function for tests.
 */
export function installGracefulShutdown(deps: ShutdownDeps): () => void {
  const proc: ShutdownProcess = deps.proc ?? process;
  const existing = installedOn.get(proc);
  if (existing) return existing;

  const exit = deps.exit ?? ((code: number) => process.exit(code));
  const deadlineMs = deps.deadlineMs ?? SHUTDOWN_DEADLINE_MS;
  const platform = deps.platform ?? process.platform;
  const { log } = deps;
  const signals: NodeJS.Signals[] =
    platform === "win32" ? ["SIGINT", "SIGTERM"] : ["SIGINT", "SIGTERM", "SIGHUP"];
  let draining = false;

  const drain = async (sig: NodeJS.Signals) => {
    log(`[shutdown] ${sig} received — draining (deadline ${Math.round(deadlineMs / 1000)}s)`);
    const force = setTimeout(() => {
      log("[shutdown] deadline reached — forcing exit");
      exit(1);
    }, deadlineMs);
    force.unref?.();
    await closeServer(deps.server, Math.max(0, deadlineMs - CLOSE_ALL_LEAD_MS), log);
    await step("stopping transports", deps.stopTransports, log);
    log("[shutdown] complete");
    await step("closing the logger", deps.closeLogger, log);
    clearTimeout(force);
    exit(0);
  };

  const listeners = new Map<NodeJS.Signals, () => void>();
  for (const sig of signals) {
    const fn = () => {
      if (draining) {
        log(`[shutdown] second ${sig} — exiting now`);
        exit(SIGNAL_EXIT_CODES[sig] ?? 1);
        return;
      }
      draining = true;
      void drain(sig);
    };
    listeners.set(sig, fn);
    proc.on(sig, fn);
  }

  const uninstall = () => {
    for (const [sig, fn] of listeners) proc.removeListener(sig, fn);
    listeners.clear();
    installedOn.delete(proc);
  };
  installedOn.set(proc, uninstall);
  return uninstall;
}
