import { getServerLogger } from "./serverLogger.js";

/**
 * Make a fatal synchronous exception leave a trace before the process goes down.
 *
 * Node's default for an uncaught exception is to dump a stack to stderr and exit immediately —
 * useful at a terminal, invisible the moment stderr isn't attached to anything a human is
 * watching (a detached `npm run dev`, a container whose logs nobody tailed at that second). The
 * crash that prompted this: a large Velociraptor hunt collect died mid-import with zero trace
 * anywhere — not the console, not the session log file — because nothing in the process had ever
 * been told to write one before Node exited.
 *
 * UNLIKE unhandledRejectionNet, this does NOT keep the server running afterward. Node's own
 * guidance is explicit: resuming normal operation after an uncaught exception can leave the
 * process in a corrupted state (a lock never released, a stream half-written, a lost promise
 * still pending on a lower stack frame that will never resolve). So this logs, then exits — the
 * fix is turning a silent crash into a diagnosable one, not turning the crash into a recovery.
 *
 * The exit is deliberately not immediate: the log line above is written to a buffered file
 * stream, and `process.exit()` does not wait for pending writes to flush. A short delay gives the
 * write a chance to land on disk before the process dies (see `EXIT_DELAY_MS`) — the earlier net
 * for unhandled rejections doesn't need this because it never exits at all.
 */

let installed = false;

const EXIT_DELAY_MS = 250;

/**
 * Arm the net. Idempotent — startServer may run more than once in a single process (tests, the
 * SEA entry), and a second listener would double-exit (harmless, but pointless).
 *
 * Call this ONLY from a real server entry point, never at module scope. Unit tests that build an
 * app with createApp() must keep Node's fatal default: an uncaught exception leaked by a test is
 * a failure that should crash the test run loudly, not exit cleanly through this net.
 *
 * `exit` is injectable so tests can observe the call without actually killing the test process —
 * production callers should never pass it.
 */
export function installUncaughtExceptionNet(exit: (code: number) => void = process.exit): void {
  if (installed) return;
  installed = true;
  process.on("uncaughtException", (err: unknown) => {
    const error = err instanceof Error ? err : new Error(String(err));
    // Resolved per-event, not captured once — mirrors unhandledRejectionNet: startServer swaps the
    // console logger for the file-backed one after boot, and the dashboard's Logging toggle can
    // replace it again at runtime. This must land in whichever log is current when it fires.
    try {
      getServerLogger().error(
        `uncaught exception — the server is exiting: ` +
          `${error.name}: ${error.message}\n${error.stack ?? "(no stack available)"}`,
      );
    } catch {
      // Logging itself must never be why the crash trace is lost — fall back to stderr directly.
      console.error("uncaught exception (logger threw while reporting it):", error);
    }
    setTimeout(() => exit(1), EXIT_DELAY_MS);
  });
}

/** Test-only: forget that the net was installed so a fresh listener can be armed. */
export function resetUncaughtExceptionNetForTests(): void {
  installed = false;
}
