import { getServerLogger } from "./serverLogger.js";

/**
 * Stop one stray promise rejection from ending the whole investigation.
 *
 * Node's default for an unhandled rejection is to kill the process. On a long-lived DFIR server
 * that is the worst available response: an import, an enrichment pass, a deep pass and a synthesis
 * can all be mid-flight, and none of that work survives the exit — the analyst loses the session
 * over a bug in a code path they were not even using. The crash that prompted this was exactly
 * that: a queued job's admission promise was rejected a few milliseconds before anything awaited
 * it, and cancelling that one job took the server down with every other case operation on it.
 *
 * A rejection nobody awaited IS a bug. This net does not make it not-a-bug — it decides that the
 * bug costs one operation instead of every operation, and that the analyst finds out from a log
 * line rather than from a dead process. Fixing the leak is still the real fix; see
 * tests/server/jobCancelUnhandledRejection.test.ts for the class this is backstopping.
 *
 * The stack is always logged and never trimmed, because it is the only thing that identifies the
 * culprit — and it is easy to misread: an unhandled rejection's stack points at where the Error
 * was CONSTRUCTED, not where it escaped unhandled. Treat it as the starting point of the hunt.
 */

let installed = false;

/**
 * Arm the net. Idempotent — startServer may run more than once in a single process (tests, the
 * SEA entry), and a second listener would double every line.
 *
 * Call this ONLY from a real server entry point, never at module scope. Unit tests that build an
 * app with createApp() must keep Node's fatal default: a rejection leaked by a test is a failure
 * that should be loud, and arming the net for them would hide exactly the bugs this exists for.
 */
export function installUnhandledRejectionNet(): void {
  if (installed) return;
  installed = true;
  process.on("unhandledRejection", (reason: unknown) => {
    const error = reason instanceof Error ? reason : new Error(String(reason));
    // The logger is resolved per-event, not captured once: startServer swaps the console logger
    // for the file-backed one after boot, and the dashboard's Logging toggle can replace it again
    // at runtime. A rejection should land in whichever log is current when it fires.
    getServerLogger().error(
      `unhandled promise rejection — the server kept running, but this is a bug worth reporting: ` +
        `${error.name}: ${error.message}\n${error.stack ?? "(no stack available)"}`,
    );
  });
}

/** Test-only: forget that the net was installed so a fresh listener can be armed. */
export function resetUnhandledRejectionNetForTests(): void {
  installed = false;
}
