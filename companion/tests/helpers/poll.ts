/**
 * Deadline-based polling for tests (issue #173).
 *
 * The suite is full of `for (let i = 0; i < 100; i++) { check(); await sleep(20); }` loops. That
 * spells a budget of "100 iterations", which developers read as "2 seconds" — but it is really
 * "2 seconds of SLEEPING plus 100 round-trips", and under a loaded parallel run the round-trips
 * dominate and the sleeps overrun. Worse, when such a loop gives up it throws its OWN error, so
 * raising `testTimeout` cannot save it: the loop is the binding constraint, not Vitest.
 *
 * Measured on the #80 hunt-diff test, whose four sequential 100x20ms waits made it fail ~50% of
 * runs under heavy disk load — on master, with no source change involved.
 *
 * `pollFor` takes a WALL-CLOCK budget instead. The number of attempts then scales with how slow
 * the machine actually is, which is the property the iteration count was trying and failing to
 * express. Callers must still ensure the test's own timeout exceeds the sum of its poll budgets —
 * see POLL_TIMEOUT_MS users for the arithmetic.
 */
export const POLL_TIMEOUT_MS = 10_000;
const POLL_INTERVAL_MS = 20;

export interface PollOptions {
  /** Wall-clock budget. Keep the caller's test timeout above the SUM of its polls. */
  timeoutMs?: number;
  intervalMs?: number;
}

/**
 * Call `probe` until it returns a value that is neither `undefined` nor `null`, then return it.
 * Throws with `description` if the budget expires — phrase it as what never happened, e.g.
 * "hunt H.RUN1 reporting 2 result rows".
 */
export async function pollFor<T>(
  description: string | (() => string),
  probe: () => Promise<T | undefined | null>,
  options: PollOptions = {},
): Promise<T> {
  const timeoutMs = options.timeoutMs ?? POLL_TIMEOUT_MS;
  const intervalMs = options.intervalMs ?? POLL_INTERVAL_MS;
  const deadline = Date.now() + timeoutMs;
  let attempts = 0;

  for (;;) {
    attempts++;
    const result = await probe();
    if (result !== undefined && result !== null) return result;
    if (Date.now() >= deadline) {
      // Resolve the description LAST, so a caller can pass a closure that reports what it actually
      // observed. "never reached the state, last saw X after N attempts in Ms" is the difference
      // between a diagnosable failure and one that gets waved away as flake (issue #173).
      const what = typeof description === "function" ? description() : description;
      throw new Error(
        `timed out after ${timeoutMs}ms (${attempts} attempts) waiting for: ${what}`,
      );
    }
    await new Promise((r) => setTimeout(r, intervalMs));
  }
}
