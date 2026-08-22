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
/**
 * Every budget here is a wall-clock measurement taken on Linux. Windows CI runs the same suite on
 * fewer cores with slower filesystem calls, so the same number is not the same budget there.
 *
 * SCALE EVERY LAYER BY THE SAME FACTOR, or the relationships between them break. `POLL_TIMEOUT_MS`
 * is exported and 62 tests build their own `it()` timeout from it as `POLL_TIMEOUT_MS * 2`, and an
 * explicit `it()` timeout OVERRIDES vitest.config.ts entirely — so those tests never saw its
 * Windows scaling. Scaling only the inner poll would have put a 30s poll inside a 20s test and made
 * Windows worse than the bug it was fixing.
 *
 * Everything scaled therefore comes from `pollBudget()`, `POLL_TIMEOUT_MS` included. Because one
 * factor applies throughout, every ratio holds exactly as on Linux — above all the one this file
 * demands of callers: a test timeout above the SUM of its poll budgets.
 *
 * The budget is a BRANDED type because a raw number cannot say whether it has been scaled yet, and
 * getting that wrong is INVISIBLE ON LINUX — the factor is 1 here, so a double-scaled budget and a
 * correct one are the same value. A regex over the test sources was tried first and cannot work:
 * `timeoutMs` is also an option name for the provider, MCP and tool runners (60-odd unrelated
 * hits), and it says nothing about `const b = POLL_TIMEOUT_MS * 2` passed in a variable. The
 * compiler rejects a bare number at exactly the three call sites that are really PollOptions.
 */
const PLATFORM_SLOWDOWN = process.platform === "win32" ? 3 : 1;

/**
 * A poll budget that has already been platform-scaled. Only `pollBudget()` can make one, so a bare
 * number — including `POLL_TIMEOUT_MS * 2`, the double-scaling trap — is a compile error.
 */
export type PollBudgetMs = number & { readonly __pollBudget: unique symbol };

/** Scale a Linux-measured budget for this platform. The ONLY way to build a `timeoutMs` override. */
export const pollBudget = (linuxMs: number): PollBudgetMs => (linuxMs * PLATFORM_SLOWDOWN) as PollBudgetMs;

/** Platform-scaled default. Also the right constant for an `it()` timeout, which nothing scales. */
export const POLL_TIMEOUT_MS = pollBudget(10_000);
const POLL_INTERVAL_MS = 20;

export interface PollOptions {
  /**
   * Wall-clock budget from `pollBudget(linuxMs)`. Keep the caller's test timeout above the SUM of
   * its polls — both sides scale by the same factor, so that arithmetic is platform-independent.
   */
  timeoutMs?: PollBudgetMs;
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
  // No scaling here: pollBudget() already applied the factor, and POLL_TIMEOUT_MS is one of its
  // products. Scaling again is the bug the branded type exists to make unrepresentable.
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
      throw new Error(`timed out after ${timeoutMs}ms (${attempts} attempts) waiting for: ${what}`);
    }
    await new Promise((r) => setTimeout(r, intervalMs));
  }
}
