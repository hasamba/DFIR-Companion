/**
 * Hand the event loop one macrotask turn, so a long CPU-bound job lets queued requests (`/health`,
 * other cases, manual writes) and timers run between its phases (#2058).
 *
 * `setImmediate` runs after pending I/O callbacks, unlike `await Promise.resolve()`, which resolves as
 * a microtask and lets nothing else in. It changes no data and adds no supersede check: a caller that
 * must stop when cancelled checks its own signal around the await.
 */
export function yieldToEventLoop(): Promise<void> {
  return new Promise<void>((resolve) => setImmediate(resolve));
}

/** How long one slice of a sliced loop may run before it hands the event loop a turn (#2716). */
export const SLICE_BUDGET_MS = 25;

/**
 * A slice clock for a long loop (#2716): `due()` says the current slice has used its budget and
 * starts the next one. The loop awaits `yieldToEventLoop()` only when it is due, so a short run never
 * yields and a long one yields about every `budgetMs`.
 */
export function createSliceClock(budgetMs = SLICE_BUDGET_MS): { due(): boolean } {
  let start = performance.now();
  return {
    due() {
      const now = performance.now();
      if (now - start < budgetMs) return false;
      start = now;
      return true;
    },
  };
}

/** `items.map(fn)` in slices that yield to the event loop: the same values, in the same order. */
export async function mapYielding<T, R>(
  items: readonly T[],
  fn: (item: T, index: number) => R,
  budgetMs = SLICE_BUDGET_MS,
): Promise<R[]> {
  const clock = createSliceClock(budgetMs);
  const out: R[] = new Array<R>(items.length);
  for (let i = 0; i < items.length; i++) {
    out[i] = fn(items[i], i);
    if (clock.due()) await yieldToEventLoop();
  }
  return out;
}
