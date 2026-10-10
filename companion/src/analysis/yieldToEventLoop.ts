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
