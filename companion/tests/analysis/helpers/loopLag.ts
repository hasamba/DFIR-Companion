/**
 * Event-loop responsiveness while `work` runs (#2716): a 5 ms interval timer counts how often it got
 * to run and the longest gap between two of its turns (or between the start and its first turn).
 */
export async function loopLag(work: () => Promise<unknown>): Promise<{ ticks: number; maxGapMs: number }> {
  let ticks = 0;
  let last = performance.now();
  let maxGapMs = 0;
  const timer = setInterval(() => {
    const now = performance.now();
    maxGapMs = Math.max(maxGapMs, now - last);
    last = now;
    ticks++;
  }, 5);
  try {
    await work();
  } finally {
    clearInterval(timer);
  }
  maxGapMs = Math.max(maxGapMs, performance.now() - last);
  return { ticks, maxGapMs };
}
