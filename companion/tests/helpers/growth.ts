import { expect } from "vitest";

// Shared growth-ratio harness for "this path scales linearly, not quadratically" tests. Extracted
// from tests/analysis/loadTest.test.ts (#183, #366) so the linear-time scan checks can use the same
// proven measurement instead of single-shot Date.now() timings, which flaked on slow runners (#2444).
// The rationale for each part — CPU time instead of wall clock, batched windows for the ~15.6ms
// Windows CPU-clock tick, best-of-N, full-size warm-up, limit = baseline*GROWTH_LIMIT + FLOOR_MS —
// is documented beside it below. The figures in the comments were measured on loadTest's paths.

// The full input is this many times the baseline. The bigger the gap, the wider the separation
// between acceptable and quadratic growth: at 8x input, linear costs 8x and quadratic costs 64x —
// room on both sides.
export const GROWTH_FACTOR = 8;

export interface Measurement {
  ms: number;
  result: unknown;
}

// Best of N runs, measured in CPU time rather than wall clock.
//
// Wall clock counts every millisecond this process spends descheduled while some other test
// worker holds the core, so under a loaded machine it reports the machine's contention, not the
// code's cost. Best-of-N was meant to absorb that, and does when a stall is occasional — but it
// only helps if SOME sample runs clean, and the full-size run is GROWTH_FACTOR times longer than
// the baseline, so under sustained load it is proportionally likelier that every one of its
// samples is hit while the short baseline escapes. That asymmetry inflates the ratio and fails
// the assertion for reasons that have nothing to do with the code under test.
//
// process.cpuUsage() counts only cycles actually burned on this process's behalf, so time spent
// waiting for a core simply isn't counted. Every measured fn here is synchronous, so nothing else
// in this worker can run inside the window and contribute. Same minimum-of-N, honest clock.
//
// What that clock does NOT give is equal resolution everywhere. On Linux it is microsecond-grained,
// but on Windows it advances in ~15.6ms scheduler ticks, so any run cheaper than one tick measures
// as exactly 0. Three of the paths below cost 0.1-4.6 CPU-ms at baseline size, so on the Windows
// release runner their baselines read 0 — and a 0 baseline collapses the allowance in
// expectSubQuadratic() from baseline*GROWTH_LIMIT + FLOOR_MS to FLOOR_MS alone, several times
// tighter than intended. That is what failed the release job during #366, on a path nobody had
// touched: correlateEvents reported "0.0ms → 93.0ms" against a 25ms limit.
//
// So time a BATCH of calls and divide. The window then clears the tick and the per-call figure is
// honest on every platform. Every figure in the table below is per-call CPU-time.
export const MIN_SAMPLE_MS = 50; // ~3 Windows ticks, so quantization error is well under 1%.
// Backstop against a path so cheap it could never fill a window. Reaching it needs a call under
// ~0.01ms, and at that size the full-size run is under a millisecond too — orders of magnitude
// inside FLOOR_MS — so the assertion still cannot fail on an unresolved measurement.
export const MAX_BATCH = 4096;

export function bestOf(fn: () => unknown, repeats: number): Measurement {
  let batch = 1;
  let ms = Infinity;
  let result: unknown;
  for (let i = 0; i < repeats; i++) {
    // Double the batch until one window clears MIN_SAMPLE_MS. Doubling rather than scaling a pilot
    // estimate, because the reading being calibrated against is exactly the one that can come back
    // 0 — there is nothing to divide by. Undersized windows are discarded rather than counted,
    // since a reading below the clock's resolution is the very thing this avoids.
    //
    // `batch` lives outside the repeat loop, so this converges once and later repeats go straight
    // through: the total cost is `repeats` honest windows plus one batch's worth of calibration.
    // A path that already fills a window on its own — renderMarkdownReport at ~500ms — settles at
    // batch 1 on its first sample and keeps it, so it is measured exactly as it was before.
    for (;;) {
      const start = process.cpuUsage();
      for (let j = 0; j < batch; j++) result = fn();
      const { user, system } = process.cpuUsage(start);
      const elapsed = (user + system) / 1000; // microseconds → milliseconds
      if (elapsed >= MIN_SAMPLE_MS || batch >= MAX_BATCH) {
        const perCall = elapsed / batch;
        if (perCall < ms) ms = perCall;
        break;
      }
      batch *= 2;
    }
  }
  return { ms, result };
}

// How much slower the same code may get when its input grows GROWTH_FACTOR (8x) along one
// dimension. Linear work costs 8x; a quadratic regression costs 64x.
//
// Measured in CPU time over 6 idle runs (ratio range, and how much of its own allowance the
// WORST of those runs actually used — the allowance being baseline*GROWTH_LIMIT + FLOOR_MS):
//   buildSynthesisContext  2.5-4.4x  in IOC count (linear)          worst run used 13%
//   renderMarkdownReport   4.2-5.9x  (linear)                       worst run used 18%
//   filterEventsByScope    7.7-13.7x (linear; ~1ms baseline, noisy) worst run used 20%
//   correlateEvents        7.4-18.2x (~n^1.25, sort + windowed scan) worst run used 49%
//
// Read the ratio spread and the allowance column together. correlateEvents touching 18x looks
// close to 32, but its high ratios come from runs where the BASELINE landed near 5ms, and there
// FLOOR_MS dominates the limit — so the assertion still had 2.1x of room. Every path keeps at
// least 2x, and 32 stays 2x below the 64x a genuinely quadratic path would cost.
export const GROWTH_LIMIT = 32;
// Absolute slack (CPU-ms), so a very small baseline — where measurement resolution and JIT
// variance dominate and the ratio stops meaning anything — can't fail the assertion on noise
// alone. This carries more weight than it looks: it is what keeps the cheap paths, and
// correlateEvents on its fastest-baseline runs, comfortably inside the limit even when their raw
// ratio spikes. Any genuinely quadratic path costs far more than this at 10k events, so it does
// not blunt the check.
export const FLOOR_MS = 25;

export interface Growth {
  baseline: Measurement;
  full: Measurement;
  label: string;
  dimension: string;
}

// Measures one hot path at both input sizes. The full-size run happens FIRST as a discarded
// warmup: V8 needs a few thousand iterations of the inner loops before it settles on
// optimized code, and without this the baseline (measured first) absorbs the whole JIT cost
// — enough to make a cheap path look like it got *faster* on 8x the input.
export function measureGrowth(
  label: string,
  dimension: string,
  baselineFn: () => unknown,
  fullFn: () => unknown,
  repeats: number,
): Growth {
  fullFn();
  const baseline = bestOf(baselineFn, repeats);
  const full = bestOf(fullFn, repeats);
  return { baseline, full, label, dimension };
}

// Asserts the growth ratio, and returns the full-size result so the caller can assert on it.
export function expectSubQuadratic(measured: Growth): unknown {
  const { baseline, full, label, dimension } = measured;
  const limit = baseline.ms * GROWTH_LIMIT + FLOOR_MS;
  const growth = baseline.ms > 0 ? `${(full.ms / baseline.ms).toFixed(1)}x` : "n/a";
  const detail =
    `${label} (${dimension}): ${baseline.ms.toFixed(1)}ms → ${full.ms.toFixed(1)}ms ` +
    `(${growth} for ${GROWTH_FACTOR}x input)`;
  // Logged unconditionally so a slow-but-passing trend is still visible in the run output.
  console.log(`[load] ${detail}`);
  expect(
    full.ms,
    `${detail} — expected under ${limit.toFixed(1)}ms; growth this steep means the path went super-linear`,
  ).toBeLessThan(limit);
  return full.result;
}

/**
 * Asserts that run(n) -> run(n * GROWTH_FACTOR) grows linearly, not quadratically (#2444).
 * Returns the full-size result so a caller can assert on it. Choose `n` so the baseline costs about
 * a millisecond or more; the batching in bestOf takes care of clock resolution below that.
 */
export function expectLinearScan(
  label: string,
  run: (n: number) => unknown,
  n: number,
  repeats = 3,
): unknown {
  return expectSubQuadratic(
    measureGrowth(
      label,
      `${GROWTH_FACTOR}x input`,
      () => run(n),
      () => run(n * GROWTH_FACTOR),
      repeats,
    ),
  );
}
