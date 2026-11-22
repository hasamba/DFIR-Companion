import { describe, it, expect } from "vitest";
import {
  HEAVY_READ_BYTES_PER_EVENT,
  HEAVY_READ_COUNT_TTL_MS,
  createHeavyReadBudget,
  processHeavyReadSnapshot,
  type HeavyReadMemorySnapshot,
} from "../../src/composition/heavyReadMemoryBudget.js";

// #2846: the heavy-read gate's memory budget. Stubbed counts and memory snapshots only — no
// multi-GB fixture.

const GB = 1024 ** 3;
const roomy: HeavyReadMemorySnapshot = { availableBytes: 32 * GB };

describe("heavy-read memory budget (#2846)", () => {
  it("estimates a read from the case's event count", async () => {
    const budget = createHeavyReadBudget({ countEvents: async () => 72_000, probe: () => roomy });
    expect(await budget.estimate("c1")).toBe(72_000 * HEAVY_READ_BYTES_PER_EVENT);
  });

  it("covers the costliest read measured on the 72k-event case (cockpit cold load, 2.95 GB)", () => {
    expect(72_000 * HEAVY_READ_BYTES_PER_EVENT).toBeGreaterThanOrEqual(2.95e9);
  });

  it("counts a case once for a burst, again after the TTL", async () => {
    let now = 0;
    let calls = 0;
    const budget = createHeavyReadBudget({
      countEvents: async () => {
        calls++;
        return 10;
      },
      probe: () => roomy,
      now: () => now,
    });
    await Promise.all(Array.from({ length: 33 }, () => budget.estimate("c1")));
    expect(calls).toBe(1);
    now = HEAVY_READ_COUNT_TTL_MS - 1;
    await budget.estimate("c1");
    expect(calls).toBe(1);
    now = HEAVY_READ_COUNT_TTL_MS;
    await budget.estimate("c1");
    expect(calls).toBe(2);
    await budget.estimate("c2");
    expect(calls).toBe(3); // per case
  });

  it("charges a case it cannot count as too large to share (it runs alone), and retries the count", async () => {
    let fail = true;
    const budget = createHeavyReadBudget({
      countEvents: async () => {
        if (fail) throw new Error("index busy");
        return 5;
      },
      probe: () => roomy,
    });
    expect(await budget.estimate("c1")).toBe(Number.POSITIVE_INFINITY);
    expect(budget.fits(Number.POSITIVE_INFINITY, 0)).toBe(false);
    fail = false;
    expect(await budget.estimate("c1")).toBe(5 * HEAVY_READ_BYTES_PER_EVENT); // a failure is not cached
  });

  it("an empty case costs nothing and always fits", async () => {
    const budget = createHeavyReadBudget({
      countEvents: async () => 0,
      probe: () => ({ availableBytes: 0 }),
    });
    expect(await budget.estimate("c1")).toBe(0);
    expect(budget.fits(0, 10 * GB)).toBe(true);
  });

  it("fits only within the memory the OS can still give, less reads and imports already admitted", () => {
    let snap: HeavyReadMemorySnapshot = { availableBytes: 10 * GB };
    let imports = 0;
    const budget = createHeavyReadBudget({
      countEvents: async () => 0,
      probe: () => snap,
      importReservedBytes: () => imports,
    });
    expect(budget.fits(3 * GB, 0)).toBe(true);
    expect(budget.fits(3 * GB, 7 * GB)).toBe(true);
    expect(budget.fits(3 * GB, 7.5 * GB)).toBe(false);
    imports = 4 * GB;
    expect(budget.fits(3 * GB, 3 * GB)).toBe(true);
    expect(budget.fits(3 * GB, 3.5 * GB)).toBe(false);
    snap = { availableBytes: 2 * GB };
    imports = 0;
    expect(budget.fits(3 * GB, 0)).toBe(false);
  });

  it("reads the process's own memory by default", () => {
    expect(processHeavyReadSnapshot().availableBytes).toBeGreaterThan(0);
  });
});
