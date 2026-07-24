import { describe, it, expect, beforeEach } from "vitest";
import { AttemptLimiter, SlidingWindowLimiter, resetLimiters, getUnlockLimiter, getAiLimiter } from "../../src/http/rateLimiter.js";

describe("AttemptLimiter", () => {
  let limiter: AttemptLimiter;

  beforeEach(() => {
    limiter = new AttemptLimiter(3, 1000); // 3 attempts, 1s lockout
  });

  it("allows attempts below the threshold", () => {
    expect(limiter.remainingLockout("key1")).toBe(0);
    limiter.recordFailure("key1");
    limiter.recordFailure("key1");
    expect(limiter.remainingLockout("key1")).toBe(0); // not locked yet (3 is the threshold)
  });

  it("locks out after maxAttempts failures with exponential backoff", () => {
    limiter.recordFailure("key1");
    limiter.recordFailure("key1");
    const lockout = limiter.recordFailure("key1");
    expect(lockout).toBeGreaterThanOrEqual(1000);
    expect(limiter.remainingLockout("key1")).toBeGreaterThan(0);
  });

  it("doubles the lockout on each subsequent cycle", () => {
    // First lockout: 1s
    limiter.recordFailure("k"); limiter.recordFailure("k"); let lock = limiter.recordFailure("k");
    expect(lock).toBeGreaterThanOrEqual(1000);
    // Clear lockout by advancing time
    const future = Date.now() + lock + 1;
    // Second cycle: 2s
    limiter.recordFailure("k", future); limiter.recordFailure("k", future); lock = limiter.recordFailure("k", future);
    expect(lock).toBeGreaterThanOrEqual(2000);
  });

  it("caps lockout at 10 minutes", () => {
    const lim = new AttemptLimiter(1, 600_000);
    lim.recordFailure("k");
    // After many cycles, the lockout should be capped at 600_000 (10min)
    let now = Date.now();
    for (let i = 0; i < 20; i++) {
      const lock = lim.recordFailure("k", now);
      now += lock + 1;
    }
    const finalLock = lim.recordFailure("k", now);
    expect(finalLock).toBeLessThanOrEqual(600_000);
  });

  it("clears the counter on success", () => {
    limiter.recordFailure("key1");
    limiter.recordFailure("key1");
    limiter.clear("key1");
    // After clear, the next 2 failures should not lock (counter reset)
    limiter.recordFailure("key1");
    limiter.recordFailure("key1");
    expect(limiter.remainingLockout("key1")).toBe(0);
  });

  it("tracks keys independently", () => {
    limiter.recordFailure("a");
    limiter.recordFailure("a");
    limiter.recordFailure("a");
    expect(limiter.remainingLockout("a")).toBeGreaterThan(0);
    expect(limiter.remainingLockout("b")).toBe(0);
  });
});

describe("SlidingWindowLimiter", () => {
  it("allows requests up to the cap", () => {
    const lim = new SlidingWindowLimiter(5, 10_000);
    expect(lim.tryAcquire("k")).toBe(true);
    expect(lim.tryAcquire("k")).toBe(true);
    expect(lim.tryAcquire("k")).toBe(true);
    expect(lim.tryAcquire("k")).toBe(true);
    expect(lim.tryAcquire("k")).toBe(true);
  });

  it("rejects requests past the cap", () => {
    const lim = new SlidingWindowLimiter(3, 10_000);
    lim.tryAcquire("k"); lim.tryAcquire("k"); lim.tryAcquire("k");
    expect(lim.tryAcquire("k")).toBe(false);
  });

  it("resets after the window expires", () => {
    const lim = new SlidingWindowLimiter(2, 100);
    const now = Date.now();
    lim.tryAcquire("k", now); lim.tryAcquire("k", now);
    expect(lim.tryAcquire("k", now)).toBe(false);
    // After the window, it should reset
    expect(lim.tryAcquire("k", now + 200)).toBe(true);
  });

  it("tracks keys independently", () => {
    const lim = new SlidingWindowLimiter(1, 10_000);
    expect(lim.tryAcquire("a")).toBe(true);
    expect(lim.tryAcquire("a")).toBe(false);
    expect(lim.tryAcquire("b")).toBe(true);
  });
});

describe("limiter singletons", () => {
  beforeEach(() => resetLimiters());

  it("getUnlockLimiter returns a shared instance", () => {
    const a = getUnlockLimiter();
    const b = getUnlockLimiter();
    expect(a).toBe(b);
  });

  it("getAiLimiter returns a shared instance", () => {
    const a = getAiLimiter();
    const b = getAiLimiter();
    expect(a).toBe(b);
  });

  it("resetLimiters creates fresh instances", () => {
    const a = getUnlockLimiter();
    resetLimiters();
    const b = getUnlockLimiter();
    expect(a).not.toBe(b);
  });
});