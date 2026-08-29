import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  AttemptLimiter,
  SlidingWindowLimiter,
  resetLimiters,
  getUnlockLimiter,
  getAiLimiter,
  getDeterministicImportLimiter,
} from "../../src/http/rateLimiter.js";

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

  it("doubles the lockout on each SINGLE subsequent failure once already locked out once", () => {
    // First lockout requires the full maxAttempts (3) failures: 1s
    limiter.recordFailure("k");
    limiter.recordFailure("k");
    let lock = limiter.recordFailure("k");
    expect(lock).toBe(1000);
    // After the first lockout, a SINGLE further failure immediately re-locks — no free guesses —
    // and doubles the duration each time. This is what the real /unlock route relies on: it only
    // ever calls recordFailure once per real-world retry (it skips the call entirely while
    // remainingLockout() is still positive), so the escalation must happen on failure #1 of each
    // cycle, not require maxAttempts MORE failures to build back up.
    lock = limiter.recordFailure("k", Date.now() + lock + 1);
    expect(lock).toBe(2000);
    lock = limiter.recordFailure("k", Date.now() + lock + 1);
    expect(lock).toBe(4000);
  });

  it("matches the real /unlock route's call pattern: one recordFailure per wait-then-retry cycle", () => {
    // Reproduces #244's actual wiring (casePassword.ts only calls recordFailure when NOT already
    // locked — a locked request short-circuits to 429 before ever reaching it) to guard against
    // the escalation silently degrading to "doubles every maxAttempts cumulative failures" again
    // (which stayed flat at the FIRST lockout duration for `maxAttempts` real-world retries).
    const lim = new AttemptLimiter(5, 30_000);
    let now = 0;
    const lockouts: number[] = [];
    for (let i = 0; i < 15; i++) {
      const remaining = lim.remainingLockout("c1", now);
      if (remaining > 0) {
        now += remaining;
        continue;
      }
      const lockout = lim.recordFailure("c1", now);
      if (lockout > 0) lockouts.push(lockout);
    }
    // 5 failures to arm the first lockout, then every SINGLE further real attempt re-locks and
    // doubles: 30s, 60s, 120s, 240s, 480s, 600s(capped)...
    expect(lockouts.slice(0, 6)).toEqual([30_000, 60_000, 120_000, 240_000, 480_000, 600_000]);
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

  // #244 shipped with no key eviction at all: this limiter runs BEFORE any caseId-existence
  // check (it gates /unlock itself), so a stream of distinct garbage/enumerated caseIds grows
  // its Map forever on a long-running server. sweep() bounds that.
  describe("sweep (memory bound against an unbounded key stream)", () => {
    it("removes an entry that has been idle past maxIdleMs", () => {
      limiter.recordFailure("stale-key", 0);
      const removed = limiter.sweep(3_600_001, 3_600_000); // 1ms past the 1h default idle window
      expect(removed).toBe(1);
      expect(limiter.remainingLockout("stale-key", 3_600_001)).toBe(0);
    });

    it("keeps a recently-active entry, including one still mid-lockout", () => {
      limiter.recordFailure("k", 0);
      limiter.recordFailure("k", 0);
      limiter.recordFailure("k", 0); // 3rd failure, locks for 1000ms starting at t=0
      const removed = limiter.sweep(500, 3_600_000); // mid-lockout, well within the idle window too
      expect(removed).toBe(0);
      expect(limiter.remainingLockout("k", 500)).toBeGreaterThan(0);
    });

    it("does not disturb unrelated keys", () => {
      limiter.recordFailure("stale", 0);
      limiter.recordFailure("fresh", 5_000_000);
      limiter.sweep(5_000_000, 3_600_000); // "stale" is idle-expired, "fresh" was just touched
      expect(limiter.remainingLockout("fresh", 5_000_000)).toBe(0); // still tracked, just not locked (1 failure)
      limiter.recordFailure("fresh", 5_000_000);
      expect(limiter.remainingLockout("fresh", 5_000_000)).toBe(0); // 2 failures total, not yet the 3-failure threshold
    });
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
    lim.tryAcquire("k");
    lim.tryAcquire("k");
    lim.tryAcquire("k");
    expect(lim.tryAcquire("k")).toBe(false);
  });

  it("resets after the window expires", () => {
    const lim = new SlidingWindowLimiter(2, 100);
    const now = Date.now();
    lim.tryAcquire("k", now);
    lim.tryAcquire("k", now);
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

  // #244 shipped with no key eviction: this limiter runs BEFORE any caseId-existence check (it
  // gates /import et al. via a bare app.use), so a stream of distinct garbage/enumerated caseIds
  // grows its Map forever on a long-running server. sweep() bounds that.
  describe("sweep (memory bound against an unbounded key stream)", () => {
    it("removes a window that has fully expired", () => {
      const lim = new SlidingWindowLimiter(5, 1000);
      lim.tryAcquire("stale", 0);
      const removed = lim.sweep(1001); // 1ms past window end
      expect(removed).toBe(1);
    });

    it("keeps a window still in progress", () => {
      const lim = new SlidingWindowLimiter(5, 1000);
      lim.tryAcquire("active", 0);
      const removed = lim.sweep(500); // still within the window
      expect(removed).toBe(0);
      // proves it wasn't swept: the count is still tracked, not reset to a fresh window of 1
      lim.tryAcquire("active", 500);
      lim.tryAcquire("active", 500);
      lim.tryAcquire("active", 500);
      lim.tryAcquire("active", 500);
      expect(lim.tryAcquire("active", 500)).toBe(false); // 6th request in the SAME window over cap 5
    });
  });
});

describe("limiter singletons", () => {
  beforeEach(() => resetLimiters());
  afterEach(() => resetLimiters()); // release the sweep timers started by tests above

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

  it("getDeterministicImportLimiter returns a shared instance that resetLimiters clears", () => {
    const a = getDeterministicImportLimiter();
    expect(getDeterministicImportLimiter()).toBe(a);
    resetLimiters();
    expect(getDeterministicImportLimiter()).not.toBe(a); // reset drops the singleton + its sweep timer
  });

  it("resetLimiters clears the deterministic-import limiter's counts (no leak across cases)", () => {
    const lim = getDeterministicImportLimiter();
    // Exhaust a small custom window so the contract is deterministic regardless of the 300/min default.
    const one = new SlidingWindowLimiter(1, 60_000);
    expect(one.tryAcquire("case-x")).toBe(true);
    expect(one.tryAcquire("case-x")).toBe(false);
    // The real singleton is a fresh object after reset, so its request counts start over.
    resetLimiters();
    expect(getDeterministicImportLimiter()).not.toBe(lim);
  });
});
