// Lightweight in-memory rate limiter — no external dependencies, suitable for a localhost tool.
// Two modes:
//   1. Per-key attempt limiter (e.g. brute-force protection on /unlock): tracks failed attempts
//      per key (caseId), applies exponential backoff after N failures, and lockout for a cooldown.
//   2. Sliding-window rate limiter (e.g. AI-cost DoS): caps total requests per window per key.

import type { Request, Response, NextFunction } from "express";

/** Per-key attempt tracker with exponential backoff + lockout. */
export class AttemptLimiter {
  private attempts = new Map<string, { count: number; lockedUntil: number; cycles: number; lastSeen: number }>();
  private readonly maxAttempts: number;
  private readonly lockoutMs: number;

  /** @param maxAttempts  failed attempts before the FIRST lockout kicks in (default 5). Every
   *                      failure after that immediately re-locks (no free guesses in between),
   *                      doubling the lockout each time.
   *  @param lockoutMs    first lockout duration (default 30s, doubles each subsequent lockout up to 10min) */
  constructor(maxAttempts = 5, lockoutMs = 30_000) {
    this.maxAttempts = maxAttempts;
    this.lockoutMs = lockoutMs;
  }

  /** Returns the remaining lockout time in ms, or 0 if not locked. */
  remainingLockout(key: string, now = Date.now()): number {
    const rec = this.attempts.get(key);
    if (!rec || rec.lockedUntil <= now) return 0;
    return rec.lockedUntil - now;
  }

  /** Record a failed attempt. Returns the lockout time in ms (0 = not yet locked).
   *
   *  Before the first lockout, `maxAttempts` failures are needed to trigger it (so a single
   *  mistyped password doesn't lock anyone out). After that, `cycles` tracks how many times
   *  this key has been locked out — every SINGLE further failure re-locks immediately (the
   *  threshold drops to 1), and the lockout doubles each time, so an attacker who keeps waiting
   *  out the lockout and retrying never gets a free burst of guesses between escalations. */
  recordFailure(key: string, now = Date.now()): number {
    const rec = this.attempts.get(key) ?? { count: 0, lockedUntil: 0, cycles: 0, lastSeen: now };
    rec.lastSeen = now;
    rec.count += 1;
    const threshold = rec.cycles === 0 ? this.maxAttempts : 1;
    if (rec.count >= threshold) {
      const lockout = Math.min(this.lockoutMs * Math.pow(2, rec.cycles), 600_000);
      rec.lockedUntil = now + lockout;
      rec.cycles += 1;
      rec.count = 0;
      this.attempts.set(key, rec);
      return lockout;
    }
    this.attempts.set(key, rec);
    return 0;
  }

  /** Clear the attempt counter for a key (call on success). */
  clear(key: string): void {
    this.attempts.delete(key);
  }

  /** Drop entries idle for longer than `maxIdleMs` (default 1h — well past the 10min lockout
   *  cap, so an actively-escalating attacker's cycle count isn't lost mid-attack). Bounds memory
   *  for a long-running process against a stream of distinct keys (garbage/enumerated caseIds
   *  hitting this limiter cost nothing to try, since it runs before any caseId-existence check).
   *  Returns the number of entries removed. */
  sweep(now = Date.now(), maxIdleMs = 3_600_000): number {
    let removed = 0;
    for (const [key, rec] of this.attempts) {
      if (now - rec.lastSeen > maxIdleMs) { this.attempts.delete(key); removed++; }
    }
    return removed;
  }

  /** Express middleware factory: gates on a key extracted from the request. */
  middleware(keyFn: (req: Request) => string) {
    return (req: Request, res: Response, next: NextFunction): void => {
      const key = keyFn(req);
      const remaining = this.remainingLockout(key);
      if (remaining > 0) {
        res.setHeader("Retry-After", String(Math.ceil(remaining / 1000)));
        res.status(429).json({ error: "too many attempts, try again later", retryAfterMs: remaining });
        return;
      }
      next();
    };
  }
}

/** Sliding-window rate limiter: caps total requests per window per key. */
export class SlidingWindowLimiter {
  private counts = new Map<string, { windowStart: number; count: number }>();
  private readonly maxRequests: number;
  private readonly windowMs: number;

  /** @param maxRequests  max requests per window
   *  @param windowMs      window duration in ms */
  constructor(maxRequests: number, windowMs: number) {
    this.maxRequests = maxRequests;
    this.windowMs = windowMs;
  }

  /** Returns true if the request is allowed (and counts it); false if rate-limited. */
  tryAcquire(key: string, now = Date.now()): boolean {
    const rec = this.counts.get(key);
    if (!rec || rec.windowStart + this.windowMs <= now) {
      this.counts.set(key, { windowStart: now, count: 1 });
      return true;
    }
    rec.count += 1;
    return rec.count <= this.maxRequests;
  }

  /** Drop windows that have already fully expired — nothing reads them again until the key
   *  reappears, at which point tryAcquire starts a fresh window anyway. Bounds memory for a
   *  long-running process against a stream of distinct keys (this limiter runs before any
   *  caseId-existence check, so a garbage/enumerated caseId costs nothing to try). Returns the
   *  number of entries removed. */
  sweep(now = Date.now()): number {
    let removed = 0;
    for (const [key, rec] of this.counts) {
      if (rec.windowStart + this.windowMs <= now) { this.counts.delete(key); removed++; }
    }
    return removed;
  }

  /** Express middleware factory: gates on a key extracted from the request. */
  middleware(keyFn: (req: Request) => string) {
    return (req: Request, res: Response, next: NextFunction): void => {
      const key = keyFn(req);
      if (!this.tryAcquire(key)) {
        res.status(429).json({ error: "rate limit exceeded, slow down" });
        return;
      }
      next();
    };
  }
}

// Module-level singletons, created once by the server. Each gets its own periodic sweep so a
// long-running process doesn't accumulate one Map entry per distinct (possibly garbage/attacker-
// enumerated) key forever — see AttemptLimiter.sweep / SlidingWindowLimiter.sweep.
const SWEEP_INTERVAL_MS = 5 * 60_000;

let _unlockLimiter: AttemptLimiter | null = null;
let _aiLimiter: SlidingWindowLimiter | null = null;
let _unlockSweepTimer: NodeJS.Timeout | null = null;
let _aiSweepTimer: NodeJS.Timeout | null = null;

export function getUnlockLimiter(): AttemptLimiter {
  if (!_unlockLimiter) {
    const limiter = new AttemptLimiter(5, 30_000);
    _unlockLimiter = limiter;
    _unlockSweepTimer = setInterval(() => limiter.sweep(), SWEEP_INTERVAL_MS);
    _unlockSweepTimer.unref?.();
  }
  return _unlockLimiter;
}

export function getAiLimiter(): SlidingWindowLimiter {
  if (!_aiLimiter) {
    const limiter = new SlidingWindowLimiter(20, 60_000);
    _aiLimiter = limiter;
    _aiSweepTimer = setInterval(() => limiter.sweep(), SWEEP_INTERVAL_MS);
    _aiSweepTimer.unref?.();
  }
  return _aiLimiter;
}

/** Reset singletons (tests). Also clears each singleton's sweep timer so repeated
 *  reset+get cycles in a test suite don't stack up abandoned intervals. */
export function resetLimiters(): void {
  if (_unlockSweepTimer) clearInterval(_unlockSweepTimer);
  if (_aiSweepTimer) clearInterval(_aiSweepTimer);
  _unlockSweepTimer = null;
  _aiSweepTimer = null;
  _unlockLimiter = null;
  _aiLimiter = null;
}