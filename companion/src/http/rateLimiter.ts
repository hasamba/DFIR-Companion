// Lightweight in-memory rate limiter — no external dependencies, suitable for a localhost tool.
// Two modes:
//   1. Per-key attempt limiter (e.g. brute-force protection on /unlock): tracks failed attempts
//      per key (caseId), applies exponential backoff after N failures, and lockout for a cooldown.
//   2. Sliding-window rate limiter (e.g. AI-cost DoS): caps total requests per window per key.

import type { Request, Response, NextFunction } from "express";

/** Per-key attempt tracker with exponential backoff + lockout. */
export class AttemptLimiter {
  private attempts = new Map<string, { count: number; lockedUntil: number }>();
  private readonly maxAttempts: number;
  private readonly lockoutMs: number;

  /** @param maxAttempts  failed attempts before lockout kicks in (default 5)
   *  @param lockoutMs    lockout duration after maxAttempts (default 30s, doubles each cycle up to 10min) */
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

  /** Record a failed attempt. Returns the lockout time in ms (0 = not yet locked). */
  recordFailure(key: string, now = Date.now()): number {
    const rec = this.attempts.get(key) ?? { count: 0, lockedUntil: 0 };
    rec.count += 1;
    if (rec.count >= this.maxAttempts) {
      const lockout = Math.min(this.lockoutMs * Math.pow(2, Math.floor(rec.count / this.maxAttempts) - 1), 600_000);
      rec.lockedUntil = now + lockout;
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

// Module-level singletons, created once by the server.
let _unlockLimiter: AttemptLimiter | null = null;
let _aiLimiter: SlidingWindowLimiter | null = null;

export function getUnlockLimiter(): AttemptLimiter {
  if (!_unlockLimiter) _unlockLimiter = new AttemptLimiter(5, 30_000);
  return _unlockLimiter;
}

export function getAiLimiter(): SlidingWindowLimiter {
  if (!_aiLimiter) _aiLimiter = new SlidingWindowLimiter(20, 60_000);
  return _aiLimiter;
}

/** Reset singletons (tests). */
export function resetLimiters(): void {
  _unlockLimiter = null;
  _aiLimiter = null;
}