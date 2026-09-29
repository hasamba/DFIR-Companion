// Lightweight in-memory rate limiter — no external dependencies, suitable for a localhost tool.
// Two modes:
//   1. Per-key attempt limiter (e.g. brute-force protection on /unlock): tracks failed attempts
//      per key (caseId), applies exponential backoff after N failures, and lockout for a cooldown.
//   2. Sliding-window rate limiter (e.g. AI-cost DoS): caps total requests per window per key.

import { AsyncLocalStorage } from "node:async_hooks";
import type { Request, Response, NextFunction } from "express";

/** What one serialized {@link AttemptLimiter.attemptFor} decided; `value` is what the check proved. */
export type AttemptResult<T> =
  { kind: "locked"; retryAfterMs: number } | { kind: "ok"; value: T } | { kind: "failed"; lockoutMs: number };

/** What one serialized {@link AttemptLimiter.attempt} decided. */
export type AttemptOutcome =
  /** The key was locked out before the check ran; nothing was tried. */
  | { kind: "locked"; retryAfterMs: number }
  /** The check passed; the key's failure count was cleared. */
  | { kind: "ok" }
  /** The check failed; `lockoutMs` > 0 means this failure locked the key out. */
  | { kind: "failed"; lockoutMs: number };

/** Per-key attempt tracker with exponential backoff + lockout. */
export class AttemptLimiter {
  private attempts = new Map<
    string,
    { count: number; lockedUntil: number; cycles: number; lastSeen: number }
  >();
  /** The tail of each key's in-flight {@link attempt} chain; see that method. */
  private inflight = new Map<string, Promise<unknown>>();
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

  /**
   * Check the lockout, run `check`, and record its outcome — as ONE step per key.
   *
   * The three calls this replaces (remainingLockout → verify → recordFailure/clear) were only ever
   * atomic by accident: the verification was a synchronous scrypt that held the event loop, so no
   * second request could reach the check before the first had recorded its failure. With the
   * derivation on the threadpool (#863) that ordering is gone — a burst of N wrong guesses would
   * all pass the lockout check, all pay for a derivation, and only then count, so the "five
   * attempts" budget bounded nothing and a lucky success could clear failures still in flight.
   *
   * Attempts on one key are therefore chained: each waits for the previous to finish before it
   * looks at the lockout, so the sixth wrong guess in a burst is refused without a derivation, a
   * correct guess clears only the failures that were counted before it, and one key can hold at
   * most one derivation on the threadpool at a time. Keys never wait on each other. Every caller
   * that verifies against the same key — /unlock and /captures share this limiter on purpose —
   * has to come through here, or the budget is shared in name only.
   */
  async attempt(key: string, check: () => Promise<boolean>): Promise<AttemptOutcome> {
    const result = await this.attemptFor(key, async () => ((await check()) ? true : null));
    return result.kind === "ok" ? { kind: "ok" } : result;
  }

  /**
   * {@link attempt} for a check whose success carries something the caller needs — the identity a
   * login just verified, say (#872). A non-null result IS the success; `null` is a failed attempt.
   *
   * This is where both forms are actually serialized. Returning the value through the limiter is
   * what lets a caller that needs it still come through here: the alternative is assigning it to a
   * variable from inside the check, which reads as the same code and quietly reopens the ordering
   * hole the moment someone moves the lockout test back out of the chain.
   */
  async attemptFor<T>(key: string, check: () => Promise<T | null>): Promise<AttemptResult<T>> {
    const previous = this.inflight.get(key) ?? Promise.resolve();
    const run = previous.then(async (): Promise<AttemptResult<T>> => {
      const retryAfterMs = this.remainingLockout(key);
      if (retryAfterMs > 0) return { kind: "locked", retryAfterMs };
      const value = await check();
      if (value !== null) {
        this.clear(key);
        return { kind: "ok", value };
      }
      return { kind: "failed", lockoutMs: this.recordFailure(key) };
    });
    // The chain link must never reject, or every later attempt on the key would fail with the
    // first one's error; the caller still sees its own rejection through `run`.
    const link = run.then(
      () => undefined,
      () => undefined,
    );
    this.inflight.set(key, link);
    try {
      return await run;
    } finally {
      if (this.inflight.get(key) === link) this.inflight.delete(key);
    }
  }

  /** Drop entries idle for longer than `maxIdleMs` (default 1h — well past the 10min lockout
   *  cap, so an actively-escalating attacker's cycle count isn't lost mid-attack). Bounds memory
   *  for a long-running process against a stream of distinct keys (garbage/enumerated caseIds
   *  hitting this limiter cost nothing to try, since it runs before any caseId-existence check).
   *  Returns the number of entries removed. */
  sweep(now = Date.now(), maxIdleMs = 3_600_000): number {
    let removed = 0;
    for (const [key, rec] of this.attempts) {
      if (now - rec.lastSeen > maxIdleMs) {
        this.attempts.delete(key);
        removed++;
      }
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

  /** Returns true if the request is allowed (and counts it); false if rate-limited. A refused
   *  request is not counted: it consumed nothing, and counting it would leave a {@link refund}
   *  unable to bring the window back under the cap (#1825). */
  tryAcquire(key: string, now = Date.now()): boolean {
    const rec = this.counts.get(key);
    if (!rec || rec.windowStart + this.windowMs <= now) {
      this.counts.set(key, { windowStart: now, count: 1 });
      return true;
    }
    if (rec.count >= this.maxRequests) return false;
    rec.count += 1;
    return true;
  }

  /** Give back one request that {@link tryAcquire} allowed at `acquiredAt` (#1825). Only while the
   *  key's window is still the one that request was counted in: a slot from an expired window is
   *  never refunded into the next one. */
  refund(key: string, acquiredAt: number): void {
    const rec = this.counts.get(key);
    if (!rec || rec.windowStart > acquiredAt || rec.count <= 0) return;
    rec.count -= 1;
  }

  /** Time left in the key's current window, in ms: when a refused caller may try again (#1794).
   *  0 for a key with no window or an expired one. Pass the same `now` the refusal used, so the
   *  answer cannot fall to 0 between the two calls at the window's last millisecond. */
  retryAfterMs(key: string, now = Date.now()): number {
    const rec = this.counts.get(key);
    return rec ? Math.max(0, rec.windowStart + this.windowMs - now) : 0;
  }

  /** Drop windows that have already fully expired — nothing reads them again until the key
   *  reappears, at which point tryAcquire starts a fresh window anyway. Bounds memory for a
   *  long-running process against a stream of distinct keys (this limiter runs before any
   *  caseId-existence check, so a garbage/enumerated caseId costs nothing to try). Returns the
   *  number of entries removed. */
  sweep(now = Date.now()): number {
    let removed = 0;
    for (const [key, rec] of this.counts) {
      if (rec.windowStart + this.windowMs <= now) {
        this.counts.delete(key);
        removed++;
      }
    }
    return removed;
  }

  /** Express middleware factory: gates on a key extracted from the request. */
  middleware(keyFn: (req: Request) => string) {
    return (req: Request, res: Response, next: NextFunction): void => {
      const key = keyFn(req);
      const now = Date.now();
      if (!this.tryAcquire(key, now)) {
        sendRateLimited(res, this.retryAfterMs(key, now), "rate limit exceeded, slow down");
        return;
      }
      next();
    };
  }
}

/** One request's claim on the per-case AI budget, kept on `res.locals` until the answer is sent. */
interface AiBudgetCharge {
  key: string;
  at: number;
  /** The route said no model call was made (a skip answer, an AI-off import). */
  unspent: boolean;
  /** A model call went out while the request ran (noteAiCallStarted). Wins over any refund. */
  spent: boolean;
}

const AI_CHARGE_LOCAL = "aiBudgetCharge";

// The charge of the request whose handler is running, so the model-call chokepoint can mark it spent
// without a route having to (#1825): a deep pass spends its observation calls and may still answer
// 409 at the final synthesis gate, and that 409 must not refund the calls already made.
const aiSpendScope = new AsyncLocalStorage<AiBudgetCharge>();

/** Called by the provider-call chokepoint (analyzeProvider, under analyzeRestored) just before a
 *  model call goes out: the request that caused it keeps its AI-budget slot, whatever status it
 *  answers with. The Jev client does not call it — the Jev route marks its own no-call answer. */
export function noteAiCallStarted(): void {
  const charge = aiSpendScope.getStore();
  if (charge) charge.spent = true;
}

/** Run `fn` (the rest of the request) so a model call inside it marks this request's charge spent. */
export function runWithAiSpendTracking(res: Response, fn: () => void): void {
  const charge = aiBudgetCharge(res);
  if (charge) aiSpendScope.run(charge, fn);
  else fn();
}

/** Statuses that answer a request the route refused before any AI work: every 4xx except 429 (a
 *  limit, not a refusal of the input) and 499 (cancelled mid-run, so a model call may have been
 *  made), and 501 (no AI provider configured). */
function isRefusalStatus(status: number): boolean {
  return (status >= 400 && status < 500 && status !== 429 && status !== 499) || status === 501;
}

/**
 * Take one slot from the per-case AI budget for this request, and give it back when the answer
 * turns out to be a refusal made before any AI work (#1825) — a 400 for a malformed body, a 409
 * gate, a 501 with no provider — or a route marked it {@link markAiBudgetUnspent}. Twenty
 * malformed posts used to block the next real /synthesize with a 429.
 *
 * A model call made while the request runs marks it spent ({@link noteAiCallStarted}), and a spent
 * request is never refunded. Refunds only on a sent answer ('finish'). A request whose client disconnects stays charged: it
 * may have started a model call, and refunding it would let a client start runs and drop them in a
 * loop. A 5xx (a model call that failed) and a 202 (AI work continuing in the background) stay
 * charged too.
 */
export function chargeAiBudget(
  res: Response,
  key: string,
): { ok: true } | { ok: false; retryAfterMs: number } {
  const limiter = getAiLimiter();
  const now = Date.now();
  if (!limiter.tryAcquire(key, now)) return { ok: false, retryAfterMs: limiter.retryAfterMs(key, now) };
  const charge: AiBudgetCharge = { key, at: now, unspent: false, spent: false };
  res.locals[AI_CHARGE_LOCAL] = charge;
  res.once("finish", () => {
    if (charge.spent) return;
    if (charge.unspent || isRefusalStatus(res.statusCode)) limiter.refund(charge.key, charge.at);
  });
  return { ok: true };
}

function aiBudgetCharge(res: Response): AiBudgetCharge | undefined {
  const charge: unknown = res.locals?.[AI_CHARGE_LOCAL];
  return charge && typeof charge === "object" ? (charge as AiBudgetCharge) : undefined;
}

/** The route answered without making a model call (#1825), so its AI-budget slot goes back. */
export function markAiBudgetUnspent(res: Response): void {
  const charge = aiBudgetCharge(res);
  if (charge) charge.unspent = true;
}

/** A 429 that says when to retry — the `Retry-After` header (whole seconds, at least 1) and the
 *  same wait in ms in the body, as {@link AttemptLimiter.middleware} answers (#1794). */
export function sendRateLimited(res: Response, retryAfterMs: number, error: string): void {
  const seconds = Math.max(1, Math.ceil(retryAfterMs / 1000));
  res.setHeader("Retry-After", String(seconds));
  res.status(429).json({ error, retryAfterMs: Math.max(retryAfterMs, 1) });
}

// Module-level singletons, created once by the server. Each gets its own periodic sweep so a
// long-running process doesn't accumulate one Map entry per distinct (possibly garbage/attacker-
// enumerated) key forever — see AttemptLimiter.sweep / SlidingWindowLimiter.sweep.
const SWEEP_INTERVAL_MS = 5 * 60_000;

let _unlockLimiter: AttemptLimiter | null = null;
let _aiLimiter: SlidingWindowLimiter | null = null;
let _importLimiter: AttemptLimiter | null = null;
let _importIpLimiter: SlidingWindowLimiter | null = null;
let _detImportLimiter: SlidingWindowLimiter | null = null;
let _detImportSweepTimer: NodeJS.Timeout | null = null;
let _unlockSweepTimer: NodeJS.Timeout | null = null;
let _aiSweepTimer: NodeJS.Timeout | null = null;
let _importSweepTimer: NodeJS.Timeout | null = null;
let _importIpSweepTimer: NodeJS.Timeout | null = null;
let _loginLimiter: AttemptLimiter | null = null;
let _loginIpLimiter: SlidingWindowLimiter | null = null;
let _loginSweepTimer: NodeJS.Timeout | null = null;
let _loginIpSweepTimer: NodeJS.Timeout | null = null;
let _oidcStartLimiter: SlidingWindowLimiter | null = null;
let _oidcStartSweepTimer: NodeJS.Timeout | null = null;
let _bootstrapLimiter: AttemptLimiter | null = null;
let _bootstrapSweepTimer: NodeJS.Timeout | null = null;
let _slashSecretLimiter: AttemptLimiter | null = null;
let _slashSecretSweepTimer: NodeJS.Timeout | null = null;

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

/** Per-case budget for the DETERMINISTIC import routes (/import, /import-file). These parse and
 *  grade evidence with no LLM call — the 20/min AI limiter blocked bulk folder imports (a real
 *  Velociraptor collection is 20-60 files; a replay of these four cases lost 44 of 124 files to
 *  HTTP 429). Kept SEPARATE and generous so a folder import completes, while still bounding a
 *  runaway loop. The AI cost an import can trigger (a background re-synthesis) is not metered here
 *  because it is already bounded elsewhere: synthesis is an EXCLUSIVE per-case job that coalesces,
 *  so N rapid imports never buy N LLM calls. Default 300/min, override with DFIR_IMPORT_RATE_MAX. */
export function getDeterministicImportLimiter(): SlidingWindowLimiter {
  if (!_detImportLimiter) {
    const max = Math.max(1, Number(process.env.DFIR_IMPORT_RATE_MAX) || 300);
    const limiter = new SlidingWindowLimiter(max, 60_000);
    _detImportLimiter = limiter;
    _detImportSweepTimer = setInterval(() => limiter.sweep(), SWEEP_INTERVAL_MS);
    _detImportSweepTimer.unref?.();
  }
  return _detImportLimiter;
}

/** Failed-decrypt limiter for POST /cases/import/encrypted. Separate from the unlock limiter
 *  because it is keyed by CLIENT IP, not caseId — an import names no case until the archive has
 *  been decrypted, and the two key spaces must not share a Map (an IP-shaped string is a legal
 *  caseId, so one bucket would let either route lock out the other). Same 5-then-backoff shape:
 *  a mistyped archive password is free, a loop of them is not. */
export function getImportLimiter(): AttemptLimiter {
  if (!_importLimiter) {
    const limiter = new AttemptLimiter(5, 30_000);
    _importLimiter = limiter;
    _importSweepTimer = setInterval(() => limiter.sweep(), SWEEP_INTERVAL_MS);
    _importSweepTimer.unref?.();
  }
  return _importLimiter;
}

/** Request budget for POST /cases/import/encrypted, keyed by client IP and consumed by every
 *  attempt that reaches decryption — whatever the outcome. It exists because the failure limiter
 *  above deliberately does not count a CaseImportConflictError (the archive opened; that is an
 *  analyst re-importing, not an attack) and a conflict still pays for a full synchronous scrypt
 *  derivation, so repeated conflicts were an unmetered way to block the event loop (#424).
 *
 *  10 a minute: a whole-case import is a rare, heavyweight operation, so this is far above real
 *  use and still bounds the derivations one client can buy. */
export function getImportIpLimiter(): SlidingWindowLimiter {
  if (!_importIpLimiter) {
    const limiter = new SlidingWindowLimiter(10, 60_000);
    _importIpLimiter = limiter;
    _importIpSweepTimer = setInterval(() => limiter.sweep(), SWEEP_INTERVAL_MS);
    _importIpSweepTimer.unref?.();
  }
  return _importIpLimiter;
}

/** Per-ACCOUNT failed-login limiter for POST /auth/local/login, keyed by client IP + username.
 *  That key is what makes it insufficient on its own: an unauthenticated caller who rotates the
 *  username gets a fresh bucket per request, so this limiter alone bounded brute force against one
 *  named account while bounding nothing per client (#421). Pair it with getLoginIpLimiter().
 *
 *  It used to be a bare `new AttemptLimiter(...)` module constant in authRoutes.ts, with no sweep
 *  scheduled — one permanent Map entry per (ip, username) ever tried. */
export function getLoginLimiter(): AttemptLimiter {
  if (!_loginLimiter) {
    const limiter = new AttemptLimiter(5, 30_000);
    _loginLimiter = limiter;
    _loginSweepTimer = setInterval(() => limiter.sweep(), SWEEP_INTERVAL_MS);
    _loginSweepTimer.unref?.();
  }
  return _loginLimiter;
}

/** Client-wide login budget, keyed by IP alone and consumed by EVERY login attempt — not only the
 *  failures — because the cost being bounded is the scrypt verification itself, which a miss pays
 *  in full against the dummy hash. 60 a minute is far past any human at a login form and still
 *  caps one client at roughly one password hash per second. */
export function getLoginIpLimiter(): SlidingWindowLimiter {
  if (!_loginIpLimiter) {
    const limiter = new SlidingWindowLimiter(60, 60_000);
    _loginIpLimiter = limiter;
    _loginIpSweepTimer = setInterval(() => limiter.sweep(), SWEEP_INTERVAL_MS);
    _loginIpSweepTimer.unref?.();
  }
  return _loginIpLimiter;
}

/** Per-IP budget for GET /auth/oidc/start, the one PUBLIC route that allocates server state.
 *  Every call stores a state, nonce, verifier, return path and expiry for ten minutes, so without
 *  a limiter an unauthenticated caller could allocate memory as fast as it could issue requests —
 *  no credentials, no provider round-trip needed. 20 a minute is far past a human clicking
 *  "Sign in with SSO" (each click is one flow, and a retry after a provider error is another),
 *  and it caps one client's outstanding flows well below the client's own hard flow ceiling. */
export function getOidcStartLimiter(): SlidingWindowLimiter {
  if (!_oidcStartLimiter) {
    const limiter = new SlidingWindowLimiter(20, 60_000);
    _oidcStartLimiter = limiter;
    _oidcStartSweepTimer = setInterval(() => limiter.sweep(), SWEEP_INTERVAL_MS);
    _oidcStartSweepTimer.unref?.();
  }
  return _oidcStartLimiter;
}

/** The one key {@link getBootstrapLimiter} is ever consulted with. There is exactly one bootstrap
 *  token per deployment, so the budget is the TOKEN's, not the client's — see the factory. */
export const BOOTSTRAP_LIMITER_KEY = "bootstrap";

/** Failed-guess budget for POST /auth/bootstrap (#920). Same shape as the login lockout — five
 *  failures, then 30s doubling to 10min — but keyed on a single constant rather than per client:
 *  a guesser gains nothing by rotating source addresses, because it is the token being guessed,
 *  not an account. The prize is the deployment's first administrator, so the lockout is allowed
 *  to bite the legitimate operator too: an operator who cannot bootstrap because someone is
 *  hammering the endpoint has learned that someone is on the network before the first admin
 *  exists, which is the thing they most need to know. Not consulted in loopback mode, where a
 *  non-loopback caller is refused without a guess having been made — counting those would let
 *  a LAN neighbour lock the operator out of a token-less setup. */
export function getBootstrapLimiter(): AttemptLimiter {
  if (!_bootstrapLimiter) {
    const limiter = new AttemptLimiter(5, 30_000);
    _bootstrapLimiter = limiter;
    _bootstrapSweepTimer = setInterval(() => limiter.sweep(), SWEEP_INTERVAL_MS);
    _bootstrapSweepTimer.unref?.();
  }
  return _bootstrapLimiter;
}

/** Failed-guess budget for the shared-secret slash-command endpoints — Teams and Telegram (#944).
 *  Same schedule as the bootstrap limiter, and keyed the same way, on a constant per platform
 *  (the limiter's own key is the platform name). Each platform has ONE operator secret, so the
 *  budget is the secret's: a guesser gains nothing by rotating source addresses, and nothing by
 *  rotating the channel id either, which the request body lets them choose per call. A locked
 *  secret refuses even the correct value — a war-room bot that goes quiet because someone is
 *  hammering its webhook is the operator's signal that someone is. Slack is not consulted here:
 *  its requests are HMAC-signed over the body inside a replay window, not compared to a secret. */
export function getSlashCommandSecretLimiter(): AttemptLimiter {
  if (!_slashSecretLimiter) {
    const limiter = new AttemptLimiter(5, 30_000);
    _slashSecretLimiter = limiter;
    _slashSecretSweepTimer = setInterval(() => limiter.sweep(), SWEEP_INTERVAL_MS);
    _slashSecretSweepTimer.unref?.();
  }
  return _slashSecretLimiter;
}

/** Reset singletons (tests). Also clears each singleton's sweep timer so repeated
 *  reset+get cycles in a test suite don't stack up abandoned intervals. */
export function resetLimiters(): void {
  if (_unlockSweepTimer) clearInterval(_unlockSweepTimer);
  if (_aiSweepTimer) clearInterval(_aiSweepTimer);
  if (_importSweepTimer) clearInterval(_importSweepTimer);
  if (_importIpSweepTimer) clearInterval(_importIpSweepTimer);
  if (_detImportSweepTimer) clearInterval(_detImportSweepTimer);
  if (_loginSweepTimer) clearInterval(_loginSweepTimer);
  if (_loginIpSweepTimer) clearInterval(_loginIpSweepTimer);
  if (_oidcStartSweepTimer) clearInterval(_oidcStartSweepTimer);
  if (_bootstrapSweepTimer) clearInterval(_bootstrapSweepTimer);
  if (_slashSecretSweepTimer) clearInterval(_slashSecretSweepTimer);
  _unlockSweepTimer = null;
  _aiSweepTimer = null;
  _importSweepTimer = null;
  _importIpSweepTimer = null;
  _detImportSweepTimer = null;
  _unlockLimiter = null;
  _aiLimiter = null;
  _importLimiter = null;
  _importIpLimiter = null;
  _detImportLimiter = null;
  _loginSweepTimer = null;
  _loginIpSweepTimer = null;
  _loginLimiter = null;
  _loginIpLimiter = null;
  _oidcStartSweepTimer = null;
  _oidcStartLimiter = null;
  _bootstrapSweepTimer = null;
  _bootstrapLimiter = null;
  _slashSecretSweepTimer = null;
  _slashSecretLimiter = null;
}
