// #2711: ONE rate limiter per Telegram bot, shared by every sender in this process — alerts, command
// replies and the Watson mirror. Telegram's limits belong to the bot, not to a feature: about one
// message a second per chat, 20 a minute per group, about 30 a second overall. Three senders that
// each stayed under those numbers on their own could still go over together and draw 429s.
//
// Lanes, highest first: alert > reply > mirror.
// - A waiting alert goes before any waiting reply or mirror send, and nothing lower may take the slot
//   of a chat a higher lane is waiting for. An alert's wait never depends on how long the mirror's
//   backlog is: only on per-chat spacing (≤ 1 s after the last send to that chat, by anyone), an
//   active 429 pause, and its own budget.
// - Lower lanes leave headroom: the mirror may use 20 of the 25 sends a second and 15 of a group's 20
//   a minute; replies 23 and 18. Every cap counts ALL lanes' sends — it is one shared history.
// - A 429 pauses the whole bot until its retry_after has passed. Telegram does not say whether a
//   flood limit was the chat's or the bot's, so the safe reading is the bot's. Overlapping pauses
//   extend to the later end, never shorten.
//
// Reserve, then commit. acquire() resolves with a reservation once a send may go. A held reservation
// counts as a send for everyone else, so no second sender is granted in the gap. commit() checks the
// limits again at that instant and records the send then; false means the slot was lost (a 429 pause
// began, or the gap ran so long that the chat's next slot went to someone else) and the caller
// acquires again.
//
// In memory, like the mirror's old limiter: a restart starts clean, and a 429 still pauses.

export type TelegramLane = "alert" | "reply" | "mirror";

const LANE_RANK: Readonly<Record<TelegramLane, number>> = { alert: 0, reply: 1, mirror: 2 };
const GROUP_CAP: Readonly<Record<TelegramLane, number>> = { alert: 20, reply: 18, mirror: 15 };
const GLOBAL_CAP: Readonly<Record<TelegramLane, number>> = { alert: 25, reply: 23, mirror: 20 };

const PER_CHAT_MS = 1_000;
const GROUP_WINDOW_MS = 60_000;
const GLOBAL_WINDOW_MS = 1_000;
/** How soon a waiter held back by a higher one looks again. */
const BLOCKED_TICK_MS = 25;
/** A reservation neither committed nor released stops counting after this (a caller that died). */
const RESERVATION_TTL_MS = 30_000;
/** A 429 with no retry_after. */
const DEFAULT_RETRY_AFTER_MS = 5_000;

export interface TelegramSendRequest {
  chatId: string;
  lane: TelegramLane;
  /** Groups, supergroups and channels have a per-minute cap. Default: any id that is not a positive number. */
  isGroup?: boolean;
  /** Give up (TelegramRateLimitError) rather than wait longer than this from the first acquire. */
  maxWaitMs?: number;
}

export interface TelegramReservation {
  /** Record the send now. false: the slot was lost meanwhile — acquire again. */
  commit(): boolean;
  /** Not sending after all (revoked, stopped). */
  release(): void;
  /** Telegram answered 429: pause this bot. */
  backOff(retryAfterMs: number): void;
}

export class TelegramRateLimitError extends Error {
  constructor(readonly waitMs: number) {
    super(`rate limited by Telegram — try again in ${Math.max(1, Math.ceil(waitMs / 1000))} s`);
    this.name = "TelegramRateLimitError";
  }
}

export interface LimiterClock {
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
}

interface Waiter {
  readonly seq: number;
  readonly chatId: string;
  readonly lane: TelegramLane;
  readonly isGroup: boolean;
  reservedAt?: number;
}

interface Sent {
  readonly chatId: string;
  readonly at: number;
}

const realSleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms).unref?.());

/** Telegram group, supergroup and channel ids are negative; `@name` is a public channel or group. */
export function isGroupChatId(chatId: string): boolean {
  return !/^\d+$/.test(chatId.trim());
}

/** Wait until the oldest of the last `cap` events (sorted ascending) leaves the window. */
function capWait(times: readonly number[], cap: number, windowMs: number, now: number): number {
  return times.length >= cap ? Math.max(0, times[times.length - cap] + windowMs - now) : 0;
}

export class TelegramBotLimiter {
  /** The limiter's clock (injectable for tests); deadlines are measured on it. */
  readonly now: () => number;
  private readonly sleep: (ms: number) => Promise<void>;
  private sent: readonly Sent[] = [];
  private readonly waiters = new Set<Waiter>();
  private pausedUntil = 0;
  private seq = 0;

  constructor(clock: LimiterClock = {}) {
    this.now = clock.now ?? Date.now;
    this.sleep = clock.sleep ?? realSleep;
  }

  /** Resolves when the send may go. Queue position is taken synchronously, at the call. */
  async acquire(req: TelegramSendRequest): Promise<TelegramReservation> {
    const w: Waiter = {
      seq: this.seq++,
      chatId: req.chatId,
      lane: req.lane,
      isGroup: req.isGroup ?? isGroupChatId(req.chatId),
    };
    this.waiters.add(w);
    const deadline = req.maxWaitMs === undefined ? Infinity : this.now() + req.maxWaitMs;
    try {
      for (;;) {
        const now = this.now();
        const wait = this.waitFor(w, now);
        if (wait <= 0) {
          w.reservedAt = now;
          return this.reservation(w);
        }
        if (now + wait > deadline) throw new TelegramRateLimitError(wait);
        await this.sleep(wait);
      }
    } catch (err) {
      this.waiters.delete(w);
      throw err;
    }
  }

  /** Pause every send from this bot until retryAfterMs from now (never shortens a longer pause). */
  backOff(retryAfterMs: number): void {
    this.pausedUntil = Math.max(this.pausedUntil, this.now() + Math.max(0, retryAfterMs));
  }

  private reservation(w: Waiter): TelegramReservation {
    let done = false;
    const finish = () => {
      done = true;
      this.waiters.delete(w);
    };
    return {
      commit: () => {
        if (done) return false;
        const now = this.now();
        // Limits only: priority was settled at the grant, and a held reservation already kept every
        // later grant off this slot. What can change in the gap is a 429 pause, or a send someone
        // made after this reservation ran past its TTL.
        if (this.ownWait(w, now) > 0) {
          finish();
          return false;
        }
        this.sent = [...this.sent.filter((s) => s.at > now - GROUP_WINDOW_MS), { chatId: w.chatId, at: now }];
        finish();
        return true;
      },
      release: () => {
        if (!done) finish();
      },
      backOff: (ms) => this.backOff(ms),
    };
  }

  /** 0 when w may go now; otherwise how long to wait before looking again. */
  private waitFor(w: Waiter, now: number): number {
    const own = this.ownWait(w, now);
    if (own > 0) return own;
    const rank = LANE_RANK[w.lane];
    for (const v of this.waiters) {
      if (v === w || v.reservedAt !== undefined) continue; // a reservation already counts in ownWait
      const vRank = LANE_RANK[v.lane];
      const outranks = vRank < rank || (vRank === rank && v.seq < w.seq);
      if (!outranks) continue;
      // A higher lane waiting for this same chat keeps it, even while it waits out its own spacing.
      if (vRank < rank && v.chatId === w.chatId) return BLOCKED_TICK_MS;
      if (this.ownWait(v, now) <= 0) return BLOCKED_TICK_MS;
    }
    return 0;
  }

  /** The wait from the limits alone: the pause, per-chat spacing, the group and overall caps. */
  private ownWait(w: Waiter, now: number): number {
    const events = this.events(w, now);
    const chat = events.filter((e) => e.chatId === w.chatId).map((e) => e.at);
    const all = events.map((e) => e.at);
    const last = chat.at(-1);
    return Math.max(
      0,
      this.pausedUntil - now,
      last === undefined ? 0 : last + PER_CHAT_MS - now,
      w.isGroup ? capWait(chat, GROUP_CAP[w.lane], GROUP_WINDOW_MS, now) : 0,
      capWait(
        all.filter((t) => t > now - GLOBAL_WINDOW_MS),
        GLOBAL_CAP[w.lane],
        GLOBAL_WINDOW_MS,
        now,
      ),
    );
  }

  /** Committed sends in the last minute plus everyone else's live reservations, oldest first. */
  private events(w: Waiter, now: number): Sent[] {
    const held: Sent[] = [];
    for (const v of this.waiters) {
      if (v === w || v.reservedAt === undefined || v.reservedAt <= now - RESERVATION_TTL_MS) continue;
      held.push({ chatId: v.chatId, at: v.reservedAt });
    }
    return [...this.sent.filter((s) => s.at > now - GROUP_WINDOW_MS), ...held].sort((a, b) => a.at - b.at);
  }
}

/** acquire + commit with no gap between them, re-queuing if the slot was lost. Same absolute deadline. */
export async function acquireAndCommit(
  limiter: TelegramBotLimiter,
  req: TelegramSendRequest,
): Promise<TelegramReservation> {
  const now = limiter.now;
  const deadline = req.maxWaitMs === undefined ? undefined : now() + req.maxWaitMs;
  for (;;) {
    const maxWaitMs = deadline === undefined ? undefined : Math.max(0, deadline - now());
    const slot = await limiter.acquire({ ...req, maxWaitMs });
    if (slot.commit()) return slot;
  }
}

/** The bot id is the part of the token before ':' — a rotated token for the same bot keeps its history. */
function botIdOf(token: string | undefined): string {
  return (token ?? "").trim().split(":")[0] ?? "";
}

/** One limiter per bot. The token itself is never kept, only its bot id. */
export class TelegramLimiters {
  private readonly bots = new Map<string, TelegramBotLimiter>();

  constructor(private readonly clock: LimiterClock = {}) {}

  forToken(token: string | undefined): TelegramBotLimiter {
    const id = botIdOf(token);
    const found = this.bots.get(id);
    if (found) return found;
    const made = new TelegramBotLimiter(this.clock);
    this.bots.set(id, made);
    return made;
  }

  /** Tests only: forget every bot's history. */
  reset(): void {
    this.bots.clear();
  }
}

/** The process's view of each bot. Every production Telegram sender is handed this one. */
export const sharedTelegramLimiters = new TelegramLimiters();

/** retry_after from a 429 body (JSON text or parsed), in ms. undefined when the status is not 429. */
export function telegramRetryAfterMs(status: number, body: unknown): number | undefined {
  if (status !== 429) return undefined;
  let parsed: unknown = body;
  if (typeof body === "string") {
    try {
      parsed = JSON.parse(body);
    } catch {
      parsed = undefined;
    }
  }
  const after = Number(
    (parsed as { parameters?: { retry_after?: unknown } } | undefined)?.parameters?.retry_after,
  );
  return Number.isFinite(after) && after > 0 ? after * 1000 : DEFAULT_RETRY_AFTER_MS;
}

export interface LimitedSendOptions {
  /** Retry once after a 429 only when its retry_after is at most this. 0 = never retry. */
  maxRetryWaitMs: number;
}

/**
 * One send through the bot's limiter: wait for a slot, send, and on a 429 pause the bot and (once,
 * when the wait is short enough) send again. No limiter → just send, the way it was before #2711.
 * Throws TelegramRateLimitError when the slot would come later than req.maxWaitMs.
 */
export async function sendWithTelegramLimit<R>(
  limiter: TelegramBotLimiter | undefined,
  req: TelegramSendRequest,
  attempt: () => Promise<R>,
  retryAfterOf: (result: R) => number | undefined | Promise<number | undefined>,
  opts: LimitedSendOptions,
): Promise<R> {
  if (!limiter) return attempt();
  const now = limiter.now;
  const deadline = req.maxWaitMs === undefined ? undefined : now() + req.maxWaitMs;
  for (let tries = 0; ; tries++) {
    const maxWaitMs = deadline === undefined ? undefined : Math.max(0, deadline - now());
    const slot = await acquireAndCommit(limiter, { ...req, maxWaitMs });
    const result = await attempt();
    const after = await retryAfterOf(result);
    if (after === undefined) return result;
    slot.backOff(after);
    if (tries >= 1 || after > opts.maxRetryWaitMs) return result;
  }
}
