import type { WatsonChat } from "../../analysis/ai/watson/types.js";
import type { Logger } from "../../logging/logger.js";
import {
  buildMirrorMessages,
  mirrorFooter,
  replaceWorkstationRoots,
  turnPlainText,
  type WorkstationRoot,
} from "./watsonMirrorFormat.js";
import { mirrorBackoffMs, type MirrorSendOutcome } from "./watsonMirrorSender.js";
import {
  TelegramBotLimiter,
  type TelegramReservation,
  type TelegramSendRequest,
} from "../../analysis/notify/telegramRateLimiter.js";
import type { WatsonMirrorEntry, WatsonMirrorStore } from "./watsonMirrorStore.js";
import {
  allTurns,
  ECHO_TTL_MS,
  matchEchoes,
  resolvePending,
  turnsAfterCursor,
  type ExpectedEcho,
  type MirrorHistory,
} from "./watsonMirrorTurns.js";

// #2647: the Telegram mirror service. A chat bound to a case that ran `/dfir mirror on` gets every
// new turn of the case's Watson chat.
//
//   notify(caseId) — on every Watson chat change (and once at start): a serialized, coalescing scan per
//     case enqueues the turns each mirroring chat has not seen (enqueue is persisted first).
//   flush(chatId) — one at a time per chat: re-check the chat may still receive (revocation), mask,
//     format, send in order, then mark sent. Answers to a waiting analyst go at once; the rest waits
//     for the 60 s batch window. Failures retry on their own timer, with no new Watson activity.
//
// Everything outside the store is injected (composition/watsonMirrorWiring.ts), so tests drive it with
// a fake Bot API, a fake clock and fake timers.

export const MIRROR_BATCH_WINDOW_MS = 60_000;
/** A held chat re-checks its masking this often. */
export const MIRROR_HOLD_RECHECK_MS = 60_000;

export const HELD_TEXT = "Held: open the dashboard to review.";
/** #2710: sent once when turns between the cursor and the history window were never mirrored. */
export const GAP_TEXT =
  "Older Watson turns were not mirrored (the Companion was offline too long). See the dashboard for the full chat.";

/** Why a chat may not receive now. "pause" keeps its queue (an archived case); the rest switch it off. */
export type MirrorLiveness =
  | { ok: true }
  | { ok: false; action: "pause"; reason: string }
  | { ok: false; action: "disable"; reason: string };

/** The text masked with the case's anonymization list, or why it may not be sent (the chat is held). */
export type MirrorMasking = { ok: true; text: string } | { ok: false; reason: string };

export interface WatsonMirrorDeps {
  store: WatsonMirrorStore;
  loadChat: (caseId: string) => Promise<WatsonChat>;
  /** The newest turns of the append-only history (bounded), and whether older ones remain. */
  loadHistory: (caseId: string) => Promise<MirrorHistory>;
  /** Bound, mirroring, case present and unlocked, the enabling user still allowed. */
  liveness: (entry: WatsonMirrorEntry) => Promise<MirrorLiveness>;
  /** Re-mask `raw` with the case's anonymization list; not ok when masking fails or names await approval. */
  masking: (caseId: string, raw: string) => Promise<MirrorMasking>;
  /** botToken: the bot the slot was reserved on (#2711) — send from that same bot. */
  send: (chatId: string, text: string, botToken?: string) => Promise<MirrorSendOutcome>;
  /**
   * #2711: the bot's shared limiter (mirror lane: after alerts and command replies). Absent → a
   * private limiter on this service's clock, which is what the unit tests use.
   */
  limiter?: TelegramSendGate;
  audit: (caseId: string, action: string, detail: string, outcome?: "error") => void;
  roots: readonly WorkstationRoot[];
  publicUrl: () => string | undefined;
  log: Logger;
  now?: () => number;
  /** Schedules fn after ms; returns a cancel function. Real timers are unref'd. */
  setTimer?: (fn: () => void, ms: number) => () => void;
  sleep?: (ms: number) => Promise<void>;
  batchWindowMs?: number;
}

/** A slot in the bot's limiter, and the token of the bot it was reserved on. */
export interface TelegramSendGate {
  acquire(req: TelegramSendRequest): Promise<TelegramReservation & { readonly botToken?: string }>;
}

const realTimer = (fn: () => void, ms: number): (() => void) => {
  const t = setTimeout(fn, ms);
  t.unref?.();
  return () => clearTimeout(t);
};
const realSleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms).unref?.());

export class WatsonMirror {
  private readonly now: () => number;
  private readonly setTimer: (fn: () => void, ms: number) => () => void;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly windowMs: number;
  private readonly limiter: TelegramSendGate;
  private readonly scans = new Map<string, { running: Promise<void>; again: boolean }>();
  private readonly flushes = new Map<string, Promise<void>>();
  private readonly timers = new Map<string, { at: number; cancel: () => void }>();
  private echoes: ExpectedEcho[] = [];
  private stopped = false;

  constructor(private readonly deps: WatsonMirrorDeps) {
    this.now = deps.now ?? Date.now;
    this.setTimer = deps.setTimer ?? realTimer;
    this.sleep = deps.sleep ?? realSleep;
    this.windowMs = deps.batchWindowMs ?? MIRROR_BATCH_WINDOW_MS;
    this.limiter = deps.limiter ?? new TelegramBotLimiter({ now: this.now, sleep: this.sleep });
  }

  /** Resume after a restart: scan every case that has a mirroring chat. */
  async start(): Promise<void> {
    const cases = new Set((await this.deps.store.list().catch(() => [])).map((e) => e.caseId));
    await Promise.all([...cases].map((id) => this.notify(id)));
  }

  stop(): void {
    this.stopped = true;
    for (const t of this.timers.values()) t.cancel();
    this.timers.clear();
  }

  /** Resolves once no scan or send is in flight (shutdown and tests). */
  async idle(): Promise<void> {
    while (this.scans.size || this.flushes.size) {
      await Promise.all([...[...this.scans.values()].map((s) => s.running), ...this.flushes.values()]);
      await new Promise((r) => setImmediate(r));
    }
  }

  /** A Telegram question is about to become a turn: do not send it back to the chat that asked it. */
  expectEcho(chatId: string, caseId: string, actor: string, text: string): void {
    this.echoes = [...this.echoes, { chatId, caseId, actor, text, until: this.now() + ECHO_TTL_MS }];
  }

  /** The Watson chat of `caseId` changed. Coalesces: a scan running now runs once more after it. */
  notify(caseId: string): Promise<void> {
    if (this.stopped) return Promise.resolve();
    const cur = this.scans.get(caseId);
    if (cur) {
      cur.again = true;
      return cur.running;
    }
    const slot = { running: Promise.resolve(), again: false };
    slot.running = (async () => {
      do {
        slot.again = false;
        await this.scan(caseId).catch((err) =>
          this.deps.log.warn(`[telegram-mirror] scan failed: ${(err as Error).message}`, { caseId }),
        );
      } while (slot.again && !this.stopped);
      this.scans.delete(caseId);
    })();
    this.scans.set(caseId, slot);
    return slot.running;
  }

  private async scan(caseId: string): Promise<void> {
    const entries = await this.deps.store.listCase(caseId);
    if (entries.length === 0) return;
    const live = (await this.deps.loadChat(caseId)).turns;
    let history: Promise<MirrorHistory> | undefined;
    const readHistory = () => (history ??= this.deps.loadHistory(caseId));
    for (const entry of entries) {
      const { turns: fresh, gap } = await turnsAfterCursor(entry, live, readHistory);
      const known = new Set([...entry.pending, ...entry.sent]);
      const unseen = fresh.filter((t) => !known.has(t.id));
      const last = fresh.at(-1);
      if (last) {
        const { skip, remaining } = matchEchoes(entry.chatId, caseId, unseen, this.echoes, this.now());
        this.echoes = remaining;
        const skipped = new Set(skip);
        await this.deps.store.enqueue(
          entry.chatId,
          unseen.filter((t) => !skipped.has(t.id)).map((t) => t.id),
          last.id,
        );
        if (skip.length) await this.deps.store.markSent(entry.chatId, skip, []);
      }
      if (gap) await this.recordGap(entry);
      if (gap || entry.pending.length || unseen.length) this.schedule(entry.chatId, 0);
    }
  }

  /** Run flush(chatId) after ms; an earlier timer for the chat wins. */
  private schedule(chatId: string, ms: number): void {
    if (this.stopped) return;
    const at = this.now() + Math.max(0, ms);
    const cur = this.timers.get(chatId);
    if (cur && cur.at <= at) return;
    cur?.cancel();
    const cancel = this.setTimer(
      () => {
        this.timers.delete(chatId);
        void this.flush(chatId);
      },
      Math.max(0, ms),
    );
    this.timers.set(chatId, { at, cancel });
  }

  /** Send what the chat has pending, one flush at a time per chat. */
  flush(chatId: string): Promise<void> {
    const prev = this.flushes.get(chatId) ?? Promise.resolve();
    const run = prev
      .then(() => this.flushOnce(chatId))
      .catch((err) => this.deps.log.warn(`[telegram-mirror] send failed: ${(err as Error).message}`));
    this.flushes.set(chatId, run);
    void run.then(() => {
      if (this.flushes.get(chatId) === run) this.flushes.delete(chatId);
    });
    return run;
  }

  private async flushOnce(chatId: string): Promise<void> {
    if (this.stopped) return;
    const entry = await this.deps.store.get(chatId);
    if (!entry || (entry.pending.length === 0 && !entry.gapPending)) return;
    if (!(await this.stillLive(entry))) return;
    const now = this.now();
    const retryAt = entry.retry ? Date.parse(entry.retry.nextAt) : NaN;
    if (Number.isFinite(retryAt) && retryAt > now) return this.schedule(chatId, retryAt - now);

    const { caseId } = entry;
    const chat = await this.deps.loadChat(caseId);
    let found = resolvePending(entry.pending, chat.turns);
    // A pending turn that rotated out of the live chat (or the turn before it, for urgency) is read
    // from the append-only history.
    if (found.missing.length || !chat.turns.some((t) => t.id === entry.pending[0])) {
      found = resolvePending(
        entry.pending,
        allTurns((await this.deps.loadHistory(caseId)).turns, chat.turns),
      );
    }
    const { turns, urgent, missing } = found;
    if (missing.length) await this.deps.store.markSent(chatId, missing, []); // gone from chat and history
    if (turns.length === 0 && !entry.gapPending) return;
    const lastBatch = entry.lastBatchAt ? Date.parse(entry.lastBatchAt) : NaN;
    if (!urgent && Number.isFinite(lastBatch) && lastBatch + this.windowMs > now) {
      return this.schedule(chatId, lastBatch + this.windowMs - now);
    }
    const raw = turns.map((t) => turnPlainText(t, chat.proposals)).join("\n\n");
    const masking = await this.deps.masking(caseId, replaceWorkstationRoots(raw, this.deps.roots));
    if (!masking.ok) return this.hold(entry, masking.reason);
    if (entry.held) {
      await this.deps.store.patch(chatId, { held: false });
      this.deps.audit(caseId, "watson-mirror-hold-cleared", `Telegram chat ${chatId}: mirroring resumed`);
    }
    if (entry.gapPending && !(await this.sendGapNotice(entry))) return;
    if (turns.length === 0) return;
    const messages = buildMirrorMessages(masking.text, mirrorFooter(caseId, this.deps.publicUrl()));
    const ids = await this.sendAll(entry, messages);
    if (!ids) return;
    await this.deps.store.markSent(
      chatId,
      turns.map((t) => t.id),
      ids,
    );
    await this.deps.store.patch(chatId, {
      lastBatchAt: new Date(this.now()).toISOString(),
      retry: undefined,
    });
    const after = await this.deps.store.get(chatId);
    if (after?.pending.length) this.schedule(chatId, 0);
  }

  /** Re-check before every send. A chat that may no longer receive is switched off (or paused). */
  private async stillLive(entry: WatsonMirrorEntry): Promise<boolean> {
    const live = await this.deps.liveness(entry);
    if (live.ok) return true;
    if (live.action === "disable") {
      await this.deps.store.disable(entry.chatId);
      this.deps.audit(
        entry.caseId,
        "watson-mirror-auto-off",
        `Telegram chat ${entry.chatId}: mirroring switched off (${live.reason})`,
      );
    }
    return false;
  }

  private async hold(entry: WatsonMirrorEntry, reason: string): Promise<void> {
    if (!entry.held) {
      await this.deps.store.patch(entry.chatId, { held: true });
      this.deps.audit(
        entry.caseId,
        "watson-mirror-held",
        `Telegram chat ${entry.chatId}: held (${reason})`,
        "error",
      );
      const footer = mirrorFooter(entry.caseId, this.deps.publicUrl());
      const sent = await this.sendOne(entry, buildMirrorMessages(HELD_TEXT, footer)[0]);
      if (sent.kind === "sent") await this.deps.store.addMessageIds(entry.chatId, [sent.messageId]);
    }
    this.schedule(entry.chatId, MIRROR_HOLD_RECHECK_MS);
  }

  /**
   * #2710: turns older than the history window were never mirrored. The notice is owed (persisted)
   * BEFORE the send is tried: the enqueue before this moved the cursor past the gap, so no later scan
   * would see it again. Audited once, here.
   */
  private async recordGap(entry: WatsonMirrorEntry): Promise<void> {
    await this.deps.store.patch(entry.chatId, { gapPending: true });
    this.deps.audit(
      entry.caseId,
      "watson-mirror-gap",
      `Telegram chat ${entry.chatId}: older Watson turns were not mirrored (beyond the history window)`,
    );
  }

  /**
   * Send the owed gap notice ahead of the batch, once the chat is not held. Cleared only after Telegram
   * accepted it; a failure retries on the normal backoff (the batch waits behind it, keeping order).
   * Switching the mirror off drops the entry and the notice with it. true = sent, go on.
   */
  private async sendGapNotice(entry: WatsonMirrorEntry): Promise<boolean> {
    const footer = mirrorFooter(entry.caseId, this.deps.publicUrl());
    const out = await this.sendOne(entry, buildMirrorMessages(GAP_TEXT, footer)[0]);
    if (out.kind === "revoked") return false;
    if (out.kind !== "sent") {
      await this.failed(entry, out);
      return false;
    }
    await this.deps.store.addMessageIds(entry.chatId, [out.messageId]);
    await this.deps.store.patch(entry.chatId, { gapPending: false, retry: undefined });
    return true;
  }

  /**
   * Re-read right before a send (after any throttle wait): the chat must still have the SAME
   * enablement (not switched off, or off and on again) and still pass the liveness check — bound,
   * allowlisted, case present and unlocked. A batch never outlives its authorization.
   */
  private async stillAuthorized(entry: WatsonMirrorEntry): Promise<boolean> {
    const cur = await this.deps.store.get(entry.chatId);
    const same =
      !!cur &&
      cur.caseId === entry.caseId &&
      cur.enabledAt === entry.enabledAt &&
      cur.enabledBy === entry.enabledBy;
    return same && (await this.stillLive(cur));
  }

  private async sendOne(
    entry: WatsonMirrorEntry,
    text: string,
  ): Promise<MirrorSendOutcome | { kind: "revoked" }> {
    const isGroup = entry.chatType !== "private";
    for (;;) {
      // Wait for the slot FIRST, then re-check: a send never outlives its authorization, however long
      // it queued behind alerts and replies.
      const slot = await this.limiter.acquire({ chatId: entry.chatId, lane: "mirror", isGroup });
      if (this.stopped || !(await this.stillAuthorized(entry))) {
        slot.release();
        return { kind: "revoked" };
      }
      if (!slot.commit()) continue; // the slot went while we checked (a 429 pause): queue again
      const out = await this.deps.send(entry.chatId, text, slot.botToken);
      if (out.kind === "rate_limited") slot.backOff(out.retryAfterMs); // pauses the whole bot
      return out;
    }
  }

  /** Send the messages in order. The Telegram ids, or undefined when a failure stopped the batch. */
  private async sendAll(
    entry: WatsonMirrorEntry,
    messages: readonly string[],
  ): Promise<number[] | undefined> {
    const ids: number[] = [];
    for (const m of messages) {
      if (this.stopped) return undefined;
      const out = await this.sendOne(entry, m);
      if (out.kind === "sent") {
        ids.push(out.messageId);
        continue;
      }
      if (out.kind === "revoked") return undefined; // switched off or replaced mid-batch: stop here
      await this.failed(entry, out);
      return undefined;
    }
    return ids;
  }

  private async failed(
    entry: WatsonMirrorEntry,
    out: Exclude<MirrorSendOutcome, { kind: "sent" }>,
  ): Promise<void> {
    const { chatId, caseId } = entry;
    if (out.kind === "gone") {
      await this.deps.store.disable(chatId);
      this.deps.log.warn(`[telegram-mirror] chat ${chatId} is gone (${out.reason}); mirroring switched off`);
      this.deps.audit(
        caseId,
        "watson-mirror-auto-off",
        `Telegram chat ${chatId}: mirroring switched off (${out.reason})`,
      );
      return;
    }
    const attempt = entry.retry?.attempt ?? 0;
    const delay = out.kind === "rate_limited" ? out.retryAfterMs : mirrorBackoffMs(attempt);
    const nextAttempt = out.kind === "rate_limited" ? attempt : attempt + 1;
    const nextAt = new Date(this.now() + delay).toISOString();
    await this.deps.store.patch(chatId, { retry: { attempt: nextAttempt, nextAt } });
    this.deps.log.warn(
      `[telegram-mirror] chat ${chatId}: ${out.kind} (${"reason" in out ? out.reason : "retry_after"}); retry in ${delay} ms`,
    );
    // A refused message is a formatter or content problem, not weather: tell the analyst once.
    if (out.kind === "rejected" && attempt === 0) {
      this.deps.audit(
        caseId,
        "watson-mirror-refused",
        `Telegram refused a mirrored message: ${out.reason}`,
        "error",
      );
    }
    this.schedule(chatId, delay);
  }
}
