import { resolveToken, type TokenSource } from "../../analysis/telegramPoller.js";

// #2647: the Telegram mirror's Bot API calls. Separate from sendTelegramMessage (alerts and command
// replies stay exactly as they are): this one sends HTML, always turns link previews off, returns the
// message id, and classifies every failure so the service can decide what to do.
//
// Link previews are off on every mirror send: a Watson answer carries attacker URLs and domains, and a
// preview makes Telegram's servers fetch them — which tells the attacker someone is looking.

const DEFAULT_API = "https://api.telegram.org";
const SEND_TIMEOUT_MS = 15_000;

export type MirrorSendOutcome =
  | { kind: "sent"; messageId: number }
  /** 429: wait this long, then try the same message again. */
  | { kind: "rate_limited"; retryAfterMs: number }
  /** 403 (kicked, blocked) or 400 "chat not found": the chat is gone, stop mirroring to it. */
  | { kind: "gone"; reason: string }
  /** Any other 4xx: this message was refused (a formatter bug must never read as "the chat left"). */
  | { kind: "rejected"; reason: string }
  /** 5xx, a network failure or no token: retry on the backoff schedule. */
  | { kind: "transient"; reason: string };

interface BotApiBody {
  ok?: boolean;
  description?: string;
  result?: { message_id?: unknown; username?: unknown };
  parameters?: { retry_after?: unknown };
}

const apiUrl = (apiBase: string | undefined, token: string, method: string): string =>
  `${(apiBase ?? DEFAULT_API).replace(/\/+$/, "")}/bot${token}/${method}`;

function classify(status: number, body: BotApiBody): MirrorSendOutcome {
  const reason = body.description ?? `HTTP ${status}`;
  if (status === 429) {
    const after = Number(body.parameters?.retry_after);
    return { kind: "rate_limited", retryAfterMs: Number.isFinite(after) && after > 0 ? after * 1000 : 5_000 };
  }
  if (status === 403 || (status === 400 && /chat not found/i.test(reason))) return { kind: "gone", reason };
  if (status >= 400 && status < 500) return { kind: "rejected", reason };
  return { kind: "transient", reason };
}

export async function sendMirrorMessage(input: {
  botToken: TokenSource;
  chatId: string;
  text: string;
  apiBase?: string;
  fetchFn?: typeof fetch;
}): Promise<MirrorSendOutcome> {
  const token = resolveToken(input.botToken);
  if (!token) return { kind: "transient", reason: "DFIR_TELEGRAM_BOT_TOKEN is not set" };
  const doFetch = input.fetchFn ?? fetch;
  try {
    const res = await doFetch(apiUrl(input.apiBase, token, "sendMessage"), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        chat_id: input.chatId,
        text: input.text,
        parse_mode: "HTML",
        link_preview_options: { is_disabled: true },
      }),
      signal: AbortSignal.timeout(SEND_TIMEOUT_MS),
    });
    const body = (await res.json().catch(() => ({}))) as BotApiBody;
    if (res.ok && body.ok !== false) {
      const id = Number(body.result?.message_id);
      return { kind: "sent", messageId: Number.isInteger(id) ? id : 0 };
    }
    return classify(res.status, body);
  } catch (err) {
    return { kind: "transient", reason: (err as Error).message };
  }
}

/** The bot's @username, for spotting a mention in a group. undefined when Telegram cannot say. */
export async function fetchBotUsername(input: {
  botToken: TokenSource;
  apiBase?: string;
  fetchFn?: typeof fetch;
}): Promise<string | undefined> {
  const token = resolveToken(input.botToken);
  if (!token) return undefined;
  try {
    const res = await (input.fetchFn ?? fetch)(apiUrl(input.apiBase, token, "getMe"), {
      signal: AbortSignal.timeout(SEND_TIMEOUT_MS),
    });
    const body = (await res.json().catch(() => ({}))) as BotApiBody;
    const name = body.result?.username;
    return res.ok && typeof name === "string" && name ? name : undefined;
  } catch {
    return undefined;
  }
}

// ── Retry schedule ────────────────────────────────────────────────────────────────────

const BACKOFF_MS = [5_000, 30_000, 120_000, 600_000];
const BACKOFF_MAX_MS = 3_600_000;

/** Delay before retry number `attempt` (0-based): 5 s, 30 s, 2 min, 10 min, then hourly. */
export function mirrorBackoffMs(attempt: number): number {
  return BACKOFF_MS[attempt] ?? BACKOFF_MAX_MS;
}

// ── Mirror-only rate limiter ──────────────────────────────────────────────────────────

const PER_CHAT_MS = 1_000;
const GROUP_WINDOW_MS = 60_000;
const GROUP_MAX = 20;
const GLOBAL_WINDOW_MS = 1_000;
const GLOBAL_MAX = 25;

/**
 * Telegram's limits for one bot, for the mirror's own sends: 1 message a second per chat, 20 a minute
 * per group, 25 a second overall. Alerts and command replies do not go through it (a shared limiter
 * across all of them is a follow-up). In memory: a restart starts clean, and a 429 still waits.
 */
export class MirrorRateLimiter {
  private readonly perChat = new Map<string, number[]>();
  private global: number[] = [];

  /** How long to wait before the next send to this chat may go out (0 = now). */
  waitMs(chatId: string, isGroup: boolean, now: number): number {
    const sent = (this.perChat.get(chatId) ?? []).filter((t) => t > now - GROUP_WINDOW_MS);
    const last = sent.at(-1);
    const chatWait = last === undefined ? 0 : Math.max(0, last + PER_CHAT_MS - now);
    const groupWait =
      isGroup && sent.length >= GROUP_MAX
        ? Math.max(0, sent[sent.length - GROUP_MAX] + GROUP_WINDOW_MS - now)
        : 0;
    const recent = this.global.filter((t) => t > now - GLOBAL_WINDOW_MS);
    const globalWait =
      recent.length >= GLOBAL_MAX
        ? Math.max(0, recent[recent.length - GLOBAL_MAX] + GLOBAL_WINDOW_MS - now)
        : 0;
    return Math.max(chatWait, groupWait, globalWait);
  }

  record(chatId: string, _isGroup: boolean, now: number): void {
    const kept = (this.perChat.get(chatId) ?? []).filter((t) => t > now - GROUP_WINDOW_MS);
    this.perChat.set(chatId, [...kept, now]);
    this.global = [...this.global.filter((t) => t > now - GLOBAL_WINDOW_MS), now];
  }
}
