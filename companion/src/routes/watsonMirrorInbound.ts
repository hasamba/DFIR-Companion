import { WATSON_TURN_TEXT_MAX } from "../analysis/ai/watson/chatStore.js";
import type { SlashCommandResponse } from "../analysis/slashCommand.js";
import { bindingKey } from "../analysis/slashCommandStore.js";
import { sendTelegramMessage, type TelegramMessage } from "../analysis/telegramPoller.js";
import { sharedTelegramLimiters } from "../analysis/notify/telegramRateLimiter.js";
import {
  mirrorAudit,
  onTelegramAllowlist,
  telegramApiBase,
  telegramBotToken,
} from "./watsonMirrorSupport.js";
import { fetchBotUsername } from "../integrations/telegram/watsonMirrorSender.js";
import { resolveToken } from "../analysis/telegramPoller.js";
import { captureCaseScope } from "../storage/caseIncarnation.js";
import type { RouteContext } from "./context.js";
import { guardCase } from "./slashCaseGuard.js";
import type { DispatchInput, DispatchResult } from "./slashCommand.js";
import { runWatsonSlash } from "./watsonSlash.js";

// #2647: plain text in a Telegram chat that mirrors a case becomes a Watson question for the BOUND
// case — straight to the Watson round, never through the `/dfir` resolver (which can take the first
// word for a case id and collapses whitespace). Same authority as `/dfir ask`, but only a user on the
// Telegram allowlist may ask (user decision 2026-11-19). In a group only a message that replies to a
// message the mirror sent, or mentions the bot, counts; the rest is ignored and never reaches the AI.
// Only `update.message` is read: an edited message is never a new question.

export type MirrorInbound =
  /** Not a mirror question: dispatch as a command, exactly as before. */
  | { kind: "command" }
  /** Group chatter or a replayed update: no reply, no AI call, no rate-limit spend. */
  | { kind: "ignore" }
  /** `seenKey` is committed only once the question is accepted (after the rate limit), see askFromMirror. */
  | { kind: "question"; caseId: string; text: string; seenKey?: string };

const usernames = new Map<string, Promise<string | undefined>>();

/** The bot's @username, asked once per token (a rotated token asks again). */
function botUsername(): Promise<string | undefined> {
  const token = resolveToken(telegramBotToken);
  if (!token) return Promise.resolve(undefined);
  let cached = usernames.get(token);
  if (!cached) {
    cached = fetchBotUsername({ botToken: token, apiBase: telegramApiBase() }).then((name) => {
      if (!name) usernames.delete(token); // ask again next time
      return name;
    });
    usernames.set(token, cached);
  }
  return cached;
}

/** The mention spans of `@name` in the message (Telegram's entities, else a plain search). */
function mentionSpans(message: TelegramMessage, text: string, name: string): Array<[number, number]> {
  const want = `@${name}`.toLowerCase();
  const spans = (message.entities ?? [])
    .filter((e) => e.type === "mention" && typeof e.offset === "number" && typeof e.length === "number")
    .map((e): [number, number] => [e.offset!, e.offset! + e.length!])
    .filter(([a, b]) => text.slice(a, b).toLowerCase() === want);
  if (spans.length || message.entities?.length) return spans;
  const i = text.toLowerCase().indexOf(want);
  return i >= 0 ? [[i, i + want.length]] : [];
}

const withoutSpans = (text: string, spans: Array<[number, number]>): string =>
  [...spans]
    .sort((a, b) => b[0] - a[0])
    .reduce((acc, [a, b]) => acc.slice(0, a) + acc.slice(b), text)
    .replace(/\s+/g, " ")
    .trim();

/** Decide what an incoming Telegram message is, before any rate limit or AI spend. */
export async function classifyMirrorInbound(
  ctx: RouteContext,
  message: TelegramMessage | undefined,
): Promise<MirrorInbound> {
  const store = ctx.options.watsonMirrorStore;
  const text = typeof message?.text === "string" ? message.text : "";
  const chatId = String(message?.chat?.id ?? "");
  if (!message || !store || !ctx.watsonMirror?.() || !chatId || !text.trim() || text.trim().startsWith("/"))
    return { kind: "command" };
  const entry = await store.get(chatId).catch(() => undefined);
  if (!entry) return { kind: "command" };
  let question = text.trim();
  if ((message.chat?.type ?? entry.chatType) !== "private") {
    const replyId = message.reply_to_message?.message_id;
    const replied = typeof replyId === "number" && entry.messageIds.includes(replyId);
    const name = replied ? undefined : await botUsername();
    const spans = name ? mentionSpans(message, text, name) : [];
    if (!replied && spans.length === 0) return { kind: "ignore" };
    question = withoutSpans(text, spans);
    if (!question) return { kind: "ignore" };
  }
  // A replay of an update already accepted is ignored here, before any rate limit. It is NOT marked
  // seen yet: a question the rate limit refuses must still run when Telegram delivers it again.
  const seenKey = typeof message.message_id === "number" ? `${chatId}:${message.message_id}` : undefined;
  if (seenKey && (await store.hasInbound(seenKey))) return { kind: "ignore" };
  return { kind: "question", caseId: entry.caseId, text: question, ...(seenKey ? { seenKey } : {}) };
}

const card = (title: string): SlashCommandResponse => ({ title, lines: [] });
const flat = (r: SlashCommandResponse): string =>
  [r.title, ...r.lines.filter(Boolean).map((l) => `• ${l}`)].join("\n");

/**
 * Run a plain-text question: "Asking Watson…" now, the answer later through the mirror. Called after
 * the rate limit accepted it; the update is marked seen first (persisted), so a replay runs no second
 * round. undefined = that replay: answer nothing.
 */
export async function askFromMirror(
  input: DispatchInput,
  q: { caseId: string; text: string; seenKey?: string },
): Promise<DispatchResult | undefined> {
  const { ctx, channelId, userId, channelStore } = input;
  if (q.seenKey && !(await ctx.options.watsonMirrorStore?.markInbound(q.seenKey))) return undefined;
  const refuse = (title: string): DispatchResult => ({ reply: card(title), ephemeral: true });
  if (!onTelegramAllowlist(userId)) {
    mirrorAudit(ctx, `telegram:${userId}`)(
      q.caseId,
      "slash-command-denied",
      `Watson question from Telegram chat ${channelId}: user not on the allowlist`,
      "error",
    );
    return refuse(`User ${userId || "(unknown)"} is not permitted to run /dfir ask.`);
  }
  const binding = await channelStore.get(bindingKey("telegram", channelId)).catch(() => undefined);
  if (binding?.caseId !== q.caseId)
    return refuse(`User ${userId} may only use this channel's bound case — this channel has no binding.`);
  const guard = await guardCase(ctx, q.caseId);
  if (guard) return refuse(guard);
  const actor = `${userId} via telegram`; // the same actor `/dfir ask` writes
  const text = q.text.slice(0, WATSON_TURN_TEXT_MAX);
  ctx.watsonMirror?.()?.expectEcho(channelId, q.caseId, actor, text);
  const inCase = captureCaseScope(ctx.store.casesRoot, q.caseId);
  return {
    reply: card("Asking Watson…"),
    ephemeral: true,
    background: () =>
      inCase(async () => {
        const result = await runWatsonSlash(ctx, q.caseId, text, actor);
        // A refusal never becomes a Watson turn, so the mirror would stay silent: say it here.
        if (!result.ok) {
          await sendTelegramMessage({
            botToken: telegramBotToken,
            apiBase: telegramApiBase(),
            chatId: channelId,
            text: flat(result.reply),
            log: ctx.serverLogger,
            limiters: sharedTelegramLimiters, // #2711
          });
        }
        mirrorAudit(ctx, `telegram:${userId}`)(
          q.caseId,
          "slash-command-ask",
          `Watson question from Telegram chat ${channelId} → ${result.ok ? "Watson answered" : result.reply.title.slice(0, 200)}`,
          ...(result.ok ? [] : (["error"] as const)),
        );
      }),
  };
}
