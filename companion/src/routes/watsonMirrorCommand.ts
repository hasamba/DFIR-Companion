import type { ResolvedSlashCommand } from "../analysis/slashCommand.js";
import type { ChannelBinding } from "../analysis/slashCommand.js";
import { escapeMirrorHtml } from "../integrations/telegram/watsonMirrorFormat.js";
import { sendMirrorMessage } from "../integrations/telegram/watsonMirrorSender.js";
import { mirrorAudit, telegramAllowlist, telegramApiBase, telegramBotToken } from "./watsonMirrorSupport.js";
import type { RouteContext } from "./context.js";
import { guardCase } from "./slashCaseGuard.js";

// #2647: `/dfir mirror on|off` from a Telegram chat, and the hooks that switch a chat off when its
// binding changes. Turning mirroring ON is stricter than every other command (user decision
// 2026-11-19): it is refused until the Telegram user allowlist is set, and only listed users may do it.
// An open bot would otherwise let anyone who finds it start a standing feed of a case to their chat.

export interface MirrorCommandInput {
  platform: string;
  channelId: string;
  userId: string;
  chatType?: string;
  ctx: RouteContext;
}

/**
 * What `/dfir mirror` answers: a string for the webhook reply, or (#2709) text the command already sent
 * to the chat itself, so its message id is recorded and the webhook gets an empty ack.
 */
export type MirrorReply = string | { readonly text: string; readonly quiet: true };

const ALLOWLIST_NEEDED =
  "Mirroring needs the Telegram user allowlist. Set DFIR_TELEGRAM_ACTION_USERS in the Companion's .env " +
  "to the numeric Telegram user ids allowed to turn it on, restart the Companion, and try again.";

async function mirrorOn(
  input: MirrorCommandInput,
  binding: ChannelBinding | undefined,
): Promise<MirrorReply> {
  const { ctx, channelId, userId } = input;
  const allow = telegramAllowlist();
  if (allow.length === 0) return ALLOWLIST_NEEDED;
  if (!allow.includes(userId)) return `User ${userId || "(unknown)"} is not permitted to turn on mirroring.`;
  if (!(telegramBotToken() ?? "").trim())
    return "Mirroring needs DFIR_TELEGRAM_BOT_TOKEN, so the Companion can send to this chat.";
  if (!binding) return "Bind this chat to a case first with `/dfir bind <caseId>`.";
  const guard = await guardCase(ctx, binding.caseId);
  if (guard) return guard;
  const store = ctx.options.watsonMirrorStore!;
  const current = await store.get(channelId);
  if (current?.caseId === binding.caseId) return `This chat already mirrors case ${binding.caseId}.`;
  // No history replay: the cursor starts at the newest turn the chat has now.
  const chat = await ctx.options.watsonChatStore?.load(binding.caseId).catch(() => undefined);
  const cursor = chat?.turns.at(-1)?.id;
  await store.enable(channelId, {
    caseId: binding.caseId,
    chatType: input.chatType || "private",
    by: userId,
    boundAt: binding.boundAt,
    at: new Date().toISOString(),
    ...(cursor ? { cursor } : {}),
  });
  mirrorAudit(ctx, `telegram:${userId}`)(
    binding.caseId,
    "watson-mirror-on",
    `Telegram chat ${channelId} now mirrors the Watson chat (turned on by user ${userId})`,
  );
  const text =
    `Mirroring started for case ${binding.caseId}. New Watson turns will appear here. ` +
    "Ask by replying to a mirrored message or mentioning the bot. Stop with `/dfir mirror off`.";
  return sendStarted(store, channelId, text);
}

/**
 * #2709: send "Mirroring started" through the Bot API and record its id, so a group reply to it counts
 * as a question like a reply to any mirrored message. A failed send falls back to the webhook reply.
 */
async function sendStarted(
  store: NonNullable<RouteContext["options"]["watsonMirrorStore"]>,
  chatId: string,
  text: string,
): Promise<MirrorReply> {
  const out = await sendMirrorMessage({
    botToken: telegramBotToken,
    apiBase: telegramApiBase(),
    chatId,
    text: escapeMirrorHtml(text),
  });
  if (out.kind !== "sent") return text;
  await store.addMessageIds(chatId, [out.messageId]).catch(() => undefined);
  return { text, quiet: true };
}

/** The reply to `/dfir mirror on|off`. The permission gate (isAllowed) has already run. */
export async function runMirrorCommand(
  input: MirrorCommandInput,
  cmd: ResolvedSlashCommand,
  binding: ChannelBinding | undefined,
): Promise<MirrorReply> {
  const { ctx, channelId, userId } = input;
  if (input.platform !== "telegram") return "Mirroring is available for Telegram chats only.";
  if (!ctx.options.watsonMirrorStore || !ctx.watsonMirror?.())
    return "Mirroring is not available on this server.";
  if (cmd.arg === "on") return mirrorOn(input, binding);
  if (cmd.arg !== "off") return "Usage: /dfir mirror on|off";
  const gone = await ctx.options.watsonMirrorStore.disable(channelId);
  if (!gone) return "This chat is not mirroring a case.";
  mirrorAudit(ctx, `telegram:${userId}`)(
    gone.caseId,
    "watson-mirror-off",
    `Telegram chat ${channelId} stopped mirroring the Watson chat (user ${userId})`,
  );
  return `Mirroring stopped for case ${gone.caseId}.`;
}

/** Unbind, or a bind to another case: the chat stops mirroring the old case at once. */
export async function stopMirrorOnRebind(
  ctx: RouteContext,
  platform: string,
  channelId: string,
  nextCaseId?: string,
): Promise<void> {
  const store = ctx.options.watsonMirrorStore;
  if (platform !== "telegram" || !store) return;
  const cur = await store.get(channelId).catch(() => undefined);
  if (!cur || cur.caseId === nextCaseId) return;
  await store.disable(channelId).catch(() => undefined);
  mirrorAudit(ctx, "telegram-mirror")(
    cur.caseId,
    "watson-mirror-auto-off",
    `Telegram chat ${channelId}: mirroring switched off (the chat was ${nextCaseId ? "bound to another case" : "unbound"})`,
  );
}

/** Does this Telegram chat mirror `caseId`? Then `/dfir ask` acks briefly and the mirror delivers the answer. */
export async function chatMirrorsCase(
  ctx: RouteContext,
  platform: string,
  channelId: string,
  caseId: string,
) {
  if (platform !== "telegram" || !ctx.watsonMirror?.()) return false;
  const cur = await ctx.options.watsonMirrorStore?.get(channelId).catch(() => undefined);
  return cur?.caseId === caseId;
}
