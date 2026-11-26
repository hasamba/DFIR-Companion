import { logActivity } from "../analysis/activityLog.js";
import { parseHostList } from "../analysis/slashCommandAuth.js";
import { bindingKey } from "../analysis/slashCommandStore.js";
import type { MirrorLiveness } from "../integrations/telegram/watsonMirror.js";
import type { WatsonMirrorEntry } from "../integrations/telegram/watsonMirrorStore.js";
import { captureCaseScope } from "../storage/caseIncarnation.js";
import type { RouteContext } from "./context.js";

// #2647: what the Telegram mirror's routes and its wiring share: the bot settings, read live (the
// token is on the /settings/reload allowlist), and the case activity-log writer.

export const telegramBotToken = (): string | undefined => process.env.DFIR_TELEGRAM_BOT_TOKEN;
export const telegramApiBase = (): string | undefined =>
  (process.env.DFIR_TELEGRAM_API_BASE ?? "").trim() || undefined;
export const telegramAllowlist = (): string[] => parseHostList(process.env.DFIR_TELEGRAM_ACTION_USERS);

/**
 * Is this Telegram user on DFIR_TELEGRAM_ACTION_USERS? Fails CLOSED: with no allowlist nobody may ask
 * Watson from a mirroring chat, keep a mirror alive, or press a proposal button (unlike the `/dfir`
 * commands, which are open on an unconfigured localhost tool).
 */
export function onTelegramAllowlist(userId: string | undefined): boolean {
  const allow = telegramAllowlist();
  return !!userId && allow.length > 0 && allow.includes(userId);
}

/**
 * May this chat still receive (and act on) turns of this case? Run by the mirror before every send,
 * and by a proposal button press (#2712) before and while deciding.
 */
export async function mirrorLiveness(ctx: RouteContext, entry: WatsonMirrorEntry): Promise<MirrorLiveness> {
  if (!onTelegramAllowlist(entry.enabledBy))
    return {
      ok: false,
      action: "disable",
      reason: "the user who turned it on is no longer on the allowlist",
    };
  const binding = await ctx.options.slashCommandChannelStore?.get(bindingKey("telegram", entry.chatId));
  // Unbind and a bind to another case switch the chat off at once (watsonMirrorCommand.ts); this
  // catches a binding changed any other way.
  if (!binding || binding.caseId !== entry.caseId)
    return { ok: false, action: "disable", reason: "the chat is no longer bound to the case" };
  let meta;
  try {
    meta = await ctx.store.getCaseMeta(entry.caseId);
  } catch {
    return { ok: false, action: "pause", reason: "the case could not be read" };
  }
  if (!meta) return { ok: false, action: "disable", reason: "the case was deleted" };
  if (meta.password) return { ok: false, action: "disable", reason: "the case is password-protected" };
  if (meta.status === "archived") return { ok: false, action: "pause", reason: "the case is archived" };
  return { ok: true };
}

/** Write one mirror line into the case's activity log, in the case's scope; never into a deleted case. */
export function mirrorAudit(ctx: RouteContext, actor: string) {
  return (caseId: string, action: string, detail: string, outcome?: "error"): void => {
    const { store, options } = ctx;
    void store
      .caseExists(caseId)
      .then((exists) => {
        if (!exists) return;
        void captureCaseScope(
          store.casesRoot,
          caseId,
        )(() =>
          logActivity(options.activityLogStore, options.onActivity, caseId, {
            actor,
            category: "collaboration",
            action,
            detail,
            ...(outcome ? { outcome } : {}),
          }),
        );
      })
      .catch(() => undefined);
  };
}
