import { logActivity } from "../analysis/activityLog.js";
import { parseHostList } from "../analysis/slashCommandAuth.js";
import { captureCaseScope } from "../storage/caseIncarnation.js";
import type { RouteContext } from "./context.js";

// #2647: what the Telegram mirror's routes and its wiring share: the bot settings, read live (the
// token is on the /settings/reload allowlist), and the case activity-log writer.

export const telegramBotToken = (): string | undefined => process.env.DFIR_TELEGRAM_BOT_TOKEN;
export const telegramApiBase = (): string | undefined =>
  (process.env.DFIR_TELEGRAM_API_BASE ?? "").trim() || undefined;
export const telegramAllowlist = (): string[] => parseHostList(process.env.DFIR_TELEGRAM_ACTION_USERS);

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
