import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { PresidioPendingStore } from "../analysis/presidioPending.js";
import { bindingKey } from "../analysis/slashCommandStore.js";
import {
  WatsonMirror,
  type MirrorLiveness,
  type MirrorMasking,
} from "../integrations/telegram/watsonMirror.js";
import { workstationRoots } from "../integrations/telegram/watsonMirrorFormat.js";
import { sendMirrorMessage } from "../integrations/telegram/watsonMirrorSender.js";
import type { WatsonMirrorEntry } from "../integrations/telegram/watsonMirrorStore.js";
import { getServerLogger } from "../logging/serverLogger.js";
import type { RouteContext } from "../routes/context.js";
import { jevMasking } from "../routes/jevMasking.js";
import {
  mirrorAudit,
  telegramAllowlist,
  telegramApiBase,
  telegramBotToken,
} from "../routes/watsonMirrorSupport.js";

// #2647: builds the ONE Telegram mirror of an app from the route context, the way
// watsonReactorWiring.ts builds the reactor. Off in demo mode and whenever the bot, the mirror store
// or the Watson chat is not configured.

/**
 * How far back the mirror reads the append-only history when its cursor rotated out of the live chat
 * (400 turns): turns written while the server was down. A gap larger than this is not resent.
 */
const MIRROR_HISTORY_TURNS = 5000;

/** What onWatson needs from the mirror: a "this case's chat changed" signal. */
export interface WatsonMirrorSink {
  notify(caseId: string): void;
}

/**
 * The late link between onWatson (built before the app) and the mirror (built after the routes):
 * notify() is a no-op until attach() is called.
 */
export function createWatsonMirrorLink(): WatsonMirrorSink & { attach(sink: WatsonMirrorSink): void } {
  let target: WatsonMirrorSink | undefined;
  return {
    notify: (caseId) => target?.notify(caseId),
    attach: (sink) => {
      target = sink;
    },
  };
}

/** The install directory (the repository or package root), for the `<companion>` replacement. */
function installDir(): string {
  try {
    return resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
  } catch {
    return "";
  }
}

/** Before every send: may this chat still receive turns of this case? */
async function liveness(ctx: RouteContext, entry: WatsonMirrorEntry): Promise<MirrorLiveness> {
  const allow = telegramAllowlist();
  if (allow.length === 0 || !allow.includes(entry.enabledBy))
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

/**
 * Re-mask with the case's own anonymization list (the saved chat holds restored real values). Fails
 * closed: a masking error, or names waiting for approval in the Anonymization panel, holds the chat.
 * No Presidio scan per message (user decision 2026-11-19).
 */
async function masking(ctx: RouteContext, caseId: string): Promise<MirrorMasking> {
  const stateStore = ctx.options.stateStore;
  if (!stateStore) return { ok: false, reason: "the case state is not available" };
  try {
    const state = await stateStore.load(caseId);
    const { masker } = await jevMasking(ctx.store, caseId, state);
    if (masker.anon && (await new PresidioPendingStore(ctx.store).load(caseId)).length > 0)
      return { ok: false, reason: "names await approval in the Anonymization panel" };
    return { ok: true, mask: masker.mask };
  } catch (err) {
    getServerLogger().warn(`[telegram-mirror] masking failed: ${(err as Error).message}`, { caseId });
    return { ok: false, reason: "masking failed" };
  }
}

export function createAppWatsonMirror(ctx: RouteContext): WatsonMirror | undefined {
  const { options, store } = ctx;
  const chatStore = options.watsonChatStore;
  const mirrorStore = options.watsonMirrorStore;
  if (options.demoMode || !chatStore || !mirrorStore || !options.slashCommandChannelStore) return undefined;
  return new WatsonMirror({
    store: mirrorStore,
    loadChat: (caseId) => chatStore.load(caseId),
    loadHistory: async (caseId) =>
      (await chatStore.history.page(caseId, { limit: MIRROR_HISTORY_TURNS })).turns,
    liveness: (entry) => liveness(ctx, entry),
    masking: (caseId) => masking(ctx, caseId),
    send: (chatId, text) =>
      sendMirrorMessage({ botToken: telegramBotToken, apiBase: telegramApiBase(), chatId, text }),
    audit: mirrorAudit(ctx, "telegram-mirror"),
    roots: workstationRoots({
      casesRoot: store.casesRoot,
      dataDir: dirname(store.casesRoot),
      installDirs: [process.cwd(), installDir()],
    }),
    publicUrl: () => (process.env.DFIR_PUBLIC_URL ?? "").trim() || undefined,
    log: getServerLogger(),
  });
}

/**
 * A case became password-protected: every chat mirroring it stops at once and must turn mirroring on
 * again from the chat after the case is unlocked (the pre-send check would also catch it). Audited.
 */
export function stopMirroringLockedCase(
  mirrorStore: { disableCase(caseId: string): Promise<readonly { chatId: string }[]> } | undefined,
  audit: (caseId: string, detail: string) => void,
  caseId: string,
): void {
  if (!mirrorStore) return;
  void mirrorStore
    .disableCase(caseId)
    .then((gone) => {
      for (const c of gone) audit(caseId, `Telegram chat ${c.chatId}: mirroring switched off (password set)`);
    })
    .catch((err) =>
      getServerLogger().warn(`[telegram-mirror] could not stop mirroring: ${(err as Error).message}`, {
        caseId,
      }),
    );
}

/**
 * Build the mirror, hand it to onWatson, and resume: turns written while the server was down go out
 * now. Called once per app, after the routes (routeRegistry.ts); the host stops it on shutdown.
 */
export function startAppWatsonMirror(ctx: RouteContext): WatsonMirror | undefined {
  const mirror = createAppWatsonMirror(ctx);
  if (!mirror) return undefined;
  ctx.options.onWatsonMirrorReady?.(mirror);
  void mirror.start();
  return mirror;
}
