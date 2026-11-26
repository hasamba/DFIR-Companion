import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { caseMasker, withSendMasking } from "../analysis/ai/maskRequest.js";
import { PresidioPendingStore } from "../analysis/presidioPending.js";
import {
  WatsonMirror,
  type MirrorMasking,
  type TelegramSendGate,
} from "../integrations/telegram/watsonMirror.js";
import { sharedTelegramLimiters } from "../analysis/notify/telegramRateLimiter.js";
import { resolveToken } from "../analysis/telegramPoller.js";
import { workstationRoots } from "../integrations/telegram/watsonMirrorFormat.js";
import { sendMirrorMessage } from "../integrations/telegram/watsonMirrorSender.js";
import { getServerLogger } from "../logging/serverLogger.js";
import type { RouteContext } from "../routes/context.js";
import { jevAnonStores } from "../routes/jevMasking.js";
import {
  mirrorAudit,
  mirrorLiveness,
  telegramApiBase,
  telegramBotToken,
} from "../routes/watsonMirrorSupport.js";

// #2647: builds the ONE Telegram mirror of an app from the route context, the way
// watsonReactorWiring.ts builds the reactor. Off in demo mode and whenever the bot, the mirror store
// or the Watson chat is not configured.

/**
 * How far back the mirror reads the append-only history when its cursor rotated out of the live chat
 * (400 turns): turns written while the server was down. A gap larger than this is not resent; the
 * chat gets a one-line notice instead (#2710).
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

const PENDING_NAMES: MirrorMasking = { ok: false, reason: "names await approval in the Anonymization panel" };

/**
 * Re-mask with the case's own anonymization list (the saved chat holds restored real values). Fails
 * closed: a masking error, or names waiting for approval in the Anonymization panel, holds the chat.
 * No Presidio scan per message (user decision 2026-11-19).
 *
 * #2708: masks under the case's masking-map lock, like a real AI send (withSendMasking), so a token it
 * mints for a value new to the case is saved and the AI and reports reuse it. A held flush saves nothing.
 */
export async function mirrorMaskText(ctx: RouteContext, caseId: string, raw: string): Promise<MirrorMasking> {
  const stateStore = ctx.options.stateStore;
  if (!stateStore) return { ok: false, reason: "the case state is not available" };
  try {
    const state = await stateStore.load(caseId);
    const opts = jevAnonStores(ctx.store);
    const sendCtx = { log: getServerLogger(), opts };
    return await withSendMasking<MirrorMasking>(sendCtx, caseId, async (identity) => {
      const masker = await caseMasker(sendCtx, caseId, state, undefined, undefined, identity);
      if (masker.anon && (await new PresidioPendingStore(ctx.store).load(caseId)).length > 0)
        return { anon: null, result: PENDING_NAMES };
      return { anon: masker.anon, result: { ok: true, text: masker.mask(raw) } };
    });
  } catch (err) {
    getServerLogger().warn(`[telegram-mirror] masking failed: ${(err as Error).message}`, { caseId });
    return { ok: false, reason: "masking failed" };
  }
}

/**
 * #2711: the mirror's slots come from the bot's shared limiter, the one alerts and command replies use.
 * The token is read once per slot, so the slot and the send are the same bot even across a reload.
 */
export const sharedMirrorGate: TelegramSendGate = {
  acquire: async (req) => {
    const botToken = resolveToken(telegramBotToken);
    const slot = await sharedTelegramLimiters.forToken(botToken).acquire(req);
    return { ...slot, botToken };
  },
};

export function createAppWatsonMirror(ctx: RouteContext): WatsonMirror | undefined {
  const { options, store } = ctx;
  const chatStore = options.watsonChatStore;
  const mirrorStore = options.watsonMirrorStore;
  if (options.demoMode || !chatStore || !mirrorStore || !options.slashCommandChannelStore) return undefined;
  return new WatsonMirror({
    store: mirrorStore,
    loadChat: (caseId) => chatStore.load(caseId),
    loadHistory: (caseId) => chatStore.history.page(caseId, { limit: MIRROR_HISTORY_TURNS }),
    liveness: (entry) => mirrorLiveness(ctx, entry),
    masking: (caseId, raw) => mirrorMaskText(ctx, caseId, raw),
    send: (chatId, text, botToken, replyMarkup) =>
      sendMirrorMessage({
        botToken: botToken ?? telegramBotToken,
        apiBase: telegramApiBase(),
        chatId,
        text,
        ...(replyMarkup ? { replyMarkup } : {}),
      }),
    limiter: sharedMirrorGate,
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
