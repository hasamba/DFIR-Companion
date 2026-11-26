import {
  applyWatsonProposal,
  decisionDetail,
  WatsonProposalConflict,
  WatsonProposalNotFoundError,
  WatsonProposalStateError,
} from "../analysis/ai/watson/proposals.js";
import { newWatsonId } from "../analysis/ai/watson/roundProposals.js";
import type { WatsonProposal } from "../analysis/ai/watson/types.js";
import { SlidingWindowLimiter } from "../http/rateLimiter.js";
import {
  parseMirrorCallback,
  presserId,
  telegramActor,
  telegramApprovable,
  type MirrorButtonAction,
  type TelegramPresser,
} from "../integrations/telegram/watsonMirrorActions.js";
import { answerCallbackQuery } from "../integrations/telegram/watsonMirrorSender.js";
import type { WatsonMirrorEntry } from "../integrations/telegram/watsonMirrorStore.js";
import { captureCaseScope } from "../storage/caseIncarnation.js";
import type { RouteContext } from "./context.js";
import { watsonProposalDeps } from "./watsonDeps.js";
import {
  mirrorAudit,
  mirrorLiveness,
  onTelegramAllowlist,
  telegramApiBase,
  telegramBotToken,
} from "./watsonMirrorSupport.js";

// #2712: a press on a mirrored proposal's Apply / Reject button. Both Telegram ingress paths (the
// poller and the webhook) hand the callback_query here.
//
// Trust boundary: everything in the callback is untrusted. The data names only an opaque token and a
// decision (apply or reject — never undo); the token maps to (chat, proposal) in the mirror store; the
// proposal's kind and status are read from the chat store. A press is accepted only from a user on
// DFIR_TELEGRAM_ACTION_USERS, in the chat that owns the token, while that chat is still bound to the case
// and mirroring it under the SAME enablement, on a case that exists, is not password-protected, closed
// or archived. The whole check runs before the decision AND again under the chat lock, right before the
// write (applyWatsonProposal's authorize hook). The decision goes through the dashboard's own path.
//
// Every answer is a FIXED toast: no case id, title or error text (a toast skips the mirror's masking).

export interface TelegramCallbackQuery {
  id?: unknown;
  from?: TelegramPresser;
  message?: { message_id?: unknown; chat?: { id?: unknown } };
  data?: unknown;
}

export const TOAST = {
  invalid: "This button is not valid.",
  notAllowed: "You are not permitted to decide Watson proposals from Telegram.",
  expired: "This button has expired. Open the dashboard.",
  unavailable: "This chat can no longer decide for this case. Open the dashboard.",
  decided: "Already decided. Open the dashboard to see it.",
  dashboardOnly: "Decide this one in the dashboard.",
  changed: "The case changed since Watson proposed this. Open the dashboard.",
  gone: "This proposal is gone.",
  failed: "Could not do that. Open the dashboard.",
  replay: "Already handled.",
  busy: "Too many presses. Try again in a minute.",
  notConfigured: "Watson is not set up on the Companion.",
  applied: "Applied.",
  rejected: "Rejected.",
} as const;

/** A press makes no model call, so it spends no AI budget; it has its own bound per chat. */
const PRESSES_PER_MINUTE = 20;
const newPressLimiter = (): SlidingWindowLimiter => new SlidingWindowLimiter(PRESSES_PER_MINUTE, 60_000);
let pressLimiter = newPressLimiter();

/** A refusal raised under the chat lock: nothing was written. */
class PressRefused extends Error {
  constructor(readonly toast: string) {
    super(toast);
    this.name = "PressRefused";
  }
}

interface Press {
  chatId: string;
  userId: string;
  token: string;
}

/** Read the case once, failing closed: unreadable, missing, password-protected, closed or archived → no. */
async function caseWritable(ctx: RouteContext, caseId: string): Promise<boolean> {
  try {
    const meta = await ctx.store.getCaseMeta(caseId);
    return !!meta && !meta.password && meta.status !== "closed" && meta.status !== "archived";
  } catch {
    return false;
  }
}

/** The full authorization of a press. The chat's current entry and the proposal id, or the toast. */
async function authority(
  ctx: RouteContext,
  press: Press,
): Promise<{ entry: WatsonMirrorEntry; proposalId: string } | string> {
  const store = ctx.options.watsonMirrorStore;
  if (!store) return TOAST.notConfigured;
  if (!onTelegramAllowlist(press.userId)) return TOAST.notAllowed;
  const found = await store.findAction(press.token);
  if (!found || found.entry.chatId !== press.chatId) return TOAST.expired;
  // The token lives in the chat's entry, so finding it means this enablement is still the current one.
  const { entry, proposalId } = found;
  if (!(await mirrorLiveness(ctx, entry)).ok || !(await caseWritable(ctx, entry.caseId)))
    return TOAST.unavailable;
  return { entry, proposalId };
}

/** Was the decision recorded after all (an audit write failed after the commit)? */
async function committed(
  ctx: RouteContext,
  caseId: string,
  proposalId: string,
  action: MirrorButtonAction,
  actor: string,
): Promise<WatsonProposal | undefined> {
  const chat = await ctx.options.watsonChatStore?.load(caseId).catch(() => undefined);
  const p = chat?.proposals.find((x) => x.id === proposalId);
  if (!p) return undefined;
  if (action === "reject") return p.status === "rejected" ? p : undefined;
  return p.status === "applied" && p.appliedBy === actor ? p : undefined;
}

function refusalToast(err: unknown): string | undefined {
  if (err instanceof PressRefused) return err.toast;
  if (err instanceof WatsonProposalStateError) return TOAST.decided;
  if (err instanceof WatsonProposalNotFoundError) return TOAST.gone;
  if (err instanceof WatsonProposalConflict) return TOAST.changed;
  return undefined;
}

/**
 * The result reaches Telegram as a normal mirrored turn: one system note in the case chat. Its text
 * names the change, not the user (system text reaches the model's prompt; the actor does not).
 */
async function noteDecision(
  ctx: RouteContext,
  caseId: string,
  action: MirrorButtonAction,
  p: WatsonProposal,
  actor: string,
): Promise<void> {
  const chatStore = ctx.options.watsonChatStore;
  if (!chatStore) return;
  try {
    const turn = {
      id: newWatsonId("wt"),
      at: new Date().toISOString(),
      role: "system" as const,
      actor,
      text: `${decisionDetail(action, p)} from Telegram.`,
    };
    await chatStore.update(caseId, (c) => ({ ...c, turns: [...c.turns, turn] }));
  } catch (err) {
    ctx.serverLogger.warn(`[telegram-mirror] could not note a Telegram decision: ${(err as Error).message}`, {
      caseId,
    });
  }
}

/** Decide the proposal behind an authorized press. The toast to answer with. */
async function decide(ctx: RouteContext, press: Press, action: MirrorButtonAction, from: TelegramPresser) {
  const deps = watsonProposalDeps(ctx);
  if (!deps) return TOAST.notConfigured;
  const auth = await authority(ctx, press);
  if (typeof auth === "string") return auth;
  const { caseId } = auth.entry;
  const { proposalId } = auth;
  const stored = (await deps.chatStore.load(caseId)).proposals.find((x) => x.id === proposalId);
  if (!stored) return TOAST.gone;
  if (stored.status !== "pending") return TOAST.decided;
  // Kind from storage, never from the callback: a launch or a promotion is never decided here.
  if (!telegramApprovable(stored)) return TOAST.dashboardOnly;
  const actor = telegramActor(from);
  const authorize = async (p: WatsonProposal): Promise<void> => {
    const again = await authority(ctx, press);
    if (typeof again === "string") throw new PressRefused(again);
    if (again.entry.caseId !== caseId || again.proposalId !== proposalId)
      throw new PressRefused(TOAST.expired);
    if (!telegramApprovable(p)) throw new PressRefused(TOAST.dashboardOnly);
  };
  const inCase = captureCaseScope(ctx.store.casesRoot, caseId);
  try {
    let decided: WatsonProposal | undefined;
    try {
      const result = await inCase(() =>
        applyWatsonProposal(deps, caseId, proposalId, action, actor, {
          pendingOnly: true,
          detailSuffix: ` (Telegram user ${press.userId}, chat ${press.chatId})`,
          authorize,
        }),
      );
      if (result.state) ctx.options.onStateChanged?.(caseId);
      decided = result.chat.proposals.find((x) => x.id === proposalId);
    } catch (err) {
      const toast = refusalToast(err);
      if (toast) return toast;
      decided = await committed(ctx, caseId, proposalId, action, actor);
      if (!decided) {
        ctx.serverLogger.warn(`[telegram-mirror] a Telegram decision failed: ${(err as Error).message}`, {
          caseId,
        });
        return TOAST.failed;
      }
      ctx.options.onStateChanged?.(caseId); // committed: the case may have changed
    }
    await inCase(() => noteDecision(ctx, caseId, action, decided ?? stored, actor));
    return action === "apply" ? TOAST.applied : TOAST.rejected;
  } finally {
    ctx.options.onWatson?.(caseId); // the mirror sends the note; the panel refreshes
  }
}

/**
 * Handle one button press. The toast to answer with, or undefined when the callback has no id (there
 * is nothing to answer).
 */
export async function handleMirrorCallback(
  ctx: RouteContext,
  cq: TelegramCallbackQuery | undefined,
): Promise<string | undefined> {
  const id = typeof cq?.id === "string" && cq.id ? cq.id : undefined;
  if (!cq || !id) return undefined;
  const store = ctx.options.watsonMirrorStore;
  if (!store || !ctx.watsonMirror?.()) return TOAST.notConfigured;
  const chatId = String(cq.message?.chat?.id ?? "");
  const userId = presserId(cq.from);
  const parsed = parseMirrorCallback(cq.data);
  if (!/^-?\d{1,20}$/.test(chatId) || !userId || !parsed) return TOAST.invalid;
  // Limited per (chat, user) BEFORE the durable dedup write: one member cannot lock others out, and
  // a flood cannot push accepted messages out of the shared dedup list.
  if (!pressLimiter.tryAcquire(`${chatId}:${userId}`)) return TOAST.busy;
  if (!(await store.markInbound(`cb:${id}`))) return TOAST.replay;
  const press: Press = { chatId, userId, token: parsed.token };
  if (!onTelegramAllowlist(userId)) {
    const found = await store.findAction(parsed.token).catch(() => undefined);
    if (found && found.entry.chatId === chatId)
      mirrorAudit(ctx, `telegram:${userId}`)(
        found.entry.caseId,
        "slash-command-denied",
        `Watson proposal button from Telegram chat ${chatId}: user not on the allowlist`,
        "error",
      );
    return TOAST.notAllowed;
  }
  try {
    return await decide(ctx, press, parsed.action, cq.from ?? {});
  } catch (err) {
    ctx.serverLogger.warn(`[telegram-mirror] a button press failed: ${(err as Error).message}`);
    return TOAST.failed;
  }
}

/** handleMirrorCallback that never rejects: a store failure answers the generic refusal. */
function safeHandle(ctx: RouteContext, cq: TelegramCallbackQuery | undefined): Promise<string | undefined> {
  return handleMirrorCallback(ctx, cq).catch((err: unknown) => {
    ctx.serverLogger.warn(`[telegram-mirror] a button press failed: ${(err as Error).message}`);
    return TOAST.failed;
  });
}

/** The webhook's reply: Telegram runs the answerCallbackQuery it names, so no extra Bot API call. */
export async function mirrorCallbackWebhookReply(
  ctx: RouteContext,
  cq: TelegramCallbackQuery | undefined,
): Promise<Record<string, unknown>> {
  const toast = await safeHandle(ctx, cq);
  if (toast === undefined) return {};
  return { method: "answerCallbackQuery", callback_query_id: String(cq?.id), text: toast };
}

/** The poller's path: decide, then answer through the Bot API. Never rejects. */
export async function answerMirrorCallback(
  ctx: RouteContext,
  cq: TelegramCallbackQuery | undefined,
): Promise<void> {
  const toast = await safeHandle(ctx, cq);
  if (toast === undefined) return;
  await answerCallbackQuery({
    botToken: telegramBotToken,
    apiBase: telegramApiBase(),
    callbackQueryId: String(cq?.id),
    text: toast,
  });
}

/** Tests: a fresh press budget. */
export function resetMirrorPressLimiter(): void {
  pressLimiter = newPressLimiter();
}
