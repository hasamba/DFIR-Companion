import { PresidioApprovalRequired } from "../../presidio.js";
import type { InvestigationState } from "../../stateTypes.js";
import { retryPolicy } from "../aiContext.js";
import { isRetryableError } from "../retry.js";
import { WATSON_TURN_TEXT_MAX } from "./chatStore.js";
import { WATSON_HISTORY_ID } from "./historyStore.js";
import { WATSON_CASE_EVENTS_MAX, type WatsonPromptInput } from "./promptBuilder.js";
import { sanitizeWatsonReply, type WatsonReply } from "./replySchema.js";
import { callWatson, choosePaste, headExcerpt, searchExcerpt, watsonBaseInput } from "./requestBuild.js";
import {
  limitReached,
  NO_SPEND,
  seedStandardQuestions,
  spendDelta,
  WatsonAiOff,
  WatsonCostLimitReached,
  watsonSpend,
  type WatsonRoundContext,
  type WatsonSpend,
} from "./roundContext.js";
import { mergeOutcome, type Outcome } from "./roundOutcome.js";
import { newWatsonId } from "./roundProposals.js";
import type { WatsonChat, WatsonCoverage, WatsonPaste, WatsonTurn } from "./types.js";

export { WatsonAiOff, WatsonCostLimitReached, type WatsonRoundContext } from "./roundContext.js";

// One Watson round: the analyst's message in, Watson's turn and pending proposals out.
//
// Rounds on one case run one at a time (the chain below), so a second message waits for the first
// answer and its prompt contains it. Every chat write goes through chatStore.update(), which merges
// into the FRESH chat, so a paste or a case event added while the model thinks is never lost. The
// model is reached only through callAiJson, which keeps the anonymizer and Presidio on (spec §8).

export interface WatsonRoundInput {
  text: string;
  actor?: string;
  pasteId?: string;
}

const searchSkipped = (why: string): string =>
  `(Watson wanted to search the pasted text, but ${why}, so it did not.)`;
const searchFailed = (err: unknown): string =>
  `(Watson's search of the pasted text failed: ${err instanceof Error ? err.message : String(err)})`.slice(
    0,
    600,
  );

const chains = new Map<string, Promise<unknown>>();

export function runWatsonRound(
  ctx: WatsonRoundContext,
  caseId: string,
  input: WatsonRoundInput,
): Promise<WatsonChat> {
  const prev = chains.get(caseId) ?? Promise.resolve();
  const run = prev.then(() => runRound(ctx, caseId, input));
  const tail = run.catch(() => undefined);
  chains.set(caseId, tail);
  void tail.then(() => {
    if (chains.get(caseId) === tail) chains.delete(caseId);
  });
  return run;
}

const chatSpend = (c: WatsonChat): WatsonSpend => ({ usd: c.costUSD, tokens: c.tokens });

async function runRound(
  ctx: WatsonRoundContext,
  caseId: string,
  input: WatsonRoundInput,
): Promise<WatsonChat> {
  if (!(await ctx.isAiEnabled(caseId))) throw new WatsonAiOff();
  const start = await ctx.chatStore.load(caseId);
  const reached = limitReached(ctx, chatSpend(start));
  if (reached) throw new WatsonCostLimitReached(reached);

  // The paste this message carries, else the newest one no successful round has read yet. An unread
  // paste is attached on its own at most once, so a head that always fails cannot block Watson.
  const { paste, newPaste, auto } = choosePaste(start, input.pasteId);
  const analystTurn: WatsonTurn = {
    id: newWatsonId("wt"),
    at: new Date().toISOString(),
    role: "analyst",
    text: input.text.slice(0, WATSON_TURN_TEXT_MAX),
    ...(input.actor ? { actor: input.actor } : {}),
    ...(paste && input.pasteId ? { pasteId: paste.id } : {}),
  };
  // Saved BEFORE the model call: the analyst's words survive any failure below.
  const chat = await ctx.chatStore.update(caseId, (c) => ({ ...c, turns: [...c.turns, analystTurn] }));

  const counter = { calls: 0 };
  let outcome: Outcome = { reply: null, shownEvents: [], questions: [] };
  let before: WatsonSpend | null = null;
  let saved: WatsonChat | undefined;
  try {
    before = await watsonSpend(ctx, caseId);
    outcome = await converse(ctx, caseId, chat, analystTurn, { paste: newPaste, auto }, counter, before);
  } catch (error) {
    outcome = { ...outcome, reply: null, error };
  } finally {
    // Every exit charges the round, and every exit leaves a turn: a reply or an error.
    const after = await watsonSpend(ctx, caseId).catch(() => null);
    const spent = before && after ? spendDelta(before, after) : NO_SPEND;
    saved = await ctx.chatStore.update(caseId, (fresh) => mergeOutcome(fresh, outcome, spent, counter.calls));
  }
  const failure = outcome.error ?? outcome.rethrow;
  if (failure) {
    ctx.log?.warn(`Watson round failed: ${failure instanceof Error ? failure.message : String(failure)}`, {
      caseId,
    });
  }
  if (failure instanceof PresidioApprovalRequired) throw failure;
  return saved;
}

async function converse(
  ctx: WatsonRoundContext,
  caseId: string,
  chat: WatsonChat,
  analystTurn: WatsonTurn,
  attach: { paste: WatsonPaste | undefined; auto: boolean },
  counter: { calls: number },
  before: WatsonSpend,
): Promise<Outcome> {
  const newPaste = attach.paste;
  let headFailed = false;
  const shownEvents = chat.pendingCaseEvents.slice(0, WATSON_CASE_EVENTS_MAX);
  let questions: InvestigationState["keyQuestions"] = [];
  let cover: WatsonCoverage | undefined;
  let first: WatsonReply;
  let ask: (input: WatsonPromptInput) => Promise<WatsonReply>;
  let base: WatsonPromptInput;
  try {
    // The board and the Key Questions section show the seeded questions now, whatever the round does.
    if (await seedStandardQuestions(ctx, caseId)) ctx.onStateChanged?.(caseId);
    const state = await ctx.stateStore.load(caseId);
    questions = state.keyQuestions;
    // The analyst's message is the ANALYST block; it is not repeated as recent chat.
    const others = { ...chat, turns: chat.turns.filter((t) => t.id !== analystTurn.id) };
    ({ base, cover } = await watsonBaseInput(ctx, caseId, state, others, analystTurn.text, true));
    const known = {
      questions: new Set(state.keyQuestions.map((q) => q.id)),
      pastes: new Set(chat.pastes.map((p) => p.id)),
      events: new Set(state.forensicTimeline.map((e) => e.id)),
    };
    ask = async (input) => {
      const raw = await guardedCall(
        ctx,
        caseId,
        counter,
        () => spentNow(ctx, caseId, chat, before),
        (one) => callWatson(one, caseId, state, ctx.provider, input),
      );
      return sanitizeWatsonReply(raw, known.questions, known.pastes, known.events);
    };
    // A stored file that is gone or unreadable never fails the round: Watson answers without it.
    const excerpt = newPaste
      ? await headExcerpt(ctx, caseId, newPaste).catch(() => {
          headFailed = true;
          return undefined;
        })
      : undefined;
    first = await ask(excerpt ? { ...base, pasteExcerpt: excerpt } : base);
  } catch (error) {
    // An auto-attached head is not tried again; the paste stays stored and searchable.
    // A Presidio hold is not a failure to read: the paste stays unread for the approved retry.
    const held = error instanceof PresidioApprovalRequired;
    const giveUp = newPaste && (headFailed || (attach.auto && !held)) ? newPaste : undefined;
    return {
      reply: null,
      error,
      shownEvents,
      questions,
      ...(giveUp ? { readPasteIds: [giveUp.id], unreadable: giveUp } : {}),
    };
  }
  const read = {
    ...(newPaste ? { readPasteIds: [newPaste.id], ...(headFailed ? { unreadable: newPaste } : {}) } : {}),
    ...(cover ? { coverage: cover } : {}),
  };
  if (!first.search) return { reply: first, shownEvents, questions, ...read };
  const kept: Outcome = { reply: { ...first, search: null }, shownEvents, questions, ...read };
  // At most one search hop per round. From here on a failure never loses the first reply.
  try {
    const now = await spentNow(ctx, caseId, chat, before).catch(() => null);
    if (!now) return { ...kept, note: searchSkipped("its cost could not be checked") };
    const reached = limitReached(ctx, now);
    if (reached) return { ...kept, note: searchSkipped(`this case reached its Watson ${reached}`) };
    const excerpt = await searchExcerpt(ctx, caseId, chat, first.search);
    if (!excerpt) return kept;
    const second = await ask({ ...base, pasteExcerpt: excerpt });
    // A paste read through a search counts as read; the history is not a paste.
    const readId = excerpt.pasteId === WATSON_HISTORY_ID ? [] : [excerpt.pasteId];
    return {
      ...kept,
      reply: { ...second, search: null },
      readPasteIds: [...(kept.readPasteIds ?? []), ...readId],
    };
  } catch (error) {
    return { ...kept, note: searchFailed(error), rethrow: error };
  }
}

/** Watson's spend on the case now: the chat's total before this round plus what the round used. */
async function spentNow(
  ctx: WatsonRoundContext,
  caseId: string,
  chat: WatsonChat,
  before: WatsonSpend,
): Promise<WatsonSpend> {
  const d = spendDelta(before, await watsonSpend(ctx, caseId));
  return { usd: chat.costUSD + d.usd, tokens: chat.tokens + d.tokens };
}

/**
 * One model call with Watson's own retry loop, so the cost and token limits are checked before EVERY
 * provider attempt (a retry on a malformed reply included), and `counter` counts attempts, not calls.
 * callAiJson runs with retries off; the same policy and the same retry rules apply out here.
 */
async function guardedCall<T>(
  ctx: WatsonRoundContext,
  caseId: string,
  counter: { calls: number },
  spent: () => Promise<WatsonSpend>,
  call: (one: WatsonRoundContext) => Promise<T>,
): Promise<T> {
  const { retries, backoffMs } = retryPolicy(ctx);
  const one: WatsonRoundContext = { ...ctx, opts: { ...ctx.opts, retries: 0 } };
  const limited = ctx.costLimitUSD !== undefined || ctx.tokenLimit !== undefined;
  for (let attempt = 0; ; attempt++) {
    const reached = limited ? limitReached(ctx, await spent()) : null;
    if (reached) throw new WatsonCostLimitReached(reached);
    counter.calls++;
    try {
      return await call(one);
    } catch (err) {
      if (attempt >= retries || !isRetryableError(err)) throw err;
      ctx.log?.warn(`Watson call attempt ${attempt + 1} failed; retrying`, { caseId });
      await new Promise((r) => setTimeout(r, backoffMs * 2 ** attempt));
    }
  }
}
