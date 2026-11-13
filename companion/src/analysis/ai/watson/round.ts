import { PresidioApprovalRequired } from "../../presidio.js";
import type { InvestigationState } from "../../stateTypes.js";
import { callAiJson, retryPolicy } from "../aiContext.js";
import { AiReplyUnreadableError } from "../aiReplyUnreadable.js";
import { AiAnswerParseError } from "../providerCall.js";
import { isRetryableError } from "../retry.js";
import { getWatsonPrompt } from "../prompts/index.js";
import { WATSON_TURN_TEXT_MAX } from "./chatStore.js";
import { promptEntities } from "./pasteEntities.js";
import { pasteHead, searchPaste } from "./pasteSearch.js";
import { buildWatsonUserPrompt, WATSON_CASE_EVENTS_MAX, type WatsonPromptInput } from "./promptBuilder.js";
import { sanitizeWatsonReply, watsonReplySchema, type WatsonReply } from "./replySchema.js";
import {
  buildWatsonCaseContext,
  coverageOf,
  limitReached,
  mainLanguages,
  NO_SPEND,
  readPasteText,
  seedStandardQuestions,
  spendDelta,
  WatsonAiOff,
  WatsonCostLimitReached,
  watsonSpend,
  type WatsonRoundContext,
  type WatsonSpend,
} from "./roundContext.js";
import { buildProposals, newWatsonId } from "./roundProposals.js";
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

const LABEL = "watson";
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

/** What the model calls produced, for the final merge. */
interface Outcome {
  reply: WatsonReply | null;
  note?: string;
  error?: unknown;
  /** Thrown to the route after the save (a Presidio hold), even when a first reply was kept. */
  rethrow?: unknown;
  /** Pastes no longer unread: read by a reply, by a search hop, or given up on (see `unreadable`). */
  readPasteIds?: string[];
  /** A paste Watson could not read (its head failed, or its file is gone): told once, then dropped. */
  unreadable?: WatsonPaste;
  shownEvents: string[];
  questions: InvestigationState["keyQuestions"];
  /** Set only when the forensic timeline was trimmed to fit the prompt (#452). */
  coverage?: WatsonCoverage;
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

  // The paste this message carries, else the newest one no successful round has read yet.
  const pasteId = input.pasteId ?? start.unreadPasteIds.at(-1);
  const paste = pasteId ? start.pastes.find((p) => p.id === pasteId) : undefined;
  const analystTurn: WatsonTurn = {
    id: newWatsonId("wt"),
    at: new Date().toISOString(),
    role: "analyst",
    text: input.text.slice(0, WATSON_TURN_TEXT_MAX),
    ...(input.actor ? { actor: input.actor } : {}),
    ...(paste && input.pasteId ? { pasteId: paste.id } : {}),
  };
  const unread = paste && start.unreadPasteIds.includes(paste.id);
  const newPaste = paste && (unread || !pasteAnswered(start.turns, paste.id)) ? paste : undefined;
  // An unread paste is attached on its own at most once, so a head that always fails cannot block Watson.
  const auto = !input.pasteId && !!newPaste;
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
    const cc = await buildWatsonCaseContext(ctx, caseId, state);
    cover = coverageOf(cc);
    base = {
      state,
      // The analyst's message is the ANALYST block; it is not repeated as recent chat.
      chat: { ...chat, turns: chat.turns.filter((t) => t.id !== analystTurn.id) },
      analystText: analystTurn.text,
      caseContext: cc.text,
      mainLanguages: await mainLanguages(ctx, caseId, state),
    };
    const known = {
      questions: new Set(state.keyQuestions.map((q) => q.id)),
      pastes: new Set(chat.pastes.map((p) => p.id)),
    };
    ask = async (input) => {
      const prompt = buildWatsonUserPrompt(input);
      const raw = await guardedCall(
        ctx,
        caseId,
        counter,
        () => spentNow(ctx, caseId, chat, before),
        (one) =>
          callAiJson(
            one,
            caseId,
            state,
            ctx.provider,
            LABEL,
            getWatsonPrompt,
            prompt,
            (r) => watsonReplySchema.parse(r),
            { promptEntities: promptEntities(prompt) },
          ),
      );
      return sanitizeWatsonReply(raw, known.questions, known.pastes);
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
    const target = chat.pastes.find((p) => p.id === first.search?.pasteId);
    if (!target) return kept;
    const found = searchPaste(await readPasteText(ctx.cases, caseId, target), first.search.terms);
    const second = await ask({
      ...base,
      pasteExcerpt: {
        pasteId: target.id,
        filename: target.filename,
        text: found.excerpt || `(no line matched: ${first.search.terms.join(", ")})`,
        truncated: found.truncated,
      },
    });
    // A paste read through a search counts as read.
    return {
      ...kept,
      reply: { ...second, search: null },
      readPasteIds: [...(kept.readPasteIds ?? []), target.id],
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

async function headExcerpt(
  ctx: WatsonRoundContext,
  caseId: string,
  paste: WatsonPaste,
): Promise<NonNullable<WatsonPromptInput["pasteExcerpt"]>> {
  const text = await readPasteText(ctx.cases, caseId, paste);
  const head = pasteHead(text);
  const shownLines = head ? head.split("\n").length : 0;
  return { pasteId: paste.id, filename: paste.filename, text: head, truncated: shownLines < paste.lines };
}

/** A paste counts as shown only once a Watson turn answered the turn that carried it. */
function pasteAnswered(turns: readonly WatsonTurn[], pasteId: string): boolean {
  return turns.some((t, i) => t.pasteId === pasteId && turns[i + 1]?.role === "watson");
}

/** Remove each shown event once, so an event added during the round stays for the next one. */
function withoutShown(pending: readonly string[], shown: readonly string[]): string[] {
  const left = [...shown];
  return pending.filter((e) => {
    const i = left.indexOf(e);
    if (i === -1) return true;
    left.splice(i, 1);
    return false;
  });
}

function errorText(err: unknown): string {
  if (err instanceof PresidioApprovalRequired) {
    return "Watson's message is held: Presidio found values that need your approval before they go to the AI.";
  }
  if (err instanceof AiAnswerParseError || err instanceof AiReplyUnreadableError) {
    return "Watson's reply could not be read. Send your message again.";
  }
  const msg = err instanceof Error ? err.message : String(err);
  return `Watson could not answer: ${msg}`.slice(0, 600);
}

function mergeOutcome(fresh: WatsonChat, outcome: Outcome, spent: WatsonSpend, calls: number): WatsonChat {
  const at = new Date().toISOString();
  const charged = {
    ...fresh,
    costUSD: fresh.costUSD + spent.usd,
    tokens: fresh.tokens + spent.tokens,
    calls: fresh.calls + calls,
  };
  const { reply } = outcome;
  if (!reply) {
    const turn: WatsonTurn = {
      id: newWatsonId("wt"),
      at,
      role: "system",
      text: errorText(outcome.error),
      error: true,
      costUSD: spent.usd,
    };
    return withUnreadable({ ...charged, turns: [...charged.turns, turn] }, outcome, at);
  }
  const turnId = newWatsonId("wt");
  const proposals = buildProposals(reply, outcome.questions, turnId);
  const text = outcome.note ? `${reply.message}\n\n${outcome.note}`.trim() : reply.message;
  const turn: WatsonTurn = {
    id: turnId,
    at,
    role: "watson",
    text,
    ...(reply.workingOn ? { workingOn: reply.workingOn } : {}),
    ...(reply.learned ? { learned: reply.learned } : {}),
    ...(reply.request ? { request: reply.request } : {}),
    ...(outcome.coverage ? { coverage: outcome.coverage } : {}),
    ...(proposals.length ? { proposalIds: proposals.map((p) => p.id) } : {}),
    costUSD: spent.usd,
  };
  return withUnreadable(
    {
      ...charged,
      turns: [...charged.turns, turn],
      proposals: [...charged.proposals, ...proposals],
      // An empty memory is a lost field, not a decision to forget: keep the old one.
      memory: reply.memory.trim() ? reply.memory : charged.memory,
      pendingCaseEvents: withoutShown(charged.pendingCaseEvents, outcome.shownEvents),
    },
    outcome,
    at,
  );
}

/** Drop the pastes this round read or gave up on from the unread list, and say which one it gave up on. */
function withUnreadable(chat: WatsonChat, outcome: Outcome, at: string): WatsonChat {
  const done = new Set(outcome.readPasteIds ?? []);
  const unreadPasteIds = chat.unreadPasteIds.filter((id) => !done.has(id));
  const p = outcome.unreadable;
  if (!p) return { ...chat, unreadPasteIds };
  const note: WatsonTurn = {
    id: newWatsonId("wt"),
    at,
    role: "system",
    text: `Watson could not read ${p.filename}. It stays stored as evidence — ask Watson to search it.`,
  };
  return { ...chat, unreadPasteIds, turns: [...chat.turns, note] };
}
