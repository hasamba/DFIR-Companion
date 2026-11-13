import { PresidioApprovalRequired } from "../../presidio.js";
import type { InvestigationState } from "../../stateTypes.js";
import { callAiJson } from "../aiContext.js";
import { AiReplyUnreadableError } from "../aiReplyUnreadable.js";
import { AiAnswerParseError } from "../providerCall.js";
import { getWatsonPrompt } from "../prompts/index.js";
import { WATSON_TURN_TEXT_MAX } from "./chatStore.js";
import { unseenPromptEntities } from "./pasteEntities.js";
import { pasteHead, searchPaste } from "./pasteSearch.js";
import { buildWatsonUserPrompt, WATSON_CASE_EVENTS_MAX, type WatsonPromptInput } from "./promptBuilder.js";
import { sanitizeWatsonReply, watsonReplySchema, type WatsonReply } from "./replySchema.js";
import {
  buildWatsonCaseContext,
  costLimitReached,
  mainLanguages,
  readPasteText,
  seedStandardQuestions,
  WatsonAiOff,
  WatsonCostLimitReached,
  watsonSpend,
  type WatsonRoundContext,
} from "./roundContext.js";
import { buildProposals, newWatsonId } from "./roundProposals.js";
import type { WatsonChat, WatsonPaste, WatsonTurn } from "./types.js";

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
const SEARCH_SKIPPED_NOTE =
  "(Watson wanted to search the pasted text, but this case reached its Watson cost limit, so it did not.)";

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
  shownEvents: string[];
  questions: InvestigationState["keyQuestions"];
}

async function runRound(
  ctx: WatsonRoundContext,
  caseId: string,
  input: WatsonRoundInput,
): Promise<WatsonChat> {
  if (!(await ctx.isAiEnabled(caseId))) throw new WatsonAiOff();
  const start = await ctx.chatStore.load(caseId);
  if (costLimitReached(ctx, start.costUSD))
    throw new WatsonCostLimitReached(start.costUSD, ctx.costLimitUSD ?? 0);

  const paste = input.pasteId ? start.pastes.find((p) => p.id === input.pasteId) : undefined;
  const analystTurn: WatsonTurn = {
    id: newWatsonId("wt"),
    at: new Date().toISOString(),
    role: "analyst",
    text: input.text.slice(0, WATSON_TURN_TEXT_MAX),
    ...(input.actor ? { actor: input.actor } : {}),
    ...(paste ? { pasteId: paste.id } : {}),
  };
  const newPaste = paste && !pasteAnswered(start.turns, paste.id) ? paste : undefined;
  // Saved BEFORE the model call: the analyst's words survive any failure below.
  const chat = await ctx.chatStore.update(caseId, (c) => ({ ...c, turns: [...c.turns, analystTurn] }));

  const spentBefore = await watsonSpend(ctx, caseId);
  const counter = { calls: 0 };
  const outcome = await converse(ctx, caseId, chat, analystTurn, newPaste, counter, spentBefore);
  const spent = Math.max(0, (await watsonSpend(ctx, caseId).catch(() => spentBefore)) - spentBefore);

  const saved = await ctx.chatStore.update(caseId, (fresh) =>
    mergeOutcome(fresh, outcome, spent, counter.calls),
  );
  if (outcome.error) {
    ctx.log?.warn(`Watson round failed: ${(outcome.error as Error)?.message ?? String(outcome.error)}`, {
      caseId,
    });
  }
  if (outcome.error instanceof PresidioApprovalRequired) throw outcome.error;
  return saved;
}

async function converse(
  ctx: WatsonRoundContext,
  caseId: string,
  chat: WatsonChat,
  analystTurn: WatsonTurn,
  newPaste: WatsonPaste | undefined,
  counter: { calls: number },
  spentBefore: number,
): Promise<Outcome> {
  const shownEvents = chat.pendingCaseEvents.slice(0, WATSON_CASE_EVENTS_MAX);
  let questions: InvestigationState["keyQuestions"] = [];
  try {
    await seedStandardQuestions(ctx, caseId);
    const state = await ctx.stateStore.load(caseId);
    questions = state.keyQuestions;
    const caseContext = await buildWatsonCaseContext(ctx, caseId, state);
    const base: WatsonPromptInput = {
      state,
      // The analyst's message is the ANALYST block; it is not repeated as recent chat.
      chat: { ...chat, turns: chat.turns.filter((t) => t.id !== analystTurn.id) },
      analystText: analystTurn.text,
      caseContext,
      mainLanguages: await mainLanguages(ctx, caseId, state),
    };
    const known = {
      questions: new Set(state.keyQuestions.map((q) => q.id)),
      pastes: new Set(chat.pastes.map((p) => p.id)),
    };
    const ask = async (input: WatsonPromptInput): Promise<WatsonReply> => {
      const prompt = buildWatsonUserPrompt(input);
      counter.calls++;
      const raw = await callAiJson(
        ctx,
        caseId,
        state,
        ctx.provider,
        LABEL,
        getWatsonPrompt,
        prompt,
        (r) => watsonReplySchema.parse(r),
        { promptEntities: unseenPromptEntities(prompt, caseContext) },
      );
      return sanitizeWatsonReply(raw, known.questions, known.pastes);
    };

    const first = await ask(
      newPaste ? { ...base, pasteExcerpt: await headExcerpt(ctx, caseId, newPaste) } : base,
    );
    if (!first.search) return { reply: first, shownEvents, questions };
    // At most one search hop per round, and only while the case is under its cost limit.
    const spentSoFar = Math.max(0, (await watsonSpend(ctx, caseId)) - spentBefore);
    if (costLimitReached(ctx, chat.costUSD + spentSoFar)) {
      return { reply: { ...first, search: null }, note: SEARCH_SKIPPED_NOTE, shownEvents, questions };
    }
    const target = chat.pastes.find((p) => p.id === first.search?.pasteId);
    if (!target) return { reply: { ...first, search: null }, shownEvents, questions };
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
    return { reply: { ...second, search: null }, shownEvents, questions };
  } catch (error) {
    return { reply: null, error: error ?? new Error("unknown error"), shownEvents, questions };
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

function mergeOutcome(fresh: WatsonChat, outcome: Outcome, spent: number, calls: number): WatsonChat {
  const at = new Date().toISOString();
  const charged = { ...fresh, costUSD: fresh.costUSD + spent, calls: fresh.calls + calls };
  const { reply } = outcome;
  if (!reply) {
    const turn: WatsonTurn = {
      id: newWatsonId("wt"),
      at,
      role: "system",
      text: errorText(outcome.error),
      error: true,
      costUSD: spent,
    };
    return { ...charged, turns: [...charged.turns, turn] };
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
    ...(proposals.length ? { proposalIds: proposals.map((p) => p.id) } : {}),
    costUSD: spent,
  };
  return {
    ...charged,
    turns: [...charged.turns, turn],
    proposals: [...charged.proposals, ...proposals],
    // An empty memory is a lost field, not a decision to forget: keep the old one.
    memory: reply.memory.trim() ? reply.memory : charged.memory,
    pendingCaseEvents: withoutShown(charged.pendingCaseEvents, outcome.shownEvents),
  };
}
