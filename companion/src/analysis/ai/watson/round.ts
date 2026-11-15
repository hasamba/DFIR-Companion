import { PresidioApprovalRequired } from "../../presidio.js";
import type { InvestigationState } from "../../stateTypes.js";
import { WATSON_TURN_TEXT_MAX } from "./chatStore.js";
import { WATSON_CASE_EVENTS_MAX, type WatsonPromptInput } from "./promptBuilder.js";
import { sanitizeWatsonReply, type WatsonReply } from "./replySchema.js";
import { callWatson, choosePaste, headExcerpt, watsonBaseInput } from "./requestBuild.js";
import { secondHop, type HopInput } from "./roundHop.js";
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
import { guardedCall, spentNow } from "./guardedCall.js";
import { excerptRoster } from "./rowTextHosts.js";
import { mergeMaskRoster, type WatsonMaskRoster } from "./superRoster.js";
import { runToolLoop, ToolModeFallback, type ToolLoopInput } from "./toolLoop.js";
import { markToolsRejected, watsonToolCap } from "./toolMode.js";
import {
  engaged,
  reactionFailed,
  reactionTurn,
  WATSON_REACTION_PROMPT,
  withReactionResult,
} from "./reactionState.js";
import { autoAfterRound, carriedHeldIds, type WatsonRoundSource } from "./autoApply.js";
import { mergeOutcome, type Outcome } from "./roundOutcome.js";
import { newWatsonId } from "./roundProposals.js";
import { revalidatePromotion, withCitedPromotion } from "./roundPromote.js";
import { earlierShownIds } from "./rawReferences.js";
import { citationSets, withWriteInputs } from "./roundWrites.js";
import { withVeloLaunch } from "./velo/veloLaunchProposals.js";
import { withRoundInventory } from "./velo/veloFleet.js";
import type { WatsonChat, WatsonCoverage, WatsonPaste, WatsonTurn } from "./types.js";

export { WatsonAiOff, WatsonCostLimitReached, type WatsonRoundContext } from "./roundContext.js";
export { WATSON_REACTION_PROMPT } from "./reactionState.js";

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
  /** Spec §4.4 door rule: false drops the reply's writes (question proposals stay). Default true. */
  allowWrites?: boolean;
  /**
   * An automatic reaction to case events (reactor.ts): a system turn instead of an analyst turn, no
   * round at all when no event is pending, no writes when an import is among the events shown, and a
   * cost/token limit is thrown like a Presidio hold so the reactor can pause.
   */
  reaction?: boolean;
  /**
   * A reaction to the result of Watson's own launch: the held-promotion proposals that result
   * created (from the pending `hunt` events). Auto applies only those the round actually showed.
   */
  heldProposalIds?: string[];
  /** The held promotions this message's paste created (routes/watson.ts): Auto may apply them. */
  pasteProposalIds?: string[];
  /**
   * Where the message came from. Only a message an analyst sent in the dashboard's Watson panel
   * ("dashboard", set by routes/watson.ts) may launch in Auto mode; every other source holds (G12).
   */
  source?: WatsonRoundSource;
}

const chains = new Map<string, Promise<unknown>>();

export function runWatsonRound(
  ctx: WatsonRoundContext,
  caseId: string,
  input: WatsonRoundInput,
): Promise<WatsonChat> {
  const prev = chains.get(caseId) ?? Promise.resolve();
  const run = prev.then(() => runRound(withRoundInventory(ctx), caseId, input)); // one inventory read (G16)
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
  // An analyst message that ran first read every event: nothing is left to react to.
  if (input.reaction && start.pendingCaseEvents.length === 0) return start;
  const reached = limitReached(ctx, chatSpend(start));
  if (reached) throw new WatsonCostLimitReached(reached);

  // The paste this message carries, else the newest one no successful round has read yet. An unread
  // paste is attached on its own at most once, so a head that always fails cannot block Watson.
  const { paste, newPaste, auto } = choosePaste(start, input.pasteId);
  const analystTurn: WatsonTurn = input.reaction
    ? reactionTurn(start)
    : {
        id: newWatsonId("wt"),
        at: new Date().toISOString(),
        role: "analyst",
        text: input.text.slice(0, WATSON_TURN_TEXT_MAX),
        ...(input.actor ? { actor: input.actor } : {}),
        ...(paste && input.pasteId ? { pasteId: paste.id } : {}),
      };
  const promptTurn = { id: analystTurn.id, text: input.reaction ? WATSON_REACTION_PROMPT : analystTurn.text };
  // Saved BEFORE the model call: the analyst's words survive any failure below.
  const chat = await ctx.chatStore.update(caseId, (c) => {
    const base = input.reaction ? c : engaged(c);
    return { ...base, turns: [...base.turns, analystTurn] };
  });

  const counter = { calls: 0 };
  const turnId = newWatsonId("wt"); // Watson's turn: Auto applies only its proposals
  let outcome: Outcome = { reply: null, shownEvents: [], questions: [] };
  let before: WatsonSpend | null = null;
  let saved: WatsonChat | undefined;
  let mayWrite = false; // the door rule's verdict: Auto applies no carried rows when writes are off
  try {
    before = await watsonSpend(ctx, caseId);
    const attach = { paste: newPaste, auto, reaction: input.reaction === true };
    outcome = await converse(ctx, caseId, chat, promptTurn, attach, counter, before);
    // Spec §4.4: a reaction to an import writes nothing, judged on the events the prompt showed.
    const importShown = input.reaction === true && outcome.shownEvents.some((e) => e.kind === "import");
    mayWrite = input.allowWrites !== false && !importShown;
    outcome = await withWriteInputs(ctx, caseId, outcome, mayWrite);
    // Evidence first: the raw rows the reply cites are promoted before the turn is saved (D9).
    outcome = await withCitedPromotion(ctx, caseId, outcome, mayWrite, turnId, chat);
    outcome = await withVeloLaunch(ctx, caseId, outcome, mayWrite);
  } catch (error) {
    outcome = { ...outcome, reply: null, error };
  } finally {
    // Every exit charges the round, and every exit leaves a turn: a reply or an error.
    const after = await watsonSpend(ctx, caseId).catch(() => null);
    const spent = before && after ? spendDelta(before, after) : NO_SPEND;
    const failed = input.reaction === true && reactionFailed(outcome.reply, outcome.error);
    saved = await ctx.chatStore.update(caseId, (fresh) => {
      // D9b: an undo of the promotion while the round ran drops what rested on it before it is added.
      const checked = revalidatePromotion(fresh, outcome);
      const merged = mergeOutcome(fresh, { ...checked, turnId }, spent, counter.calls);
      return input.reaction ? withReactionResult(merged, failed) : merged;
    });
  }
  const failure = outcome.error ?? outcome.rethrow;
  if (failure) {
    ctx.log?.warn(`Watson round failed: ${failure instanceof Error ? failure.message : String(failure)}`, {
      caseId,
    });
  }
  if (failure instanceof PresidioApprovalRequired) throw failure;
  if (input.reaction && failure instanceof WatsonCostLimitReached) throw failure;
  // Auto mode acts only on a round that produced Watson's turn; a launch is not a model call.
  if (!ctx.auto || !outcome.reply) return saved;
  const reaction = input.reaction === true;
  const pasteId = mayWrite && input.pasteId && input.pasteProposalIds?.length ? input.pasteId : undefined;
  const round = {
    turnId,
    reaction,
    ...(input.source ? { source: input.source } : {}),
    heldIds: mayWrite ? carriedHeldIds(reaction, input.heldProposalIds, outcome.shownEvents) : [],
    ...(pasteId ? { paste: { pasteId, proposalIds: input.pasteProposalIds ?? [] } } : {}),
  };
  return autoAfterRound(ctx.auto, caseId, round, saved, (line) => ctx.log?.warn(line, { caseId }));
}

async function converse(
  ctx: WatsonRoundContext,
  caseId: string,
  chat: WatsonChat,
  analystTurn: Pick<WatsonTurn, "id" | "text">,
  attach: { paste: WatsonPaste | undefined; auto: boolean; reaction: boolean },
  counter: { calls: number },
  before: WatsonSpend,
): Promise<Outcome> {
  const newPaste = attach.paste;
  let headFailed = false;
  const shownEvents = chat.pendingCaseEvents.slice(0, WATSON_CASE_EVENTS_MAX);
  let questions: InvestigationState["keyQuestions"] = [];
  let cover: WatsonCoverage | undefined;
  let first: WatsonReply;
  let ask: HopInput["ask"];
  let base: WatsonPromptInput;
  let state: InvestigationState;
  let excerpt: WatsonPromptInput["pasteExcerpt"];
  let fallback: Outcome | ToolModeFallback | undefined;
  let ceiling: number | undefined;
  // F1: rows the tool loop showed before it fell back. The hop's reply may cite them, so they promote.
  let loopShown: ReadonlySet<string> = new Set();
  // The paste head's names: masked on every send of the round, and saved on every return.
  let headNames: WatsonMaskRoster | undefined;
  try {
    // The board and the Key Questions section show the seeded questions now, whatever the round does.
    if (await seedStandardQuestions(ctx, caseId)) ctx.onStateChanged?.(caseId);
    state = await ctx.stateStore.load(caseId);
    questions = state.keyQuestions;
    // The analyst's message is the ANALYST block; it is not repeated as recent chat.
    const others = { ...chat, turns: chat.turns.filter((t) => t.id !== analystTurn.id) };
    ({ base, cover } = await watsonBaseInput(ctx, caseId, state, others, analystTurn.text, true));
    // Option B: ids an EARLIER super-timeline search showed pass the sanitizer too, so the
    // promotion step (roundPromote.ts) sees them and drops whole any item resting on one.
    const known = {
      questions: new Set(state.keyQuestions.map((q) => q.id)),
      pastes: new Set(chat.pastes.map((p) => p.id)),
      events: new Set([...state.forensicTimeline.map((e) => e.id), ...earlierShownIds(chat)]),
      citations: citationSets(chat.pastes, state.findings),
    };
    const veloOn = base.velo !== undefined;
    // Only a super-timeline hop's call passes `extra`: the raw rows it showed may be cited there alone.
    ask = async (input, extra) => {
      const raw = await guardedCall(
        ctx,
        caseId,
        counter,
        () => spentNow(ctx, caseId, chat, before),
        (one) => callWatson(one, caseId, state, ctx.provider, input),
        ceiling === undefined ? {} : { ceiling },
      );
      const more = [...loopShown, ...(extra ?? [])];
      const events = more.length ? new Set([...known.events, ...more]) : known.events;
      return sanitizeWatsonReply(raw, known.questions, known.pastes, events, known.citations, veloOn);
    };
    // A stored file that is gone or unreadable never fails the round: Watson answers without it.
    excerpt = newPaste
      ? await headExcerpt(ctx, caseId, newPaste).catch(() => {
          headFailed = true;
          return undefined;
        })
      : undefined;
    headNames = excerptRoster(excerpt?.text);
    if (headNames) base = { ...base, rawRoster: mergeMaskRoster(base.rawRoster, headNames) };
    const cap = watsonToolCap(ctx, attach.reaction);
    if (cap > 0) {
      // R1, controller ruling on review I1: cap + 1 provider calls per question, the hop's included.
      ceiling = counter.calls + cap + 1;
      const rest = { shownEvents, questions, ...readOf(newPaste, headFailed, cover) };
      const spent = () => spentNow(ctx, caseId, chat, before);
      const loop = {
        ctx,
        caseId,
        chat,
        state,
        base,
        head: excerpt,
        cap,
        ceiling,
        known,
        counter,
        spent,
        rest,
        ask,
      };
      fallback = await toolRound({ ...loop, reaction: attach.reaction });
      if (!(fallback instanceof ToolModeFallback)) return withNames(fallback, headNames);
      if (fallback.carried.superRoster) {
        base = { ...base, rawRoster: mergeMaskRoster(base.rawRoster, fallback.carried.superRoster) };
      }
      loopShown = new Set((fallback.carried.superShown ?? []).map((e) => e.id));
    }
    first = await ask(excerpt ? { ...base, pasteExcerpt: excerpt } : base);
  } catch (error) {
    // An auto-attached head is not tried again; the paste stays stored and searchable.
    // A Presidio hold is not a failure to read: the paste stays unread for the approved retry.
    const held = error instanceof PresidioApprovalRequired;
    const giveUp = newPaste && (headFailed || (attach.auto && !held)) ? newPaste : undefined;
    const failed: Outcome = {
      reply: null,
      error,
      shownEvents,
      questions,
      ...(giveUp ? { readPasteIds: [giveUp.id], unreadable: giveUp } : {}),
    };
    // A fallback hop that fails still keeps what the tool loop read: those rows were sent.
    const kept = fallback instanceof ToolModeFallback ? withCarried(failed, fallback.carried) : failed;
    return withNames(kept, headNames);
  }
  const read = readOf(newPaste, headFailed, cover);
  // At most one search or lookup hop per round (roundHop.ts); its failure never loses this reply.
  const hop = await secondHop({
    ctx,
    caseId,
    chat,
    state,
    first,
    base,
    head: excerpt,
    ask,
    spent: () => spentNow(ctx, caseId, chat, before),
    rest: { shownEvents, questions, ...read },
    reaction: attach.reaction,
    ...(fallback instanceof ToolModeFallback
      ? { superLeft: fallback.superLeft, lookupsLeft: fallback.lookupsLeft }
      : {}),
    ...(ceiling !== undefined ? { callsLeft: callsLeftOf(counter, ceiling) } : {}),
  });
  return withNames(
    fallback instanceof ToolModeFallback ? withCarried(hop, fallback.carried) : hop,
    headNames,
  );
}

/** The outcome with the paste head's names on its roster: the head was sent, so they are kept. */
const withNames = (o: Outcome, names: WatsonMaskRoster | undefined): Outcome =>
  names ? { ...o, superRoster: mergeMaskRoster(o.superRoster, names) } : o;

const callsLeftOf = (counter: { calls: number }, ceiling: number) => (): number => ceiling - counter.calls;

/** What a reply marks read: the attached paste, and the coverage note. */
const readOf = (paste: WatsonPaste | undefined, headFailed: boolean, cover: WatsonCoverage | undefined) => ({
  ...(paste ? { readPasteIds: [paste.id], ...(headFailed ? { unreadable: paste } : {}) } : {}),
  ...(cover ? { coverage: cover } : {}),
});

/** The tool loop, or the fallback that sends the round to the hop (D7b, D12). Other throws propagate. */
async function toolRound(i: ToolLoopInput): Promise<Outcome | ToolModeFallback> {
  try {
    return await runToolLoop(i);
  } catch (err) {
    if (!(err instanceof ToolModeFallback)) throw err;
    if (err.remember) markToolsRejected(i.ctx.provider);
    i.ctx.log?.warn(`Watson tool mode fell back to one lookup: ${err.message}`, { caseId: i.caseId });
    return err;
  }
}

/**
 * The hop's outcome with what the tool loop read before it fell back: the rows were sent. The loop's
 * shown rows join the hop's, so a cited one is promoted (F1). The hop's own lookup joins the list, so
 * the card shows it (F2).
 */
function withCarried(o: Outcome, c: ToolModeFallback["carried"]): Outcome {
  const read = [...(o.readPasteIds ?? []), ...(c.readPasteIds ?? [])];
  const lookups = [...(c.lookups ?? []), ...(o.lookedUp ? [o.lookedUp] : [])];
  const seen = new Set((o.superShown ?? []).map((e) => e.id));
  const shown = [...(o.superShown ?? []), ...(c.superShown ?? []).filter((e) => !seen.has(e.id))];
  return {
    ...o,
    ...(c.lookups && lookups.length ? { lookups } : {}),
    ...(shown.length ? { superShown: shown } : {}),
    ...(c.superRoster || o.superRoster ? { superRoster: mergeMaskRoster(c.superRoster, o.superRoster) } : {}),
    ...(read.length ? { readPasteIds: [...new Set(read)] } : {}),
  };
}
