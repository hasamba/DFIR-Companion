import { PresidioApprovalRequired } from "../../presidio.js";
import type { InvestigationState } from "../../stateTypes.js";
import { AiReplyUnreadableError } from "../aiReplyUnreadable.js";
import { AiAnswerParseError } from "../providerCall.js";
import type { WatsonReply } from "./replySchema.js";
import type { WatsonSpend } from "./roundContext.js";
import type { WatsonWriteInputs } from "./roundWrites.js";
import { buildProposals, newWatsonId } from "./roundProposals.js";
import type { WatsonChat, WatsonCoverage, WatsonPaste, WatsonTurn } from "./types.js";

// How a round's result is folded into the saved chat: the Outcome the model calls produced, the turn
// built from it, and the unread-paste bookkeeping. Pure functions over the FRESH chat, so a paste or
// a case event added while the model thought is never lost.

/** What the model calls produced, for the final merge. */
export interface Outcome {
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
  /** What the reply's writes need from disk (roundWrites.ts); without it no write is proposed. */
  writeInputs?: WatsonWriteInputs;
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

export function mergeOutcome(
  fresh: WatsonChat,
  outcome: Outcome,
  spent: WatsonSpend,
  calls: number,
): WatsonChat {
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
  const proposals = buildProposals(reply, outcome.questions, turnId, outcome.writeInputs);
  const text = outcome.note ? `${reply.message}\n\n${outcome.note}`.trim() : reply.message;
  const turn: WatsonTurn = {
    id: turnId,
    at,
    role: "watson",
    text,
    ...(reply.workingOn ? { workingOn: reply.workingOn } : {}),
    ...(reply.learned ? { learned: reply.learned } : {}),
    ...(reply.request ? { request: reply.request } : {}),
    ...(reply.answer ? { answer: reply.answer } : {}),
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
