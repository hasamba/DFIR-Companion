import { PresidioApprovalRequired } from "../../presidio.js";
import type { ForensicEvent, InvestigationState } from "../../stateTypes.js";
import { AiReplyUnreadableError } from "../aiReplyUnreadable.js";
import { AiAnswerParseError } from "../providerCall.js";
import type { RawRefs } from "./rawReferences.js";
import type { WatsonReply } from "./replySchema.js";
import { WatsonCancelled, type WatsonSpend } from "./roundContext.js";
import type { WatsonWriteInputs } from "./roundWrites.js";
import { buildProposals, newWatsonId } from "./roundProposals.js";
import { WATSON_MAX_SUPER_SEARCHES } from "./toolMode.js";
import { mergeMaskRoster, type WatsonMaskRoster } from "./superRoster.js";
import type {
  WatsonCaseEvent,
  WatsonChat,
  WatsonCoverage,
  WatsonLookedUp,
  WatsonPaste,
  WatsonProposalStatus,
  WatsonRequest,
  WatsonTurn,
  WatsonVeloLaunchProposal,
} from "./types.js";
import { vqlSizeProblem } from "../../vqlInput.js";

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
  shownEvents: WatsonCaseEvent[];
  questions: InvestigationState["keyQuestions"];
  /** Set only when the forensic timeline was trimmed to fit the prompt (#452). */
  coverage?: WatsonCoverage;
  /** The launch Watson's Velociraptor request became (velo/veloLaunchProposals.ts), before its turn id. */
  veloProposal?: Omit<WatsonVeloLaunchProposal, "turnId">;
  /** Why a Velociraptor request became no proposal (blocked VQL, a re-run, an unknown host). */
  veloNote?: string;
  /** What the reply's writes need from disk (roundWrites.ts); without it no write is proposed. */
  writeInputs?: WatsonWriteInputs;
  /** The forensic-timeline events the round's lookup showed Watson (Task 11), for the card. */
  lookedUp?: WatsonLookedUp;
  /** Tool mode (phase 5): one entry per tool call that ran, in order (D9). */
  lookups?: WatsonLookedUp[];
  /** Tool mode: the question asked for a super-timeline search past its limit (R2). */
  superCapHit?: boolean;
  /** The id Watson's turn gets (round.ts sets it, so Auto knows which proposals are this round's). */
  turnId?: string;
  /** The raw rows the round's super-timeline search showed Watson (for promotion of what it cites). */
  superShown?: ForensicEvent[];
  /** The names those rows printed: persisted on the chat even when the reply failed (the model saw them). */
  superRoster?: WatsonMaskRoster;
  /** Proposals already in the chat that the turn lists (the round's own promotion record, roundPromote.ts). */
  extraProposalIds?: string[];
  /** D9b: each reply item's rawEvidenceIds, keyed by its position in the reply (rawReferences.ts refKey). */
  rawEvidence?: Map<string, string[]>;
  /** The round's super-timeline promotion, for the final save's revalidation (roundPromote.ts). */
  promotion?: WatsonRoundPromotion;
}

/** The round's promotion as revalidatePromotion needs it: the reply before settling, and what kept it. */
export interface WatsonRoundPromotion {
  proposalId: string;
  /** The record's statuses under which the items resting on it stay. */
  keep: WatsonProposalStatus[];
  unsettled: WatsonReply;
  refs: RawRefs[];
  /** Cited ids correlation had already folded into a live event: landed whatever the record does. */
  folded: Map<string, string>;
}

/** The chat with the round's super-timeline roster folded into its persisted one (D2d). */
const withRoster = (chat: WatsonChat, roster: WatsonMaskRoster | undefined): WatsonChat =>
  roster ? { ...chat, maskRoster: mergeMaskRoster(chat.maskRoster, roster) } : chat;

const sameEvent = (a: WatsonCaseEvent, b: WatsonCaseEvent): boolean =>
  a.kind === b.kind && a.text === b.text && a.at === b.at;

/**
 * Remove each shown event once, so an event added during the round stays for the next one. Compared
 * by value: the fresh chat is read back from disk, so no object is the one the round showed.
 */
function withoutShown(
  pending: readonly WatsonCaseEvent[],
  shown: readonly WatsonCaseEvent[],
): WatsonCaseEvent[] {
  const left = [...shown];
  return pending.filter((e) => {
    const i = left.findIndex((s) => sameEvent(s, e));
    if (i === -1) return true;
    left.splice(i, 1);
    return false;
  });
}

function errorText(err: unknown): string {
  if (err instanceof WatsonCancelled) return err.message;
  if (err instanceof PresidioApprovalRequired) {
    return "This message waits for your approval. Presidio found values that you must approve before they go to the AI.";
  }
  if (err instanceof AiAnswerParseError || err instanceof AiReplyUnreadableError) {
    return "The companion cannot read Watson's reply. Send your message again.";
  }
  const msg = err instanceof Error ? err.message : String(err);
  return `Watson could not answer: ${msg}`.slice(0, 600);
}

/** H1: the answer's canonical raw evidence, stamped on the question "Add to open questions" makes. */
function answerEvidence(reply: WatsonReply, outcome: Outcome): Pick<WatsonTurn, "answerRawEvidenceIds"> {
  const ids = reply.answer ? outcome.rawEvidence?.get("answer") : undefined;
  return ids?.length ? { answerRawEvidenceIds: [...ids] } : {};
}

/** Tool mode: the round's lookups and its super-search limit flag, for the turn and the error turn (D5). */
const savedLookups = (o: Outcome): Pick<WatsonTurn, "lookups" | "superCapHit" | "superCapLimit"> => ({
  ...(o.lookups?.length ? { lookups: o.lookups } : {}),
  ...(o.superCapHit ? { superCapHit: true, superCapLimit: WATSON_MAX_SUPER_SEARCHES } : {}),
});

export function mergeOutcome(
  fresh: WatsonChat,
  outcome: Outcome,
  spent: WatsonSpend,
  calls: number,
): WatsonChat {
  const at = new Date().toISOString();
  const charged = {
    ...withRoster(fresh, outcome.superRoster),
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
      ...savedLookups(outcome),
    };
    return withUnreadable({ ...charged, turns: [...charged.turns, turn] }, outcome, at);
  }
  const turnId = outcome.turnId ?? newWatsonId("wt");
  const proposals = [
    ...buildProposals(reply, outcome.questions, turnId, outcome.writeInputs, outcome.rawEvidence),
    ...(outcome.veloProposal ? [{ ...outcome.veloProposal, turnId }] : []),
  ];
  // The round's promotion record is already in the chat: the turn lists it, it is not added again.
  const proposalIds = [...proposals.map((p) => p.id), ...(outcome.extraProposalIds ?? [])];
  const notes = [outcome.note, outcome.veloNote].filter((n): n is string => !!n);
  const text = notes.length ? [reply.message, ...notes].join("\n\n").trim() : reply.message;
  const turn: WatsonTurn = {
    id: turnId,
    at,
    role: "watson",
    text,
    ...(reply.workingOn ? { workingOn: reply.workingOn } : {}),
    ...(reply.learned ? { learned: reply.learned } : {}),
    ...(reply.request ? { request: storedRequest(reply.request) } : {}),
    ...(reply.answer ? { answer: reply.answer } : {}),
    ...answerEvidence(reply, outcome),
    ...(outcome.coverage ? { coverage: outcome.coverage } : {}),
    ...(outcome.veloNote ? { veloNote: outcome.veloNote } : {}),
    ...(outcome.lookedUp ? { lookedUp: outcome.lookedUp } : {}),
    ...savedLookups(outcome),
    ...(proposalIds.length ? { proposalIds } : {}),
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
    text: `Watson could not read ${p.filename}. The file stays in the case as evidence. Ask Watson to search it.`,
  };
  return { ...chat, unreadPasteIds, turns: [...chat.turns, note] };
}

/** The stored copy of a refused oversize VQL is clipped: it never ran, and the chat file stays small (G16). */
export const REFUSED_VQL_KEEP = 2000;

export function storedRequest(request: WatsonRequest): WatsonRequest {
  if (request.kind !== "velociraptor" || !vqlSizeProblem(request.vql)) return request;
  const more = request.vql.length - REFUSED_VQL_KEEP;
  const vql = `${request.vql.slice(0, REFUSED_VQL_KEEP)}…(${more} more characters. This VQL is too long, so it did not run.)`;
  return { ...request, vql };
}
