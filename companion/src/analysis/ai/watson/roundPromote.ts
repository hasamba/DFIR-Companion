import { stateEventResolver } from "../../eventAliasLookup.js";
import type { ForensicEvent, InvestigationState } from "../../stateTypes.js";
import { recordWatsonActivity } from "./proposals.js";
import { collectRawRefs, earlierShownIds, settleRawRefs, type RawRefs } from "./rawReferences.js";
import { evidenceStanding, watsonLandedRows } from "./rawEvidence.js";
import type { WatsonReply } from "./replySchema.js";
import { cancelReason } from "./roundCancel.js";
import type { WatsonRoundContext } from "./roundContext.js";
import type { Outcome, WatsonRoundPromotion } from "./roundOutcome.js";
import { newWatsonId } from "./roundProposals.js";
import type { WatsonChat, WatsonEventPromoteProposal, WatsonProposalStatus } from "./types.js";

export type { WatsonRoundPromotion } from "./roundOutcome.js";
import { promoteRows } from "./writers/eventPromoteWriter.js";

// Evidence first (phase 4, D4/D6/D9): every super-timeline row Watson's reply cites is promoted into
// the forensic timeline BEFORE the turn is saved, the way explainEvent promotes what it explains.
// Rows it saw but did not cite stay raw. An item that rests on a raw row that did not land — the
// round may not write, the case froze, the promotion failed, or the row came from an earlier search —
// is dropped whole. The promotion is one durable, undoable record: the intent is saved first, then
// the rows are promoted, then the record is marked applied (D9). Fails closed: anything unexpected
// settles the reply with nothing landed.

export const WATSON_PROMOTION_ACTOR = "Watson";

const OUT_OF_DATE = "Watson promoted super-timeline rows it cited";
const plural = (n: number, one: string, many = `${one}s`): string => `${n} ${n === 1 ? one : many}`;
const rows = (n: number): string => plural(n, "super-timeline row");

const WITHHELD = {
  writes: "this round cannot write to the case",
  unwired: "the super-timeline is not available on this server",
  frozen: "someone closed or archived the case, or turned off AI, during the round",
};
const withheldNote = (n: number, why: string): string =>
  `(Watson cited ${rows(n)}, but it promoted nothing, because ${why}.)`;
const failedNote = (n: number, err: unknown): string =>
  `(Watson cited ${rows(n)}, but it could not promote ${n === 1 ? "it" : "them"} (${errText(err)}). Watson promoted nothing.)`.slice(
    0,
    600,
  );
const recordNote = (n: number): string =>
  `(Watson promoted ${rows(n)}, but it could not save the record. Press Apply on the card to finish it.)`;
const stuckNote = (n: number): string =>
  `(Watson promoted ${rows(n)}, but it could not finish the record. Press Apply to finish it.)`;
const earlierNote = (n: number): string =>
  `(Watson cited ${rows(n)} from an earlier search that ${n === 1 ? "is" : "are"} not in the forensic timeline. Watson promotes only rows from the search in this round.)`;
const droppedNote = (n: number): string =>
  `(Watson removed ${plural(n, "item")} that used ${n === 1 ? "it" : "them"}.)`;
export const UNDONE_NOTE =
  "(Someone undid the rows that Watson promoted before Watson saved its answer. Watson removed the items that used these rows.)";

const errText = (err: unknown): string => (err instanceof Error ? err.message : String(err));
const joinNotes = (...notes: (string | undefined)[]): string | undefined =>
  notes.filter((n): n is string => !!n).join("\n\n") || undefined;

/** What the round's reply references among raw rows, and what it may promote. */
interface Plan {
  reply: WatsonReply;
  refs: RawRefs[];
  /** This round's shown rows the reply cites: the only rows it may promote. */
  cited: ForensicEvent[];
  /** Cited ids correlation already folded into a live event: they count as landed, at that event. */
  folded: Map<string, string>;
  /** Cited earlier-search ids that are not in the forensic timeline: they never land. */
  earlier: number;
}

async function planRefs(
  ctx: WatsonRoundContext,
  caseId: string,
  outcome: Outcome,
  reply: WatsonReply,
  chat: WatsonChat,
): Promise<Plan> {
  const shown = outcome.superShown ?? [];
  // Applied records' rows, and a stuck (pending) record's rows that carry its stamp (H4).
  const promoted = await watsonLandedRows(ctx.stateStore, caseId, chat);
  const candidates = [...new Set([...shown.map((e) => e.id), ...earlierShownIds(chat), ...promoted])];
  const standing = await evidenceStanding(ctx.stateStore, caseId, candidates);
  // Controller ruling (refines D4): a row live only because Watson's promotion landed it is raw
  // evidence for a later item too, already landed at itself, so the item records it.
  const kept = candidates.filter((id) => standing.live.has(id) && promoted.has(id));
  const folded = new Map([...standing.folded, ...kept.map((id) => [id, id] as const)]);
  const raw = new Set([...candidates.filter((id) => !standing.live.has(id)), ...kept]);
  const refs = collectRawRefs(reply, raw);
  const citedIds = new Set(refs.flatMap((r) => r.ids).filter((id) => !folded.has(id)));
  const cited = shown.filter((e) => citedIds.has(e.id));
  const earlier = citedIds.size - cited.length;
  return { reply, refs, cited, folded, earlier };
}

/** The outcome with its reply settled against `landed`, and the round's notes. */
function settled(
  outcome: Outcome,
  plan: Plan,
  landed: ReadonlyMap<string, string>,
  note?: string,
  promotion?: WatsonRoundPromotion,
): Outcome {
  const s = settleRawRefs(plan.reply, plan.refs, landed);
  const all = joinNotes(
    outcome.note,
    note,
    plan.earlier ? earlierNote(plan.earlier) : undefined,
    s.dropped ? droppedNote(s.dropped) : undefined,
  );
  return {
    ...outcome,
    reply: s.reply,
    rawEvidence: s.evidence,
    ...(all ? { note: all } : {}),
    ...(promotion ? { extraProposalIds: [promotion.proposalId], promotion } : {}),
  };
}

/** Why the round may not promote, or null when it may (D6, D6c: checked before anything is saved). */
async function whyWithheld(
  ctx: WatsonRoundContext,
  caseId: string,
  mayWrite: boolean,
): Promise<string | null> {
  if (!mayWrite) return WITHHELD.writes;
  if (!ctx.rawSearch) return WITHHELD.unwired;
  return (await ctx.rawSearch.writable(caseId)) ? null : WITHHELD.frozen;
}

/**
 * Promote the super-timeline rows the reply cites (this round's search only), then settle the reply:
 * citations rewritten to the canonical ids, items resting on rows that did not land dropped whole.
 */
export async function withCitedPromotion(
  ctx: WatsonRoundContext,
  caseId: string,
  outcome: Outcome,
  mayWrite: boolean,
  turnId: string,
  chat: WatsonChat,
): Promise<Outcome> {
  const reply = outcome.reply;
  if (!reply) return outcome;
  let plan: Plan | undefined;
  try {
    plan = await planRefs(ctx, caseId, outcome, reply, chat);
    if (!plan.refs.length) return outcome;
    if (!plan.cited.length) return settled(outcome, plan, plan.folded);
    const why = await whyWithheld(ctx, caseId, mayWrite);
    if (why) return settled(outcome, plan, plan.folded, withheldNote(plan.cited.length, why));
    // The first promotion write is the round's irreversible point: a stop before it promotes nothing.
    if (cancelReason(ctx.signal)) return outcome;
    return await promote(ctx, caseId, outcome, plan, turnId);
  } catch (err) {
    ctx.log?.warn(`Watson could not settle its super-timeline citations: ${errText(err)}`, { caseId });
    return failClosed(outcome, reply, chat, plan, err);
  }
}

/** Nothing landed: every item resting on any id a super-timeline search showed is dropped. */
function failClosed(
  outcome: Outcome,
  reply: WatsonReply,
  chat: WatsonChat,
  plan: Plan | undefined,
  err: unknown,
): Outcome {
  const shown = [...(outcome.superShown ?? []).map((e) => e.id), ...earlierShownIds(chat)];
  const refs = plan?.refs ?? collectRawRefs(reply, new Set(shown));
  const all: Plan = plan ?? { reply, refs, cited: [], folded: new Map(), earlier: 0 };
  return settled(outcome, all, new Map(), failedNote(Math.max(1, all.cited.length), err));
}

/** The cited ids that are live after the promotion, each mapped to the event that holds it now. */
function landedIn(state: InvestigationState, plan: Plan): Map<string, string> {
  const resolve = stateEventResolver(state);
  const live = new Set(state.forensicTimeline.map((e) => e.id));
  const landed = new Map(plan.folded);
  for (const e of plan.cited) {
    const at = resolve(e.id);
    if (live.has(at)) landed.set(e.id, at);
  }
  return landed;
}

/** D9 steps 1-4: intent, guard, rows, record, then the best-effort side effects. */
async function promote(
  ctx: WatsonRoundContext,
  caseId: string,
  outcome: Outcome,
  plan: Plan,
  turnId: string,
): Promise<Outcome> {
  const raw = ctx.rawSearch as NonNullable<WatsonRoundContext["rawSearch"]>;
  const intent: WatsonEventPromoteProposal = {
    id: newWatsonId("wp"),
    turnId,
    kind: "event_promote",
    targetId: plan.cited[0]?.id ?? "",
    events: plan.cited,
    source: "supertimeline",
    promotedAt: new Date().toISOString(),
    status: "pending",
  };
  await ctx.chatStore.update(caseId, (c) => ({ ...c, proposals: [...c.proposals, intent] }));
  if (!(await raw.writable(caseId).catch(() => false))) {
    await dropIntent(ctx, caseId, intent.id);
    return settled(outcome, plan, plan.folded, withheldNote(plan.cited.length, WITHHELD.frozen));
  }
  let result: Awaited<ReturnType<typeof promoteRows>>;
  try {
    result = await promoteRows(raw.writer, caseId, intent);
  } catch (err) {
    ctx.log?.warn(`Watson could not promote the super-timeline rows it cited: ${errText(err)}`, { caseId });
    return promotionFailed(ctx, caseId, outcome, plan, intent, err);
  }
  const landed = landedIn(result.state, plan);
  const saved = await recordApplied(ctx, caseId, result.proposal);
  const effectNote = await sideEffects(ctx, caseId, saved);
  const promotion: WatsonRoundPromotion = {
    proposalId: intent.id,
    keep: keepFor(saved),
    unsettled: plan.reply,
    refs: plan.refs,
    folded: plan.folded,
  };
  const note = saved ? undefined : recordNote(result.proposal.createdEventIds?.length ?? 0);
  return settled(outcome, plan, landed, joinNotes(note, effectNote), promotion);
}

const keepFor = (saved: WatsonEventPromoteProposal | null): WatsonProposalStatus[] =>
  saved ? ["applied"] : ["pending", "applied"];

/** D9 step 3: the record marked applied by Watson; null when that save failed (it stays pending). */
async function recordApplied(
  ctx: WatsonRoundContext,
  caseId: string,
  done: WatsonEventPromoteProposal,
): Promise<WatsonEventPromoteProposal | null> {
  const applied: WatsonEventPromoteProposal = {
    ...done,
    status: "applied",
    appliedAt: new Date().toISOString(),
    appliedBy: WATSON_PROMOTION_ACTOR,
  };
  try {
    await ctx.chatStore.update(caseId, (c) => ({
      ...c,
      proposals: c.proposals.map((p) => (p.id === applied.id ? applied : p)),
    }));
    return applied;
  } catch (err) {
    ctx.log?.warn(`Watson promoted rows but could not record it: ${errText(err)}`, { caseId });
    return null;
  }
}

/** R5: a side effect that failed twice is told on Watson's turn, never only logged. */
const SIDE_EFFECT_NOTE = {
  log: "(Watson promoted the rows. It could not write the activity log entry. The rows are in the forensic timeline.)",
  outOfDate:
    "(Watson promoted the rows. It could not mark the conclusions out of date. Run synthesis again to update them.)",
};

/** Run a step; on failure run it again up to `tries` times in all. Returns true when a try worked. */
async function twice(ctx: WatsonRoundContext, caseId: string, what: string, run: () => unknown, tries = 2) {
  for (let attempt = 1; attempt <= tries; attempt++) {
    try {
      await run();
      return true;
    } catch (err) {
      ctx.log?.warn(
        `Watson promoted rows but could not ${what} (try ${attempt} of ${tries}): ${errText(err)}`,
        {
          caseId,
        },
      );
    }
  }
  return false;
}

/**
 * D9 step 4: never a promotion failure. The activity entry is the one an analyst's apply writes. The
 * out-of-date mark is retried once (R5); the activity entry is not (a retry could duplicate it). The
 * notes name the steps that still failed.
 */
async function sideEffects(
  ctx: WatsonRoundContext,
  caseId: string,
  saved: WatsonEventPromoteProposal | null,
): Promise<string | undefined> {
  const writer = (ctx.rawSearch as NonNullable<WatsonRoundContext["rawSearch"]>).writer;
  const notes: string[] = [];
  const marked = await twice(ctx, caseId, "mark the conclusions out of date", () =>
    writer.markConclusionsOutOfDate(caseId, OUT_OF_DATE),
  );
  if (!marked) notes.push(SIDE_EFFECT_NOTE.outOfDate);
  if (saved) {
    // One try only: a write that threw after it landed would give a duplicate entry on a retry.
    const logged = await twice(
      ctx,
      caseId,
      "log the promotion",
      () => recordWatsonActivity(writer, caseId, "apply", saved, WATSON_PROMOTION_ACTOR),
      1,
    );
    if (!logged) notes.push(SIDE_EFFECT_NOTE.log);
  }
  try {
    ctx.onStateChanged?.(caseId);
  } catch (err) {
    ctx.log?.warn(`Watson promoted rows but could not tell the dashboard: ${errText(err)}`, { caseId });
  }
  return joinNotes(...notes);
}

/**
 * The promotion threw. Rows may still have landed (a failure after the save): then the pending
 * record stays and is linked, so the analyst's Apply adopts them as one undoable operation. Either
 * way nothing the reply rests on counts as landed.
 */
async function promotionFailed(
  ctx: WatsonRoundContext,
  caseId: string,
  outcome: Outcome,
  plan: Plan,
  intent: WatsonEventPromoteProposal,
  err: unknown,
): Promise<Outcome> {
  const found = await ctx.stateStore
    .forensicRowsById(
      caseId,
      intent.events.map((e) => e.id),
    )
    .catch(() => []);
  const landed = found.filter((r) => r.event.promotedAt === intent.promotedAt).length;
  if (!landed) {
    await dropIntent(ctx, caseId, intent.id);
    return settled(outcome, plan, plan.folded, failedNote(plan.cited.length, err));
  }
  // The case changed: say so, and still tell the conclusions and the dashboard (review I3).
  const effectNote = await sideEffects(ctx, caseId, null);
  const s = settled(outcome, plan, plan.folded, joinNotes(stuckNote(landed), effectNote));
  return { ...s, extraProposalIds: [intent.id] };
}

/** Remove an intent that never promoted anything, so no card offers to finish it. Best effort. */
async function dropIntent(ctx: WatsonRoundContext, caseId: string, id: string): Promise<void> {
  await ctx.chatStore
    .update(caseId, (c) => ({ ...c, proposals: c.proposals.filter((p) => p.id !== id) }))
    .catch((err: unknown) =>
      ctx.log?.warn(`Watson could not remove its unused promotion record: ${errText(err)}`, { caseId }),
    );
}

/**
 * Inside the final chat update (D9b): when the round's promotion record is no longer what the round
 * left it (an analyst undid it while the answer was being saved), every item resting on its rows is
 * dropped before it is added, and the turn no longer lists the record.
 */
export function revalidatePromotion(fresh: WatsonChat, outcome: Outcome): Outcome {
  const pr = outcome.promotion;
  if (!pr || !outcome.reply) return outcome;
  const record = fresh.proposals.find((p) => p.id === pr.proposalId);
  if (record && pr.keep.includes(record.status)) return outcome;
  const s = settleRawRefs(pr.unsettled, pr.refs, pr.folded);
  const { promotion: _gone, ...rest } = outcome;
  return {
    ...rest,
    reply: {
      ...outcome.reply,
      answer: s.reply.answer,
      questionUpdates: s.reply.questionUpdates,
      newQuestions: s.reply.newQuestions,
      writes: s.reply.writes,
    },
    rawEvidence: s.evidence,
    extraProposalIds: [],
    note: joinNotes(outcome.note, UNDONE_NOTE),
  };
}
