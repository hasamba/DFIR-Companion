import { toAnonPolicy } from "../../anonControl.js";
import type { InvestigationState } from "../../stateTypes.js";
import { WATSON_HISTORY_ID } from "./historyStore.js";
import type { WatsonPromptInput } from "./promptBuilder.js";
import type { WatsonReply } from "./replySchema.js";
import { assertCanContinue } from "./guardedCall.js";
import { searchExcerpt } from "./requestBuild.js";
import { limitReached, type WatsonRoundContext, type WatsonSpend } from "./roundContext.js";
import type { Outcome } from "./roundOutcome.js";
import { isSuperLookup } from "./lookupSchema.js";
import { excerptRoster } from "./rowTextHosts.js";
import { maskRosterFull, mergeMaskRoster } from "./superRoster.js";
import { searchSuperTimeline, type WatsonRawSearchDeps } from "./superTimelineSearch.js";
import { lookupTimeline } from "./timelineLookup.js";
import type { WatsonChat, WatsonLookup } from "./types.js";

// A round's one extra hop (round.ts): a search of a stored paste or the chat history, OR a lookup of
// forensic-timeline events (Task 11), OR one targeted search of the super-timeline (phase 4) — never
// two, never more than one. The lookup dispatches on its source: a super-timeline lookup never reaches
// the forensic lookup, and a forensic one never reaches the raw record. The same cost and token checks
// run before the second call, and from here on a failure never loses the first reply: it adds a note
// to it instead.

type PasteExcerpt = NonNullable<WatsonPromptInput["pasteExcerpt"]>;

export interface HopInput {
  ctx: WatsonRoundContext;
  caseId: string;
  chat: WatsonChat;
  state: InvestigationState;
  first: WatsonReply;
  base: WatsonPromptInput;
  /** The paste head the first call carried: a lookup's second call keeps it. */
  head: PasteExcerpt | undefined;
  /** `extraIds`: event ids the reply may cite besides the forensic timeline's (the raw rows shown). */
  ask(input: WatsonPromptInput, extraIds?: ReadonlySet<string>): Promise<WatsonReply>;
  /** Watson's spend on the case now (the round's own calls included). */
  spent(): Promise<WatsonSpend>;
  /** The first call's outcome without its reply. */
  rest: Omit<Outcome, "reply">;
  /** An automatic reaction round: it never searches the super-timeline (D6). */
  reaction?: boolean;
  /** After a tool-mode fallback: super-timeline searches the question may still run (R2). */
  superLeft?: number;
  /** Tool mode: provider calls the question may still make (R1, cap + 1 in all). 0 or less: no hop. */
  callsLeft?: () => number;
  /** After a tool-mode fallback: lookups the question may still run (F2). 0 or less: no hop. */
  lookupsLeft?: number;
}

type HopKind = "paste" | "lookup" | "super";

const oneLine = (s: string, max = 600): string => s.slice(0, max);
const errText = (err: unknown): string => (err instanceof Error ? err.message : String(err));

const WANTED: Record<HopKind, string> = {
  paste: "search the pasted text",
  lookup: "look up forensic-timeline events",
  super: "search the super-timeline",
};
const FAILED: Record<HopKind, string> = {
  paste: "Watson could not search the pasted text",
  lookup: "Watson could not look up forensic-timeline events",
  super: "Watson could not search the super-timeline",
};
const skipped = (kind: HopKind, why: string): string => `(Watson did not ${WANTED[kind]}, because ${why}.)`;
const failed = (kind: HopKind, err: unknown): string => oneLine(`(${FAILED[kind]}: ${errText(err)})`);
const dropped = (why: string): string =>
  oneLine(`(Watson did not do its timeline lookup, because the lookup is not valid: ${why}.)`);
/** D6, the analyst's decision: the raw record is searched only when the analyst asks something. */
export const REACTION_WHY = "Watson searches the raw record only when you ask it a question";
export const UNWIRED_WHY = "the super-timeline is not available on this server";
/** R1: tool mode makes at most cap + 1 provider calls per question, the hop included (STE). */
export const LIMIT_NOTE = "(Watson reached its lookup limit for this question.)";
/** R2: a question makes at most two super-timeline searches, a fallback hop included. */
export const SUPER_CAP_WHY = "it used both super-timeline searches for this question";
/** H5: no name is ever sent unmasked, so a full roster refuses the search (STE). */
export const ROSTER_FULL_NOTE =
  "(Watson cannot search the super-timeline now. The list of masked names is full.)";

const joinNotes = (...notes: (string | undefined)[]): string | undefined =>
  notes.filter((n): n is string => !!n).join("\n\n") || undefined;

const withNote = (o: Outcome, note: string | undefined): Outcome => {
  const all = joinNotes(o.note, note);
  return all ? { ...o, note: all } : o;
};

/** Shown on the turn when the hop's answer asked for another search or lookup (user report 2026-11-16). */
export const WANTS_MORE_NOTE =
  'Watson asked for another search or lookup, but one round runs only one. In Auto mode Watson runs it in its next round. In Approve mode, send "continue".';

/** The hop's answer as the round's reply: its own search or lookup ask cannot run in this round. */
function settleSecond(o: Outcome, second: WatsonReply): Outcome {
  const wants = !!second.search || second.lookup?.ok === true;
  const reply = { ...second, search: null, lookup: null };
  return wants ? { ...withNote(o, WANTS_MORE_NOTE), reply, wantsMore: true } : { ...o, reply };
}

const failedOutcome = (kept: Outcome, kind: HopKind, error: unknown): Outcome => ({
  ...withNote(kept, failed(kind, error)),
  rethrow: error,
});

const hopKind = (first: WatsonReply, lookup: WatsonLookup | undefined): HopKind =>
  first.search ? "paste" : lookup && isSuperLookup(lookup) ? "super" : "lookup";

/** Run the hop the first reply asked for, if any, and return the round's outcome. */
export async function secondHop(h: HopInput): Promise<Outcome> {
  const { first } = h;
  const lookup: WatsonLookup | undefined = first.lookup?.ok ? first.lookup.query : undefined;
  const drop = first.lookup && !first.lookup.ok ? dropped(first.lookup.why) : undefined;
  const kept = withNote({ ...h.rest, reply: { ...first, search: null, lookup: null } }, drop);
  if (!first.search && !lookup) return kept;
  const kind = hopKind(first, lookup);
  // No I/O before these two: neither a reaction nor a server without the seam ever searches raw rows.
  if (kind === "super" && h.reaction) return withNote(kept, skipped(kind, REACTION_WHY));
  if (kind === "super" && !h.ctx.rawSearch) return withNote(kept, skipped(kind, UNWIRED_WHY));
  if (h.callsLeft && h.callsLeft() <= 0) return withNote(kept, LIMIT_NOTE);
  if (h.lookupsLeft !== undefined && h.lookupsLeft <= 0) return withNote(kept, LIMIT_NOTE);
  if (kind === "super" && h.superLeft !== undefined && h.superLeft <= 0) {
    return { ...withNote(kept, skipped(kind, SUPER_CAP_WHY)), superCapHit: true };
  }
  try {
    const now = await h.spent().catch(() => null);
    if (!now) return withNote(kept, skipped(kind, "it could not check its cost"));
    const reached = limitReached(h.ctx, now);
    if (reached) return withNote(kept, skipped(kind, `this case reached its Watson ${reached}`));
    // A stop, AI off or a closed case before the hop's lookup starts: no lookup and no second send.
    await assertCanContinue(h.ctx, h.caseId);
    if (first.search) return await searchHop(h, kept, first.search);
    if (kind === "super") return await superHop(h, kept, lookup as WatsonLookup);
    return await lookupHop(h, kept, lookup as WatsonLookup);
  } catch (error) {
    return failedOutcome(kept, kind, error);
  }
}

async function searchHop(
  h: HopInput,
  kept: Outcome,
  search: NonNullable<WatsonReply["search"]>,
): Promise<Outcome> {
  const excerpt = await searchExcerpt(h.ctx, h.caseId, h.chat, search);
  if (!excerpt) return kept;
  // Codex #6: the excerpt's names ride on the outcome BEFORE the call, so a failed call keeps them.
  const names = excerptRoster(excerpt.text);
  const rostered: Outcome = names ? { ...kept, superRoster: mergeMaskRoster(kept.superRoster, names) } : kept;
  let second: WatsonReply;
  try {
    second = await h.ask({ ...h.base, pasteExcerpt: excerpt });
  } catch (error) {
    return failedOutcome(rostered, "paste", error);
  }
  // A paste read through a search counts as read; the history is not a paste.
  const readId = excerpt.pasteId === WATSON_HISTORY_ID ? [] : [excerpt.pasteId];
  return { ...settleSecond(rostered, second), readPasteIds: [...(kept.readPasteIds ?? []), ...readId] };
}

async function lookupHop(h: HopInput, kept: Outcome, query: WatsonLookup): Promise<Outcome> {
  const { excerpt, lookedUp } = await lookupTimeline(h.ctx, h.caseId, h.state, query);
  const input = { ...h.base, ...(h.head ? { pasteExcerpt: h.head } : {}), lookupExcerpt: excerpt };
  const second = await h.ask(input);
  return { ...settleSecond(kept, second), lookedUp };
}

/** Whether the AI-call gate masks for this case. Fails closed: a store that cannot be read counts as on. */
export async function maskingOn(ctx: WatsonRoundContext, caseId: string): Promise<boolean> {
  const store = ctx.opts.anonStore;
  if (!store) return false; // no store: the gate does not anonymize either
  return store.load(caseId).then(
    (control) => toAnonPolicy(control).enabled,
    () => true,
  );
}

/**
 * One bounded super-timeline search, then the second call with its rows. Only that call may cite the
 * rows shown. The roster and the search record ride on the outcome even when the call fails.
 */
async function superHop(h: HopInput, kept: Outcome, query: WatsonLookup): Promise<Outcome> {
  const raw = h.ctx.rawSearch as WatsonRawSearchDeps;
  const found = await searchSuperTimeline(h.ctx, raw.reader, h.caseId, h.state, query);
  // Before anything is sent: rows whose names do not fit the roster are never shown (H5).
  // Only when the provider call would mask: with anonymization off the search runs, and the roster
  // still records the names so masking turned on later knows them.
  if (maskRosterFull(h.chat.maskRoster, found.roster) && (await maskingOn(h.ctx, h.caseId)))
    return withNote(kept, ROSTER_FULL_NOTE);
  const shownIds = found.shown.map((e) => e.id);
  // M2: the roster AND the search record ride on the outcome even when the call fails, so the card
  // still says the search ran: the rows were already sent.
  const rostered: Outcome = {
    ...kept,
    superRoster: found.roster,
    lookedUp: { ...found.lookedUp, shownIds },
  };
  const input: WatsonPromptInput = {
    ...h.base,
    ...(h.head ? { pasteExcerpt: h.head } : {}),
    superExcerpt: found.excerpt,
    // The base roster (paste head, tool-loop names) stays: a future base field may print them.
    rawRoster: mergeMaskRoster(h.base.rawRoster, found.roster),
  };
  let second: WatsonReply;
  try {
    second = await h.ask(input, new Set(shownIds));
  } catch (error) {
    return failedOutcome(rostered, "super", error);
  }
  return { ...settleSecond(rostered, second), superShown: found.shown };
}
