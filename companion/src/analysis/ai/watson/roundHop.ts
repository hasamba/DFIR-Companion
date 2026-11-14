import type { InvestigationState } from "../../stateTypes.js";
import { WATSON_HISTORY_ID } from "./historyStore.js";
import type { WatsonPromptInput } from "./promptBuilder.js";
import type { WatsonReply } from "./replySchema.js";
import { searchExcerpt } from "./requestBuild.js";
import { limitReached, type WatsonRoundContext, type WatsonSpend } from "./roundContext.js";
import type { Outcome } from "./roundOutcome.js";
import { isSuperLookup } from "./lookupSchema.js";
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
  paste: "Watson's search of the pasted text failed",
  lookup: "Watson's forensic-timeline lookup failed",
  super: "Watson's super-timeline search failed",
};
const skipped = (kind: HopKind, why: string): string =>
  `(Watson wanted to ${WANTED[kind]}, but ${why}, so it did not.)`;
const failed = (kind: HopKind, err: unknown): string => oneLine(`(${FAILED[kind]}: ${errText(err)})`);
const dropped = (why: string): string =>
  oneLine(`(Watson asked for a timeline lookup that was not valid (${why}), so it did not run.)`);
/** D6, the analyst's decision: the raw record is searched only when the analyst asks something. */
const REACTION_WHY = "it searches the raw record only when you ask it something";
const UNWIRED_WHY = "the super-timeline is not available on this server";

const joinNotes = (...notes: (string | undefined)[]): string | undefined =>
  notes.filter((n): n is string => !!n).join("\n\n") || undefined;

const withNote = (o: Outcome, note: string | undefined): Outcome => {
  const all = joinNotes(o.note, note);
  return all ? { ...o, note: all } : o;
};

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
  try {
    const now = await h.spent().catch(() => null);
    if (!now) return withNote(kept, skipped(kind, "its cost could not be checked"));
    const reached = limitReached(h.ctx, now);
    if (reached) return withNote(kept, skipped(kind, `this case reached its Watson ${reached}`));
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
  const second = await h.ask({ ...h.base, pasteExcerpt: excerpt });
  // A paste read through a search counts as read; the history is not a paste.
  const readId = excerpt.pasteId === WATSON_HISTORY_ID ? [] : [excerpt.pasteId];
  return {
    ...kept,
    reply: { ...second, search: null, lookup: null },
    readPasteIds: [...(kept.readPasteIds ?? []), ...readId],
  };
}

async function lookupHop(h: HopInput, kept: Outcome, query: WatsonLookup): Promise<Outcome> {
  const { excerpt, lookedUp } = await lookupTimeline(h.ctx, h.caseId, h.state, query);
  const input = { ...h.base, ...(h.head ? { pasteExcerpt: h.head } : {}), lookupExcerpt: excerpt };
  const second = await h.ask(input);
  return { ...kept, reply: { ...second, search: null, lookup: null }, lookedUp };
}

/**
 * One bounded super-timeline search, then the second call with its rows. Only that call may cite the
 * rows shown. The roster rides on the outcome even when the call fails: the rows were already sent.
 */
async function superHop(h: HopInput, kept: Outcome, query: WatsonLookup): Promise<Outcome> {
  const raw = h.ctx.rawSearch as WatsonRawSearchDeps;
  const found = await searchSuperTimeline(h.ctx, raw.reader, h.caseId, h.state, query);
  const rostered: Outcome = { ...kept, superRoster: found.roster };
  const input: WatsonPromptInput = {
    ...h.base,
    ...(h.head ? { pasteExcerpt: h.head } : {}),
    superExcerpt: found.excerpt,
    rawRoster: found.roster,
  };
  const shownIds = found.shown.map((e) => e.id);
  let second: WatsonReply;
  try {
    second = await h.ask(input, new Set(shownIds));
  } catch (error) {
    return failedOutcome(rostered, "super", error);
  }
  return {
    ...rostered,
    reply: { ...second, search: null, lookup: null },
    lookedUp: { ...found.lookedUp, shownIds },
    superShown: found.shown,
  };
}
