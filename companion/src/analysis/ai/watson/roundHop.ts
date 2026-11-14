import type { InvestigationState } from "../../stateTypes.js";
import { WATSON_HISTORY_ID } from "./historyStore.js";
import type { WatsonPromptInput } from "./promptBuilder.js";
import type { WatsonReply } from "./replySchema.js";
import { searchExcerpt } from "./requestBuild.js";
import { limitReached, type WatsonRoundContext, type WatsonSpend } from "./roundContext.js";
import type { Outcome } from "./roundOutcome.js";
import { lookupTimeline } from "./timelineLookup.js";
import type { WatsonChat, WatsonLookup } from "./types.js";

// A round's one extra hop (round.ts): a search of a stored paste or the chat history, OR a lookup of
// forensic-timeline events (Task 11) — never both, never more than one. The same cost and token
// checks run before the second call, and from here on a failure never loses the first reply: it adds
// a note to it instead.

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
  ask(input: WatsonPromptInput): Promise<WatsonReply>;
  /** Watson's spend on the case now (the round's own calls included). */
  spent(): Promise<WatsonSpend>;
  /** The first call's outcome without its reply. */
  rest: Omit<Outcome, "reply">;
}

const oneLine = (s: string, max = 600): string => s.slice(0, max);
const errText = (err: unknown): string => (err instanceof Error ? err.message : String(err));

const skipped = (lookup: boolean, why: string): string =>
  lookup
    ? `(Watson wanted to look up forensic-timeline events, but ${why}, so it did not.)`
    : `(Watson wanted to search the pasted text, but ${why}, so it did not.)`;
const failed = (lookup: boolean, err: unknown): string =>
  oneLine(
    lookup
      ? `(Watson's forensic-timeline lookup failed: ${errText(err)})`
      : `(Watson's search of the pasted text failed: ${errText(err)})`,
  );
const dropped = (why: string): string =>
  oneLine(`(Watson asked for a timeline lookup that was not valid (${why}), so it did not run.)`);

const joinNotes = (...notes: (string | undefined)[]): string | undefined =>
  notes.filter((n): n is string => !!n).join("\n\n") || undefined;

const withNote = (o: Outcome, note: string | undefined): Outcome => {
  const all = joinNotes(o.note, note);
  return all ? { ...o, note: all } : o;
};

/** Run the hop the first reply asked for, if any, and return the round's outcome. */
export async function secondHop(h: HopInput): Promise<Outcome> {
  const { first } = h;
  const lookup: WatsonLookup | undefined = first.lookup?.ok ? first.lookup.query : undefined;
  const drop = first.lookup && !first.lookup.ok ? dropped(first.lookup.why) : undefined;
  const kept = withNote({ ...h.rest, reply: { ...first, search: null, lookup: null } }, drop);
  if (!first.search && !lookup) return kept;
  const isLookup = !first.search;
  try {
    const now = await h.spent().catch(() => null);
    if (!now) return withNote(kept, skipped(isLookup, "its cost could not be checked"));
    const reached = limitReached(h.ctx, now);
    if (reached) return withNote(kept, skipped(isLookup, `this case reached its Watson ${reached}`));
    if (first.search) return await searchHop(h, kept, first.search);
    return await lookupHop(h, kept, lookup as WatsonLookup);
  } catch (error) {
    return { ...withNote(kept, failed(isLookup, error)), rethrow: error };
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
