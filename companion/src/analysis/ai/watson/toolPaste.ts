import { WATSON_HISTORY_ID } from "./historyStore.js";
import { WATSON_LOOKUP_LIMITS } from "./lookupSchema.js";
import { WATSON_PASTE_PROMPT_MAX } from "./promptBuilder.js";
import { MAX_SEARCH_TERMS, MAX_TERM_CHARS } from "./replySchema.js";
import { searchExcerpt, type SearchExcerpt } from "./requestBuild.js";
import type { WatsonRoundContext } from "./roundContext.js";
import type { WatsonChat, WatsonLookedUp } from "./types.js";

// The paste and history tools (phase 5). The hop's reply sanitizer quietly trims a bad 'search'; a
// tool call is checked here instead, and a bad one is refused with a reason the model reads. The
// server enforces every limit itself: the Gemini adapter strips the schema keywords that state them.
// The counts are honest (Codex P2-6): 'shown' counts only the matching rows that reach the model.

type PasteExcerpt = Omit<SearchExcerpt, "matchedLines" | "emittedMatchLines">;

/** A search that ran: the excerpt to render, the card's record and, for a paste, the paste read. */
export interface PasteToolRun {
  excerpt: PasteExcerpt;
  lookedUp: WatsonLookedUp;
  readPasteId?: string;
}

/** The checked terms, or why they cannot be used. */
export function checkTerms(raw: unknown): string[] | { why: string } {
  if (!Array.isArray(raw)) return { why: "'terms' must be a list of words" };
  if (raw.length < 1 || raw.length > MAX_SEARCH_TERMS) {
    return { why: `'terms' must have 1 to ${MAX_SEARCH_TERMS} words` };
  }
  if (raw.some((t) => typeof t !== "string" || t.trim() === "")) return { why: "each term must be text" };
  if (raw.some((t: string) => t.length > MAX_TERM_CHARS)) {
    return { why: `each term must have ${MAX_TERM_CHARS} characters or fewer` };
  }
  return raw as string[];
}

/** The stored paste the id names, or why the id cannot be used. */
function checkPasteId(chat: WatsonChat, raw: unknown): string | { why: string } {
  if (typeof raw !== "string" || raw.trim() === "" || raw.length > WATSON_LOOKUP_LIMITS.idChars) {
    return { why: "'pasteId' must be a paste id from STORED PASTES" };
  }
  if (raw === WATSON_HISTORY_ID) return { why: "use history_search for the chat history" };
  if (!chat.pastes.some((p) => p.id === raw)) return { why: "no stored paste has that id" };
  return raw;
}

/** Whole numbered rows only, at most `max` characters: a row is never cut in half. */
export function clipRows(text: string, max: number): string {
  if (text.length <= max) return text;
  const out: string[] = [];
  let used = 0;
  for (const row of text.split("\n")) {
    const cost = row.length + (out.length ? 1 : 0);
    if (used + cost > max) break;
    out.push(row);
    used += cost;
  }
  return out.join("\n");
}

const ROW_NO = /^(\d+): /;

/** Clip to the prompt limit first, then count the matching rows that survived the clip. */
function honest(found: SearchExcerpt): { excerpt: PasteExcerpt; shown: number; matched: number } {
  const { matchedLines, emittedMatchLines, ...rest } = found;
  const text = clipRows(rest.text, WATSON_PASTE_PROMPT_MAX);
  const rows = new Set(text.split("\n").flatMap((r) => ROW_NO.exec(r)?.[1] ?? []));
  const shown = emittedMatchLines.filter((n) => rows.has(String(n))).length;
  const truncated = rest.truncated || text.length < rest.text.length;
  return { excerpt: { ...rest, text, truncated }, shown, matched: matchedLines };
}

const quoted = (terms: readonly string[]): string => terms.map((t) => `"${t}"`).join(", ");
/** The stored description is bounded like the forensic one: it is persisted on the chat turn (M5). */
export const WATSON_SEARCH_WHAT_MAX = 200;
const capped = (s: string): string =>
  s.length > WATSON_SEARCH_WHAT_MAX ? `${s.slice(0, WATSON_SEARCH_WHAT_MAX)}…` : s;

async function runSearch(
  ctx: WatsonRoundContext,
  caseId: string,
  chat: WatsonChat,
  pasteId: string,
  terms: string[],
): Promise<PasteToolRun | { why: string }> {
  const found = await searchExcerpt(ctx, caseId, chat, { pasteId, terms });
  if (!found) return { why: "no stored paste has that id" };
  const { excerpt, shown, matched } = honest(found);
  const history = pasteId === WATSON_HISTORY_ID;
  const what = capped(
    `${history ? "the chat history" : `the paste ${excerpt.filename}`} for ${quoted(terms)}`,
  );
  const lookedUp: WatsonLookedUp = { source: history ? "history" : "paste", shown, matched, what };
  return history ? { excerpt, lookedUp } : { excerpt, lookedUp, readPasteId: excerpt.pasteId };
}

/** paste_search: a checked paste id and terms, then the search. */
export async function runPasteTool(
  ctx: WatsonRoundContext,
  caseId: string,
  chat: WatsonChat,
  input: Record<string, unknown>,
): Promise<PasteToolRun | { why: string }> {
  const id = checkPasteId(chat, input.pasteId);
  if (typeof id !== "string") return id;
  const terms = checkTerms(input.terms);
  if (!Array.isArray(terms)) return terms;
  return runSearch(ctx, caseId, chat, id, terms);
}

/** history_search: checked terms, then a search of the full chat history. Never a paste read. */
export async function runHistoryTool(
  ctx: WatsonRoundContext,
  caseId: string,
  chat: WatsonChat,
  input: Record<string, unknown>,
): Promise<PasteToolRun | { why: string }> {
  const terms = checkTerms(input.terms);
  if (!Array.isArray(terms)) return terms;
  return runSearch(ctx, caseId, chat, WATSON_HISTORY_ID, terms);
}
