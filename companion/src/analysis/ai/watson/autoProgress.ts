import type { InvestigationState } from "../../stateTypes.js";
import { shownSteps } from "./shownSteps.js";
import type { WatsonChat, WatsonLookup } from "./types.js";

// Auto keeps working (user decision of 2026-11-16, after #2645 stopped Auto after one step): Watson's
// own rounds stop only when the investigation is done or every open item needs a person. A round makes
// progress when it gives a card (a write, a launch) or runs a search or lookup that did not run yet in
// this chain. Two of Watson's own rounds in a row without progress set the item Watson worked on aside,
// and Watson moves to the next open Key Question or next step. When every open item is set aside, Auto
// stops and lists what is left. It always ends without trusting the model: each item is set aside once
// per chain, and searches count as progress only up to WATSON_AUTO_SEARCHES_KEPT per chain. An
// analyst's message clears all of it (reactionState.ts `engaged`).

/** Watson's own rounds in a row without progress after which the item it works on is set aside. */
export const WATSON_AUTO_IDLE_MAX = 2;
/** Distinct searches and lookups per chain that count as progress; past it, only a card does. */
export const WATSON_AUTO_SEARCHES_KEPT = 40;
/** Set-aside items kept per chain (far above the board's open items). */
export const WATSON_AUTO_SET_ASIDE_MAX = 100;
const KEY_CHARS = 400;

/** An open Key Question (unknown or partial) or a next step on the board. */
export interface WatsonOpenItem {
  id: string;
  kind: "question" | "step";
  text: string;
  /** Where to look, or what to collect: what the item needs. */
  needs: string;
}

/** What a finished round did, for the progress check. */
export interface WatsonRoundWork {
  /** A round Watson started itself: only these count toward the idle limit. */
  reaction: boolean;
  /** The round gave at least one card (a proposal: a write, a status change, a launch). */
  card: boolean;
  /** Keys of the searches and lookups the round ran (searchKey, lookupKey). */
  ranSearches: readonly string[];
  /** The item ids Watson named in 'focusIds'. */
  focusIds: readonly string[];
  /** Watson's 'workingOn' text: board ids named in it count as its focus too. */
  workingOn: string;
  /** The round showed new evidence (an import): the set-aside items may move again. */
  newEvidence?: boolean;
  /** What Watson asked a person for, when that answer will not wake Watson by itself. */
  asked?: string;
}

export type WatsonAutoVerdict =
  | { kind: "go" }
  /** The items just set aside; open items are still left. */
  | { kind: "moveOn"; setAside: WatsonOpenItem[]; asked?: boolean }
  /** Every open item is set aside: what is left needs a person. */
  | { kind: "done"; left: WatsonOpenItem[] }
  /** No progress, and the item Watson worked on is unknown or already set aside. */
  | { kind: "stuck"; left: WatsonOpenItem[] };

const norm = (s: string): string => s.trim().toLowerCase().slice(0, KEY_CHARS);

/** A paste search's key: the paste and its terms, without case, order or repeats. */
export function searchKey(pasteId: string, terms: readonly string[]): string {
  return `paste:${pasteId}:${[...new Set(terms.map(norm))].sort().join("\u0000")}`;
}

/** A lookup's key: its fields in a fixed order, lists sorted. */
export function lookupKey(q: WatsonLookup): string {
  const list = (a?: string[]) => (a ? [...new Set(a.map(norm))].sort() : undefined);
  const fixed = {
    s: q.source ?? "forensic",
    f: list(q.findingIds),
    e: list(q.eventIds),
    from: q.from,
    to: q.to,
    host: q.host ? norm(q.host) : undefined,
    text: q.text ? norm(q.text) : undefined,
    hash: q.hash ? norm(q.hash) : undefined,
  };
  return `lookup:${JSON.stringify(fixed)}`;
}

/** The board's open items: Key Questions not answered or not answerable, then the shown next steps. */
export function openItems(state: InvestigationState | null): WatsonOpenItem[] {
  if (!state) return [];
  const questions = (state.keyQuestions ?? [])
    .filter((q) => q.status !== "answered" && q.status !== "unanswerable")
    .map((q) => ({ id: q.id, kind: "question" as const, text: q.question, needs: q.pointer ?? "" }));
  // Only the steps the prompt shows: a step Watson cannot see can never be worked or set aside.
  const steps = shownSteps(state).map((s) => ({
    id: s.id,
    kind: "step" as const,
    text: s.action,
    needs: s.pointer ?? "",
  }));
  return [...questions, ...steps];
}

const escapeRe = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** The open items Watson worked on: its focusIds, and board ids named as whole words in workingOn. */
export function focusOf(work: WatsonRoundWork, open: readonly WatsonOpenItem[]): WatsonOpenItem[] {
  const named = new Set(work.focusIds.map((id) => id.trim()));
  return open.filter(
    (item) =>
      named.has(item.id) ||
      new RegExp(`(^|[^A-Za-z0-9_-])${escapeRe(item.id)}($|[^A-Za-z0-9_-])`).test(work.workingOn),
  );
}

/** The chat after the round's progress bookkeeping, and what Auto does next. Pure. */
export function judgeRound(
  chat: WatsonChat,
  state: InvestigationState | null,
  work: WatsonRoundWork,
): { chat: WatsonChat; verdict: WatsonAutoVerdict } {
  const tried = chat.autoSearchesRun ?? [];
  const room = Math.max(0, WATSON_AUTO_SEARCHES_KEPT - tried.length);
  const fresh = [...new Set(work.ranSearches)].filter((k) => !tried.includes(k)).slice(0, room);
  const searches = [...tried, ...fresh];
  const progress = work.card || fresh.length > 0 || work.newEvidence === true;
  const aside = work.newEvidence ? [] : (chat.autoSetAside ?? []);
  const open = openItems(state);
  const focus = focusOf(work, open)
    .map((i) => i.id)
    .filter((id) => !aside.includes(id));
  const keep = { searches, aside };
  // A request for a person (a file, a query, a launch waiting for approval) sets its item aside at
  // once: its answer will not wake Watson, and the other open items still can move.
  if (work.asked) return setAside(chat, open, focus, keep, true);
  if (progress || !work.reaction) {
    const streak = progress
      ? { idle: 0, on: [] }
      : { idle: chat.autoIdleRounds ?? 0, on: chat.autoIdleFocus ?? [] };
    return { chat: withProgress(chat, streak, keep), verdict: { kind: "go" } };
  }
  const streak = idleStreak(chat, focus);
  if (streak.idle < WATSON_AUTO_IDLE_MAX) {
    return { chat: withProgress(chat, streak, keep), verdict: { kind: "go" } };
  }
  return setAside(chat, open, streak.on, keep, false, streak.idle);
}

/**
 * The idle streak after one more idle round of Watson's own. It counts per item: a round on another
 * item starts a new streak, so an item is set aside only after WATSON_AUTO_IDLE_MAX idle rounds on it
 * (Codex stop review of #2648). Rounds that name no open item keep counting together, and end "stuck".
 */
function idleStreak(chat: WatsonChat, focus: readonly string[]): Streak {
  const idle = chat.autoIdleRounds ?? 0;
  const before = chat.autoIdleFocus ?? [];
  if (idle === 0) return { idle: 1, on: [...focus] };
  if (before.length === 0 && focus.length === 0) return { idle: idle + 1, on: [] };
  const same = focus.filter((id) => before.includes(id));
  return same.length ? { idle: idle + 1, on: same } : { idle: 1, on: [...focus] };
}

interface Streak {
  idle: number;
  /** The items every round of the streak worked on. */
  on: readonly string[];
}

interface Kept {
  searches: readonly string[];
  aside: readonly string[];
}

/** Set the given items aside: move on while open items are left, else done; none: stuck. */
function setAside(
  chat: WatsonChat,
  open: readonly WatsonOpenItem[],
  ids: readonly string[],
  keep: Kept,
  asked: boolean,
  idle = 0,
): { chat: WatsonChat; verdict: WatsonAutoVerdict } {
  const newly = open.filter((item) => ids.includes(item.id) && !keep.aside.includes(item.id));
  if (newly.length === 0) {
    const streak = { idle, on: [] };
    return { chat: withProgress(chat, streak, keep), verdict: { kind: "stuck", left: [...open] } };
  }
  const nextAside = [...keep.aside, ...newly.map((i) => i.id)].slice(0, WATSON_AUTO_SET_ASIDE_MAX);
  const saved = withProgress(chat, { idle: 0, on: [] }, { ...keep, aside: nextAside });
  const left = open.filter((item) => !nextAside.includes(item.id));
  if (left.length === 0) return { chat: saved, verdict: { kind: "done", left: [...open] } };
  return { chat: saved, verdict: { kind: "moveOn", setAside: newly, ...(asked ? { asked: true } : {}) } };
}

function withProgress(chat: WatsonChat, streak: Streak, keep: Kept): WatsonChat {
  const { autoIdleRounds: _i, autoIdleFocus: _f, autoSearchesRun: _s, autoSetAside: _a, ...rest } = chat;
  return {
    ...rest,
    ...(streak.idle > 0 ? { autoIdleRounds: streak.idle } : {}),
    ...(streak.idle > 0 && streak.on.length ? { autoIdleFocus: [...streak.on] } : {}),
    ...(keep.searches.length ? { autoSearchesRun: [...keep.searches] } : {}),
    ...(keep.aside.length ? { autoSetAside: [...keep.aside] } : {}),
  };
}

const ITEM_LINE_CHARS = 200;
const clip = (s: string): string => (s.length > ITEM_LINE_CHARS ? `${s.slice(0, ITEM_LINE_CHARS)}…` : s);
const itemLine = (i: WatsonOpenItem): string =>
  `- [${i.id}] ${clip(i.text)}${i.needs.trim() ? ` (needs: ${clip(i.needs.trim())})` : ""}`;

export const moveOnText = (items: readonly WatsonOpenItem[]): string =>
  `Watson's last ${WATSON_AUTO_IDLE_MAX} rounds on ${items.map((i) => i.id).join(", ")} brought nothing new, ` +
  "so Watson sets them aside and moves to the next open Key Question or next step.";

export const askedMoveOnText = (items: readonly WatsonOpenItem[], asked: string): string =>
  `Watson needs this from you for ${items.map((i) => i.id).join(", ")}: ${clip(asked)}. ` +
  "Watson sets it aside and moves to the next open Key Question or next step.";

export const doneText = (left: readonly WatsonOpenItem[]): string =>
  [
    "Watson worked every open Key Question and next step, and the data it can reach gives nothing more. Auto stops here.",
    "What is left needs new evidence, a collection you approve, or an answer from the client:",
    ...left.map(itemLine),
  ].join("\n");

export const stuckText = (left: readonly WatsonOpenItem[]): string =>
  [
    `Watson made no progress in its last ${WATSON_AUTO_IDLE_MAX} rounds, and it did not name a new open item to work on. Auto stops here.`,
    ...(left.length ? ["Open items:", ...left.map(itemLine)] : []),
    "Send a message to guide Watson.",
  ].join("\n");

export const UNSAVED_PROGRESS_TEXT =
  "Watson could not save its Auto progress count, so Auto stops here. Send a message to let Watson continue.";
