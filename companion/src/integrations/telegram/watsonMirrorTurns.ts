import type { WatsonTurn } from "../../analysis/ai/watson/types.js";
import type { WatsonMirrorChat } from "./watsonMirrorStore.js";

// #2647: which turns a mirroring chat has not seen yet, and whether a batch must go out at once.
// Pure. Order follows the chat (turn ids are random, so they say nothing about order).

/** Every turn the chat ever had, in order: the history plus any live turn it lacks (a fresh chat). */
export function allTurns(history: readonly WatsonTurn[], live: readonly WatsonTurn[]): WatsonTurn[] {
  const known = new Set(history.map((t) => t.id));
  return [...history, ...live.filter((t) => !known.has(t.id))];
}

/** The newest part of the append-only history, and whether older turns remain beyond it. */
export interface MirrorHistory {
  turns: readonly WatsonTurn[];
  more: boolean;
}

/**
 * The turns after the chat's cursor. The live chat keeps only the newest 400 turns: when the cursor
 * has rotated out of it, `history()` (the append-only file) is read instead, so turns written while
 * the server was down are not lost. With no cursor, or one found nowhere, every turn since the chat
 * turned mirroring on counts; the caller drops the ones already sent or pending.
 *
 * `gap` (#2710): the cursor is older than the history window, older turns remain, and the window
 * starts after the chat turned mirroring on — so turns between the cursor and the window are lost.
 */
export async function turnsAfterCursor(
  entry: Pick<WatsonMirrorChat, "cursor" | "enabledAt">,
  live: readonly WatsonTurn[],
  history: () => Promise<MirrorHistory>,
): Promise<{ turns: WatsonTurn[]; gap: boolean }> {
  const sinceEnabled = (list: readonly WatsonTurn[]): WatsonTurn[] =>
    list.filter((t) => t.at >= entry.enabledAt);
  if (!entry.cursor) return { turns: sinceEnabled(live), gap: false };
  const i = live.findIndex((t) => t.id === entry.cursor);
  if (i >= 0) return { turns: live.slice(i + 1), gap: false };
  const window = await history();
  const all = allTurns(window.turns, live);
  const j = all.findIndex((t) => t.id === entry.cursor);
  if (j >= 0) return { turns: all.slice(j + 1), gap: false };
  const first = all[0];
  return { turns: sinceEnabled(all), gap: window.more && !!first && first.at >= entry.enabledAt };
}

/**
 * Someone is waiting: an analyst asked (dashboard or Telegram), or this is Watson's answer to an
 * analyst's message. Those go out at once; everything else (reactions, Auto rounds, notes) waits for
 * the 60 s batch.
 */
export function isUrgent(turn: WatsonTurn, previous: WatsonTurn | undefined): boolean {
  if (turn.role === "analyst") return true;
  return turn.role === "watson" && previous?.role === "analyst";
}

/** The pending turns found in `all`, in chat order, each with whether it is urgent. Unknown ids are returned apart. */
export function resolvePending(
  pending: readonly string[],
  all: readonly WatsonTurn[],
): { turns: WatsonTurn[]; urgent: boolean; missing: string[] } {
  const want = new Set(pending);
  const turns: WatsonTurn[] = [];
  let urgent = false;
  all.forEach((t, i) => {
    if (!want.has(t.id)) return;
    turns.push(t);
    if (isUrgent(t, all[i - 1])) urgent = true;
  });
  const found = new Set(turns.map((t) => t.id));
  return { turns, urgent, missing: pending.filter((id) => !found.has(id)) };
}

// ── No echo ───────────────────────────────────────────────────────────────────────────

/** How long a Telegram question waits for its turn to appear before the echo guard forgets it. */
export const ECHO_TTL_MS = 10 * 60_000;

export interface ExpectedEcho {
  chatId: string;
  caseId: string;
  actor: string;
  text: string;
  until: number;
}

/**
 * Split new analyst turns that a Telegram chat itself asked from the rest: the question is not sent
 * back to the chat it came from. Returns the ids to skip and the expectations still unmet.
 */
export function matchEchoes(
  chatId: string,
  caseId: string,
  turns: readonly WatsonTurn[],
  expected: readonly ExpectedEcho[],
  now: number,
): { skip: string[]; remaining: ExpectedEcho[] } {
  let remaining = expected.filter((e) => e.until > now);
  const skip: string[] = [];
  for (const t of turns) {
    if (t.role !== "analyst") continue;
    const hit = remaining.find(
      (e) => e.chatId === chatId && e.caseId === caseId && e.actor === t.actor && e.text === t.text,
    );
    if (!hit) continue;
    skip.push(t.id);
    remaining = remaining.filter((e) => e !== hit);
  }
  return { skip, remaining };
}
