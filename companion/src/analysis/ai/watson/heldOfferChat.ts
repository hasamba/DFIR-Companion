import type { ForensicEvent } from "../../stateTypes.js";
import { HELD_MAX, HELD_PER_PROPOSAL } from "./pasteIngestChat.js";
import { newWatsonId } from "./roundProposals.js";
import type { WatsonChat, WatsonEventPromoteProposal, WatsonPaste, WatsonTurn } from "./types.js";

// What offering queued held promotions adds to the chat (#2918, heldOffer.ts): for each source paste,
// one system turn with pending event_promote cards — the same cards a paste's own turn carries, applied
// and recorded the same way (writers/eventPromoteWriter.ts). The turn text names the paste and a count,
// never a row's content, so nothing a row says reaches Watson's prompt. Pure.

export interface QueuedOffer {
  chat: WatsonChat;
  /** Ids put on a card now. */
  offered: string[];
  /** Ids the chat already holds on a card (pending, applied, rejected or undone): not offered again. */
  covered: string[];
}

/** Every row id the chat's event_promote proposals carry, whatever their status. */
export function heldIdsInChat(chat: WatsonChat): Set<string> {
  return new Set(
    chat.proposals.flatMap((p) => (p.kind === "event_promote" ? p.events.map((e) => e.id) : [])),
  );
}

/** The paste a row came from: the one whose stored file the row names. */
export function pasteOf(chat: WatsonChat, e: ForensicEvent): WatsonPaste | undefined {
  const names = new Set(e.sourceScreenshots);
  return chat.pastes.find((p) => names.has(p.storedName));
}

const fileOf = (e: ForensicEvent): string =>
  [...e.sourceScreenshots].filter((s) => typeof s === "string").sort()[0] ?? "an earlier paste";

function chunks<T>(items: readonly T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
}

function turnText(source: string, held: number): string {
  const what =
    held === 1
      ? "To add it to the forensic timeline, apply the held-rows card below."
      : "To add them to the forensic timeline, apply the held-rows cards below.";
  return (
    `Watson finished grading rows from ${source} after an interruption. The tagger graded ${held} of ` +
    `them above Info. ${what} Until you apply a card, its rows stay in the super-timeline.`
  );
}

/**
 * The chat with up to `max` queued rows offered: rows the chat already carries on a card are skipped
 * (`covered`), the rest grouped by source paste, one system turn per group. A new object.
 */
export function withQueuedHeld(
  chat: WatsonChat,
  events: readonly ForensicEvent[],
  at: string,
  max: number = HELD_MAX,
): QueuedOffer {
  const inChat = heldIdsInChat(chat);
  const covered = events.filter((e) => inChat.has(e.id)).map((e) => e.id);
  const fresh = events.filter((e) => !inChat.has(e.id)).slice(0, max);
  const groups = new Map<string, { paste?: WatsonPaste; source: string; events: ForensicEvent[] }>();
  for (const e of fresh) {
    const paste = pasteOf(chat, e);
    const key = paste ? `paste:${paste.id}` : `file:${fileOf(e)}`;
    const group = groups.get(key) ?? { paste, source: paste?.filename ?? fileOf(e), events: [] };
    groups.set(key, { ...group, events: [...group.events, e] });
  }
  const turns: WatsonTurn[] = [];
  const proposals: WatsonEventPromoteProposal[] = [];
  for (const g of groups.values()) {
    const turnId = newWatsonId("wt");
    const cards = chunks(g.events, HELD_PER_PROPOSAL).map((rows): WatsonEventPromoteProposal => ({
      id: newWatsonId("wp"),
      turnId,
      kind: "event_promote",
      targetId: rows[0].id,
      events: rows,
      ...(g.paste ? { pasteId: g.paste.id } : {}),
      status: "pending",
    }));
    proposals.push(...cards);
    turns.push({
      id: turnId,
      at,
      role: "system",
      text: turnText(g.source, g.events.length),
      ...(g.paste ? { pasteId: g.paste.id } : {}),
      proposalIds: cards.map((p) => p.id),
    });
  }
  if (!turns.length) return { chat, offered: [], covered };
  return {
    chat: { ...chat, turns: [...chat.turns, ...turns], proposals: [...chat.proposals, ...proposals] },
    offered: fresh.map((e) => e.id),
    covered,
  };
}
