import type { ForensicEvent } from "../../stateTypes.js";
import { newWatsonId } from "./roundProposals.js";
import type { WatsonChat, WatsonEventPromoteProposal, WatsonPaste, WatsonTurn } from "./types.js";

// What a parsed Watson paste adds to the chat (spec §14): the paste with what parsing did, and,
// when it parsed into rows, one system turn before the round plus one pending event_promote
// proposal per HELD_PER_PROPOSAL held rows, capped at HELD_MAX rows with the cut stated. Pure.

export const HELD_PER_PROPOSAL = 25;
export const HELD_MAX = 200;

/** What ingesting a paste did: rows from a known format (with the held rows), or why it stayed text. */
export type WatsonPasteIngest =
  { kind: string; rows: number; held: ForensicEvent[] } | { kind: "text"; reason: string };

export const isTextIngest = (i: WatsonPasteIngest): i is { kind: "text"; reason: string } => "reason" in i;

/** The row count the import log records for the paste. */
export const ingestRows = (i: WatsonPasteIngest): number => (isTextIngest(i) ? 0 : i.rows);

function systemText(paste: WatsonPaste, kind: string, rows: number, held: number): string {
  const lead =
    `Parsed ${rows} rows from ${paste.filename} (${kind}). ` +
    `${held} rows the tagger graded above Info wait for your approval.`;
  if (held <= HELD_MAX) return lead;
  return `${lead} Only the first ${HELD_MAX} are proposed; the other ${held - HELD_MAX} stay in the super-timeline.`;
}

function chunks<T>(items: readonly T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
}

/** The chat with the paste recorded (and, for parsed rows, the system turn and held proposals). */
export function withPasteIngest(
  chat: WatsonChat,
  paste: WatsonPaste,
  ingest: WatsonPasteIngest,
  at: string = new Date().toISOString(),
): WatsonChat {
  const recorded: WatsonPaste = isTextIngest(ingest)
    ? { ...paste, parsed: { kind: "text", reason: ingest.reason } }
    : { ...paste, parsed: { kind: ingest.kind, rows: ingest.rows, held: ingest.held.length } };
  const base: WatsonChat = {
    ...chat,
    pastes: [...chat.pastes, recorded],
    unreadPasteIds: [...chat.unreadPasteIds, paste.id],
  };
  if (isTextIngest(ingest)) return base;
  const turnId = newWatsonId("wt");
  const proposals: WatsonEventPromoteProposal[] = chunks(
    ingest.held.slice(0, HELD_MAX),
    HELD_PER_PROPOSAL,
  ).map((events) => ({
    id: newWatsonId("wp"),
    turnId,
    kind: "event_promote",
    targetId: events[0].id,
    events,
    pasteId: paste.id,
    status: "pending",
  }));
  const turn: WatsonTurn = {
    id: turnId,
    at,
    role: "system",
    text: systemText(paste, ingest.kind, ingest.rows, ingest.held.length),
    pasteId: paste.id,
    ...(proposals.length ? { proposalIds: proposals.map((p) => p.id) } : {}),
  };
  return { ...base, turns: [...base.turns, turn], proposals: [...base.proposals, ...proposals] };
}
