import { siemSearchText, type SiemSearchOutcome } from "../../../siemSearch.js";
import { withCaseEvent } from "../caseEvents.js";
import type { WatsonChat, WatsonCsSearchProposal } from "../types.js";

// Reading a Watson CrowdStrike search's result back (#2666). The search job (routes/
// crowdstrikeSiemSearch.ts) calls back with its outcome; this saves it on the card and notes one
// `hunt` case event for Watson's next round, in the same update and at most once (`notified`).
// Pure, over the fresh chat.

/**
 * The card a finished search belongs to: applied, or still pending when the save after its job
 * started was lost — the job ran, so its result is never dropped and the card is set applied.
 */
export function findRunCs(chat: WatsonChat, id: string): WatsonCsSearchProposal | undefined {
  const p = chat.proposals.find((x) => x.id === id);
  return p && p.kind === "cs_search" && (p.status === "applied" || p.status === "pending") ? p : undefined;
}

/** The chat with the search's outcome on its card and its `hunt` event noted; `sent` once only. */
export function withCsResult(
  chat: WatsonChat,
  id: string,
  outcome: SiemSearchOutcome,
  at: string,
): { chat: WatsonChat; sent: boolean } {
  const p = findRunCs(chat, id);
  if (!p || p.watch?.notified) return { chat, sent: false };
  const text = siemSearchText(outcome);
  const watch = {
    state: outcome.failed ? ("failed" as const) : ("finished" as const),
    rows: outcome.rows,
    added: outcome.added,
    ...(outcome.truncated ? { truncated: true as const } : {}),
    text,
    notified: true as const,
  };
  const next: WatsonCsSearchProposal = {
    ...p,
    status: "applied",
    ...(p.appliedAt ? {} : { appliedAt: at, appliedBy: "Watson" }),
    watch,
  };
  const updated = { ...chat, proposals: chat.proposals.map((x) => (x.id === id ? next : x)) };
  return { chat: withCaseEvent(updated, { kind: "hunt", text: `Watson's ${text}` }, at), sent: true };
}
