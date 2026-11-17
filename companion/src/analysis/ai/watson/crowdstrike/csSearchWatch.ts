import { siemSearchText, type SiemSearchOutcome } from "../../../siemSearch.js";
import { withCaseEvent } from "../caseEvents.js";
import type { WatsonChat, WatsonCsSearchProposal } from "../types.js";

// Reading a Watson CrowdStrike search's result back (#2666). The search job (routes/
// crowdstrikeSiemSearch.ts) calls back with its outcome; this saves it on the card and notes one
// `hunt` case event for Watson's next round, in the same update and at most once (`notified`).
// Pure, over the fresh chat.

export function findAppliedCs(chat: WatsonChat, id: string): WatsonCsSearchProposal | undefined {
  const p = chat.proposals.find((x) => x.id === id);
  return p && p.kind === "cs_search" && p.status === "applied" ? p : undefined;
}

/** The chat with the search's outcome on its card and its `hunt` event noted; `sent` once only. */
export function withCsResult(
  chat: WatsonChat,
  id: string,
  outcome: SiemSearchOutcome,
  at: string,
): { chat: WatsonChat; sent: boolean } {
  const p = findAppliedCs(chat, id);
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
  const next = { ...p, watch };
  const updated = { ...chat, proposals: chat.proposals.map((x) => (x.id === id ? next : x)) };
  return { chat: withCaseEvent(updated, { kind: "hunt", text: `Watson's ${text}` }, at), sent: true };
}
