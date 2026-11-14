import type { WatsonChatStore } from "../analysis/ai/watson/chatStore.js";
import { withPasteIngest } from "../analysis/ai/watson/pasteIngestChat.js";
import type { WatsonChat } from "../analysis/ai/watson/types.js";
import {
  findApplied,
  withFleetResult,
  withHuntNotified,
  withWatch,
} from "../analysis/ai/watson/velo/launchWatch.js";
import type { WatsonIngested } from "./watsonVeloResults.js";

// The chat updates of Watson's result watch (watsonVeloResults.ts), split out to keep that file
// under the size cap: the finished watch with its ingested rows, a failed claim, and the fleet hook.

/** The claimed launch failed while importing: end it (it was `watching`). */
export function failClaimed(chat: WatsonChat, id: string, error: string): WatsonChat {
  const p = findApplied(chat, id);
  if (!p?.watch || p.watch.state !== "watching") return chat;
  return withWatch(chat, p, { ...p.watch, state: "failed", error });
}

/** The ingested rows on the chat (paste, system turn, held proposals) and the finished watch. */
export function withResult(
  chat: WatsonChat,
  id: string,
  r: { rows: number; added: number; ingested?: WatsonIngested; truncated?: true; total?: number },
): WatsonChat {
  const p = findApplied(chat, id);
  if (!p?.watch || p.watch.state !== "watching") return chat;
  const before = new Set(chat.proposals.map((x) => x.id));
  const next = r.ingested ? withPasteIngest(chat, r.ingested.paste, r.ingested.ingest) : chat;
  const proposalIds = next.proposals.filter((x) => !before.has(x.id)).map((x) => x.id);
  const cut = r.truncated ? { truncated: true as const, total: r.total ?? 0 } : {};
  const watch = { ...p.watch, state: "finished" as const, rows: r.rows, added: r.added, ...cut };
  return withWatch(next, p, proposalIds.length ? { ...watch, proposalIds } : watch);
}

/**
 * The fleet hook (veloHunts.ts, after the collect fills the outcome): Watson's own hunt notes one
 * `hunt` event, found nothing included. Best effort and never throws — the collect has landed.
 */
export async function noteWatsonFleetResult(
  chatStore: Pick<WatsonChatStore, "load" | "update">,
  wake: (caseId: string) => void,
  caseId: string,
  result: { huntId: string; rows: number; added: number },
  log?: (line: string) => void,
): Promise<void> {
  try {
    const at = new Date().toISOString();
    // Read first: a case that never used Watson (or this hunt is not Watson's) gets no chat write.
    if (!withFleetResult(await chatStore.load(caseId), result.huntId, result, at).id) return;
    let sent = false;
    await chatStore.update(caseId, (c) => {
      const marked = withFleetResult(c, result.huntId, result, at);
      if (!marked.id) return c;
      const r = withHuntNotified(marked.chat, marked.id, at);
      sent = r.sent;
      return r.chat;
    });
    if (sent) wake(caseId);
  } catch (err) {
    log?.(`[watson] ${caseId}: could not note the hunt result: ${msg(err)}`);
  }
}

const msg = (err: unknown): string => (err instanceof Error ? err.message : String(err));
