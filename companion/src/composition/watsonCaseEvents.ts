import type { WatsonChatStore } from "../analysis/ai/watson/chatStore.js";
import { warnLine } from "../logging/serverLogger.js";

/** Notes waiting for Watson's next round are capped, newest kept. */
export const WATSON_PENDING_EVENTS_MAX = 50;

/**
 * Add one line to the chat's pending case events, so Watson's NEXT round hears about what the analyst
 * did meanwhile. Writes through the shared chat store (the one the rounds use), so a round that is
 * running right now cannot lose it. Makes no model call. A repeat of the line just before it adds
 * nothing. Best effort: the analyst's own action has already landed, so a failure is logged only.
 */
export function noteWatsonCaseEvent(chatStore: WatsonChatStore, caseId: string, line: string): void {
  void chatStore
    .update(caseId, (chat) => {
      const last = chat.pendingCaseEvents[chat.pendingCaseEvents.length - 1];
      if (last === line) return chat;
      return {
        ...chat,
        pendingCaseEvents: [...chat.pendingCaseEvents, line].slice(-WATSON_PENDING_EVENTS_MAX),
      };
    })
    .catch((err: unknown) => {
      warnLine(`[watson] ${caseId}: could not note a case event: ${(err as Error).message}`);
    });
}
