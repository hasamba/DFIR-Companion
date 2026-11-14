import type { WatsonChatStore } from "./chatStore.js";
import { newWatsonId } from "./roundProposals.js";
import type { WatsonChat } from "./types.js";

// "New thread": the chat the model sees starts afresh, Watson's memory (the case summary, not the
// conversation) stays, and the earlier turns stay in the saved history.

const NEW_THREAD_TEXT = "New thread — Watson starts from its case memory; earlier chat stays in the history.";

export function startNewThread(chatStore: WatsonChatStore, caseId: string): Promise<WatsonChat> {
  return chatStore.update(caseId, (c) => {
    const at = new Date().toISOString();
    return {
      ...c,
      threadStartAt: at,
      turns: [...c.turns, { id: newWatsonId("wt"), at, role: "system", text: NEW_THREAD_TEXT }],
    };
  });
}
