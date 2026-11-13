import type { WatsonCaseEvent, WatsonChat } from "./types.js";

/** Notes waiting for Watson's next round are capped, newest kept. */
export const WATSON_PENDING_EVENTS_MAX = 50;

/** What a caller says happened; the time is stamped when it is noted. */
export type WatsonCaseEventNote = Omit<WatsonCaseEvent, "at">;

/**
 * The chat with one more pending case event (a new object). A repeat of the event just before it
 * adds no line but moves that line's time forward: a round showing the older one then removes only
 * that one (withoutShown compares by value), so a repeat noted mid-round is never lost. Past the
 * cap the oldest go.
 */
export function withCaseEvent(chat: WatsonChat, event: WatsonCaseEventNote, at: string): WatsonChat {
  const last = chat.pendingCaseEvents[chat.pendingCaseEvents.length - 1];
  if (last && last.kind === event.kind && last.text === event.text) {
    if (last.at === at) return chat;
    return { ...chat, pendingCaseEvents: [...chat.pendingCaseEvents.slice(0, -1), { ...last, at }] };
  }
  const noted: WatsonCaseEvent = { kind: event.kind, text: event.text, at };
  return {
    ...chat,
    pendingCaseEvents: [...chat.pendingCaseEvents, noted].slice(-WATSON_PENDING_EVENTS_MAX),
  };
}
