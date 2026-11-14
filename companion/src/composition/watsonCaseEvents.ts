import type { WatsonChatStore } from "../analysis/ai/watson/chatStore.js";
import {
  withCaseEvent,
  WATSON_PENDING_EVENTS_MAX,
  type WatsonCaseEventNote,
} from "../analysis/ai/watson/caseEvents.js";
import { STARRED_LABEL } from "../analysis/superTimeline.js";
import type { Tag } from "../analysis/tags.js";
import { warnLine } from "../logging/serverLogger.js";

export { WATSON_PENDING_EVENTS_MAX, type WatsonCaseEventNote };

/** The chat-store methods a case event needs. */
export type WatsonEventChatStore = Pick<WatsonChatStore, "load" | "update">;

/**
 * Add one event to the chat's pending case events, so Watson's NEXT round hears about what the
 * analyst did meanwhile. Writes through the shared chat store (the one the rounds use), so a round
 * that is running right now cannot lose it. Makes no model call. A repeat of the event just before
 * it adds nothing. Best effort: the analyst's own action has already landed, so a failure is logged
 * only.
 */
export function noteWatsonCaseEvent(
  chatStore: WatsonEventChatStore,
  caseId: string,
  event: WatsonCaseEventNote,
): void {
  const at = new Date().toISOString();
  void chatStore
    .update(caseId, (chat) => withCaseEvent(chat, event, at))
    .catch((err: unknown) => {
      warnLine(`[watson] ${caseId}: could not note a case event: ${(err as Error).message}`);
    });
}

/** Where a noted event goes: the reaction scheduler once the app has built one. */
export interface WatsonCaseEventSink {
  note(caseId: string, event: WatsonCaseEventNote): void;
  /** Start the quiet window for an event already saved on the chat (a `hunt` result). */
  wake?(caseId: string): void;
}

export interface WatsonCaseEvents {
  /** Note an event; with a reactor attached it also (re)starts the quiet window for a reaction. */
  note(caseId: string, event: WatsonCaseEventNote): void;
  /**
   * The import banner changed (onImportMeta). A new import wakes Watson; an undo or redo is only
   * noted, so it never wakes it.
   */
  importChanged(caseId: string, step?: "undo" | "redo"): void;
  /** The case's tags changed (onTags): a newly starred event wakes Watson, any other change does not. */
  tagsChanged(caseId: string): void;
  /**
   * The notebook changed (onNotebook). It wakes Watson only when the case's AI control includes the
   * notebook (`includeNotebook`), the one way Watson can read it; otherwise it is only noted, so an
   * edit never pays for a round that cannot see it.
   */
  notebookChanged(caseId: string): void;
  /** An event the caller saved on the chat itself (with its own guard): only wake Watson. */
  wake(caseId: string): void;
  /** Called once by createApp with the shared reactor. */
  attach(sink: WatsonCaseEventSink): void;
}

const STARS_LISTED = 5;
const NOTEBOOK_EDITED = "Analyst edited the notebook";

function starredIds(tags: readonly Tag[]): Set<string> {
  return new Set(
    tags.filter((t) => t.targetType === "event" && t.label === STARRED_LABEL).map((t) => t.targetId),
  );
}

function starText(ids: readonly string[]): string {
  const listed = ids.slice(0, STARS_LISTED).join(", ");
  const more = ids.length > STARS_LISTED ? ` and ${ids.length - STARS_LISTED} more` : "";
  return `Analyst starred ${ids.length} event${ids.length === 1 ? "" : "s"}: ${listed}${more}`;
}

/**
 * The case-event callbacks appWiring hands to createApp. Before a reactor is attached (or in an app
 * built without one) an event is only noted, as in phase 1.
 *
 * Stars: onTags carries only the case id, so the set of starred event ids is compared with the last
 * set seen for the case (kept in memory). The first sight of a case records its stars without waking
 * Watson. The content tagger never adds the reserved star, so its tag writes never wake Watson.
 */
export function createWatsonCaseEvents(
  chatStore: WatsonEventChatStore,
  tagsStore?: { load(caseId: string): Promise<Tag[]> },
  aiControl?: { load(caseId: string): Promise<{ includeNotebook?: boolean }> },
): WatsonCaseEvents {
  let sink: WatsonCaseEventSink | undefined;
  const seenStars = new Map<string, Set<string>>();
  const tagChains = new Map<string, Promise<void>>();

  const note = (caseId: string, event: WatsonCaseEventNote): void => {
    if (sink) sink.note(caseId, event);
    else noteWatsonCaseEvent(chatStore, caseId, event);
  };

  async function diffStars(caseId: string): Promise<void> {
    const now = starredIds(tagsStore ? await tagsStore.load(caseId) : []);
    const before = seenStars.get(caseId);
    seenStars.set(caseId, now);
    const fresh = before ? [...now].filter((id) => !before.has(id)) : [];
    if (fresh.length) note(caseId, { kind: "star", text: starText(fresh) });
    else noteWatsonCaseEvent(chatStore, caseId, { kind: "other", text: "Event tags or stars changed" });
  }

  // One diff at a time per case, so two quick tag writes never both see the same "before".
  function tagsChanged(caseId: string): void {
    const prev = tagChains.get(caseId) ?? Promise.resolve();
    const run = prev.then(() => diffStars(caseId));
    const tail = run.catch((err: unknown) => {
      warnLine(`[watson] ${caseId}: could not compare stars: ${(err as Error).message}`);
    });
    tagChains.set(caseId, tail);
    void tail.then(() => {
      if (tagChains.get(caseId) === tail) tagChains.delete(caseId);
    });
  }

  function importChanged(caseId: string, step?: "undo" | "redo"): void {
    if (!step) return note(caseId, { kind: "import", text: "An import finished" });
    const text = step === "undo" ? "An import was undone" : "An import undo was redone";
    noteWatsonCaseEvent(chatStore, caseId, { kind: "other", text });
  }

  // Fails closed: an unreadable AI control only notes the edit.
  function notebookChanged(caseId: string): void {
    const event: WatsonCaseEventNote = { kind: "notebook", text: NOTEBOOK_EDITED };
    void (aiControl?.load(caseId) ?? Promise.resolve({ includeNotebook: false }))
      .then((c) => c.includeNotebook === true)
      .catch(() => false)
      .then((wakes) => {
        if (wakes) note(caseId, event);
        else noteWatsonCaseEvent(chatStore, caseId, { kind: "other", text: NOTEBOOK_EDITED });
      });
  }

  return {
    note,
    importChanged,
    tagsChanged,
    notebookChanged,
    wake: (caseId) => sink?.wake?.(caseId),
    attach: (next) => {
      sink = next;
    },
  };
}
