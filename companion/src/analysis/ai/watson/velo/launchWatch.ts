import { withCaseEvent } from "../caseEvents.js";
import type { WatsonChat, WatsonLaunchWatch, WatsonProposal, WatsonVeloLaunchProposal } from "../types.js";

// Watson phase 3, Task 5: the pure half of reading a launch's result back. Every change to a
// launch's `watch` goes through one of these inside a chat-store update, so the guards (`ingested`,
// `notified`, the `watching` state) are checked and set atomically with the save.

/** How long Watson waits for a single-host collection (a proposal carries no wait of its own). */
export const WATSON_WATCH_DEFAULT_MS = 30 * 60_000;
/** How often a collection's flow status is read. */
export const WATSON_WATCH_POLL_MS = 30_000;

/** The watch a freshly launched collection is saved with; none for a fleet hunt or missing ids. */
export function initialWatch(
  p: Pick<WatsonVeloLaunchProposal, "mode">,
  launched: { flowId?: string; clientId?: string },
  at: string,
): WatsonLaunchWatch | undefined {
  if (p.mode !== "collection" || !launched.flowId || !launched.clientId) return undefined;
  return { deadline: new Date(Date.parse(at) + WATSON_WATCH_DEFAULT_MS).toISOString(), state: "watching" };
}

const plural = (n: number, word: string): string => `${n} ${word}${n === 1 ? "" : "s"}`;

/** The `hunt` event's text for a launch whose watch has ended. */
export function huntEventText(title: string, watch: WatsonLaunchWatch): string {
  const name = `Watson's hunt ${title}`;
  if (watch.state === "timeout") {
    return `${name} timed out: no result within ${WATSON_WATCH_DEFAULT_MS / 60_000} minutes`;
  }
  if (watch.state === "failed") return `${name} failed: ${watch.error ?? "unknown error"}`;
  const rows = watch.rows ?? 0;
  if (rows === 0 && !watch.added) return `${name} found nothing`;
  return `${name} finished: ${plural(rows, "row")}, ${plural(watch.added ?? 0, "new event")}`;
}

/** The applied launch with this id, or undefined. */
export function findApplied(chat: WatsonChat, id: string): WatsonVeloLaunchProposal | undefined {
  const p = chat.proposals.find((x) => x.id === id);
  return p && p.kind === "velo_launch" && p.status === "applied" ? p : undefined;
}

function withProposal(chat: WatsonChat, next: WatsonProposal): WatsonChat {
  return { ...chat, proposals: chat.proposals.map((x) => (x.id === next.id ? next : x)) };
}

/** The launch with its watch replaced (a new chat). */
export function withWatch(
  chat: WatsonChat,
  p: WatsonVeloLaunchProposal,
  watch: WatsonLaunchWatch,
): WatsonChat {
  return withProposal(chat, { ...p, watch });
}

/**
 * The chat with the launch's `hunt` event noted and `notified` set, in one step. Unchanged when
 * the launch is gone, still watching, or already notified — so the event is sent at most once.
 */
export function withHuntNotified(
  chat: WatsonChat,
  id: string,
  at: string,
): { chat: WatsonChat; sent: boolean } {
  const p = findApplied(chat, id);
  const w = p?.watch;
  if (!p || !w || w.state === "watching" || w.notified) return { chat, sent: false };
  const event = {
    kind: "hunt" as const,
    text: huntEventText(p.title, w),
    ...(w.proposalIds?.length ? { proposalIds: w.proposalIds } : {}),
  };
  const noted = withWatch(withCaseEvent(chat, event, at), p, { ...w, notified: true });
  return { chat: noted, sent: true };
}

/** End a watching launch (timeout or failure) with no rows read. Unchanged unless still watching. */
export function withWatchEnded(
  chat: WatsonChat,
  id: string,
  state: "timeout" | "failed",
  error?: string,
): WatsonChat {
  const p = findApplied(chat, id);
  if (!p?.watch || p.watch.state !== "watching") return chat;
  return withWatch(chat, p, { ...p.watch, state, ...(error ? { error } : {}) });
}

/** The applied launches whose watch still needs work: watching, or ended but not yet notified. */
export function openWatches(chat: WatsonChat): WatsonVeloLaunchProposal[] {
  return chat.proposals.filter(
    (p): p is WatsonVeloLaunchProposal =>
      p.kind === "velo_launch" &&
      p.status === "applied" &&
      !!p.watch &&
      (p.watch.state === "watching" || !p.watch.notified),
  );
}

/**
 * A fleet hunt's result: the applied hunt launched with this hunt id that has not been noted yet,
 * marked finished with its counts. A straggler re-collect of the same hunt notes nothing more.
 */
export function withFleetResult(
  chat: WatsonChat,
  huntId: string,
  result: { rows: number; added: number },
  at: string,
): { chat: WatsonChat; id?: string } {
  const p = chat.proposals.find(
    (x): x is WatsonVeloLaunchProposal =>
      x.kind === "velo_launch" &&
      x.status === "applied" &&
      x.mode === "hunt" &&
      x.launched?.huntId === huntId,
  );
  if (!p || p.watch?.notified) return { chat };
  const watch: WatsonLaunchWatch = {
    deadline: at,
    state: "finished",
    rows: result.rows,
    added: result.added,
  };
  return { chat: withWatch(chat, p, watch), id: p.id };
}
