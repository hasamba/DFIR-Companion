import type { ForensicRowStore } from "../../forensicRows.js";
import { labSetupPaths } from "../../labSetupTransfer.js";
import type { ForensicEvent } from "../../stateTypes.js";
import type { WatsonChatStore } from "./chatStore.js";
import { ackHeld, enqueueHeld, readHeldQueue, type QueuedHeld } from "./heldQueue.js";
import { withQueuedHeld } from "./heldOfferChat.js";
import { finalizeHeld, type HeldTagger } from "./heldTagger.js";
import { heldBuildWindows, heldEngineContext } from "./heldWindows.js";

// Held Watson promotions a RE-GRADE found (#2918): queued by `queueHeldRaises`, offered by
// `offerQueuedHeld` as held-rows cards in the case's Watson chat — the surface a paste's own turn and
// a Velociraptor result already use, applied and recorded the same way (eventPromoteWriter.ts).
//
// LOCKS. Queueing runs in the re-grade's tagger callback: inside the caller's import section, outside
// the state lock; it takes only the queue's own per-case chain. The offer takes the queue chain (read,
// released), then the chat's update chain, then the queue chain again (acknowledge) — never two at
// once, never the import section or the state lock, and no settle awaits it. So it cannot deadlock
// with an import or a proposal Apply (which holds the chat update and takes the state lock).
//
// BOUNDARY. Reads the forensic timeline only (the stale check, the correction context). No model call.

export interface HeldOfferDeps {
  stateDir: (caseId: string) => string;
  stateStore: Pick<ForensicRowStore, "forensicRowsById">;
  /** Absent: Watson is not configured; the queue waits. */
  chatStore?: Pick<WatsonChatStore, "update">;
  onWatson?: (caseId: string) => void;
  log?: (line: string) => void;
}

/**
 * A queued row whose suggestion is out of date: the row is back in the forensic timeline above Info
 * or promoted — something graded or promoted it meanwhile. Forensic timeline only: a row the
 * super-timeline dropped cannot be told apart, and its card still carries the full raised copy.
 */
async function staleIds(deps: HeldOfferDeps, caseId: string, queued: readonly QueuedHeld[]) {
  const rows = await deps.stateStore.forensicRowsById(
    caseId,
    queued.map((q) => q.event.id),
  );
  return new Set(
    rows.filter((r) => r.event.severity !== "Info" || !!r.event.promotedAt).map((r) => r.event.id),
  );
}

/**
 * Offer the case's queued held promotions (at most HELD_MAX per call; the rest wait for the next
 * offer). Acknowledges exactly what it read and settled: offered, stale, or already on a card. The
 * chat is written before the queue, so a crash in between re-reads entries the chat now covers, and
 * they are dropped then — each row is offered once. Returns how many rows it put on cards.
 */
export async function offerQueuedHeld(deps: HeldOfferDeps, caseId: string): Promise<number> {
  if (!deps.chatStore) return 0;
  const dir = deps.stateDir(caseId);
  const queued = await readHeldQueue(dir, deps.log);
  if (!queued.length) return 0;
  const stale = await staleIds(deps, caseId, queued);
  const live = queued.filter((q) => !stale.has(q.event.id));
  let done = new Set<string>();
  let offered = 0;
  if (live.length) {
    const at = new Date().toISOString();
    await deps.chatStore.update(caseId, (chat) => {
      const r = withQueuedHeld(
        chat,
        live.map((q) => q.event),
        at,
      );
      done = new Set([...r.offered, ...r.covered]);
      offered = r.offered.length;
      return r.chat;
    });
  }
  await ackHeld(
    dir,
    queued.filter((q) => stale.has(q.event.id) || done.has(q.event.id)),
  );
  if (offered) {
    deps.log?.(`[watson] ${caseId}: offered ${offered} held promotion(s) a re-grade found`);
    deps.onWatson?.(caseId);
  }
  return offered;
}

const running = new Map<string, Promise<void>>();
const again = new Set<string>();

/**
 * Offer the case's queue soon, without the caller waiting: one offer per case at a time, and one more
 * after it when asked meanwhile. Runs in the caller's async (case) scope. Never rejects.
 */
export function scheduleHeldOffer(deps: HeldOfferDeps, caseId: string): void {
  if (running.has(caseId)) {
    again.add(caseId);
    return;
  }
  const run = (async () => {
    await new Promise<void>((resolve) => setImmediate(resolve));
    do {
      again.delete(caseId);
      await offerQueuedHeld(deps, caseId).catch((err: unknown) =>
        deps.log?.(`[watson] ${caseId}: could not offer the held promotions: ${(err as Error).message}`),
      );
    } while (again.has(caseId));
  })().finally(() => running.delete(caseId));
  running.set(caseId, run);
}

/** Test seam: resolves once no scheduled offer runs for the case. */
export async function heldOfferIdle(caseId: string): Promise<void> {
  while (running.has(caseId)) await running.get(caseId);
}

export interface QueueRaisesDeps extends HeldOfferDeps {
  stateStore: HeldOfferDeps["stateStore"] & Parameters<typeof heldBuildWindows>[0];
}

/**
 * After a re-grade's held tagger ran on a page: put its raised copies through the paste's own
 * post-tagger corrections (finalizeHeld), queue the ones still above Info, and schedule the offer.
 * Returns the ids it could NOT queue (the caller reports them ungraded, so they keep their mark and a
 * later re-grade queues them again); [] when there was nothing to queue or it worked.
 */
export async function queueHeldRaises(
  deps: QueueRaisesDeps,
  caseId: string,
  held: Pick<HeldTagger, "held" | "offered">,
): Promise<string[]> {
  const candidates = held.held();
  if (!candidates.length) return [];
  try {
    const page = held.offered();
    const windows = await heldBuildWindows(deps.stateStore, caseId, page);
    const context = await heldEngineContext(deps.stateStore, caseId, page, candidates);
    const finalized: ForensicEvent[] = finalizeHeld(candidates, {
      windows,
      labPaths: labSetupPaths(),
      offered: context,
    });
    if (!finalized.length) return [];
    await enqueueHeld(deps.stateDir(caseId), finalized, deps.log);
    scheduleHeldOffer(deps, caseId);
    return [];
  } catch (err) {
    deps.log?.(
      `[watson] ${caseId}: could not queue ${candidates.length} held promotion(s); their rows stay waiting ` +
        `for a later re-grade: ${(err as Error).message}`,
    );
    scheduleHeldOffer(deps, caseId); // a full queue drains as its rows are offered
    return candidates.map((e) => e.id);
  }
}
