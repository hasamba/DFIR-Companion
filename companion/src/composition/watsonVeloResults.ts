import type { WatsonChatStore } from "../analysis/ai/watson/chatStore.js";
import {
  isTextIngest,
  withPasteIngest,
  type WatsonPasteIngest,
} from "../analysis/ai/watson/pasteIngestChat.js";
import type { WatsonChat, WatsonPaste, WatsonVeloLaunchProposal } from "../analysis/ai/watson/types.js";
import {
  findApplied,
  openWatches,
  WATSON_WATCH_POLL_MS,
  withFleetResult,
  withHuntNotified,
  withWatch,
  withWatchEnded,
} from "../analysis/ai/watson/velo/launchWatch.js";
import type { WatsonFlowWatch } from "../analysis/ai/watson/velo/launchTypes.js";
import type { HuntCollectResult } from "../analysis/huntOutcomes.js";

// Watson phase 3, Task 5: results come back to Watson. A fleet hunt keeps today's collect (import +
// synthesis); its one hook notes a `hunt` event for Watson's own hunt, rows or none. A single-host
// collection has no collect of its own, so it is watched here: its flow status is read every 30 s up
// to the watch's deadline; on FINISHED the rows are ingested like a chat paste (held tagger
// promotions, no synthesis), the outcome is filled by flow, and a `hunt` event wakes Watson.
//
// At most once, across restarts (the watch lives on the proposal): `ingested` is CLAIMED in a chat
// update before any row is read, and the `hunt` event is saved in the same update that sets
// `notified`. A restart that finds a claim without a result marks the launch failed (rows may or
// may not be in the case — they are never read twice); one that finds a result without the event
// sends the event. Every end state is conditional on `watching`, so a timeout is reported once.

/** The Velociraptor calls a watch makes, through the case's existing client. */
export interface WatsonFlowClient {
  flowStatus(clientId: string, flowId: string): Promise<{ state: string; error: string; rows: number }>;
}

/** What reading a finished flow's rows gives: the importer text, and the row count. */
export interface WatsonFlowRows {
  text: string;
  rows: number;
}

export interface WatsonFlowWatcherDeps {
  chatStore: Pick<WatsonChatStore, "load" | "update">;
  /** The case's Velociraptor client, or null when the case has none. */
  velo(caseId: string): WatsonFlowClient | null;
  /** Read every row of a finished flow (all its sources) as importer text. */
  readRows(caseId: string, p: WatsonVeloLaunchProposal): Promise<WatsonFlowRows>;
  /** Store the rows as evidence and ingest them like a chat paste. */
  ingest(caseId: string, p: WatsonVeloLaunchProposal, rows: WatsonFlowRows): Promise<WatsonIngested>;
  /** Fill the collection's hunt outcome by flow (a no-op once collected). */
  fillOutcome(caseId: string, ref: { flowId: string; clientId: string }, r: HuntCollectResult): Promise<void>;
  /** A frozen case takes no new evidence. */
  isFrozen(caseId: string): Promise<boolean>;
  /** Start Watson's quiet window for the `hunt` event saved on the chat. */
  wake(caseId: string): void;
  onChanged?(caseId: string): void;
  now?(): number;
  setTimer?: (fn: () => void, ms: number) => ReturnType<typeof setTimeout>;
  pollMs?: number;
  log?(line: string): void;
}

export interface WatsonIngested {
  paste: WatsonPaste;
  ingest: WatsonPasteIngest;
}

const INTERRUPTED = "Watson was interrupted while reading the results; check the case before re-running it";

export class WatsonFlowWatcher implements WatsonFlowWatch {
  private readonly timers = new Map<string, ReturnType<typeof setTimeout>>();
  private readonly inFlight = new Set<Promise<void>>();
  private stopped = false;

  constructor(private readonly deps: WatsonFlowWatcherDeps) {}

  /** Start (or keep) the poll for one applied collection. */
  watch(caseId: string, proposalId: string): void {
    const key = `${caseId}\u0000${proposalId}`;
    if (this.stopped || this.timers.has(key)) return;
    const set = this.deps.setTimer ?? setTimeout;
    const timer = set(() => {
      this.timers.delete(key);
      this.track(this.tick(caseId, proposalId));
    }, this.deps.pollMs ?? WATSON_WATCH_POLL_MS);
    timer.unref?.();
    this.timers.set(key, timer);
  }

  /** At startup, for one case: notify ended watches, end expired ones once, resume the rest. */
  async resume(caseId: string): Promise<void> {
    const chat = await this.deps.chatStore.load(caseId);
    for (const p of openWatches(chat)) await this.tickOnce(caseId, p.id, true);
  }

  stop(): void {
    this.stopped = true;
    for (const t of this.timers.values()) clearTimeout(t);
    this.timers.clear();
  }

  async settled(): Promise<void> {
    while (this.inFlight.size) await Promise.all([...this.inFlight]);
  }

  private track(run: Promise<void>): void {
    const p = run.catch((err: unknown) => this.deps.log?.(`[watson] result watch failed: ${msg(err)}`));
    this.inFlight.add(p);
    void p.finally(() => this.inFlight.delete(p));
  }

  private async tick(caseId: string, id: string): Promise<void> {
    if (!this.stopped) await this.tickOnce(caseId, id, false);
  }

  private async tickOnce(caseId: string, id: string, startup: boolean): Promise<void> {
    const p = findApplied(await this.deps.chatStore.load(caseId), id);
    const w = p?.watch;
    if (!p || !w) return;
    if (w.state !== "watching") return this.notify(caseId, p); // ended earlier, event not yet sent
    if (w.ingested) return this.end(caseId, id, "failed", INTERRUPTED); // a claim with no result
    if ((this.deps.now?.() ?? Date.now()) >= Date.parse(w.deadline)) return this.end(caseId, id, "timeout");
    if (startup) return this.watch(caseId, id);
    await this.poll(caseId, p);
  }

  private async poll(caseId: string, p: WatsonVeloLaunchProposal): Promise<void> {
    const { flowId = "", clientId = "" } = p.launched ?? {};
    const client = this.deps.velo(caseId);
    if (!client) return this.end(caseId, p.id, "failed", "the case no longer has a Velociraptor server");
    let status: { state: string; error: string };
    try {
      status = await client.flowStatus(clientId, flowId);
    } catch (err) {
      this.deps.log?.(`[watson] ${caseId}: flow ${flowId} status read failed: ${msg(err)}`);
      return this.watch(caseId, p.id); // transient: try again until the deadline
    }
    const state = status.state.toUpperCase();
    if (state === "ERROR") return this.end(caseId, p.id, "failed", status.error || "the collection failed");
    if (state !== "FINISHED") return this.watch(caseId, p.id);
    await this.collect(caseId, p.id);
  }

  /** Claim the ingest, read and ingest the rows, record the result; then fill and notify. */
  private async collect(caseId: string, id: string): Promise<void> {
    if (await this.deps.isFrozen(caseId)) return this.end(caseId, id, "failed", "the case is closed");
    let claimed: WatsonVeloLaunchProposal | undefined;
    await this.deps.chatStore.update(caseId, (c) => {
      const p = findApplied(c, id);
      if (!p?.watch || p.watch.state !== "watching" || p.watch.ingested) return c;
      claimed = p;
      return withWatch(c, p, { ...p.watch, ingested: true });
    });
    if (!claimed) return; // another tick (or a restart) owns it
    let result: { rows: number; added: number; ingested?: WatsonIngested };
    try {
      const rows = await this.deps.readRows(caseId, claimed);
      if (rows.rows === 0) result = { rows: 0, added: 0 };
      else {
        const ingested = await this.deps.ingest(caseId, claimed, rows);
        if (isTextIngest(ingested.ingest))
          throw new Error(`the rows could not be parsed: ${ingested.ingest.reason}`);
        result = { rows: ingested.ingest.rows, added: ingested.ingest.added ?? 0, ingested };
      }
    } catch (err) {
      await this.deps.chatStore.update(caseId, (c) => failClaimed(c, id, msg(err)));
      return this.notify(caseId, claimed);
    }
    await this.deps.chatStore.update(caseId, (c) => withResult(c, id, result));
    await this.notify(caseId, claimed);
  }

  private async end(caseId: string, id: string, state: "timeout" | "failed", error?: string): Promise<void> {
    await this.deps.chatStore.update(caseId, (c) => withWatchEnded(c, id, state, error));
    const p = findApplied(await this.deps.chatStore.load(caseId), id);
    if (p) await this.notify(caseId, p);
  }

  /** Fill the outcome (idempotent), then save the `hunt` event with `notified`, once. */
  private async notify(caseId: string, p: WatsonVeloLaunchProposal): Promise<void> {
    const { flowId, clientId } = p.launched ?? {};
    const fresh = findApplied(await this.deps.chatStore.load(caseId), p.id);
    if (fresh?.watch?.state === "finished" && flowId && clientId) {
      await this.deps.fillOutcome(
        caseId,
        { flowId, clientId },
        {
          resultRows: fresh.watch.rows ?? 0,
          addedEvents: fresh.watch.added ?? 0,
          addedIocs: 0,
          collectedAt: new Date().toISOString(),
        },
      );
    }
    let sent = false;
    await this.deps.chatStore.update(caseId, (c) => {
      const r = withHuntNotified(c, p.id, new Date(this.deps.now?.() ?? Date.now()).toISOString());
      sent = r.sent;
      return r.chat;
    });
    if (!sent) return;
    this.deps.onChanged?.(caseId);
    this.deps.wake(caseId);
  }
}

/** The claimed launch failed while reading: end it (it was `watching` with `ingested`). */
function failClaimed(chat: WatsonChat, id: string, error: string): WatsonChat {
  const p = findApplied(chat, id);
  if (!p?.watch || p.watch.state !== "watching") return chat;
  return withWatch(chat, p, { ...p.watch, state: "failed", error });
}

/** The ingested rows on the chat (paste, system turn, held proposals) and the finished watch. */
function withResult(
  chat: WatsonChat,
  id: string,
  r: { rows: number; added: number; ingested?: WatsonIngested },
): WatsonChat {
  const p = findApplied(chat, id);
  if (!p?.watch || p.watch.state !== "watching") return chat;
  const before = new Set(chat.proposals.map((x) => x.id));
  const next = r.ingested ? withPasteIngest(chat, r.ingested.paste, r.ingested.ingest) : chat;
  const proposalIds = next.proposals.filter((x) => !before.has(x.id)).map((x) => x.id);
  const watch = { ...p.watch, state: "finished" as const, rows: r.rows, added: r.added };
  return withWatch(next, p, proposalIds.length ? { ...watch, proposalIds } : watch);
}

/**
 * The fleet hook (veloHunts.ts, after the collect fills the outcome): Watson's own hunt notes one
 * `hunt` event, found nothing included. Best effort and never throws — the collect has landed.
 */
export async function noteWatsonFleetResult(
  chatStore: Pick<WatsonChatStore, "update">,
  wake: (caseId: string) => void,
  caseId: string,
  result: { huntId: string; rows: number; added: number },
  log?: (line: string) => void,
): Promise<void> {
  try {
    let sent = false;
    const at = new Date().toISOString();
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
