import type { WatsonChatStore } from "../analysis/ai/watson/chatStore.js";
import { isTextIngest, type WatsonPasteIngest } from "../analysis/ai/watson/pasteIngestChat.js";
import type { WatsonPaste, WatsonVeloLaunchProposal } from "../analysis/ai/watson/types.js";
import {
  findApplied,
  openWatches,
  WATSON_WATCH_POLL_MS,
  withHuntNotified,
  withWatch,
  withWatchEnded,
} from "../analysis/ai/watson/velo/launchWatch.js";
import type { WatsonFlowWatch } from "../analysis/ai/watson/velo/launchTypes.js";
import type { HuntCollectResult } from "../analysis/huntOutcomes.js";
import type { StagedIngest, WatsonIngestStage } from "./watsonFlowStage.js";
import { failClaimed, withResult } from "./watsonVeloResultsChat.js";

export { noteWatsonFleetResult } from "./watsonVeloResultsChat.js";

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
  /** The read was cut by the collection row cap. */
  truncated?: true;
}

export interface WatsonFlowWatcherDeps {
  chatStore: Pick<WatsonChatStore, "load" | "update">;
  /** The Velociraptor client of the server set the launch went to, or null when it is gone. */
  velo(caseId: string, p: WatsonVeloLaunchProposal): WatsonFlowClient | null;
  /** Read every row of a finished flow (all its sources) as importer text. */
  readRows(caseId: string, p: WatsonVeloLaunchProposal): Promise<WatsonFlowRows>;
  /** Store the rows as evidence and ingest them like a chat paste. */
  ingest(caseId: string, p: WatsonVeloLaunchProposal, rows: WatsonFlowRows): Promise<WatsonIngested>;
  /** Fill the collection's hunt outcome by flow (a no-op once collected). */
  fillOutcome(caseId: string, ref: { flowId: string; clientId: string }, r: HuntCollectResult): Promise<void>;
  /** Where an ingest result waits until the chat save records it (G7). Optional for tests. */
  stage?: WatsonIngestStage;
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

export const NO_LAUNCH_SERVER =
  "The Velociraptor server this collection was launched on is no longer available";

/** Past the deadline, a status or row read that keeps failing is retried this much longer. */
export const WATSON_WATCH_GRACE_MS = 60 * 60_000;
/** Ticks that throw (a failing chat store) in a row before the watch gives up until the next boot. */
export const WATSON_WATCH_MAX_FAILED_TICKS = 10;

const where = (p: WatsonVeloLaunchProposal): string =>
  `flow ${p.launched?.flowId ?? "?"}${p.hostname ? ` on ${p.hostname}` : ""}`;
const notImported = (p: WatsonVeloLaunchProposal, why: string): string =>
  `${why} (${where(p)}). The results are in Velociraptor and may not have been imported into the case`;
const interruptedImport = (p: WatsonVeloLaunchProposal): string =>
  `Watson was interrupted while importing the results of ${where(p)}: rows may have been imported, ` +
  "but rows the tagger graded above Info were not offered for approval. " +
  "Re-import the flow from Velociraptor to get them";

type Watched = WatsonVeloLaunchProposal & { watch: NonNullable<WatsonVeloLaunchProposal["watch"]> };

export class WatsonFlowWatcher implements WatsonFlowWatch {
  private readonly timers = new Map<string, ReturnType<typeof setTimeout>>();
  private readonly failedTicks = new Map<string, number>();
  private readonly collecting = new Set<string>();
  private readonly inFlight = new Set<Promise<void>>();
  private stopped = false;

  constructor(private readonly deps: WatsonFlowWatcherDeps) {}

  /** Start (or keep) the poll for one applied collection. */
  watch(caseId: string, proposalId: string): void {
    const key = keyOf(caseId, proposalId);
    if (this.stopped || this.timers.has(key)) return;
    const set = this.deps.setTimer ?? setTimeout;
    const timer = set(() => {
      this.timers.delete(key);
      this.track(
        this.tick(caseId, proposalId).then(
          () => this.ticked(key),
          (err: unknown) => this.failed(caseId, proposalId, err),
        ),
      );
    }, this.deps.pollMs ?? WATSON_WATCH_POLL_MS);
    timer.unref?.();
    this.timers.set(key, timer);
  }

  /** At startup, for one case: notify ended watches, read expired ones once, resume the rest. */
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

  private ticked(key: string): void {
    this.failedTicks.delete(key);
  }

  /** A tick that threw polls again, up to the cap; then it waits for the next boot, logged once. */
  private failed(caseId: string, id: string, err: unknown): void {
    const key = keyOf(caseId, id);
    const n = (this.failedTicks.get(key) ?? 0) + 1;
    this.failedTicks.set(key, n);
    if (n < WATSON_WATCH_MAX_FAILED_TICKS) return this.watch(caseId, id);
    this.failedTicks.delete(key);
    this.deps.log?.(
      `[watson] ${caseId}: gave up watching launch ${id} after ${n} failed attempts (${msg(err)}); it resumes on the next start`,
    );
  }

  private async tick(caseId: string, id: string): Promise<void> {
    if (!this.stopped) await this.tickOnce(caseId, id, false);
  }

  private now(): number {
    return this.deps.now?.() ?? Date.now();
  }

  private async tickOnce(caseId: string, id: string, startup: boolean): Promise<void> {
    if (this.collecting.has(keyOf(caseId, id))) return;
    const p = findApplied(await this.deps.chatStore.load(caseId), id);
    if (!p?.watch) return;
    const w = p as Watched;
    if (w.watch.state !== "watching") return this.notify(caseId, w); // ended earlier, event not yet sent
    if (w.watch.ingesting) return this.finishStaged(caseId, w);
    if (w.watch.ingested) await this.release(caseId, id); // claimed, but the ingest was never called
    const past = this.now() >= Date.parse(w.watch.deadline);
    if (startup && !past) return this.watch(caseId, id);
    await this.poll(caseId, w, past);
  }

  /** Before the deadline, poll again; after it, keep retrying a failing read for the grace period. */
  private retryOr(caseId: string, p: Watched, end: () => Promise<void>): Promise<void> | void {
    if (this.now() < Date.parse(p.watch.deadline) + WATSON_WATCH_GRACE_MS) return this.watch(caseId, p.id);
    return end();
  }

  /** Read the flow's status; past the deadline a FINISHED flow is still collected, else it times out. */
  private async poll(caseId: string, p: Watched, past: boolean): Promise<void> {
    const { flowId = "", clientId = "" } = p.launched ?? {};
    const client = this.deps.velo(caseId, p);
    if (!client) return this.end(caseId, p.id, "failed", notImported(p, NO_LAUNCH_SERVER));
    let status: { state: string; error: string; rows: number };
    try {
      status = await client.flowStatus(clientId, flowId);
    } catch (err) {
      this.deps.log?.(`[watson] ${caseId}: flow ${flowId} status read failed: ${msg(err)}`);
      const why = notImported(p, "Watson could not read the collection's status from Velociraptor");
      return this.retryOr(caseId, p, () => this.end(caseId, p.id, "timeout", why));
    }
    const state = status.state.toUpperCase();
    if (state === "ERROR") {
      return this.end(
        caseId,
        p.id,
        "failed",
        `the collection failed on the endpoint (${where(p)}): ${status.error || "no reason given"}`,
      );
    }
    if (state !== "FINISHED") return past ? this.end(caseId, p.id, "timeout") : this.watch(caseId, p.id);
    const key = keyOf(caseId, p.id);
    this.collecting.add(key);
    try {
      await this.collect(caseId, p, status.rows);
    } finally {
      this.collecting.delete(key);
    }
  }

  /** Claim, read the rows (a read failure releases the claim), mark ingesting, ingest, record. */
  private async collect(caseId: string, p: Watched, reported: number): Promise<void> {
    if (await this.deps.isFrozen(caseId)) {
      return this.end(
        caseId,
        p.id,
        "failed",
        notImported(p, "The case is closed, so Watson did not import the results"),
      );
    }
    const claimed = await this.claim(caseId, p.id, { ingested: true });
    if (!claimed) return; // another tick (or a restart) owns it
    let rows: WatsonFlowRows;
    try {
      rows = await this.deps.readRows(caseId, claimed);
      // Velociraptor counted rows the read did not return: never call that "found nothing".
      if (rows.rows === 0 && reported > 0)
        throw new Error(`${reported} rows were collected but none could be read`);
    } catch (err) {
      await this.release(caseId, p.id);
      this.deps.log?.(`[watson] ${caseId}: reading ${where(p)} failed: ${msg(err)}`);
      return this.retryOr(caseId, p, () =>
        this.end(caseId, p.id, "failed", notImported(p, `Watson could not read the results: ${msg(err)}`)),
      );
    }
    const cut = rows.truncated ? { truncated: true as const, total: reported } : {};
    if (rows.rows === 0) {
      await this.deps.chatStore.update(caseId, (c) => withResult(c, p.id, { rows: 0, added: 0 }));
      return this.notify(caseId, p);
    }
    if (!(await this.claim(caseId, p.id, { ingesting: true }))) return;
    let result: { rows: number; added: number; ingested: WatsonIngested };
    try {
      const ingested = await this.deps.ingest(caseId, claimed, rows);
      if (isTextIngest(ingested.ingest))
        throw new Error(`the rows could not be parsed: ${ingested.ingest.reason}`);
      result = { rows: ingested.ingest.rows, added: ingested.ingest.added ?? 0, ingested };
    } catch (err) {
      const why = notImported(p, `Watson could not import the results: ${msg(err)}`);
      await this.deps.chatStore.update(caseId, (c) => failClaimed(c, p.id, why));
      return this.notify(caseId, p);
    }
    const staged = { flowId: p.launched?.flowId ?? "", ...result, ...cut };
    await this.deps.stage?.save(caseId, p.id, staged).catch((err: unknown) => {
      this.deps.log?.(`[watson] ${caseId}: staging the result of ${where(p)} failed: ${msg(err)}`);
    });
    await this.record(caseId, p, staged);
  }

  /** The chat save of an ingested result (once: withResult needs `watching`), then the event. */
  private async record(caseId: string, p: WatsonVeloLaunchProposal, r: Omit<StagedIngest, "flowId">) {
    await this.deps.chatStore.update(caseId, (c) => withResult(c, p.id, r));
    await this.deps.stage?.clear(caseId, p.id).catch(() => {});
    await this.notify(caseId, p);
  }

  /** An ingest that ran but whose chat save did not: finish it from the stage, or report it lost. */
  private async finishStaged(caseId: string, p: Watched): Promise<void> {
    const staged = await this.deps.stage?.load(caseId, p.id, p.launched?.flowId ?? "");
    if (staged) return this.record(caseId, p, staged);
    return this.end(caseId, p.id, "failed", interruptedImport(p));
  }

  /** Set a flag on a watching launch, once; the launch as claimed, or undefined when another owns it. */
  private async claim(
    caseId: string,
    id: string,
    flag: { ingested: true } | { ingesting: true },
  ): Promise<Watched | undefined> {
    let claimed: Watched | undefined;
    const name = "ingested" in flag ? "ingested" : "ingesting";
    await this.deps.chatStore.update(caseId, (c) => {
      const p = findApplied(c, id);
      if (!p?.watch || p.watch.state !== "watching" || p.watch[name]) return c;
      if (name === "ingesting" && !p.watch.ingested) return c;
      claimed = { ...p, watch: { ...p.watch, ...flag } };
      return withWatch(c, p, claimed.watch);
    });
    return claimed;
  }

  /** Drop a claim whose ingest was never called (the read failed, or the server stopped mid-read). */
  private async release(caseId: string, id: string): Promise<void> {
    await this.deps.chatStore.update(caseId, (c) => {
      const p = findApplied(c, id);
      if (!p?.watch || p.watch.state !== "watching" || !p.watch.ingested || p.watch.ingesting) return c;
      const { ingested: _claim, ...watch } = p.watch;
      return withWatch(c, p, watch);
    });
  }

  private async end(caseId: string, id: string, state: "timeout" | "failed", error?: string): Promise<void> {
    await this.deps.chatStore.update(caseId, (c) => withWatchEnded(c, id, state, error));
    const p = findApplied(await this.deps.chatStore.load(caseId), id);
    if (p) await this.notify(caseId, p);
  }

  /** The outcome fill is best effort (as in the fleet collect): a failure never holds the event back. */
  private async fill(caseId: string, ref: { flowId: string; clientId: string }, rows: number, added: number) {
    try {
      const at = new Date().toISOString();
      await this.deps.fillOutcome(caseId, ref, {
        resultRows: rows,
        addedEvents: added,
        addedIocs: 0,
        collectedAt: at,
      });
    } catch (err) {
      this.deps.log?.(`[watson] ${caseId}: hunt outcome fill failed for flow ${ref.flowId}: ${msg(err)}`);
    }
  }

  /** Fill the outcome (idempotent), then save the `hunt` event with `notified`, once. */
  private async notify(caseId: string, p: WatsonVeloLaunchProposal): Promise<void> {
    const { flowId, clientId } = p.launched ?? {};
    const fresh = findApplied(await this.deps.chatStore.load(caseId), p.id);
    if (fresh?.watch?.state === "finished" && flowId && clientId) {
      await this.fill(caseId, { flowId, clientId }, fresh.watch.rows ?? 0, fresh.watch.added ?? 0);
    }
    let sent = false;
    await this.deps.chatStore.update(caseId, (c) => {
      const r = withHuntNotified(c, p.id, new Date(this.now()).toISOString());
      sent = r.sent;
      return r.chat;
    });
    if (!sent) return;
    this.deps.onChanged?.(caseId);
    this.deps.wake(caseId);
  }
}

const keyOf = (caseId: string, id: string): string => `${caseId}\u0000${id}`;

const msg = (err: unknown): string => (err instanceof Error ? err.message : String(err));
