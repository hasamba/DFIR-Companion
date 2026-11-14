import { PresidioApprovalRequired } from "../../presidio.js";
import { withCaseEvent, type WatsonCaseEventNote } from "./caseEvents.js";
import type { WatsonChatStore } from "./chatStore.js";
import { WatsonCostLimitReached, type WatsonRoundInput } from "./round.js";
import { pausedReactions } from "./reactionState.js";
import type { WatsonChat, WatsonReactionsPaused } from "./types.js";

// Automatic reaction rounds (spec §4.6). Every case event is noted on the chat and (re)starts a
// per-case quiet window; when it ends with no new event, Watson runs ONE round on everything that
// arrived. Never one round per file, and a reaction never arms another window itself: only a new
// event does. An import among the events means the round may propose no writes (spec §4.4).

/** A synthesis still running when the window ends puts the reaction off at most this many times. */
export const WATSON_REACT_REARM_MAX = 20;

export interface WatsonReactorDeps {
  chatStore: Pick<WatsonChatStore, "load" | "update">;
  runRound(caseId: string, input: WatsonRoundInput): Promise<WatsonChat>;
  /** AI on for the case, and Watson has a model. */
  isAiEnabled(caseId: string): Promise<boolean>;
  /** A synthesis (or a Second Look that re-synthesizes) is running, queued or scheduled. */
  isSynthesisBusy(caseId: string): boolean;
  isFrozen(caseId: string): Promise<boolean>;
  /** The quiet window, read on every event; 0 turns reactions off. */
  delayMs(): number;
  now?(): number;
  setTimer?: typeof setTimeout;
  /** The chat changed (a reaction or a pause turn): tell the dashboards. */
  onChanged?(caseId: string): void;
  log?(line: string): void;
}

interface Armed {
  timer: ReturnType<typeof setTimeout>;
  rearms: number;
}

const PRESIDIO_REASON = "Presidio found values that need your approval before they go to the AI";

function pauseOf(err: unknown): { why: WatsonReactionsPaused; reason: string } | null {
  if (err instanceof PresidioApprovalRequired) return { why: "presidio", reason: PRESIDIO_REASON };
  if (err instanceof WatsonCostLimitReached) {
    return { why: "limit", reason: err.message.replace(/\.\s*Raise the limit.*$/s, "") };
  }
  return null;
}

/** Whether a fire should run a round now, wait for a synthesis, or do nothing. */
type Decision = "run" | "wait" | "skip";

export class WatsonReactor {
  private readonly armed = new Map<string, Armed>();
  private readonly inFlight = new Set<Promise<void>>();
  private stopped = false;

  constructor(private readonly deps: WatsonReactorDeps) {}

  /** Note one case event and (re)start the case's quiet window. */
  note(caseId: string, event: WatsonCaseEventNote): void {
    const at = new Date(this.deps.now?.() ?? Date.now()).toISOString();
    void this.deps.chatStore
      .update(caseId, (chat) => withCaseEvent(chat, event, at))
      .catch((err: unknown) => this.warn(caseId, "could not note a case event", err));
    this.arm(caseId, 0);
  }

  /** (Re)start the quiet window for an event the caller has already saved on the chat itself. */
  wake(caseId: string): void {
    this.arm(caseId, 0);
  }

  /** Cancel every window (server shutdown); later events are only noted. */
  stop(): void {
    this.stopped = true;
    for (const { timer } of this.armed.values()) clearTimeout(timer);
    this.armed.clear();
  }

  /** Resolves once every reaction that has started has finished (tests, shutdown). */
  async settled(): Promise<void> {
    while (this.inFlight.size) await Promise.all([...this.inFlight]);
  }

  private arm(caseId: string, rearms: number): void {
    const prev = this.armed.get(caseId);
    if (prev) clearTimeout(prev.timer);
    this.armed.delete(caseId);
    const delay = this.deps.delayMs();
    if (this.stopped || delay <= 0) return;
    const set = this.deps.setTimer ?? setTimeout;
    const timer = set(() => this.fire(caseId, rearms), delay);
    timer.unref?.();
    this.armed.set(caseId, { timer, rearms });
  }

  private fire(caseId: string, rearms: number): void {
    this.armed.delete(caseId);
    const run = this.react(caseId, rearms).catch((err: unknown) =>
      this.warn(caseId, "automatic reaction failed", err),
    );
    this.inFlight.add(run);
    void run.finally(() => this.inFlight.delete(run));
  }

  private async decide(caseId: string, chat: WatsonChat, rearms: number): Promise<Decision> {
    if (this.stopped || this.deps.delayMs() <= 0) return "skip";
    // Watson unused on this case, paused, or nothing left (an analyst message already read it).
    if (!chat.analystEngaged) return "skip";
    if (chat.reactionsPaused || chat.pendingCaseEvents.length === 0) return "skip";
    if (!(await this.deps.isAiEnabled(caseId)) || (await this.deps.isFrozen(caseId))) return "skip";
    // An import with AI on starts a synthesis: react to its result, not before it.
    if (this.deps.isSynthesisBusy(caseId) && rearms < WATSON_REACT_REARM_MAX) return "wait";
    return "run";
  }

  private async react(caseId: string, rearms: number): Promise<void> {
    const chat = await this.deps.chatStore.load(caseId);
    const decision = await this.decide(caseId, chat, rearms);
    if (decision === "wait") {
      if (!this.armed.has(caseId)) this.arm(caseId, rearms + 1); // a new event re-armed it already
      return;
    }
    if (decision === "skip") return;
    const allowWrites = !chat.pendingCaseEvents.some((e) => e.kind === "import");
    const held = chat.pendingCaseEvents.flatMap((e) => (e.kind === "hunt" ? (e.proposalIds ?? []) : []));
    const input = {
      text: "",
      reaction: true,
      allowWrites,
      ...(held.length ? { heldProposalIds: held } : {}),
    };
    try {
      await this.deps.runRound(caseId, input);
    } catch (err) {
      const pause = pauseOf(err);
      if (!pause) throw err;
      await this.pause(caseId, pause.why, pause.reason);
    } finally {
      this.deps.onChanged?.(caseId);
    }
  }

  private async pause(caseId: string, why: WatsonReactionsPaused, reason: string): Promise<void> {
    const text = `Watson paused automatic reactions: ${reason}. Send a message to resume.`;
    await this.deps.chatStore.update(caseId, (c) => pausedReactions(c, why, text));
  }

  private warn(caseId: string, what: string, err: unknown): void {
    this.deps.log?.(`[watson] ${caseId}: ${what}: ${err instanceof Error ? err.message : String(err)}`);
  }
}
