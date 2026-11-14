import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  WATSON_REACT_REARM_MAX,
  WatsonReactor,
  type WatsonReactorDeps,
} from "../../../src/analysis/ai/watson/reactor.js";
import type { WatsonRoundInput } from "../../../src/analysis/ai/watson/round.js";
import { WatsonCostLimitReached } from "../../../src/analysis/ai/watson/round.js";
import { emptyWatsonChat, type WatsonChat } from "../../../src/analysis/ai/watson/types.js";
import { PresidioApprovalRequired } from "../../../src/analysis/presidio.js";
import type { Tag } from "../../../src/analysis/tags.js";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { WATSON_MAX_TURNS, WatsonChatStore } from "../../../src/analysis/ai/watson/chatStore.js";
import type { WatsonReply } from "../../../src/analysis/ai/watson/replySchema.js";
import { mergeOutcome } from "../../../src/analysis/ai/watson/roundOutcome.js";
import type { CaseStore } from "../../../src/storage/caseStore.js";
import { createWatsonCaseEvents } from "../../../src/composition/watsonCaseEvents.js";
import { watsonReactDelayMs } from "../../../src/composition/watsonReactorWiring.js";

// Spec §4.6: Watson reacts by itself to what lands in the case — one round after things go quiet,
// never per file, never chaining rounds, and an import reaction writes nothing to case sections.

const CASE = "c1";
const SEC = 1000;
const DELAY = 60 * SEC;

/** An in-memory chat store with the real one's serialized update(). */
class MemoryChats {
  chat: WatsonChat = emptyWatsonChat();
  private chain: Promise<unknown> = Promise.resolve();
  async load(): Promise<WatsonChat> {
    return this.chat;
  }
  update(_caseId: string, fn: (c: WatsonChat) => WatsonChat | Promise<WatsonChat>): Promise<WatsonChat> {
    const run = this.chain.then(async () => {
      this.chat = await fn(this.chat);
      return this.chat;
    });
    this.chain = run.catch(() => undefined);
    return run;
  }
  /** Wait for every queued write. */
  drain(): Promise<WatsonChat> {
    return this.update(CASE, (c) => c);
  }
}

const okReply = {
  message: "Noted.",
  workingOn: "",
  learned: "",
  questionUpdates: [],
  newQuestions: [],
  request: null,
  search: null,
  memory: "",
} as unknown as WatsonReply;

const analystTurn = { id: "wt-1", at: "2026-11-01T00:00:00Z", role: "analyst" as const, text: "hello" };

interface Setup {
  reactor: WatsonReactor;
  chats: MemoryChats;
  rounds: WatsonRoundInput[];
  busy: { value: boolean };
  deps: WatsonReactorDeps;
}

function setup(over: Partial<WatsonReactorDeps> = {}, opts: { analyst?: boolean } = {}): Setup {
  const chats = new MemoryChats();
  if (opts.analyst !== false) chats.chat = { ...chats.chat, turns: [analystTurn], analystEngaged: true };
  const rounds: WatsonRoundInput[] = [];
  const busy = { value: false };
  const deps: WatsonReactorDeps = {
    chatStore: chats,
    // A round consumes the pending events, as runWatsonRound does.
    runRound: async (_caseId, input) => {
      rounds.push(input);
      return chats.update(CASE, (c) => ({ ...c, pendingCaseEvents: [] }));
    },
    isAiEnabled: async () => true,
    isSynthesisBusy: () => busy.value,
    isFrozen: async () => false,
    delayMs: () => DELAY,
    ...over,
  };
  return { reactor: new WatsonReactor(deps), chats, rounds, busy, deps };
}

async function advance(s: Setup, ms: number): Promise<void> {
  await vi.advanceTimersByTimeAsync(ms);
  await s.reactor.settled();
  await s.chats.drain();
}

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
});
afterEach(() => {
  vi.useRealTimers();
});

describe("WatsonReactor", () => {
  it("40 imports one second apart → one round after the quiet window, with no writes", async () => {
    const s = setup();
    for (let i = 0; i < 40; i++) {
      s.reactor.note(CASE, { kind: "import", text: `An import finished (${i})` });
      await advance(s, SEC);
    }
    expect(s.rounds).toHaveLength(0);
    await advance(s, DELAY);
    expect(s.rounds).toEqual([{ text: "", reaction: true, allowWrites: false }]);
    await advance(s, DELAY * 3);
    expect(s.rounds, "a reaction never arms another timer itself").toHaveLength(1);
  });

  it("caps the pending events at 50 through the shared note", async () => {
    const s = setup({ delayMs: () => 0 });
    for (let i = 0; i < 70; i++) s.reactor.note(CASE, { kind: "import", text: `file ${i}` });
    const chat = await s.chats.drain();
    expect(chat.pendingCaseEvents).toHaveLength(50);
    expect(chat.pendingCaseEvents.at(-1)).toMatchObject({ kind: "import", text: "file 69" });
  });

  it("a synthesis busy at fire time → re-armed; the round runs after it ends", async () => {
    const s = setup();
    s.busy.value = true;
    s.reactor.note(CASE, { kind: "import", text: "An import finished" });
    await advance(s, DELAY);
    expect(s.rounds).toHaveLength(0);
    await advance(s, DELAY);
    expect(s.rounds).toHaveLength(0);
    s.busy.value = false;
    await advance(s, DELAY);
    expect(s.rounds).toHaveLength(1);
  });

  it(`re-arms at most ${WATSON_REACT_REARM_MAX} times, then reacts anyway`, async () => {
    const s = setup();
    s.busy.value = true;
    s.reactor.note(CASE, { kind: "notebook", text: "Analyst edited the notebook" });
    for (let i = 0; i < WATSON_REACT_REARM_MAX; i++) await advance(s, DELAY);
    expect(s.rounds).toHaveLength(0);
    await advance(s, DELAY);
    expect(s.rounds).toHaveLength(1);
  });

  it("a case where Watson was never used → no round, nothing written", async () => {
    const s = setup({}, { analyst: false });
    s.reactor.note(CASE, { kind: "import", text: "An import finished" });
    await advance(s, DELAY);
    expect(s.rounds).toHaveLength(0);
    expect(s.chats.chat.turns).toHaveLength(0);
  });

  it("a case whose analyst turns rolled off past the turn cap still reacts", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-watson-react-cap-"));
    const real = new WatsonChatStore({ stateDir: () => root } as unknown as CaseStore);
    await real.update(CASE, (c) => ({ ...c, turns: [analystTurn] }));
    const watsonTurns = Array.from({ length: WATSON_MAX_TURNS + 5 }, (_, i) => ({
      ...analystTurn,
      id: `w${i}`,
      role: "watson" as const,
    }));
    await real.update(CASE, (c) => ({ ...c, turns: [...c.turns, ...watsonTurns] }));
    const stored = await real.load(CASE);
    expect(stored.turns.some((t) => t.role === "analyst")).toBe(false);
    expect(stored.analystEngaged).toBe(true);

    const s = setup({}, { analyst: false });
    s.chats.chat = stored;
    s.reactor.note(CASE, { kind: "notebook", text: "Analyst edited the notebook" });
    await advance(s, DELAY);
    expect(s.rounds).toHaveLength(1);
  });

  it("a repeat of the shown event noted mid-round is kept for the next reaction", async () => {
    const s = setup();
    let release: () => void = () => undefined;
    const rounds: WatsonRoundInput[] = [];
    const reactor = new WatsonReactor({
      ...s.deps,
      now: () => Date.now() + rounds.length * 5000,
      // The real merge: remove each shown event once, by value.
      runRound: async (_c, input) => {
        const shown = [...(await s.chats.load()).pendingCaseEvents];
        rounds.push(input);
        if (rounds.length === 1) await new Promise<void>((r) => (release = r));
        return s.chats.update(CASE, (c) =>
          mergeOutcome(c, { reply: okReply, shownEvents: shown, questions: [] }, { usd: 0, tokens: 0 }, 1),
        );
      },
    });
    reactor.note(CASE, { kind: "import", text: "An import finished" });
    await vi.advanceTimersByTimeAsync(DELAY);
    reactor.note(CASE, { kind: "import", text: "An import finished" }); // import B lands mid-round
    await s.chats.drain();
    release();
    await reactor.settled();
    expect((await s.chats.drain()).pendingCaseEvents).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(DELAY);
    await reactor.settled();
    expect(rounds, "Watson reacts to import B too").toHaveLength(2);
  });

  it("AI off, a frozen case, or no pending events → no round", async () => {
    for (const over of [{ isAiEnabled: async () => false }, { isFrozen: async () => true }]) {
      const s = setup(over);
      s.reactor.note(CASE, { kind: "import", text: "An import finished" });
      await advance(s, DELAY);
      expect(s.rounds).toHaveLength(0);
    }
    const s = setup();
    s.reactor.note(CASE, { kind: "import", text: "An import finished" });
    await s.chats.drain();
    s.chats.chat = { ...s.chats.chat, pendingCaseEvents: [] }; // an analyst message read them first
    await advance(s, DELAY);
    expect(s.rounds).toHaveLength(0);
  });

  it("DFIR_AI_WATSON_REACT_DELAY_SEC=0 → never arms (the event is still noted)", async () => {
    const s = setup({ delayMs: () => watsonReactDelayMs({ DFIR_AI_WATSON_REACT_DELAY_SEC: "0" }) });
    s.reactor.note(CASE, { kind: "import", text: "An import finished" });
    await advance(s, DELAY * 10);
    expect(s.rounds).toHaveLength(0);
    expect(s.chats.chat.pendingCaseEvents).toHaveLength(1);
  });

  it("reads the delay setting: blank or junk → 60 s, a number → that many seconds", () => {
    expect(watsonReactDelayMs({})).toBe(60_000);
    expect(watsonReactDelayMs({ DFIR_AI_WATSON_REACT_DELAY_SEC: "" })).toBe(60_000);
    expect(watsonReactDelayMs({ DFIR_AI_WATSON_REACT_DELAY_SEC: "soon" })).toBe(60_000);
    expect(watsonReactDelayMs({ DFIR_AI_WATSON_REACT_DELAY_SEC: "-5" })).toBe(60_000);
    expect(watsonReactDelayMs({ DFIR_AI_WATSON_REACT_DELAY_SEC: "30" })).toBe(30_000);
    expect(watsonReactDelayMs({ DFIR_AI_WATSON_REACT_DELAY_SEC: "0" })).toBe(0);
  });

  it("a Presidio hold pauses reactions until an analyst message clears the pause", async () => {
    const held = new PresidioApprovalRequired([]);
    const s = setup({
      runRound: async () => {
        throw held;
      },
    });
    const changed = vi.fn();
    const reactor = new WatsonReactor({ ...s.deps, onChanged: changed });
    reactor.note(CASE, { kind: "notebook", text: "Analyst edited the notebook" });
    await vi.advanceTimersByTimeAsync(DELAY);
    await reactor.settled();
    const chat = await s.chats.drain();
    expect(chat.reactionsPaused).toBe("presidio");
    const turn = chat.turns.at(-1);
    expect(turn?.role).toBe("system");
    expect(turn?.text).toMatch(/^Watson paused automatic reactions: .+\. Send a message to resume\.$/);
    expect(changed).toHaveBeenCalledWith(CASE);

    // A later note while paused → no round.
    const runs = vi.fn(s.deps.runRound);
    const paused = new WatsonReactor({ ...s.deps, runRound: runs });
    paused.note(CASE, { kind: "notebook", text: "Analyst edited it again" });
    await vi.advanceTimersByTimeAsync(DELAY);
    await paused.settled();
    expect(runs).not.toHaveBeenCalled();

    // The analyst's next message clears the pause (round.ts); reactions resume.
    s.chats.chat = { ...s.chats.chat, reactionsPaused: undefined };
    const resumed = setup();
    resumed.chats.chat = s.chats.chat;
    resumed.reactor.note(CASE, { kind: "notebook", text: "And once more" });
    await advance(resumed, DELAY);
    expect(resumed.rounds).toHaveLength(1);
  });

  it("a cost or token limit on a reaction pauses with the limit reason", async () => {
    const s = setup({
      runRound: async () => {
        throw new WatsonCostLimitReached("cost limit ($5.00)");
      },
    });
    s.reactor.note(CASE, { kind: "notebook", text: "Analyst edited the notebook" });
    await advance(s, DELAY);
    expect(s.chats.chat.reactionsPaused).toBe("limit");
    expect(s.chats.chat.turns.at(-1)?.text).toContain("cost limit ($5.00)");
  });

  it("events arriving during a reaction arm a new window", async () => {
    let release: () => void = () => undefined;
    const s = setup();
    const rounds: WatsonRoundInput[] = [];
    const reactor = new WatsonReactor({
      ...s.deps,
      runRound: async (_c, input) => {
        rounds.push(input);
        await new Promise<void>((r) => (release = r));
        return s.chats.update(CASE, (c) => ({ ...c, pendingCaseEvents: c.pendingCaseEvents.slice(1) }));
      },
    });
    reactor.note(CASE, { kind: "notebook", text: "first" });
    await vi.advanceTimersByTimeAsync(DELAY);
    reactor.note(CASE, { kind: "star", text: "Analyst starred 1 event: e1" });
    release();
    await reactor.settled();
    await vi.advanceTimersByTimeAsync(DELAY);
    release();
    await reactor.settled();
    expect(rounds).toHaveLength(2);
  });

  it("stop() cancels every armed timer", async () => {
    const s = setup();
    s.reactor.note(CASE, { kind: "import", text: "An import finished" });
    s.reactor.stop();
    await advance(s, DELAY * 2);
    expect(s.rounds).toHaveLength(0);
  });
});

describe("star detection (createWatsonCaseEvents)", () => {
  const star = (id: string): Tag => ({
    id: `t-${id}`,
    targetType: "event",
    targetId: id,
    label: "starred",
    author: "analyst",
    createdAt: "2026-11-01T00:00:00Z",
  });
  const taggerTag = (id: string): Tag => ({
    id: `t-x-${id}`,
    targetType: "event",
    targetId: id,
    label: "lolbin",
    author: "tagger:rule",
    createdAt: "2026-11-01T00:00:00Z",
  });

  it("a tagger tag write → no round; a new star → one round with writes allowed", async () => {
    const s = setup();
    let tags: Tag[] = [star("e1")];
    const events = createWatsonCaseEvents(s.chats, { load: async () => tags });
    events.attach(s.reactor);

    events.tagsChanged(CASE); // first sight: recorded, no wake
    await advance(s, DELAY);
    tags = [...tags, taggerTag("e2"), taggerTag("e3")];
    events.tagsChanged(CASE); // the tagger: no new star
    await advance(s, DELAY);
    expect(s.rounds).toHaveLength(0);

    tags = [...tags, star("e4")];
    events.tagsChanged(CASE);
    await advance(s, DELAY);
    expect(s.rounds).toEqual([{ text: "", reaction: true, allowWrites: true }]);
  });

  it("an import wakes Watson; an import undo or redo is only noted and never wakes it", async () => {
    const s = setup();
    const events = createWatsonCaseEvents(s.chats);
    events.attach(s.reactor);
    events.importChanged(CASE, "undo");
    events.importChanged(CASE, "redo");
    await advance(s, DELAY);
    expect(s.rounds).toHaveLength(0);
    expect(s.chats.chat.pendingCaseEvents).toMatchObject([
      { kind: "other", text: "An import was undone" },
      { kind: "other", text: "An import undo was redone" },
    ]);
    events.importChanged(CASE);
    await advance(s, DELAY);
    expect(s.rounds).toEqual([{ text: "", reaction: true, allowWrites: false }]);
  });

  it("a notebook edit wakes Watson only when the case's AI control includes the notebook", async () => {
    const s = setup();
    let includeNotebook = false;
    const events = createWatsonCaseEvents(s.chats, undefined, { load: async () => ({ includeNotebook }) });
    events.attach(s.reactor);
    events.notebookChanged(CASE);
    await advance(s, DELAY);
    expect(s.rounds).toHaveLength(0);
    expect(s.chats.chat.pendingCaseEvents).toMatchObject([
      { kind: "other", text: "Analyst edited the notebook" },
    ]);
    includeNotebook = true;
    events.notebookChanged(CASE);
    await advance(s, DELAY);
    expect(s.rounds).toEqual([{ text: "", reaction: true, allowWrites: true }]);
  });

  it("a notebook edit is only noted when the AI control cannot be read", async () => {
    const s = setup();
    const events = createWatsonCaseEvents(s.chats, undefined, {
      load: async () => {
        throw new Error("unreadable");
      },
    });
    events.attach(s.reactor);
    events.notebookChanged(CASE);
    await advance(s, DELAY);
    expect(s.rounds).toHaveLength(0);
    expect(s.chats.chat.pendingCaseEvents).toMatchObject([
      { kind: "other", text: "Analyst edited the notebook" },
    ]);
  });

  it("without a reactor, events are only noted (phase 1)", async () => {
    const chats = new MemoryChats();
    const events = createWatsonCaseEvents(chats);
    events.note(CASE, { kind: "import", text: "An import finished" });
    const chat = await chats.drain();
    expect(chat.pendingCaseEvents).toMatchObject([{ kind: "import", text: "An import finished" }]);
  });
});
