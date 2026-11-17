import { describe, expect, it } from "vitest";
import {
  WATSON_AUTO_SEARCHES_KEPT,
  focusOf,
  judgeRound,
  lookupKey,
  openItems,
  searchKey,
  type WatsonRoundWork,
} from "../../../src/analysis/ai/watson/autoProgress.js";
import { emptyWatsonChat } from "../../../src/analysis/ai/watson/types.js";
import { emptyState, type InvestigationState } from "../../../src/analysis/stateTypes.js";

const state = (): InvestigationState => ({
  ...emptyState("c"),
  keyQuestions: [
    { id: "q1", question: "Q1?", status: "partial", answer: "", pointer: "p1" },
    { id: "q2", question: "Q2?", status: "answered", answer: "a", pointer: "" },
    { id: "q3", question: "Q3?", status: "unanswerable", answer: "", pointer: "" },
  ],
  nextSteps: [{ id: "n1", priority: "high", action: "Do it", rationale: "r", pointer: "host" }],
});

const work = (w: Partial<WatsonRoundWork> = {}): WatsonRoundWork => ({
  reaction: true,
  card: false,
  ranSearches: [],
  focusIds: [],
  workingOn: "",
  ...w,
});

describe("autoProgress", () => {
  it("open items are unknown/partial questions and every next step", () => {
    expect(openItems(state()).map((i) => i.id)).toEqual(["q1", "n1"]);
    expect(openItems(null)).toEqual([]);
  });

  it("search keys ignore case, order and repeats; lookup keys ignore list order", () => {
    expect(searchKey("p", ["B", "a", "a"])).toBe(searchKey("p", ["a", "b"]));
    expect(searchKey("p", ["a"])).not.toBe(searchKey("q", ["a"]));
    expect(lookupKey({ eventIds: ["e2", "e1"] })).toBe(lookupKey({ eventIds: ["e1", "e2"] }));
    expect(lookupKey({ text: "x" })).not.toBe(lookupKey({ text: "x", source: "supertimeline" }));
  });

  it("focus comes from focusIds and whole-word ids in workingOn, never a part of a word", () => {
    const open = openItems(state());
    expect(focusOf(work({ focusIds: ["q1"] }), open).map((i) => i.id)).toEqual(["q1"]);
    expect(focusOf(work({ workingOn: "n1 (high): do it" }), open).map((i) => i.id)).toEqual(["n1"]);
    expect(focusOf(work({ workingOn: "n10 and q1x" }), open)).toEqual([]);
  });

  it("an item is set aside once; a repeat of a set-aside focus is stuck, not a new move", () => {
    let chat = emptyWatsonChat();
    const step = (w: Partial<WatsonRoundWork>) => {
      const r = judgeRound(chat, state(), work(w));
      chat = r.chat;
      return r.verdict.kind;
    };
    expect(step({ focusIds: ["q1"] })).toBe("go");
    expect(step({ focusIds: ["q1"] })).toBe("moveOn");
    expect(chat.autoSetAside).toEqual(["q1"]);
    expect(step({ focusIds: ["q1"] })).toBe("go");
    expect(step({ focusIds: ["q1"] })).toBe("stuck");
  });

  it("searches count as progress only up to the per-chain cap, so Auto always ends", () => {
    const full = Array.from({ length: WATSON_AUTO_SEARCHES_KEPT }, (_, i) => `k${i}`);
    const chat = { ...emptyWatsonChat(), autoSearchesRun: full, autoIdleRounds: 1, autoIdleFocus: ["n1"] };
    const r = judgeRound(chat, state(), work({ ranSearches: ["new"], focusIds: ["n1"] }));
    expect(r.verdict.kind).toBe("moveOn");
    expect(r.chat.autoSearchesRun).toHaveLength(WATSON_AUTO_SEARCHES_KEPT);
  });

  it("the last open item set aside ends Auto with every open item listed", () => {
    const chat = { ...emptyWatsonChat(), autoSetAside: ["q1"], autoIdleRounds: 1, autoIdleFocus: ["n1"] };
    const r = judgeRound(chat, state(), work({ focusIds: ["n1"] }));
    expect(r.verdict).toEqual({ kind: "done", left: openItems(state()) });
  });

  it("a request for a person sets its item aside at once, with no idle rounds", () => {
    const r = judgeRound(emptyWatsonChat(), state(), work({ focusIds: ["q1"], asked: "the file x" }));
    expect(r.verdict).toMatchObject({ kind: "moveOn", asked: true });
    expect(r.chat.autoSetAside).toEqual(["q1"]);
  });

  it("a request for a person also sets aside the items it names by id (user report of 2026-11-17)", () => {
    const r = judgeRound(
      emptyWatsonChat(),
      state(),
      work({ workingOn: "", asked: "the owner must confirm step n1" }),
    );
    expect(r.verdict).toMatchObject({ kind: "moveOn", asked: true });
    expect(r.chat.autoSetAside).toEqual(["n1"]);
  });

  it("a request that names an item sets aside only that item, not the one Watson worked on", () => {
    const r = judgeRound(
      emptyWatsonChat(),
      state(),
      work({ focusIds: ["q1"], asked: "the owner must confirm n1" }),
    );
    expect(r.chat.autoSetAside).toEqual(["n1"]);
  });

  it("new evidence (an import) clears the set-aside items and counts as progress", () => {
    const chat = { ...emptyWatsonChat(), autoSetAside: ["q1"], autoIdleRounds: 1 };
    const r = judgeRound(chat, state(), work({ newEvidence: true }));
    expect(r.verdict.kind).toBe("go");
    expect(r.chat.autoSetAside).toBeUndefined();
    expect(r.chat.autoIdleRounds).toBeUndefined();
  });

  it("open steps are only the ones the prompt shows (the 15 most urgent)", () => {
    const many = Array.from({ length: 20 }, (_, i) => ({
      id: `s${i}`,
      priority: i < 5 ? "low" : "high",
      action: "a",
      rationale: "r",
      pointer: "",
    }));
    const st = { ...state(), nextSteps: many } as InvestigationState;
    const ids = openItems(st)
      .filter((i) => i.kind === "step")
      .map((i) => i.id);
    expect(ids).toHaveLength(15);
    expect(ids).not.toContain("s0");
  });

  it("the idle count is per item: one idle round each on two items sets neither aside", () => {
    let chat = emptyWatsonChat();
    const step = (w: Partial<WatsonRoundWork>) => {
      const r = judgeRound(chat, state(), work(w));
      chat = r.chat;
      return r.verdict.kind;
    };
    expect(step({ focusIds: ["q1"] })).toBe("go");
    expect(step({ focusIds: ["n1"] })).toBe("go");
    expect(chat.autoSetAside).toBeUndefined();
    expect(chat.autoIdleFocus).toEqual(["n1"]);
    expect(step({ focusIds: ["n1"] })).toBe("moveOn");
    expect(chat.autoSetAside).toEqual(["n1"]);
  });

  it("a round on two items, then one of them, sets aside only the one worked twice", () => {
    const st = {
      ...state(),
      keyQuestions: [
        ...state().keyQuestions,
        { id: "q4", question: "Q4?", status: "unknown" as const, answer: "", pointer: "" },
      ],
    };
    let chat = emptyWatsonChat();
    chat = judgeRound(chat, st, work({ focusIds: ["q1", "n1"] })).chat;
    const r = judgeRound(chat, st, work({ focusIds: ["n1"] }));
    expect(r.verdict).toMatchObject({ kind: "moveOn" });
    expect(r.chat.autoSetAside).toEqual(["n1"]);
  });
});
