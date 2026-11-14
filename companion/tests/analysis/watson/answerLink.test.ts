import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { ActivityLogStore } from "../../../src/analysis/activityLog.js";
import {
  addAnswerAsQuestion,
  normalizeQuestionText,
  WatsonQuestionOnBoard,
} from "../../../src/analysis/ai/watson/addQuestion.js";
import { WatsonChatStore } from "../../../src/analysis/ai/watson/chatStore.js";
import { WatsonProposalConflict } from "../../../src/analysis/ai/watson/proposals.js";
import type { WatsonAnswer } from "../../../src/analysis/ai/watson/types.js";
import { StateLock } from "../../../src/analysis/stateLock.js";
import { StateStore } from "../../../src/analysis/stateStore.js";
import { emptyState, type InvestigationQuestion } from "../../../src/analysis/stateTypes.js";
import { CaseStore } from "../../../src/storage/caseStore.js";

// Task 10: Watson must not offer to add a key question that is already on the board.

const CASE = "c1";
const ON_BOARD: InvestigationQuestion = {
  id: "q-ia",
  question: "What was the initial access vector?",
  status: "unknown",
  answer: "",
  pointer: "",
};

async function harness(answer: Partial<WatsonAnswer>) {
  const root = await mkdtemp(join(tmpdir(), "dfir-watson-link-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: CASE, name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(cases);
  await stateStore.save({ ...emptyState(CASE), keyQuestions: [ON_BOARD] });
  const chatStore = new WatsonChatStore(cases);
  const full: WatsonAnswer = {
    question: "Do we know the initial access?",
    status: "unknown",
    answer: "Not from the case yet.",
    pointer: "",
    relatedEventIds: [],
    ...answer,
  };
  await chatStore.update(CASE, (c) => ({
    ...c,
    turns: [{ id: "wt-1", at: "2026-01-01T00:00:00Z", role: "watson", text: "x", answer: full }],
  }));
  const deps = {
    stateStore,
    stateLock: new StateLock(),
    chatStore,
    activity: new ActivityLogStore(cases),
    markConclusionsOutOfDate: async () => {},
  };
  return { deps, stateStore, chatStore };
}

describe("normalizeQuestionText", () => {
  it("lowercases, strips punctuation, collapses spaces and drops leading filler", () => {
    expect(normalizeQuestionText("  What was   the Initial-Access vector?? ")).toBe("initial access vector");
    expect(normalizeQuestionText("Do we know the initial access vector")).toBe("initial access vector");
    expect(normalizeQuestionText("What is the scope?")).toBe("scope");
    expect(normalizeQuestionText("Which host ran it?")).toBe("which host ran it");
  });
});

describe("addAnswerAsQuestion refuses a question already on the board", () => {
  it("refuses an answer Watson linked to an existing key question, naming it", async () => {
    const h = await harness({ matchesQuestionId: "q-ia" });
    const err = await addAnswerAsQuestion(h.deps, CASE, "wt-1").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(WatsonQuestionOnBoard);
    expect(err).toBeInstanceOf(WatsonProposalConflict);
    expect((err as Error).message).toBe(
      "This question is already on the board: What was the initial access vector?",
    );
    expect((await h.chatStore.load(CASE)).proposals).toHaveLength(0);
    expect((await h.stateStore.loadOverview(CASE)).keyQuestions).toHaveLength(1);
  });

  it("refuses an unlinked answer whose question normalizes to one on the board", async () => {
    const h = await harness({ question: "Do we know the initial access vector?" });
    await expect(addAnswerAsQuestion(h.deps, CASE, "wt-1")).rejects.toThrow(
      "This question is already on the board: What was the initial access vector?",
    );
  });

  it("adds a link whose question was since removed from the board", async () => {
    const h = await harness({ matchesQuestionId: "q-gone", question: "Which host ran it?" });
    const out = await addAnswerAsQuestion(h.deps, CASE, "wt-1");
    expect(out.state.keyQuestions.map((q) => q.question)).toContain("Which host ran it?");
  });

  it("still adds a genuinely new question", async () => {
    const h = await harness({ question: "Which account ran the encoded command?" });
    const out = await addAnswerAsQuestion(h.deps, CASE, "wt-1");
    expect(out.state.keyQuestions).toHaveLength(2);
  });
});
