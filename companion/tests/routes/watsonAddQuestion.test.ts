import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { ActivityLogStore } from "../../src/analysis/activityLog.js";
import { WatsonChatStore } from "../../src/analysis/ai/watson/chatStore.js";
import type { WatsonAnswer } from "../../src/analysis/ai/watson/types.js";
import { StateLock } from "../../src/analysis/stateLock.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import { createApp } from "../../src/server.js";
import { CaseStore } from "../../src/storage/caseStore.js";

// Task 10: POST …/watson/turns/:tid/add-question refuses a question already on the board (409).

const CASE = "c1";
const BOARD_TEXT = "What was the initial access vector?";

async function appWith(answer: Partial<WatsonAnswer>) {
  const root = await mkdtemp(join(tmpdir(), "dfir-watson-addq-"));
  const store = new CaseStore(root);
  await store.createCase({ caseId: CASE, name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(store);
  await stateStore.save({
    ...emptyState(CASE),
    keyQuestions: [{ id: "q-ia", question: BOARD_TEXT, status: "unknown", answer: "", pointer: "" }],
  });
  const chatStore = new WatsonChatStore(store);
  const full: WatsonAnswer = {
    question: "Do we know the initial access?",
    status: "unknown",
    answer: "Not yet.",
    pointer: "",
    relatedEventIds: [],
    ...answer,
  };
  await chatStore.update(CASE, (c) => ({
    ...c,
    turns: [{ id: "wt-1", at: "2026-01-01T00:00:00Z", role: "watson", text: "x", answer: full }],
  }));
  return createApp(store, {
    stateStore,
    stateLock: new StateLock(),
    activityLogStore: new ActivityLogStore(store),
    watsonChatStore: chatStore,
  });
}

const add = (app: Awaited<ReturnType<typeof appWith>>) =>
  request(app).post(`/cases/${CASE}/watson/turns/wt-1/add-question`);

describe("add-question refuses a duplicate key question", () => {
  it("answers 409 in plain English for an answer linked to a key question", async () => {
    const res = await add(await appWith({ matchesQuestionId: "q-ia" }));
    expect(res.status).toBe(409);
    expect(res.body.error).toBe(`This question is already on the board: ${BOARD_TEXT}`);
  });

  it("answers 409 for a question that normalizes to one on the board", async () => {
    const res = await add(await appWith({ question: "Do we know the initial access vector?" }));
    expect(res.status).toBe(409);
    expect(res.body.error).toBe(`This question is already on the board: ${BOARD_TEXT}`);
  });

  it("adds a genuinely new question", async () => {
    const res = await add(await appWith({ question: "Which account ran the encoded command?" }));
    expect(res.status).toBe(200);
    expect(res.body.state.keyQuestions).toHaveLength(2);
  });
});
