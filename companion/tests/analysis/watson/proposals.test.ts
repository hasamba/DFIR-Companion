import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { ActivityLogStore, NewActivityEntry } from "../../../src/analysis/activityLog.js";
import { addAnswerAsQuestion } from "../../../src/analysis/ai/watson/addQuestion.js";
import { WatsonChatStore } from "../../../src/analysis/ai/watson/chatStore.js";
import {
  applyWatsonProposal,
  WatsonProposalConflict,
  WatsonProposalNotFoundError,
  WatsonProposalStateError,
} from "../../../src/analysis/ai/watson/proposals.js";
import { emptyWatsonChat, type WatsonProposal } from "../../../src/analysis/ai/watson/types.js";
import { StateLock } from "../../../src/analysis/stateLock.js";
import type { StateStore } from "../../../src/analysis/stateStore.js";
import {
  emptyState,
  type InvestigationQuestion,
  type InvestigationState,
} from "../../../src/analysis/stateTypes.js";
import type { CaseStore } from "../../../src/storage/caseStore.js";

const CASE = "c1";

const original: InvestigationQuestion = {
  id: "q1",
  question: "What was the initial access vector?",
  status: "unknown",
  answer: "",
  pointer: "collect the mail logs",
  relatedFindingIds: ["f1"],
};

const updated: InvestigationQuestion = {
  ...original,
  status: "answered",
  answer: "A phishing mail from mailer.example.com",
  pointer: "row 12 of the pasted mail log",
  pinned: true,
  author: "watson",
};

const fresh: InvestigationQuestion = {
  id: "wq-1",
  question: "Did the attacker reach the file server?",
  status: "unknown",
  answer: "",
  pointer: "Watson asks: lateral movement is open",
  pinned: true,
  author: "watson",
};

const updateProposal: WatsonProposal = {
  id: "wp-u",
  turnId: "t1",
  kind: "question_update",
  questionId: "q1",
  before: original,
  after: updated,
  status: "pending",
};

const newProposal: WatsonProposal = {
  id: "wp-n",
  turnId: "t1",
  kind: "question_new",
  questionId: "wq-1",
  after: fresh,
  status: "pending",
};

function memoryStore(initial: InvestigationState) {
  let current = initial;
  let saves = 0;
  const store = {
    loadOverview: async () => current,
    saveOverview: async (s: InvestigationState) => {
      current = s;
      saves++;
    },
    load: async () => {
      throw new Error("whole-case load must not be used");
    },
    save: async () => {
      throw new Error("whole-case save must not be used");
    },
  } as unknown as StateStore;
  return {
    store,
    get state() {
      return current;
    },
    set state(s: InvestigationState) {
      current = s;
    },
    get saves() {
      return saves;
    },
  };
}

describe("applyWatsonProposal", () => {
  let dir: string;
  let chatStore: WatsonChatStore;
  let mem: ReturnType<typeof memoryStore>;
  let entries: NewActivityEntry[];
  let deps: Parameters<typeof applyWatsonProposal>[0];

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "watson-proposals-"));
    chatStore = new WatsonChatStore({ stateDir: () => dir } as unknown as CaseStore);
    await chatStore.save(CASE, { ...emptyWatsonChat(), proposals: [updateProposal, newProposal] });
    mem = memoryStore({ ...emptyState(CASE), keyQuestions: [original] });
    entries = [];
    const activity = {
      add: async (_caseId: string, e: NewActivityEntry) => {
        entries.push(e);
        return e;
      },
    } as unknown as ActivityLogStore;
    deps = {
      stateStore: mem.store,
      stateLock: new StateLock(),
      chatStore,
      activity,
      markConclusionsOutOfDate: async () => {},
    };
  });

  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  const statusOf = async (id: string) =>
    (await chatStore.load(CASE)).proposals.find((p) => p.id === id)?.status;

  it("apply writes the new answer pinned and authored by Watson, and marks the proposal applied", async () => {
    mem.state = {
      ...mem.state,
      keyQuestions: [{ ...original, synthesisDisagrees: { status: "partial", answer: "old" } }],
    };
    const out = await applyWatsonProposal(deps, CASE, "wp-u", "apply", "alice");
    const q = mem.state.keyQuestions.find((x) => x.id === "q1");
    expect(q).toMatchObject({ status: "answered", answer: updated.answer, pinned: true, author: "watson" });
    expect(q?.synthesisDisagrees).toBeUndefined();
    expect(out.state?.keyQuestions.find((x) => x.id === "q1")?.status).toBe("answered");
    expect(out.chat.proposals.find((p) => p.id === "wp-u")?.status).toBe("applied");
    expect(await statusOf("wp-u")).toBe("applied");
    expect(entries).toEqual([
      expect.objectContaining({
        actor: "alice",
        category: "ai",
        action: "watson.apply",
        targetType: "question",
        targetId: "q1",
      }),
    ]);
    expect(entries[0].detail.length).toBeGreaterThan(0);
  });

  it("apply protects a question synthesis had answered: the synthesis mark is cleared", async () => {
    const bySynth = {
      ...original,
      status: "partial" as const,
      answer: "synthesis view",
      author: "watson" as const,
      pinned: true,
      answeredBy: "synthesis" as const,
    };
    mem.state = { ...mem.state, keyQuestions: [bySynth] };
    await chatStore.save(CASE, {
      ...emptyWatsonChat(),
      proposals: [{ ...updateProposal, before: bySynth, after: { ...updated, answeredBy: "synthesis" } }],
    });
    await applyWatsonProposal(deps, CASE, "wp-u", "apply");
    expect(mem.state.keyQuestions[0].answeredBy).toBeUndefined();
    expect(mem.state.keyQuestions[0]).toMatchObject({ status: "answered", author: "watson", pinned: true });
  });

  it("apply drops the old answer's annotations, even from a proposal saved with them", async () => {
    const annotated: InvestigationQuestion = {
      ...original,
      contradicted: { techniques: ["T1048"], eventIds: ["e1"] },
      staleReSynth: true,
      collect: { host: "HOST-A", artifact: "mail logs" },
    };
    mem.state = { ...mem.state, keyQuestions: [annotated] };
    await chatStore.save(CASE, {
      ...emptyWatsonChat(),
      proposals: [{ ...updateProposal, before: annotated, after: { ...annotated, ...updated } }],
    });
    await applyWatsonProposal(deps, CASE, "wp-u", "apply");
    const q = mem.state.keyQuestions[0];
    expect(q).toMatchObject({ status: "answered", answer: updated.answer, author: "watson" });
    expect(q.contradicted).toBeUndefined();
    expect(q.staleReSynth).toBeUndefined();
    expect(q.relatedFindingIds).toBeUndefined();
    expect(q.collect).toBeUndefined();
    await applyWatsonProposal(deps, CASE, "wp-u", "undo");
    expect(mem.state.keyQuestions[0]).toEqual(annotated);
  });

  it("apply of a new question appends it; undo removes it again", async () => {
    await applyWatsonProposal(deps, CASE, "wp-n", "apply");
    expect(mem.state.keyQuestions.map((q) => q.id)).toEqual(["q1", "wq-1"]);
    expect(mem.state.keyQuestions[1]).toMatchObject({ pinned: true, author: "watson" });
    const out = await applyWatsonProposal(deps, CASE, "wp-n", "undo");
    expect(mem.state.keyQuestions.map((q) => q.id)).toEqual(["q1"]);
    expect(out.chat.proposals.find((p) => p.id === "wp-n")?.status).toBe("undone");
    expect(entries.map((e) => e.action)).toEqual(["watson.apply", "watson.undo"]);
    expect(entries[1].targetId).toBe("wq-1");
  });

  it("undo restores the question as it was before the apply", async () => {
    await applyWatsonProposal(deps, CASE, "wp-u", "apply");
    await applyWatsonProposal(deps, CASE, "wp-u", "undo");
    expect(mem.state.keyQuestions).toEqual([original]);
    expect(await statusOf("wp-u")).toBe("undone");
  });

  it("reject changes no case state and marks the proposal rejected", async () => {
    const out = await applyWatsonProposal(deps, CASE, "wp-u", "reject");
    expect(out.state).toBeUndefined();
    expect(mem.saves).toBe(0);
    expect(mem.state.keyQuestions).toEqual([original]);
    expect(await statusOf("wp-u")).toBe("rejected");
    expect(entries).toEqual([expect.objectContaining({ action: "watson.reject", targetId: "q1" })]);
  });

  it.each([
    ["apply", "applied"],
    ["apply", "rejected"],
    ["apply", "undone"],
    ["reject", "applied"],
    ["reject", "rejected"],
    ["reject", "undone"],
    ["undo", "pending"],
    ["undo", "rejected"],
    ["undo", "undone"],
  ] as const)("refuses %s from %s with a state error and changes nothing", async (action, from) => {
    await chatStore.save(CASE, { ...emptyWatsonChat(), proposals: [{ ...updateProposal, status: from }] });
    await expect(applyWatsonProposal(deps, CASE, "wp-u", action)).rejects.toBeInstanceOf(
      WatsonProposalStateError,
    );
    expect(await statusOf("wp-u")).toBe(from);
    expect(mem.saves).toBe(0);
    expect(entries).toEqual([]);
  });

  it("an unknown proposal id throws a not-found error", async () => {
    await expect(applyWatsonProposal(deps, CASE, "wp-missing", "apply")).rejects.toBeInstanceOf(
      WatsonProposalNotFoundError,
    );
  });

  it("apply conflicts when the question changed since the proposal, and the proposal stays pending", async () => {
    mem.state = { ...mem.state, keyQuestions: [{ ...original, answer: "synthesis answered it meanwhile" }] };
    await expect(applyWatsonProposal(deps, CASE, "wp-u", "apply")).rejects.toBeInstanceOf(
      WatsonProposalConflict,
    );
    expect(await statusOf("wp-u")).toBe("pending");
    expect(mem.saves).toBe(0);
    expect(entries).toEqual([]);
  });

  it("apply conflicts when the question was deleted since the proposal", async () => {
    mem.state = { ...mem.state, keyQuestions: [] };
    await expect(applyWatsonProposal(deps, CASE, "wp-u", "apply")).rejects.toBeInstanceOf(
      WatsonProposalConflict,
    );
  });

  it("apply of a new question conflicts when the id already exists", async () => {
    mem.state = { ...mem.state, keyQuestions: [original, { ...fresh, answer: "already here" }] };
    await expect(applyWatsonProposal(deps, CASE, "wp-n", "apply")).rejects.toBeInstanceOf(
      WatsonProposalConflict,
    );
    expect(await statusOf("wp-n")).toBe("pending");
  });

  it("undo conflicts when the question changed after the apply, and the proposal stays applied", async () => {
    await applyWatsonProposal(deps, CASE, "wp-u", "apply");
    mem.state = {
      ...mem.state,
      keyQuestions: [{ ...mem.state.keyQuestions[0], status: "partial", answer: "edited by the analyst" }],
    };
    await expect(applyWatsonProposal(deps, CASE, "wp-u", "undo")).rejects.toBeInstanceOf(
      WatsonProposalConflict,
    );
    expect(await statusOf("wp-u")).toBe("applied");
    expect(mem.state.keyQuestions[0].answer).toBe("edited by the analyst");
  });

  it("undo still works when synthesis only added annotations to the applied answer", async () => {
    await applyWatsonProposal(deps, CASE, "wp-u", "apply");
    mem.state = {
      ...mem.state,
      keyQuestions: [
        { ...mem.state.keyQuestions[0], synthesisDisagrees: { status: "partial", answer: "x" } },
      ],
    };
    await applyWatsonProposal(deps, CASE, "wp-u", "undo");
    expect(mem.state.keyQuestions).toEqual([original]);
  });

  it("two concurrent applies of one proposal: one wins, the other gets a state error", async () => {
    const results = await Promise.allSettled([
      applyWatsonProposal(deps, CASE, "wp-u", "apply"),
      applyWatsonProposal(deps, CASE, "wp-u", "apply"),
    ]);
    expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
    const failed = results.find((r): r is PromiseRejectedResult => r.status === "rejected");
    expect(failed?.reason).toBeInstanceOf(WatsonProposalStateError);
    expect(mem.saves).toBe(1);
    expect(entries).toHaveLength(1);
  });

  it("the state write happens under the state lock", async () => {
    const order: string[] = [];
    const lock = deps.stateLock;
    let release!: () => void;
    const held = lock.runExclusive(CASE, async () => {
      order.push("other start");
      await new Promise<void>((r) => (release = r));
      order.push("other end");
    });
    const run = applyWatsonProposal(deps, CASE, "wp-u", "apply").then(() => order.push("apply done"));
    await new Promise((r) => setTimeout(r, 10));
    expect(mem.saves).toBe(0);
    release();
    await Promise.all([held, run]);
    expect(order).toEqual(["other start", "other end", "apply done"]);
  });
  it("a phase 1 chat file with question proposals loads unchanged and undoes as before", async () => {
    const phase1 = { ...emptyWatsonChat(), proposals: [{ ...updateProposal, status: "applied" }] };
    await writeFile(join(dir, "watson-chat.json"), JSON.stringify(phase1));
    expect((await chatStore.load(CASE)).proposals).toEqual(phase1.proposals);
    mem.state = { ...mem.state, keyQuestions: [{ ...updated }] };
    await applyWatsonProposal(deps, CASE, "wp-u", "undo", "bob");
    expect(mem.state.keyQuestions).toEqual([original]);
    expect(entries).toEqual([
      expect.objectContaining({ action: "watson.undo", targetType: "question", targetId: "q1" }),
    ]);
  });

  it("apply stamps appliedBy and appliedAt on the proposal", async () => {
    await applyWatsonProposal(deps, CASE, "wp-n", "apply", "alice");
    const p = (await chatStore.load(CASE)).proposals.find((x) => x.id === "wp-n");
    expect(p).toMatchObject({ status: "applied", appliedBy: "alice" });
    expect(p?.appliedAt).toBeTruthy();
  });

  it("addAnswerAsQuestion applies and undoes through the writer dispatch", async () => {
    const answer = {
      question: "Who sent the mail?",
      status: "answered" as const,
      answer: "mailer.example.com",
      pointer: "mail log",
      relatedEventIds: [],
    };
    await chatStore.save(CASE, {
      ...emptyWatsonChat(),
      turns: [{ id: "t9", at: "2026-01-01T00:00:00Z", role: "watson", text: "x", answer }],
    });
    const out = await addAnswerAsQuestion(deps, CASE, "t9", "alice");
    const added = out.chat.proposals[0];
    expect(added).toMatchObject({ kind: "question_new", status: "applied", appliedBy: "alice" });
    expect(mem.state.keyQuestions.map((q) => q.question)).toContain("Who sent the mail?");
    await applyWatsonProposal(deps, CASE, added.id, "undo");
    expect(mem.state.keyQuestions).toEqual([original]);
  });

  it("a kind with no writer yet is refused and stays pending", async () => {
    await chatStore.save(CASE, {
      ...emptyWatsonChat(),
      proposals: [
        {
          id: "wp-r",
          turnId: "t1",
          kind: "report_text",
          targetId: "conclusions",
          field: "conclusions",
          before: "",
          after: "x",
          status: "pending",
        },
      ],
    });
    await expect(applyWatsonProposal(deps, CASE, "wp-r", "apply")).rejects.toBeInstanceOf(
      WatsonProposalConflict,
    );
    expect(await statusOf("wp-r")).toBe("pending");
    expect(entries).toEqual([]);
  });
});
