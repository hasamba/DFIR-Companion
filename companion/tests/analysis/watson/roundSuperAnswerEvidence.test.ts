import { describe, expect, it } from "vitest";
import { addAnswerAsQuestion } from "../../../src/analysis/ai/watson/addQuestion.js";
import { applyWatsonProposal, WatsonProposalConflict } from "../../../src/analysis/ai/watson/proposals.js";
import type { WatsonChat, WatsonQuestionProposal } from "../../../src/analysis/ai/watson/types.js";
import {
  CASE,
  harness,
  lastWatsonTurn,
  promotionOf,
  reply,
  superLookup,
  turnProposals,
  writes,
} from "./superPromoteFixtures.js";

// Final review H1/H2/H4. "Add to open questions" is a door to the case: the answer's raw ids (its
// question text too) are recorded on the turn and stamped on the question it adds, so Undo of their
// promotion is refused while the question stands. An answer that names a raw row which is not in the
// forensic timeline cannot be added (controller ruling H2). Rows a stuck (pending) Watson promotion
// landed are raw evidence for later items exactly like applied ones (H4).

const NOT_LIVE =
  "This answer names a super-timeline row that is not in the forensic timeline. Ask Watson again.";

const ans = (question: string, text: string, ids: string[] = []) => ({
  answer: { question, status: "answered", answer: text, pointer: "p", relatedEventIds: ids },
});
const questionOf = (chat: WatsonChat) =>
  chat.proposals.find((p) => p.kind === "question_new") as WatsonQuestionProposal | undefined;
const keyQuestions = async (h: Awaited<ReturnType<typeof harness>>) =>
  (await h.stateStore.load(CASE)).keyQuestions.map((q) => q.question);

describe("Add to open questions records the answer's raw evidence (H1)", () => {
  it("a raw id named only in the answer's question is promoted and recorded", async () => {
    const h = await harness([reply(superLookup()), reply(ans("What did raw2 do?", "unclear"))]);
    const chat = await h.run();
    expect(promotionOf(chat)?.createdEventIds).toEqual(["raw2"]);
    expect(lastWatsonTurn(chat).answerRawEvidenceIds).toEqual(["raw2"]);
    const out = await addAnswerAsQuestion(h.deps, CASE, lastWatsonTurn(chat).id, "Ana");
    expect(questionOf(out.chat)?.rawEvidenceIds).toEqual(["raw2"]);
  });

  it("undo of the promotion is refused while the added question stands", async () => {
    const h = await harness([
      reply(superLookup()),
      reply(ans("Who ran rclone?", "raw1 shows rclone copy", ["raw1"])),
    ]);
    const chat = await h.run();
    await addAnswerAsQuestion(h.deps, CASE, lastWatsonTurn(chat).id, "Ana");
    const undo = applyWatsonProposal(h.deps, CASE, promotionOf(chat)!.id, "undo", "Ana");
    await expect(undo).rejects.toThrow(/Watson's key question \S+ cites event raw1/);
    expect(await h.row("raw1")).toBeDefined();
  });

  it("Undo pressed mid-save: the turn records no answer evidence and Add is refused", async () => {
    const h = await harness([
      reply(superLookup()),
      reply(ans("Who ran rclone?", "raw1 shows rclone copy", ["raw1"])),
    ]);
    let release!: () => void;
    const until = new Promise<void>((r) => (release = r));
    let started!: () => void;
    const held = new Promise<void>((r) => (started = r));
    h.chatStore.hook = (before, after) => {
      const was = promotionOf(before)?.status;
      if (was === "pending" && promotionOf(after)?.status === "applied")
        h.chatStore.holdNext = { until, started };
    };
    const round = h.run();
    await held;
    await applyWatsonProposal(h.deps, CASE, promotionOf(await h.chatStore.load(CASE))!.id, "undo", "Ana");
    release();
    const turn = lastWatsonTurn(await round);
    expect(turn.answerRawEvidenceIds).toBeUndefined();
    await expect(addAnswerAsQuestion(h.deps, CASE, turn.id, "Ana")).rejects.toThrow(NOT_LIVE);
  });
});

describe("Add to open questions refuses a raw row that is not in the forensic timeline (H2)", () => {
  it("a withheld round: refused with 409 copy, nothing written", async () => {
    const h = await harness([
      reply(superLookup()),
      reply(ans("Who ran rclone?", "raw1 shows rclone copy", ["raw1"])),
    ]);
    const chat = await h.run("any rclone?", { allowWrites: false });
    expect(await h.row("raw1")).toBeUndefined();
    const turn = lastWatsonTurn(chat);
    const add = addAnswerAsQuestion(h.deps, CASE, turn.id, "Ana");
    await expect(add).rejects.toBeInstanceOf(WatsonProposalConflict);
    await expect(add).rejects.toThrow(NOT_LIVE);
    const stored = await h.chatStore.load(CASE);
    expect(questionOf(stored)).toBeUndefined();
    expect(stored.turns.find((t) => t.id === turn.id)?.answerProposalId).toBeUndefined();
    expect(await keyQuestions(h)).not.toContain("Who ran rclone?");
  });

  it("after the promotion was undone: refused, nothing written", async () => {
    const h = await harness([
      reply(superLookup()),
      reply(ans("Who ran rclone?", "raw1 shows rclone copy", ["raw1"])),
    ]);
    const chat = await h.run();
    await applyWatsonProposal(h.deps, CASE, promotionOf(chat)!.id, "undo", "Ana");
    await expect(addAnswerAsQuestion(h.deps, CASE, lastWatsonTurn(chat).id, "Ana")).rejects.toThrow(NOT_LIVE);
    expect(questionOf(await h.chatStore.load(CASE))).toBeUndefined();
    expect(await keyQuestions(h)).not.toContain("Who ran rclone?");
  });

  it("an answer that names no raw row is added as before", async () => {
    const h = await harness([reply(superLookup()), reply(ans("Who ran rclone?", "e1 shows it", ["e1"]))]);
    const chat = await h.run();
    const out = await addAnswerAsQuestion(h.deps, CASE, lastWatsonTurn(chat).id, "Ana");
    expect(questionOf(out.chat)?.rawEvidenceIds).toBeUndefined();
    expect(await keyQuestions(h)).toContain("Who ran rclone?");
  });
});

describe("rows a stuck Watson promotion landed stay raw evidence (H4)", () => {
  const step = (action: string) => ({ priority: "high", action, rationale: "", pointer: "" });

  it("record save fails → later item applied → card applied → undo refused", async () => {
    const h = await harness([
      reply(superLookup()),
      reply(ans("Who ran rclone?", "raw1 shows rclone copy", ["raw1"])),
      reply(writes({ nextSteps: [step("Check raw1")] })),
    ]);
    let failed = false;
    h.chatStore.hook = (before, after) => {
      if (failed || promotionOf(before)?.status !== "pending" || promotionOf(after)?.status !== "applied")
        return;
      failed = true;
      throw new Error("disk full");
    };
    const first = await h.run();
    const stuck = promotionOf(first)!;
    expect(stuck.status).toBe("pending");
    const chat = await h.run("what next?");
    const s = turnProposals(chat).find((p) => p.kind === "next_step_new")!;
    expect("rawEvidenceIds" in s ? s.rawEvidenceIds : undefined).toEqual(["raw1"]);
    await applyWatsonProposal(h.deps, CASE, s.id, "apply", "Ana");
    await applyWatsonProposal(h.deps, CASE, stuck.id, "apply", "Ana");
    const undo = applyWatsonProposal(h.deps, CASE, stuck.id, "undo", "Ana");
    await expect(undo).rejects.toThrow(/Watson's next step \S+ cites event raw1/);
    expect(await h.row("raw1")).toBeDefined();
  });
});
