import { describe, expect, it } from "vitest";
import { applyWatsonProposal, WatsonProposalConflict } from "../../../src/analysis/ai/watson/proposals.js";
import type { WatsonChat, WatsonProposal } from "../../../src/analysis/ai/watson/types.js";
import {
  answer,
  CASE,
  harness,
  lastWatsonTurn,
  promotionOf,
  reply,
  superLookup,
  turnProposals,
  writes,
} from "./superPromoteFixtures.js";

// Task 5 fix round 1. I1 (controller ruling, refines D4): an id live in the forensic timeline only
// because an applied Watson super-timeline promotion landed it is still raw evidence for a later
// item. I2: a raw id joined to a forensic id or a word is still a mention of it.

const step = (action: string) => ({ priority: "high", action, rationale: "", pointer: "" });
const evidence = (p: WatsonProposal | undefined) =>
  p && "rawEvidenceIds" in p ? p.rawEvidenceIds : undefined;
const own = (chat: WatsonChat, kind: WatsonProposal["kind"]) =>
  turnProposals(chat).find((p) => p.kind === kind);

describe("a row an earlier round promoted stays raw evidence (I1)", () => {
  it("records it on a later next step; undo of the earlier promotion is refused while the step is applied", async () => {
    const h = await harness([
      reply(superLookup()),
      reply(answer(["raw1"])),
      reply(writes({ nextSteps: [step("Image the host from raw1")] })),
    ]);
    const first = await h.run("any rclone?");
    const promotion = promotionOf(first)!;
    const chat = await h.run("what next?");
    const s = own(chat, "next_step_new");
    expect(evidence(s)).toEqual(["raw1"]);
    await applyWatsonProposal(h.deps, CASE, s!.id, "apply", "Ana");
    const undo = applyWatsonProposal(h.deps, CASE, promotion.id, "undo", "Ana");
    await expect(undo).rejects.toBeInstanceOf(WatsonProposalConflict);
    await expect(undo).rejects.toThrow(/Watson's next step \S+ cites event raw1/);
    expect(await h.row("raw1")).toBeDefined();
  });

  it("an item naming it, applied after the earlier promotion was undone, is refused", async () => {
    const h = await harness([
      reply(superLookup()),
      reply(answer(["raw1"])),
      reply({ newQuestions: [{ question: "Who ran raw1?", why: "" }] }),
    ]);
    const first = await h.run("any rclone?");
    const chat = await h.run("who?");
    const q = own(chat, "question_new");
    expect(evidence(q)).toEqual(["raw1"]);
    await applyWatsonProposal(h.deps, CASE, promotionOf(first)!.id, "undo", "Ana");
    await expect(applyWatsonProposal(h.deps, CASE, q!.id, "apply", "Ana")).rejects.toBeInstanceOf(
      WatsonProposalConflict,
    );
  });

  it("an ordinary forensic id is not raw evidence", async () => {
    const h = await harness([reply(writes({ nextSteps: [step("Check e1 first")] }))]);
    const chat = await h.run("next?");
    expect(evidence(own(chat, "next_step_new"))).toBeUndefined();
  });
});

describe("a raw id joined to a forensic id or a word is a mention (I2)", () => {
  const body = reply(
    writes({
      report: [{ field: "conclusions", text: "Activity spans e1-raw1." }],
      nextSteps: [step("Check raw1-related shares")],
    }),
  );

  it("promotes the row and records it on the report text and the next step", async () => {
    const h = await harness([reply(superLookup()), body]);
    const chat = await h.run();
    expect(promotionOf(chat)?.createdEventIds).toEqual(["raw1"]);
    expect(evidence(own(chat, "report_text"))).toEqual(["raw1"]);
    expect(evidence(own(chat, "next_step_new"))).toEqual(["raw1"]);
  });

  it("drops the report text and the next step when the row could not be promoted", async () => {
    const h = await harness([reply(superLookup()), body], {
      onCall: (n, flags) => {
        if (n === 2) flags.frozen = true;
      },
    });
    const chat = await h.run();
    expect(await h.row("raw1")).toBeUndefined();
    expect(chat.proposals.some((p) => p.kind === "report_text" || p.kind === "next_step_new")).toBe(false);
    expect(lastWatsonTurn(chat).text).toContain("Watson removed 2 items that used them");
  });
});

// Re-review NEW-I1 (controller ruling): a raw id followed by ':' + a word or '.' + a digit is a mention
// too. The item either rests on a promoted row or is dropped — never applied with the row unpromoted.
describe("a raw id before ':' or '.'+digit is a mention", () => {
  const texts = [
    "raw1:4624 logon then exfil",
    "raw1:e1 pair",
    "See raw1:svchost.exe",
    "raw1:Mimikatz",
    "raw1.5",
  ];

  for (const text of texts) {
    it(`Approve: "${text}" promotes raw1 and records it`, async () => {
      const h = await harness([reply(superLookup()), reply(writes({ nextSteps: [step(text)] }))]);
      const chat = await h.run();
      expect((await h.row("raw1"))?.promotedAt).toBeTruthy();
      expect(evidence(own(chat, "next_step_new"))).toEqual(["raw1"]);
    });
  }

  it('Approve: "raw1:4624 logon then exfil" is dropped when raw1 could not be promoted', async () => {
    const h = await harness([reply(superLookup()), reply(writes({ nextSteps: [step(texts[0])] }))], {
      onCall: (n, flags) => {
        if (n === 2) flags.frozen = true;
      },
    });
    const chat = await h.run();
    expect(await h.row("raw1")).toBeUndefined();
    expect(chat.proposals.some((p) => p.kind === "next_step_new")).toBe(false);
  });

  it('Auto: "Timeline raw1:4624 shows it" is applied only with raw1 promoted', async () => {
    const body = writes({ report: [{ field: "conclusions", text: "Timeline raw1:4624 shows it" }] });
    const h = await harness([reply(superLookup()), reply(body)], { mode: "auto" });
    const chat = await h.run();
    const r = chat.proposals.find((p) => p.kind === "report_text");
    expect(r?.status).toBe("applied");
    expect(evidence(r)).toEqual(["raw1"]);
    expect((await h.row("raw1"))?.promotedAt).toBeTruthy();
  });
});
