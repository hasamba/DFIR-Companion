import { describe, expect, it } from "vitest";
import { RAW_CITED_WAIT } from "../../../src/analysis/ai/watson/autoApply.js";
import { applyWatsonProposal, WatsonProposalConflict } from "../../../src/analysis/ai/watson/proposals.js";
import { withCitedPromotion } from "../../../src/analysis/ai/watson/roundPromote.js";
import type { Outcome } from "../../../src/analysis/ai/watson/roundOutcome.js";
import { watsonReplySchema } from "../../../src/analysis/ai/watson/replySchema.js";
import type { WatsonProposal } from "../../../src/analysis/ai/watson/types.js";
import { demoteBelowSeverity } from "../../../src/analysis/forensicGate.js";
import { WATSON_MARKER } from "../../../src/analysis/timeline/watsonItems.js";
import {
  answer,
  CASE,
  ev,
  finding,
  harness,
  lastWatsonTurn,
  promotionOf,
  raw,
  reply,
  superLookup,
  turnProposals,
  writes,
} from "./superPromoteFixtures.js";

// Watson phase 4, Task 5 (D4, D5, D6, D9, D9b): every super-timeline row Watson's reply cites is
// promoted into the forensic timeline before its turn is saved, as one undoable record; an item that
// rests on a raw row that did not land is dropped whole.

const step = (action: string) => ({ priority: "high", action, rationale: "", pointer: "" });
const ofKind = (ps: WatsonProposal[], kind: WatsonProposal["kind"]) => ps.find((p) => p.kind === kind);

describe("Watson promotes the super-timeline rows it cites", () => {
  it("promotes the raw row Watson's answer cites, marked as Watson's, before the turn is saved", async () => {
    const h = await harness([reply(superLookup()), reply(answer(["raw1"]))]);
    const chat = await h.run();
    const row = (await h.stateStore.load(CASE)).forensicTimeline.find((e) => e.id === "raw1");
    expect(row?.provenance).toContain(WATSON_MARKER);
    expect(row?.promotedAt).toBeTruthy();
    const turn = lastWatsonTurn(chat);
    expect(turn.answer?.relatedEventIds).toEqual(["raw1"]);
    const p = turnProposals(chat).find((x) => x.kind === "event_promote");
    expect(p).toMatchObject({
      status: "applied",
      source: "supertimeline",
      appliedBy: "Watson",
      createdEventIds: ["raw1"],
      promotedAt: row?.promotedAt,
    });
    // The record survives a reload of the chat file, every new field included.
    expect(promotionOf(await h.chatStore.load(CASE))).toEqual(p);
  });

  it("does not promote rows the search showed but Watson did not cite", async () => {
    const h = await harness([reply(superLookup()), reply(answer(["raw1"]))]);
    const chat = await h.run();
    expect(await h.row("raw2")).toBeUndefined();
    expect(promotionOf(chat)?.events.map((e) => e.id)).toEqual(["raw1"]);
  });

  it("promotes nothing and adds no record when Watson cites no raw row", async () => {
    const h = await harness([reply(superLookup()), reply(answer(["e1"]))]);
    const chat = await h.run();
    expect(promotionOf(chat)).toBeUndefined();
    expect(await h.row("raw1")).toBeUndefined();
  });

  it("drops a structured citation of an id this round's search never showed", async () => {
    // raw9 is in the super-timeline, but the "rclone" search never showed it.
    const h = await harness([reply(superLookup()), reply(answer(["raw1", "raw9"]))], {
      raw: [raw("raw1"), raw("raw9", { description: "quiet raw row" })],
    });
    const chat = await h.run();
    expect(lastWatsonTurn(chat).answer?.relatedEventIds).toEqual(["raw1"]);
    expect(await h.row("raw9")).toBeUndefined();
  });

  it("promotes a raw row named only in a next step, a new question or a finding description", async () => {
    const second = reply({
      newQuestions: [{ question: "Who ran raw1?", why: "" }],
      ...writes({
        findings: [finding(["e1"], "see raw1.")],
        nextSteps: [step("Image the host of row:raw1")],
      }),
    });
    const h = await harness([reply(superLookup()), second]);
    const chat = await h.run();
    expect((await h.row("raw1"))?.provenance).toContain(WATSON_MARKER);
    const ps = turnProposals(chat);
    for (const kind of ["question_new", "finding_new", "next_step_new"] as const) {
      expect(ofKind(ps, kind), kind).toMatchObject({ status: "pending", rawEvidenceIds: ["raw1"] });
    }
    // The rawEvidenceIds survive a reload of the chat file.
    const stored = await h.chatStore.load(CASE);
    expect(stored.proposals.filter((p) => "rawEvidenceIds" in p && p.rawEvidenceIds)).toHaveLength(3);
  });

  it("promotes in Approve and in Auto; Auto never re-applies the promotion and holds the raw-cited finding (U5)", async () => {
    for (const mode of ["approve", "auto"] as const) {
      const h = await harness([reply(superLookup()), reply(writes({ findings: [finding(["raw1"])] }))], {
        mode,
      });
      const chat = await h.run();
      expect(promotionOf(chat)?.status, mode).toBe("applied");
      expect((await h.row("raw1"))?.provenance, mode).toContain(WATSON_MARKER);
      const promotions = h.entries.filter((e) => e.targetType === "event");
      expect(
        promotions.map((e) => [e.action, e.actor]),
        mode,
      ).toEqual([["watson.apply", "Watson"]]);
      const f = ofKind(chat.proposals, "finding_new");
      expect(f?.status, mode).toBe("pending");
      const held = chat.turns.some((t) => t.role === "system" && t.text.includes(RAW_CITED_WAIT));
      expect(held, mode).toBe(mode === "auto");
    }
  });

  it("promotes an Info row at Info, like explainEvent, and a later demote keeps it", async () => {
    const h = await harness([reply(superLookup()), reply(answer(["raw1"]))]);
    await h.run();
    const state = await h.stateStore.load(CASE);
    const row = state.forensicTimeline.find((e) => e.id === "raw1");
    expect(row?.severity).toBe("Info");
    expect(demoteBelowSeverity(state.forensicTimeline, "Low").kept.map((e) => e.id)).toContain("raw1");
  });

  it("withholds promotion and drops dependent items when the round may not write", async () => {
    const second = reply({
      ...answer(["raw1", "e1"]),
      newQuestions: [{ question: "Who ran raw1?", why: "" }],
    });
    const h = await harness([reply(superLookup()), second]);
    const chat = await h.run("any rclone?", { allowWrites: false });
    expect(await h.row("raw1")).toBeUndefined();
    expect(promotionOf(chat)).toBeUndefined();
    const turn = lastWatsonTurn(chat);
    expect(turn.answer?.relatedEventIds).toEqual(["e1"]);
    expect(ofKind(chat.proposals, "question_new")).toBeUndefined();
    expect(turn.text).toContain("it promoted nothing, because this round cannot write to the case");
    expect(turn.text).toContain("Watson removed 1 item that used it");
  });

  it("withCitedPromotion withholds promotion whenever mayWrite is false", async () => {
    const h = await harness([]);
    const parsed = watsonReplySchema.parse(JSON.parse(reply(answer(["raw1"]))));
    const outcome: Outcome = { reply: parsed, shownEvents: [], questions: [], superShown: [raw("raw1")] };
    const chat = await h.chatStore.load(CASE);
    const out = await withCitedPromotion(h.ctx, CASE, outcome, false, "wt-1", chat);
    expect(out.reply?.answer?.relatedEventIds).toEqual([]);
    expect(out.extraProposalIds).toBeUndefined();
    expect(await h.row("raw1")).toBeUndefined();
    expect((await h.chatStore.load(CASE)).proposals).toEqual([]);
  });

  it("rewrites a citation to the canonical id when the row folded into an existing event", async () => {
    // Same second, same text, same host: the correlation merge folds the raw twin into e9.
    const e9 = ev("e9", { description: "rclone copy share", severity: "High" });
    const twin = raw("rawT", { description: "rclone copy share" });
    const second = reply({ ...answer(["rawT"]), ...writes({ findings: [finding(["rawT"])] }) });
    const h = await harness([reply(superLookup()), second], { forensic: [ev("e1"), e9], raw: [twin] });
    const chat = await h.run();
    expect(lastWatsonTurn(chat).answer?.relatedEventIds).toEqual(["e9"]);
    const f = ofKind(turnProposals(chat), "finding_new");
    expect(f).toMatchObject({ rawEvidenceIds: ["e9"] });
    expect(f?.kind === "finding_new" ? f.after.relatedEventIds : []).toEqual(["e9"]);
    expect(promotionOf(chat)?.createdEventIds).toEqual([]);
  });

  it("writes the same activity entry an analyst's apply does and marks conclusions out of date", async () => {
    const h = await harness([reply(superLookup()), reply(answer(["raw1"]))]);
    const chat = await h.run();
    const p = promotionOf(chat);
    expect(h.entries).toEqual([
      {
        actor: "Watson",
        category: "ai",
        action: "watson.apply",
        detail: "Applied Watson's promotion of 1 super-timeline row(s) Watson cited",
        targetType: "event",
        targetId: p?.targetId,
      },
    ]);
    expect(h.outOfDate).toEqual(["Watson promoted super-timeline rows it cited"]);
    const timeline = (await h.stateStore.loadOverview(CASE)).timeline;
    expect(timeline.some((t) => t.description.includes("Watson cited 1 super-timeline row"))).toBe(true);
  });
});

describe("dependency-aware undo (D9b)", () => {
  const dependents = {
    finding: writes({ findings: [finding(["raw1"])] }),
    "key question answer": {
      questionUpdates: [
        { questionId: "wq-std-what", status: "answered", answer: "rclone, raw1", pointer: "" },
      ],
    },
    "next step": writes({ nextSteps: [step("Image the host of raw1")] }),
    "report text": writes({ report: [{ field: "conclusions", text: "Data left via rclone (raw1)." }] }),
  };

  for (const [kind, body] of Object.entries(dependents)) {
    it(`undo is refused while an applied ${kind} cites a promoted row`, async () => {
      const h = await harness([reply(superLookup()), reply(body)]);
      const chat = await h.run();
      const dep = turnProposals(chat).find((p) => p.kind !== "event_promote");
      expect(dep && "rawEvidenceIds" in dep ? dep.rawEvidenceIds : undefined).toEqual(["raw1"]);
      await applyWatsonProposal(h.deps, CASE, dep!.id, "apply", "Ana");
      const undo = applyWatsonProposal(h.deps, CASE, promotionOf(chat)!.id, "undo", "Ana");
      await expect(undo).rejects.toBeInstanceOf(WatsonProposalConflict);
      await expect(undo).rejects.toThrow(/(Watson's|Watson) .+ cites event raw1/);
      expect(await h.row("raw1")).toBeDefined();
      // Undo the dependent first, and the promotion's undo goes through.
      await applyWatsonProposal(h.deps, CASE, dep!.id, "undo", "Ana");
      await applyWatsonProposal(h.deps, CASE, promotionOf(chat)!.id, "undo", "Ana");
      expect(await h.row("raw1")).toBeUndefined();
    });
  }

  it("a dependent proposal applied after the promotion was undone is refused, nothing written", async () => {
    const body = {
      ...dependents["key question answer"],
      ...dependents["report text"],
    };
    const h = await harness([reply(superLookup()), reply(body)]);
    const chat = await h.run();
    await applyWatsonProposal(h.deps, CASE, promotionOf(chat)!.id, "undo", "Ana");
    expect(await h.row("raw1")).toBeUndefined();
    for (const kind of ["report_text", "question_update"] as const) {
      const dep = ofKind(turnProposals(chat), kind)!;
      const apply = applyWatsonProposal(h.deps, CASE, dep.id, "apply", "Ana");
      await expect(apply, kind).rejects.toBeInstanceOf(WatsonProposalConflict);
      await expect(apply, kind).rejects.toThrow(/no longer in the forensic timeline/);
    }
    expect(h.report().conclusions).toBe("old");
    const q = (await h.stateStore.loadOverview(CASE)).keyQuestions.find((x) => x.id === "wq-std-what");
    expect(q?.answer ?? "").not.toContain("raw1");
    const stored = await h.chatStore.load(CASE);
    expect(stored.proposals.filter((p) => p.status === "pending")).toHaveLength(2);
  });
});

describe("controller rulings", () => {
  // Ruling 1 (option B): an earlier round's shown raw id passes the sanitizer, so the item that rests
  // on it is dropped WHOLE — even when it has another, valid citation.
  it("drops a finding citing an earlier-round raw id that is not forensic, despite its valid citation", async () => {
    const h = await harness([
      reply(superLookup()),
      reply({ message: "seen" }),
      reply(writes({ findings: [finding(["e1", "raw2"])] })),
    ]);
    await h.run("any rclone?");
    const chat = await h.run("write it up");
    expect(ofKind(chat.proposals, "finding_new")).toBeUndefined();
    expect(await h.row("raw2")).toBeUndefined();
    expect(lastWatsonTurn(chat).text).toMatch(
      /from an earlier search[\s\S]*Watson removed 1 item that used it/,
    );
  });

  it("promotes this round's cited row and still drops an item resting on an earlier-round row", async () => {
    const h = await harness([
      reply(superLookup()),
      reply({ message: "seen" }),
      reply(superLookup()),
      reply({ ...answer(["raw1"]), ...writes({ findings: [finding(["e1", "rawOld"])] }) }),
    ]);
    await h.run("first");
    // The first round showed raw1 and raw2; make "rawOld" an earlier-shown id the case never promoted.
    await h.chatStore.update(CASE, (c) => ({
      ...c,
      turns: c.turns.map((t) =>
        t.lookedUp
          ? { ...t, lookedUp: { ...t.lookedUp, shownIds: [...(t.lookedUp.shownIds ?? []), "rawOld"] } }
          : t,
      ),
    }));
    const chat = await h.run("again");
    expect((await h.row("raw1"))?.provenance).toContain(WATSON_MARKER);
    expect(ofKind(chat.proposals, "finding_new")).toBeUndefined();
  });

  // Ruling 3 (user decision): reaction rounds never search or promote, even with writes allowed.
  it("a reaction round citing an earlier-shown row promotes nothing and drops the item", async () => {
    const h = await harness([
      reply(superLookup()),
      reply({ message: "seen" }),
      reply({ newQuestions: [{ question: "Who ran raw2?", why: "" }] }),
    ]);
    await h.run("first");
    await h.chatStore.update(CASE, (c) => ({
      ...c,
      pendingCaseEvents: [{ kind: "notebook", text: "analyst note", at: "2026-01-01T00:00:00Z" }],
    }));
    const chat = await h.run("", { reaction: true, source: undefined });
    expect(await h.row("raw2")).toBeUndefined();
    expect(promotionOf(chat)).toBeUndefined();
    expect(ofKind(chat.proposals, "question_new")).toBeUndefined();
  });
});
