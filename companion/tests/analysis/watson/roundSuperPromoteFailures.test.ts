import { describe, expect, it } from "vitest";
import { applyWatsonProposal, WatsonProposalStateError } from "../../../src/analysis/ai/watson/proposals.js";
import type { WatsonChat } from "../../../src/analysis/ai/watson/types.js";
import {
  answer,
  CASE,
  finding,
  harness,
  lastWatsonTurn,
  promotionOf,
  reply,
  superLookup,
  turnProposals,
  writes,
} from "./superPromoteFixtures.js";

// Watson phase 4, Task 5 — the D9 / D6c failure and concurrency matrix. The promotion is durable:
// intent first, then the rows, then the applied record; side effects never fail it; a frozen case or
// a failed promotion lands nothing and drops what would have rested on it.

const SECOND = reply({ ...answer(["raw1", "e1"]), ...writes({ findings: [finding(["raw1"])] }) });
const FROZEN =
  "(Watson cited 1 super-timeline row, but the case was closed, archived or had AI turned off during the round, so nothing was promoted.)";

const status = (c: WatsonChat) => promotionOf(c)?.status;
/** The update that marks the round's promotion record applied. */
const marksApplied = (before: WatsonChat, after: WatsonChat): boolean =>
  status(before) === "pending" && status(after) === "applied";
/** The update that adds the round's pending intent. */
const addsIntent = (before: WatsonChat, after: WatsonChat): boolean =>
  !promotionOf(before) && status(after) === "pending";
const watsonTurns = (c: WatsonChat) => c.turns.filter((t) => t.role === "watson").length;

function expectNothingPromoted(chat: WatsonChat) {
  const turn = lastWatsonTurn(chat);
  expect(turn.answer?.relatedEventIds).toEqual(["e1"]);
  expect(chat.proposals.some((p) => p.kind === "finding_new")).toBe(false);
  expect(promotionOf(chat)).toBeUndefined();
}

describe("Watson's promotion when something fails", () => {
  it("promoteEvents throws: no rows land, dependent items dropped, note says it failed", async () => {
    const h = await harness([reply(superLookup()), SECOND], {
      promote: () => async () => {
        throw new Error("state database is locked");
      },
    });
    const chat = await h.run();
    expect(await h.row("raw1")).toBeUndefined();
    expectNothingPromoted(chat);
    expect(lastWatsonTurn(chat).text).toMatch(/could not be promoted \(state database is locked\)/);
    expect(lastWatsonTurn(chat).text).toContain("1 item that rested on it was dropped");
  });

  it("markConclusionsOutOfDate throws after the rows landed: the record is applied and undoable, no 'failed' note", async () => {
    const h = await harness([reply(superLookup()), SECOND]);
    h.flags.markThrows = true;
    const chat = await h.run();
    expect(status(chat)).toBe("applied");
    expect(lastWatsonTurn(chat).text).not.toMatch(/could not be promoted|failed/);
    expect(turnProposals(chat).some((p) => p.kind === "finding_new")).toBe(true);
    h.flags.markThrows = false;
    await applyWatsonProposal(h.deps, CASE, promotionOf(chat)!.id, "undo", "Ana");
    expect(await h.row("raw1")).toBeUndefined();
  });

  it("activity logging throws: the record is applied, linked to the turn, no 'failed' note", async () => {
    const h = await harness([reply(superLookup()), SECOND]);
    h.flags.activityThrows = true;
    const chat = await h.run();
    expect(status(chat)).toBe("applied");
    expect(lastWatsonTurn(chat).proposalIds).toContain(promotionOf(chat)!.id);
    expect(lastWatsonTurn(chat).text).not.toMatch(/could not be promoted|failed/);
  });

  it("the 'applied' record save throws after the rows landed: the pending intent stays; Apply adopts the rows; one undoable operation", async () => {
    const h = await harness([reply(superLookup()), SECOND]);
    let failed = false;
    h.chatStore.hook = (before, after) => {
      if (failed || !marksApplied(before, after)) return;
      failed = true;
      throw new Error("disk full");
    };
    const chat = await h.run();
    expect(await h.row("raw1")).toBeDefined();
    const p = promotionOf(chat)!;
    expect(p.status).toBe("pending");
    expect(lastWatsonTurn(chat).proposalIds).toContain(p.id);
    expect(lastWatsonTurn(chat).text).toContain("press Apply on the card to finish it");
    // The rows landed, so what rests on them stays.
    expect(lastWatsonTurn(chat).answer?.relatedEventIds).toEqual(["raw1", "e1"]);
    await applyWatsonProposal(h.deps, CASE, p.id, "apply", "Ana");
    const applied = promotionOf(await h.chatStore.load(CASE))!;
    expect(applied).toMatchObject({ status: "applied", createdEventIds: ["raw1"], promotedAt: p.promotedAt });
    await applyWatsonProposal(h.deps, CASE, p.id, "undo", "Ana");
    expect(await h.row("raw1")).toBeUndefined();
  });

  it("the final turn save throws: the applied record stays in chat.proposals and its undo works", async () => {
    const h = await harness([reply(superLookup()), SECOND]);
    let failed = false;
    h.chatStore.hook = (before, after) => {
      if (failed || watsonTurns(after) <= watsonTurns(before)) return;
      failed = true;
      throw new Error("disk full");
    };
    await expect(h.run()).rejects.toThrow(/disk full/);
    const stored = await h.chatStore.load(CASE);
    expect(status(stored)).toBe("applied");
    await applyWatsonProposal(h.deps, CASE, promotionOf(stored)!.id, "undo", "Ana");
    expect(await h.row("raw1")).toBeUndefined();
  });

  it("Undo pressed between the promotion save and the final turn save drops the dependent proposals (barrier)", async () => {
    const h = await harness([
      reply(superLookup()),
      reply({
        ...answer(["raw1", "e1"]),
        ...writes({
          findings: [finding(["raw1"])],
          report: [{ field: "conclusions", text: "Data left via rclone (raw1)." }],
        }),
      }),
    ]);
    let release!: () => void;
    const until = new Promise<void>((r) => (release = r));
    let started!: () => void;
    const held = new Promise<void>((r) => (started = r));
    h.chatStore.hook = (before, after) => {
      if (marksApplied(before, after)) h.chatStore.holdNext = { until, started };
    };
    const round = h.run();
    await held;
    const id = promotionOf(await h.chatStore.load(CASE))!.id;
    await applyWatsonProposal(h.deps, CASE, id, "undo", "Ana");
    release();
    const chat = await round;
    expect(await h.row("raw1")).toBeUndefined();
    expect(chat.proposals.some((p) => p.kind === "finding_new" || p.kind === "report_text")).toBe(false);
    const turn = lastWatsonTurn(chat);
    expect(turn.answer?.relatedEventIds).toEqual(["e1"]);
    expect(turn.proposalIds ?? []).not.toContain(id);
    expect(turn.text).toContain(
      "(The rows Watson promoted were undone before its answer was saved, so items resting on them were dropped.)",
    );
  });

  it("the case is closed while the second call is in flight: nothing promoted, dependents dropped, note says why", async () => {
    const h = await harness([reply(superLookup()), SECOND], {
      onCall: (n, flags) => {
        if (n === 2) flags.frozen = true;
      },
    });
    const chat = await h.run();
    expect((await h.stateStore.load(CASE)).forensicTimeline.map((e) => e.id)).not.toContain("raw1");
    expectNothingPromoted(chat);
    expect(lastWatsonTurn(chat).text).toContain(FROZEN);
  });

  it("AI switched off mid-round: nothing promoted", async () => {
    const h = await harness([reply(superLookup()), SECOND], {
      onCall: (n, flags) => {
        if (n === 2) flags.aiOn = false;
      },
    });
    const chat = await h.run();
    expect(await h.row("raw1")).toBeUndefined();
    expectNothingPromoted(chat);
    expect(lastWatsonTurn(chat).text).toContain(FROZEN);
  });

  it("the case freezes between the intent save and the promotion: the intent is removed, nothing promoted", async () => {
    const h = await harness([reply(superLookup()), SECOND]);
    h.chatStore.hook = (before, after) => {
      if (addsIntent(before, after)) h.flags.frozen = true;
    };
    const chat = await h.run();
    expect(await h.row("raw1")).toBeUndefined();
    expectNothingPromoted(chat);
    expect(lastWatsonTurn(chat).text).toContain(FROZEN);
  });

  it("fails closed: when the citations cannot be checked, nothing resting on a shown row survives", async () => {
    const h = await harness([reply(superLookup()), SECOND]);
    const real = h.stateStore.hasForensicEventIds.bind(h.stateStore);
    h.stateStore.hasForensicEventIds = async () => {
      throw new Error("worker gone");
    };
    const chat = await h.run();
    h.stateStore.hasForensicEventIds = real;
    expect(await h.row("raw1")).toBeUndefined();
    expectNothingPromoted(chat);
    expect(lastWatsonTurn(chat).text).toMatch(/could not be promoted \(worker gone\)/);
  });

  // Task 5 review I3 + M1: the promotion threw AFTER its rows landed.
  it("promoteEvents throws after the rows landed: the note says so, conclusions and dashboard still told", async () => {
    let refreshed = 0;
    let thrown = 0;
    const h = await harness([reply(superLookup()), SECOND], {
      promote: (real) => async (caseId, events, o) => {
        const done = await real(caseId, events, o);
        if (thrown++ === 0) throw new Error("announce failed");
        return done;
      },
    });
    h.ctx.onStateChanged = () => void refreshed++;
    const chat = await h.run();
    expect(await h.row("raw1")).toBeDefined();
    const text = lastWatsonTurn(chat).text;
    expect(text).toContain(
      "Watson promoted 1 super-timeline row but could not finish recording it — press Apply to finish.",
    );
    expect(text).not.toContain("nothing was promoted");
    expect(h.outOfDate).toEqual(["Watson promoted super-timeline rows it cited"]);
    expect(refreshed).toBeGreaterThan(0);
    const p = promotionOf(chat)!;
    expect(p.status).toBe("pending");
    // Reject would leave Watson's rows with no record to undo them: the server refuses it.
    const reject = applyWatsonProposal(h.deps, CASE, p.id, "reject", "Ana");
    await expect(reject).rejects.toBeInstanceOf(WatsonProposalStateError);
    await expect(reject).rejects.toThrow(
      "Press Apply to finish this promotion; Undo is available afterwards",
    );
    await applyWatsonProposal(h.deps, CASE, p.id, "apply", "Ana");
    expect(promotionOf(await h.chatStore.load(CASE))?.createdEventIds).toEqual(["raw1"]);
  });
});
