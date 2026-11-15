import { describe, expect, it } from "vitest";
import { PresidioApprovalRequired } from "../../../src/analysis/presidio.js";
import {
  dispositionOf,
  WATSON_CANCELLED_TEXT,
  WatsonCancelled,
  type WatsonDisposition,
} from "../../../src/analysis/ai/watson/round.js";
import type { Outcome } from "../../../src/analysis/ai/watson/roundOutcome.js";
import { WatsonRunRegistry } from "../../../src/analysis/ai/watson/runRegistry.js";
import { ProviderError } from "../../../src/providers/provider.js";
import { CASE, Scripted, final, reply } from "./roundToolsFixtures.js";
import { toolHarness } from "./roundToolsFixtures.js";

// Task 6 (Codex #7): every round reports one disposition, consistent with what the save kept, so the
// message route replays an answered or cancelled round and runs a failed one again.

const answeredReply = JSON.parse(reply());
const promotion = { proposalId: "wp-x", keep: [], unsettled: answeredReply, refs: [], folded: new Map() };
const base: Outcome = { reply: null, shownEvents: [], questions: [] };

describe("dispositionOf", () => {
  it.each<[string, Outcome, unknown, WatsonDisposition]>([
    ["a saved reply", { ...base, reply: answeredReply }, undefined, "answered"],
    [
      "a stop after the commit point (the reply was saved)",
      { ...base, reply: answeredReply, stoppedAfterCommit: true },
      undefined,
      "answered",
    ],
    [
      "a stop before the commit point",
      { ...base, error: new WatsonCancelled() },
      new WatsonCancelled(),
      "cancelled",
    ],
    [
      // Not marked stoppedAfterCommit: the stop note is saved, the promotion stays. It replays.
      "a post-promotion round that carries a WatsonCancelled error",
      { ...base, error: new WatsonCancelled(), promotion: promotion },
      new WatsonCancelled(),
      "cancelled",
    ],
    ["a provider failure", { ...base, error: new Error("x") }, new Error("x"), "failed"],
    [
      "a Presidio hold, even after a first reply was kept",
      { ...base, reply: answeredReply, rethrow: new PresidioApprovalRequired([]) },
      new PresidioApprovalRequired([]),
      "failed",
    ],
  ])("%s", (_name, outcome, failure, expected) => {
    expect(dispositionOf(outcome, failure)).toBe(expected);
  });
});

describe("runWatsonRound reports one disposition on every exit", () => {
  const collect = () => {
    const seen: WatsonDisposition[] = [];
    return { seen, onDisposition: (d: WatsonDisposition) => void seen.push(d) };
  };

  it("an answered round", async () => {
    const h = await toolHarness(new Scripted([final()]));
    const c = collect();
    await h.run("hi", { onDisposition: c.onDisposition });
    expect(c.seen).toEqual(["answered"]);
  });

  it("a stopped round", async () => {
    const reg = new WatsonRunRegistry();
    const p = new Scripted([new ProviderError("Scripted transport error: aborted", "transport")], {
      onSend: () => void reg.cancel(CASE),
    });
    const h = await toolHarness(p, { ctx: { runs: reg } });
    const c = collect();
    const chat = await h.run("hi", { onDisposition: c.onDisposition });
    expect(chat.turns[chat.turns.length - 1].text).toBe(WATSON_CANCELLED_TEXT);
    expect(c.seen).toEqual(["cancelled"]);
  });

  it("a failed round, and a round refused before it starts (AI off)", async () => {
    const h = await toolHarness(new Scripted([new ProviderError("Scripted auth", "auth")]));
    const c = collect();
    await h.run("hi", { onDisposition: c.onDisposition });
    expect(c.seen).toEqual(["failed"]);
    const off = await toolHarness(new Scripted([final()]), { ctx: { isAiEnabled: async () => false } });
    const d = collect();
    await expect(off.run("hi", { onDisposition: d.onDisposition })).rejects.toThrow();
    expect(d.seen).toEqual(["failed"]);
  });
});
