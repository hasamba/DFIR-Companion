import { describe, expect, it } from "vitest";
import {
  reactionFailed,
  WATSON_REACTION_FAILURES_MAX,
  withReactionResult,
} from "../../../src/analysis/ai/watson/reactionState.js";
import { WatsonRoundTimedOut } from "../../../src/analysis/ai/watson/roundContext.js";
import { emptyWatsonChat, type WatsonChat } from "../../../src/analysis/ai/watson/types.js";
import { WatsonCancelled } from "../../../src/analysis/ai/watson/roundContext.js";
import { isRetryableError } from "../../../src/analysis/ai/retry.js";
import { WatsonRunRegistry } from "../../../src/analysis/ai/watson/runRegistry.js";

// Task 5: the per-case registry of running Watson rounds. Memory only: a restarted server knows no run.

describe("WatsonRunRegistry", () => {
  it("status shows the oldest run and the queue; end clears it", () => {
    const r = new WatsonRunRegistry(() => new Date("2026-11-15T10:00:00Z"));
    const a = r.begin("c1", { kind: "analyst", actor: "fake.user" });
    const b = r.begin("c1", { kind: "reaction" });
    expect(r.status("c1")).toEqual({
      since: "2026-11-15T10:00:00.000Z",
      kind: "analyst",
      actor: "fake.user",
      queued: 1,
    });
    a.end();
    a.end();
    expect(r.status("c1")).toEqual({ since: "2026-11-15T10:00:00.000Z", kind: "reaction", queued: 0 });
    b.end();
    expect(r.status("c1")).toBeNull();
  });

  it("cancel aborts every run of the case with a WatsonCancelled reason and returns the count", () => {
    const r = new WatsonRunRegistry();
    const a = r.begin("c1", { kind: "analyst" });
    const b = r.begin("c1", { kind: "reaction" });
    const other = r.begin("c2", { kind: "analyst" });
    expect(r.cancel("c1")).toBe(2);
    expect(a.signal.aborted).toBe(true);
    expect(b.signal.aborted).toBe(true);
    expect(a.signal.reason).toBeInstanceOf(WatsonCancelled);
    expect(other.signal.aborted).toBe(false);
    expect(r.cancel("c3")).toBe(0);
    // A second Stop counts only runs it newly aborted (review Minor 9).
    expect(r.cancel("c1")).toBe(0);
    r.begin("c1", { kind: "analyst" });
    expect(r.cancel("c1")).toBe(1);
  });

  it("a new registry (a restarted server) knows no run", () => {
    expect(new WatsonRunRegistry().status("c1")).toBeNull();
  });

  it("a cancelled reaction is not a reaction failure", () => {
    expect(reactionFailed(null, new WatsonCancelled())).toBe(false);
  });

  it("a timed-out reaction is a failure: it adds to the count, and repeated timeouts pause reactions (#2639)", () => {
    const timedOut = new WatsonRoundTimedOut(60_000);
    expect(reactionFailed(null, timedOut)).toBe(true);
    let chat: WatsonChat = { ...emptyWatsonChat(), reactionFailures: 1 };
    chat = withReactionResult(chat, reactionFailed(null, timedOut));
    expect(chat.reactionFailures).toBe(2);
    for (let i = 0; i < WATSON_REACTION_FAILURES_MAX; i++)
      chat = withReactionResult(chat, reactionFailed(null, timedOut));
    expect(chat.reactionsPaused).toBe("errors");
  });

  it("a stop is never retried", () => {
    expect(isRetryableError(new WatsonCancelled())).toBe(false);
  });
});
