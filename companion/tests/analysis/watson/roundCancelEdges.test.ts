import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { PresidioApprovalRequired } from "../../../src/analysis/presidio.js";
import { WATSON_CANCELLED_TEXT, runWatsonRound } from "../../../src/analysis/ai/watson/round.js";
import type { WatsonRoundContext } from "../../../src/analysis/ai/watson/roundContext.js";
import type { Outcome } from "../../../src/analysis/ai/watson/roundOutcome.js";
import { saveRound, WATSON_STOPPED_LATE_TEXT } from "../../../src/analysis/ai/watson/roundSave.js";
import { WatsonRunRegistry } from "../../../src/analysis/ai/watson/runRegistry.js";
import { ProviderError } from "../../../src/providers/provider.js";
import type { ConverseRequest, ConverseResult } from "../../../src/providers/toolCalling.js";
import { CASE, Scripted, final, lastTurn, reply, toolHarness } from "./roundToolsFixtures.js";
import { harness, log } from "./superPromoteFixtures.js";

// Task 5 review fixes: the edges of an analyst's Stop (the paste, the notifier, the log, a Presidio
// hold and the commit point).

const abortAware =
  (next: ConverseResult) =>
  (req: ConverseRequest): ConverseResult | Error =>
    req.signal?.aborted ? new ProviderError("Scripted transport error: aborted", "transport") : next;

/** An unread stored paste: the next round attaches its head on its own. */
async function unreadPaste(ctx: WatsonRoundContext): Promise<void> {
  const dir = ctx.cases.importsDir(CASE);
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, "watson-paste-p1.txt"), "tcp 192.0.2.5:445 netstat line\n");
  const paste = {
    id: "p1",
    storedName: "watson-paste-p1.txt",
    filename: "netstat.txt",
    bytes: 31,
    lines: 1,
    at: "2026-01-01T00:00:00Z",
  };
  await ctx.chatStore.update(CASE, (c) => ({ ...c, pastes: [...c.pastes, paste], unreadPasteIds: ["p1"] }));
}

describe("the edges of a stop", () => {
  it("a stop on the first send keeps an auto-attached paste readable and unread (review Important 1)", async () => {
    const reg = new WatsonRunRegistry();
    const p = new Scripted([abortAware(final()), final()], {
      onSend: (n) => void (n === 1 && reg.cancel(CASE)),
    });
    const h = await toolHarness(p, { ctx: { runs: reg } });
    await unreadPaste(h.ctx);
    const stopped = await h.run();
    expect(lastTurn(stopped).text).toBe(WATSON_CANCELLED_TEXT);
    expect(stopped.turns.some((t) => /could not read/.test(t.text))).toBe(false);
    expect(stopped.unreadPasteIds).toEqual(["p1"]);
    await h.run("again");
    expect(p.sent[1].userPrompt).toContain("netstat");
  });

  it("a notifier that throws never leaks the run (review Minor 7)", async () => {
    const reg = new WatsonRunRegistry();
    const onRunChange = () => {
      throw new Error("broadcast failed");
    };
    const h = await toolHarness(new Scripted([final()]), { ctx: { runs: reg, onRunChange } });
    const chat = await h.run();
    expect(lastTurn(chat).role).toBe("watson");
    expect(reg.status(CASE)).toBeNull();
  });

  it("a stop is logged at info, not as a failed round (review Minor 2)", async () => {
    const reg = new WatsonRunRegistry();
    const infos: string[] = [];
    const warns: string[] = [];
    const spy = { ...log, info: (l: string) => void infos.push(l), warn: (l: string) => void warns.push(l) };
    const p = new Scripted([final()], { onSend: () => void reg.cancel(CASE) });
    const h = await toolHarness(p, { ctx: { runs: reg, log: spy } });
    await h.run();
    expect(infos).toContain("Watson round stopped by an analyst");
    expect(warns.filter((w) => /round failed/.test(w))).toEqual([]);
  });

  it("a stop during a Presidio hold ends as the stop and asks for no approval (review Minor 6)", async () => {
    const reg = new WatsonRunRegistry();
    const h = await harness([]);
    const ctx: WatsonRoundContext = {
      ...h.ctx,
      runs: reg,
      analyzeRestored: async () => {
        reg.cancel(CASE); // the stop lands while the send waits on the hold
        throw new PresidioApprovalRequired([]);
      },
    };
    const chat = await runWatsonRound(ctx, CASE, { text: "any rclone?", source: "dashboard" });
    expect(lastTurn(chat).text).toBe(WATSON_CANCELLED_TEXT);
  });
});

describe("the commit point (review Minor 1, item 9)", () => {
  const answered: Outcome = { reply: JSON.parse(reply()), shownEvents: [], questions: [] };
  const save = { turnId: "wt-x", reaction: false, before: null, calls: 1 };

  it("a stop before the save cancels the outcome", async () => {
    const h = await harness([]);
    const ctl = new AbortController();
    ctl.abort();
    const { outcome } = await saveRound({ ...h.ctx, signal: ctl.signal }, CASE, answered, save);
    expect(outcome.reply).toBeNull();
    expect(outcome.stoppedAfterCommit).toBeUndefined();
  });

  it("a stop after the commit check is saved as answered and marked stoppedAfterCommit", async () => {
    const h = await harness([]);
    const ctl = new AbortController();
    h.chatStore.hook = () => ctl.abort(); // runs after the merge, before the write
    const { saved, outcome } = await saveRound({ ...h.ctx, signal: ctl.signal }, CASE, answered, save);
    expect(outcome.stoppedAfterCommit).toBe(true);
    // Final review F7: the analyst sees that the stop came too late.
    expect(saved.turns.at(-2)?.role).toBe("watson");
    expect(lastTurn(saved)).toMatchObject({ role: "system", text: WATSON_STOPPED_LATE_TEXT });
    expect(lastTurn(saved).error).toBeUndefined();
  });

  it("a round with no late stop gets no late-stop note", async () => {
    const h = await harness([]);
    const { saved } = await saveRound(
      { ...h.ctx, signal: new AbortController().signal },
      CASE,
      answered,
      save,
    );
    expect(saved.turns.some((t) => t.text === WATSON_STOPPED_LATE_TEXT)).toBe(false);
  });

  it("a round with no stop is not marked", async () => {
    const h = await harness([]);
    const { outcome } = await saveRound(
      { ...h.ctx, signal: new AbortController().signal },
      CASE,
      answered,
      save,
    );
    expect(outcome.stoppedAfterCommit).toBeUndefined();
  });
});
