import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { WatsonRoundContext } from "../../../src/analysis/ai/watson/roundContext.js";
import { describe, expect, it } from "vitest";
import { isRetryableError } from "../../../src/analysis/ai/retry.js";
import { getWatsonPrompt } from "../../../src/analysis/ai/prompts/index.js";
import { WATSON_TOOL } from "../../../src/analysis/ai/watson/toolSpecs.js";
import { watsonToolCap } from "../../../src/analysis/ai/watson/toolMode.js";
import { watsonToolsAddendum } from "../../../src/analysis/ai/watson/toolPrompt.js";
import { ProviderError } from "../../../src/providers/provider.js";
import { PresidioApprovalRequired } from "../../../src/analysis/presidio.js";
import {
  ThinkingBindingError,
  ToolsUnsupportedError,
  TurnBindingError,
} from "../../../src/providers/toolCalling.js";
import {
  Scripted,
  calls,
  final,
  forensic,
  lastTurn,
  loopOutcome,
  reply,
  superSearch,
  toolHarness,
} from "./roundToolsFixtures.js";
import { answer, raw } from "./superPromoteFixtures.js";
import { runWatsonRound } from "../../../src/analysis/ai/watson/round.js";

// Watson phase 5, Task 6: which mode a round runs in, and every way tool mode falls back to the
// one-step hop (D7b, D12, the Task 2/3 carry-overs).

/** An unread stored paste: the next round attaches its head on its own. */
async function unreadPaste(ctx: WatsonRoundContext): Promise<void> {
  const dir = ctx.cases.importsDir("c1");
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, "watson-paste-p1.txt"), "tcp 10.0.0.5:445 netstat line\n");
  const paste = {
    id: "p1",
    storedName: "watson-paste-p1.txt",
    filename: "netstat.txt",
    bytes: 30,
    lines: 1,
    at: "2026-01-01T00:00:00Z",
  };
  await ctx.chatStore.update("c1", (c) => ({ ...c, pastes: [...c.pastes, paste], unreadPasteIds: ["p1"] }));
}

const superAsk = { lookup: { source: "supertimeline", text: "rclone" } };

describe("tool mode or the one-step hop", () => {
  it("a reaction round runs the one-step hop even with a cap of 4 (U4)", async () => {
    const p = new Scripted([]);
    const h = await toolHarness(p);
    expect(watsonToolCap(h.ctx, true)).toBe(0);
    expect(watsonToolCap(h.ctx, false)).toBe(4);
    await h.ctx.chatStore.update("c1", (c) => ({
      ...c,
      pendingCaseEvents: [{ kind: "notebook" as const, text: "n", at: new Date().toISOString() }],
    }));
    await h.run("", { reaction: true });
    expect(p.sent).toHaveLength(0);
    expect(p.analyzed.length).toBeGreaterThan(0);
  });

  it("the loop still refuses a forced super call in a reaction context; the reader is never queried", async () => {
    const p = new Scripted([calls(superSearch({ text: "rclone" })), final()]);
    const h = await toolHarness(p);
    let queried = 0;
    const rs = h.ctx.rawSearch!;
    const ctx = {
      ...h.ctx,
      rawSearch: {
        ...rs,
        reader: {
          ...rs.reader,
          query: (...a: Parameters<typeof rs.reader.query>) => (queried++, rs.reader.query(...a)),
        },
      },
    };
    const { outcome } = await loopOutcome(ctx, { reaction: true });
    expect(queried).toBe(0);
    expect(outcome.lookups ?? []).toHaveLength(0);
  });

  it("cap 0, supportsTools false or no converseRestored → today's hop (converse never called)", async () => {
    for (const ctx of [{ maxToolCalls: 0 }, { converseRestored: undefined }]) {
      const p = new Scripted([]);
      await (await toolHarness(p, { ctx })).run();
      expect(p.sent).toHaveLength(0);
      expect(p.analyzed).toHaveLength(1);
    }
    const p = new Scripted([]);
    const h = await toolHarness(p);
    Object.defineProperty(p, "supportsTools", { value: false });
    await h.run();
    expect(p.sent).toHaveLength(0);
  });

  it("system prompt is getWatsonPrompt() + the addendum naming the offered tools", async () => {
    const p = new Scripted([final()]);
    await (await toolHarness(p)).run();
    const names = [WATSON_TOOL.forensic, WATSON_TOOL.super, WATSON_TOOL.paste];
    expect(p.sent[0].systemPrompt).toBe(`${getWatsonPrompt()}\n\n${watsonToolsAddendum(4, names)}`);
    expect(p.sent[0].tools.map((t) => t.name)).toEqual(names);
    expect(watsonToolsAddendum(4, names)).toContain("You can make up to 4 lookups for this question.");
  });

  it("isRetryableError never retries a tools, thinking or turn refusal", () => {
    expect(isRetryableError(new ToolsUnsupportedError("x"))).toBe(false);
    expect(isRetryableError(new ThinkingBindingError("x"))).toBe(false);
    expect(isRetryableError(new TurnBindingError("x"))).toBe(false);
  });
});

describe("falling back to the hop", () => {
  it("first send throws ToolsUnsupportedError → the hop answers; the next round sends no tools; a changed model tries again", async () => {
    const p = new Scripted([new ToolsUnsupportedError("no tools")], { model: "fb-1" });
    const h = await toolHarness(p);
    expect(lastTurn(await h.run()).role).toBe("watson");
    expect(p.sent).toHaveLength(1);
    expect(p.analyzed).toHaveLength(1);
    // A provider rebuilt with the same name, model and endpoint stays on the hop.
    const again = new Scripted([final()], { model: "fb-1" });
    expect(watsonToolCap({ ...h.ctx, provider: again }, false)).toBe(0);
    await (await toolHarness(again)).run();
    expect(again.sent).toHaveLength(0);
    const other = new Scripted([final()], { model: "fb-2" });
    expect(watsonToolCap({ ...h.ctx, provider: other }, false)).toBe(4);
  });

  it("a ThinkingBindingError after a lookup falls back to the hop once, keeps the roster, remembers nothing", async () => {
    const p = new Scripted(
      [calls(superSearch({ text: "rclone" })), new ThinkingBindingError("must start with a thinking block")],
      { model: "tb-1" },
    );
    const h = await toolHarness(p, { raw: [raw("raw1", { asset: "FINSRV-07" })] });
    const chat = await h.run();
    expect(lastTurn(chat).role).toBe("watson");
    expect(p.analyzed).toHaveLength(1);
    expect(chat.maskRoster?.hosts).toContain("finsrv-07");
    expect(watsonToolCap(h.ctx, false)).toBe(4);
  });

  it("a fallback hop that fails still saves the roster of rows the loop already sent", async () => {
    const refused = new ThinkingBindingError("must start with a thinking block");
    refused.usage = { inputTokens: 1000 }; // billed: the hop's call then stops at the limit
    const p = new Scripted([calls(superSearch({ text: "rclone" })), refused], { tokens: 1000 });
    const h = await toolHarness(p, { tokenLimit: 1500, raw: [raw("raw1", { asset: "FINSRV-07" })] });
    const chat = await h.run();
    expect(p.analyzed).toHaveLength(0); // the hop's call stopped at the token limit
    expect(lastTurn(chat)).toMatchObject({ role: "system", error: true });
    expect(chat.maskRoster?.hosts).toContain("finsrv-07");
  });

  it("after two super searches, the fallback hop does not run a third one (R2)", async () => {
    const p = new Scripted(
      [
        calls(superSearch({ text: "rclone" })),
        calls(superSearch({ text: "rclone copy" })),
        new ThinkingBindingError("must start with a thinking block"),
      ],
      { hop: [reply(superAsk), reply({ message: "should not run" })] },
    );
    const h = await toolHarness(p, { maxToolCalls: 4 });
    const chat = await h.run();
    expect(p.analyzed).toHaveLength(1);
    expect(lastTurn(chat).text).toContain("it used both super-timeline searches for this question");
  });

  it("a TurnBindingError or another non-transient 4xx falls back once; auth and context errors do not", async () => {
    const turn = new Scripted([new TurnBindingError("thought signature")], { model: "tn-1" });
    const ht = await toolHarness(turn);
    expect(lastTurn(await ht.run()).role).toBe("watson");
    expect(turn.analyzed).toHaveLength(1);
    expect(watsonToolCap(ht.ctx, false)).toBe(4);
    const bad = new Scripted([new ProviderError("x HTTP 400 — reasoning_details missing", "other")]);
    const hb = await toolHarness(bad, { retries: 3 });
    expect(lastTurn(await hb.run()).role).toBe("watson");
    expect(bad.sent).toHaveLength(1);
    const auth = new Scripted([new ProviderError("x HTTP 401 bad key", "auth")]);
    expect(lastTurn(await (await toolHarness(auth)).run())).toMatchObject({ error: true });
    expect(auth.analyzed).toHaveLength(0);
    const ctxErr = new Scripted([new ProviderError("x HTTP 400 (context too large): big", "other")]);
    expect(lastTurn(await (await toolHarness(ctxErr)).run())).toMatchObject({ error: true });
    expect(ctxErr.analyzed).toHaveLength(0);
  });
});

describe("the final reply in tool mode (D7)", () => {
  it("after a tool ran, 'search' and 'lookup' in the final reply are dropped and no hop runs", async () => {
    const p = new Scripted([calls(forensic({ text: "a" })), final(reply(superAsk))]);
    const chat = await (await toolHarness(p)).run();
    expect(lastTurn(chat).role).toBe("watson");
    expect(p.analyzed).toHaveLength(0);
    expect(p.sent).toHaveLength(2);
  });

  it("with NO tool run, a final reply with a lookup goes to the hop as today", async () => {
    const p = new Scripted([final(reply(superAsk))], { hop: [reply({ message: "from the hop" })] });
    const chat = await (await toolHarness(p)).run();
    expect(p.analyzed).toHaveLength(1);
    expect(lastTurn(chat).text).toContain("from the hop");
  });

  it("ids an EARLIER round's super search showed still pass the sanitizer in tool mode", async () => {
    const p = new Scripted([final(reply(superAsk))], { hop: [reply()] });
    const h = await toolHarness(p);
    await h.run(); // the hop path: the turn stores lookedUp.shownIds
    expect(p.analyzed).toHaveLength(1);
    const q = new Scripted([final(reply(answer(["raw1"])))]);
    const chat = await runWatsonRound({ ...h.ctx, provider: q, requireProvider: () => q }, "c1", {
      text: "cite it",
    });
    expect(q.sent).toHaveLength(1);
    // The sanitizer kept the earlier id, so the promotion step saw it and said why it dropped it.
    expect(lastTurn(chat).text).toMatch(/cited 1 super-timeline row from an earlier search/);
  });
});

describe("limits before every attempt (D5)", () => {
  it("the send ceiling counts retries: cap 2, transient failures → at most 3 attempts", async () => {
    const busy = () => new ProviderError("HTTP 503 busy", "transport");
    const p = new Scripted([calls(forensic({ text: "a" })), busy(), busy(), busy(), final()]);
    const chat = await (await toolHarness(p, { maxToolCalls: 2, retries: 5 })).run();
    expect(p.sent).toHaveLength(3);
    expect(lastTurn(chat)).toMatchObject({ error: true });
  });

  it("AI off during a retry backoff → no retry request is made", async () => {
    let on = true;
    const p = new Scripted(
      [calls(forensic({ text: "a" })), new ProviderError("HTTP 503", "transport"), final()],
      {
        onSend: (n) => void (n === 2 && (on = false)),
      },
    );
    const chat = await (await toolHarness(p, { retries: 3, ctx: { isAiEnabled: async () => on } })).run();
    expect(p.sent).toHaveLength(2);
    expect(lastTurn(chat).text).toMatch(/AI is off/);
  });

  it("the token limit is checked on the hop call after a no-tool final reply", async () => {
    const p = new Scripted([final(reply(superAsk))], { tokens: 1000 });
    const chat = await (await toolHarness(p, { tokenLimit: 900 })).run();
    expect(p.analyzed).toHaveLength(0);
    expect(lastTurn(chat).text).toMatch(/token limit/);
  });

  it("a billed failure that reaches the token limit is not retried", async () => {
    const billed = new ProviderError("HTTP 503 cut off", "transport");
    billed.usage = { inputTokens: 1000 };
    const p = new Scripted([calls(forensic({ text: "a" })), billed, final()], { tokens: 10 });
    const chat = await (await toolHarness(p, { retries: 3, tokenLimit: 900 })).run();
    expect(p.sent).toHaveLength(2);
    expect(lastTurn(chat).text).toMatch(/token limit/);
  });
});

describe("first-send failures keep today's rules (D7b)", () => {
  it("a Presidio hold on the first send propagates: the round throws it after saving the error turn", async () => {
    const p = new Scripted([new PresidioApprovalRequired([])]);
    const h = await toolHarness(p);
    await expect(h.run()).rejects.toBeInstanceOf(PresidioApprovalRequired);
    expect(lastTurn(await h.chatStore.load("c1"))).toMatchObject({ role: "system", error: true });
    expect(p.analyzed).toHaveLength(0);
  });

  it("a provider error on the first send gives up the auto-attached paste head, as today", async () => {
    const p = new Scripted([new ProviderError("HTTP 503 busy", "transport")]);
    const h = await toolHarness(p);
    await unreadPaste(h.ctx);
    const chat = await h.run();
    expect(p.sent[0].userPrompt).toContain("netstat");
    expect(chat.unreadPasteIds).toEqual([]);
    expect(chat.turns.some((t) => /could not read netstat\.txt/.test(t.text))).toBe(true);
  });

  it("a Presidio hold on the first send keeps the auto-attached paste unread", async () => {
    const p = new Scripted([new PresidioApprovalRequired([])]);
    const h = await toolHarness(p);
    await unreadPaste(h.ctx);
    await expect(h.run()).rejects.toBeInstanceOf(PresidioApprovalRequired);
    expect((await h.chatStore.load("c1")).unreadPasteIds).toEqual(["p1"]);
  });

  it("a bad-shape final reply is retried; the final failure reads as an unreadable reply", async () => {
    const p = new Scripted([final("[1]"), final("[2]")]);
    const chat = await (await toolHarness(p, { retries: 1 })).run();
    expect(p.sent).toHaveLength(2);
    expect(lastTurn(chat).text).toMatch(/cannot read Watson's reply/);
  });
});
