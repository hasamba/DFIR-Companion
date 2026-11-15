import { describe, expect, it } from "vitest";
import { ProviderError } from "../../../src/providers/provider.js";
import { TRIMMED_RESULT, fitTranscript } from "../../../src/analysis/ai/watson/transcriptBudget.js";
import type { ToolTurn } from "../../../src/providers/toolCalling.js";
import {
  Scripted,
  call,
  calls,
  final,
  forensic,
  lastTurn,
  loopOutcome,
  reply,
  resultsIn,
  superSearch,
  toolHarness,
} from "./roundToolsFixtures.js";
import { answer, raw } from "./superPromoteFixtures.js";

// Watson phase 5, Task 6: the tool loop in a Watson round — order, the cap, the send ceiling, the
// stops before every send, masking, the super-timeline cap, promotion and the transcript budget.

const NOT_RUN_CAP = "Not run: you used all 2 lookups for this question. Answer now from what you have.";
const NOT_RUN_SUPER = "Not run: you used both super-timeline searches for this question. Use what you have.";

describe("the tool loop", () => {
  it("runs two lookups then answers; the outcome lists both lookups in order", async () => {
    const p = new Scripted([
      calls(forensic({ text: "quiet" })),
      calls(superSearch({ text: "rclone" })),
      final(),
    ]);
    const h = await toolHarness(p);
    const { outcome, counter } = await loopOutcome(h.ctx);
    expect(outcome.lookups!.map((l) => l.source ?? "forensic")).toEqual(["forensic", "supertimeline"]);
    expect(outcome.reply?.message).toBe("I looked at the case.");
    expect(counter.calls).toBe(3);
    const q = new Scripted([
      calls(forensic({ text: "quiet" })),
      calls(superSearch({ text: "rclone" })),
      final(),
    ]);
    const chat = await (await toolHarness(q)).run();
    expect(chat.calls).toBe(3);
    expect(lastTurn(chat).role).toBe("watson");
  });

  it("cap: 3 parallel calls with cap 2 → 2 run, the 3rd gets 'Not run', the next send is toolChoice none", async () => {
    const batch = calls(forensic({ text: "a" }), forensic({ text: "b" }), forensic({ text: "c" }));
    const p = new Scripted([batch, final()]);
    const h = await toolHarness(p, { maxToolCalls: 2 });
    const { outcome } = await loopOutcome(h.ctx);
    expect(outcome.lookups).toHaveLength(2);
    const results = resultsIn(p.sent[1]);
    expect(results).toHaveLength(3);
    expect(results[2]).toMatchObject({ content: NOT_RUN_CAP, isError: true });
    expect(p.sent.map((r) => r.toolChoice)).toEqual(["auto", "none"]);
  });

  it("cap reached, the 'none' send and its finalization send call tools with no text → 'Watson did not answer after 2 lookups.'", async () => {
    const p = new Scripted([
      calls(forensic({ text: "a" }), forensic({ text: "b" })),
      calls(forensic({ text: "c" })),
      calls(forensic({ text: "d" })), // F6: one finalization send while a send is left
    ]);
    const chat = await (await toolHarness(p, { maxToolCalls: 2 })).run();
    expect(p.sent).toHaveLength(3);
    expect(lastTurn(chat)).toMatchObject({ role: "system", error: true });
    expect(lastTurn(chat).text).toContain("Watson did not answer after 2 lookups. Send your message again.");
  });

  it("cost stop mid-loop: the token limit is reached after the first lookup → no further send, roster saved", async () => {
    // A lookup costs nothing: the limit is checked before each send, so the search runs and the next send stops.
    const p = new Scripted([calls(superSearch({ text: "rclone" })), final()], { tokens: 1000 });
    const h = await toolHarness(p, { tokenLimit: 900, raw: [raw("raw1", { asset: "FINSRV-07" })] });
    const chat = await h.run();
    expect(p.sent).toHaveLength(1);
    expect(lastTurn(chat)).toMatchObject({ role: "system", error: true });
    expect(lastTurn(chat).text).toMatch(/token limit/);
    expect(chat.maskRoster?.hosts).toContain("finsrv-07");
    const q = new Scripted([calls(superSearch({ text: "rclone" })), final()], { tokens: 1000 });
    const { outcome } = await loopOutcome((await toolHarness(q, { tokenLimit: 900 })).ctx);
    expect(outcome.lookups).toHaveLength(1);
    expect(outcome.reply).toBeNull();
  });

  it("AI switched off mid-loop → WatsonAiOff error turn, no further send", async () => {
    let on = true;
    const p = new Scripted([calls(forensic({ text: "a" })), final()], { onSend: () => void (on = false) });
    const h = await toolHarness(p, { ctx: { isAiEnabled: async () => on } });
    const chat = await h.run();
    expect(p.sent).toHaveLength(1);
    expect(lastTurn(chat).text).toMatch(/AI is off for this case/);
  });

  it("case closed between two tools of one parallel batch → the second tool does not run, no further send", async () => {
    // canContinue runs before the send, again right before it goes (F4), then before each tool: the
    // fourth check sees the case closed.
    let checks = 0;
    const p = new Scripted([calls(forensic({ text: "a" }), forensic({ text: "b" })), final()]);
    const h = await toolHarness(p, { ctx: { canContinue: async () => (++checks >= 4 ? "frozen" : null) } });
    const { outcome } = await loopOutcome(h.ctx);
    expect(p.sent).toHaveLength(1);
    expect(outcome.lookups).toHaveLength(1);
    expect(String(outcome.error)).toMatch(/closed or archived/);
  });

  it("send bound: repeated unknown tools and invalid args with NO limit → at most cap+1 sends, the last is 'none'", async () => {
    const bad = () => calls(call("nope", {}), forensic({ bogus: 1 }));
    const p = new Scripted([bad(), bad(), bad(), bad(), bad(), final()]);
    const chat = await (await toolHarness(p, { maxToolCalls: 2 })).run();
    expect(p.sent).toHaveLength(3);
    expect(p.sent.at(-1)!.toolChoice).toBe("none");
    expect(lastTurn(chat)).toMatchObject({ role: "system", error: true });
  });

  it("an empty response (no text, no calls) is retried, then ends as an unreadable reply", async () => {
    const p = new Scripted([final(""), final("")]);
    const chat = await (await toolHarness(p, { retries: 1 })).run();
    expect(p.sent).toHaveLength(2);
    expect(lastTurn(chat).text).toMatch(/cannot read Watson's reply/);
  });

  it("a tool error is told to the model and the round continues to an answer", async () => {
    const p = new Scripted([calls(call("paste_search", { pasteId: "nope", terms: ["x"] })), final()]);
    const chat = await (await toolHarness(p)).run();
    expect(resultsIn(p.sent[1])[0]).toMatchObject({ isError: true });
    expect(resultsIn(p.sent[1])[0].content).toMatch(/^Lookup not run:/);
    expect(lastTurn(chat).role).toBe("watson");
  });

  it("call ids pass through unchanged, and each send carries an idSalt unique in the question", async () => {
    const p = new Scripted([
      calls(forensic({ text: "a" }, "vendor-a")),
      calls(forensic({ text: "b" }, "vendor-b")),
      final(),
    ]);
    await loopOutcome((await toolHarness(p)).ctx);
    expect(resultsIn(p.sent[2]).map((r) => r.id)).toEqual(["vendor-a", "vendor-b"]);
    expect(p.sent.map((r) => r.idSalt)).toEqual(["t0", "t1", "t2"]);
  });
});

describe("masking in the tool loop (D6, same-send roster)", () => {
  it("a host only in a super row is masked in the send that carries it; a masked arg is restored before the search", async () => {
    const tokenOf = (text: string) => text.match(/ANON_HOST_\d+/g) ?? [];
    let token = "";
    const p = new Scripted([
      calls(superSearch({ text: "rclone" })),
      (req) => {
        const result = resultsIn(req)[0].content;
        token = tokenOf(result)[0] ?? "";
        return calls(forensic({ host: token }));
      },
      final(),
    ]);
    const h = await toolHarness(p, { anonymize: true, raw: [raw("raw1", { asset: "FINSRV-07" })] });
    const { outcome } = await loopOutcome(h.ctx);
    const carried = JSON.stringify(p.sent[1]);
    expect(carried).not.toContain("FINSRV-07");
    expect(token).toMatch(/^ANON_HOST_\d+$/);
    expect(JSON.stringify(p.sent[2])).not.toContain("FINSRV-07");
    expect(outcome.lookups![1].what).toContain("FINSRV-07");
    expect(outcome.superRoster?.hosts).toContain("finsrv-07");
  });
});

describe("the super-timeline in the tool loop", () => {
  it("promotion: cited rows from two different super searches are both promoted in one record", async () => {
    const p = new Scripted([
      calls(superSearch({ text: "alpha" })),
      calls(superSearch({ text: "bravo" })),
      final(reply(answer(["ra", "rb"]))),
    ]);
    const h = await toolHarness(p, {
      raw: [raw("ra", { description: "alpha copy" }), raw("rb", { description: "bravo copy" })],
    });
    const chat = await h.run();
    expect(lastTurn(chat).role).toBe("watson");
    const promo = chat.proposals.filter((x) => x.kind === "event_promote");
    expect(promo).toHaveLength(1);
    expect(await h.row("ra")).toBeDefined();
    expect(await h.row("rb")).toBeDefined();
  });

  it("super cap: a third supertimeline_search is not run, uses a send, sets superCapHit (R2)", async () => {
    const p = new Scripted([
      calls(superSearch({ text: "rclone" })),
      calls(superSearch({ text: "rclone copy" })),
      calls(superSearch({ text: "rclone raw" })),
      final(),
    ]);
    const { outcome } = await loopOutcome((await toolHarness(p, { maxToolCalls: 6 })).ctx);
    expect(p.sent).toHaveLength(4);
    expect(resultsIn(p.sent[3]).at(-1)).toMatchObject({ content: NOT_RUN_SUPER, isError: true });
    expect(outcome.superCapHit).toBe(true);
    expect(outcome.lookups).toHaveLength(2);
  });
});

describe("the transcript budget (D4c, R1)", () => {
  const turns = (sizes: number[]): ToolTurn[] =>
    sizes.flatMap((n, i) => [
      { role: "assistant" as const, text: "", calls: [{ id: `k${i}`, name: "forensic_lookup", input: {} }] },
      { role: "tool" as const, results: [{ id: `k${i}`, name: "forensic_lookup", content: "x".repeat(n) }] },
    ]);
  const contents = (t: ToolTurn[]) =>
    t.flatMap((x) => (x.role === "tool" ? x.results.map((r) => r.content) : []));

  it("stubs the oldest results until the total fits; the newest is never stubbed", () => {
    const out = contents(fitTranscript(turns([50_000, 30_000, 20_000]), 80_000));
    expect(out[0]).toBe(TRIMMED_RESULT);
    expect(out[1]).toHaveLength(30_000);
    expect(out[2]).toHaveLength(20_000);
    expect(contents(fitTranscript(turns([90_000]), 80_000))[0]).toHaveLength(90_000);
  });

  it("leaves a transcript under the budget unchanged and never changes its input", () => {
    const t = turns([10, 20]);
    expect(fitTranscript(t, 80_000)).toEqual(t);
    fitTranscript(turns([90_000, 10]), 80_000);
    expect(contents(t)).toEqual(["x".repeat(10), "x".repeat(20)]);
  });

  it("in the loop: the model's copy is trimmed, the lookups keep the full record", async () => {
    const p = new Scripted([
      calls(superSearch({ text: "rclone" })),
      calls(forensic({ text: "quiet" })),
      calls(forensic({ text: "event" })),
      final(),
    ]);
    const { outcome } = await loopOutcome((await toolHarness(p)).ctx, { budget: 600 });
    const sizes = resultsIn(p.sent[3]).map((r) => r.content.length);
    expect(resultsIn(p.sent[1])[0].content.length).toBeGreaterThan(200);
    expect(resultsIn(p.sent[3])[0].content).toBe(TRIMMED_RESULT);
    expect(resultsIn(p.sent[3]).at(-1)!.content).not.toBe(TRIMMED_RESULT);
    expect(sizes.reduce((n, x) => n + x, 0)).toBeLessThanOrEqual(
      Math.max(600, sizes.at(-1)! + 2 * TRIMMED_RESULT.length),
    );
    expect(outcome.superShown!.length).toBeGreaterThan(0);
    expect(outcome.lookups).toHaveLength(3);
  });
});

describe("finalization (D7c, R3)", () => {
  it("after a tool ran, a non-JSON reply gets ONE 'Answer now' send with toolChoice none; a second failure is unreadable", async () => {
    const p = new Scripted([calls(forensic({ text: "a" })), final("not json"), final("still not")]);
    const chat = await (await toolHarness(p, { retries: 3 })).run();
    expect(p.sent).toHaveLength(3);
    expect(p.sent[2].toolChoice).toBe("none");
    expect(p.sent[2].systemPrompt.endsWith("Answer now. Reply with the JSON object only.")).toBe(true);
    expect(lastTurn(chat).text).toMatch(/cannot read Watson's reply/);
  });

  it("a finalization reply that parses is the answer; a ```json fence is accepted (Gemini)", async () => {
    const p = new Scripted([
      calls(forensic({ text: "a" })),
      final("oops"),
      final("```json\n" + reply() + "\n```"),
    ]);
    const chat = await (await toolHarness(p)).run();
    expect(lastTurn(chat).role).toBe("watson");
  });

  it("finalization is skipped when the send ceiling is already reached", async () => {
    const p = new Scripted([calls(forensic({ text: "a" })), final("not json"), final()]);
    const chat = await (await toolHarness(p, { maxToolCalls: 1 })).run();
    expect(p.sent).toHaveLength(2);
    expect(lastTurn(chat)).toMatchObject({ role: "system", error: true });
  });

  it("before any tool ran, a bad final reply keeps the guardedCall retry", async () => {
    const p = new Scripted([final("not json"), final()]);
    const chat = await (await toolHarness(p, { retries: 1 })).run();
    expect(p.sent).toHaveLength(2);
    expect(p.sent[1].toolChoice).toBe("auto");
    expect(lastTurn(chat).role).toBe("watson");
  });

  it("a transient error after a tool ran is retried with the same transcript; no lookup runs twice", async () => {
    const p = new Scripted([
      calls(forensic({ text: "a" })),
      new ProviderError("HTTP 503 busy", "transport"),
      final(),
    ]);
    const { outcome } = await loopOutcome((await toolHarness(p, { retries: 2 })).ctx);
    expect(p.sent).toHaveLength(3);
    expect(p.sent[2].transcript).toEqual(p.sent[1].transcript);
    expect(outcome.lookups).toHaveLength(1);
    expect(outcome.reply).not.toBeNull();
  });
});
