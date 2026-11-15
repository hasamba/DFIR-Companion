import { describe, expect, it } from "vitest";
import { fitTranscript, TRIMMED_RESULT } from "../../../src/analysis/ai/watson/transcriptBudget.js";
import { parseOpenAiTurn } from "../../../src/providers/openaiTools.js";
import { ProviderError } from "../../../src/providers/provider.js";
import { ThinkingBindingError, type ToolTurn } from "../../../src/providers/toolCalling.js";
import {
  Scripted,
  call,
  calls,
  final,
  forensic,
  lastTurn,
  reply,
  toolHarness,
} from "./roundToolsFixtures.js";

// Watson phase 5, Task 6 fix round 1: the cap+1 provider-call ceiling is strict per question, the
// hop calls included (controller ruling on review I1); M1 batch protection; M2 wire-safe duplicate
// ids; M4 no "after 0 lookups".

const superAsk = { lookup: { source: "supertimeline", text: "rclone" } };
const LIMIT = "Watson reached its lookup limit for this question.";
const total = (p: Scripted) => p.sent.length + p.analyzed.length;

describe("the cap+1 ceiling covers the hop calls (I1)", () => {
  it("cap 2: two unknown-tool sends, then a lookup request on the 'none' send → 3 calls, no hop", async () => {
    const p = new Scripted([calls(call("nope", {})), calls(call("nope", {})), final(reply(superAsk))]);
    const chat = await (await toolHarness(p, { maxToolCalls: 2 })).run();
    expect(total(p)).toBeLessThanOrEqual(3);
    expect(p.analyzed).toHaveLength(0);
    expect(lastTurn(chat).role).toBe("watson");
    expect(lastTurn(chat).text).toContain(LIMIT);
  });

  it("cap 1: a transient error and its retry, then a lookup request → 2 calls, no hop", async () => {
    const p = new Scripted([new ProviderError("HTTP 503 busy", "transport"), final(reply(superAsk))]);
    const chat = await (await toolHarness(p, { maxToolCalls: 1, retries: 2 })).run();
    expect(total(p)).toBeLessThanOrEqual(2);
    expect(p.analyzed).toHaveLength(0);
    expect(lastTurn(chat).text).toContain(LIMIT);
  });

  it("cap 2: a binding error after two lookups, hop retries on → at most 3 calls in all", async () => {
    const p = new Scripted([
      calls(forensic({ text: "a" })),
      calls(forensic({ text: "b" })),
      new ThinkingBindingError("must start with a thinking block"),
    ]);
    const chat = await (await toolHarness(p, { maxToolCalls: 2, retries: 1 })).run();
    expect(total(p)).toBeLessThanOrEqual(3);
    expect(lastTurn(chat)).toMatchObject({ role: "system", error: true });
    expect(lastTurn(chat).text).toContain(LIMIT);
  });

  it("with calls left, the no-tool hop still runs (cap 4)", async () => {
    const p = new Scripted([final(reply(superAsk))], { hop: [reply({ message: "from the hop" })] });
    const chat = await (await toolHarness(p)).run();
    expect(p.analyzed).toHaveLength(1);
    expect(lastTurn(chat).text).toContain("from the hop");
  });
});

describe("review minors", () => {
  it("M1: no result of the newest tool turn is trimmed", () => {
    const big = (id: string, n: number) => ({ id, name: "forensic_lookup", content: "x".repeat(n) });
    const turns: ToolTurn[] = [
      { role: "assistant", text: "", calls: [] },
      { role: "tool", results: [big("a", 10_000)] },
      { role: "assistant", text: "", calls: [] },
      { role: "tool", results: [big("b", 50_000), big("c", 50_000)] },
    ];
    const out = fitTranscript(turns, 80_000).flatMap((t) => (t.role === "tool" ? t.results : []));
    expect(out.map((r) => (r.content === TRIMMED_RESULT ? "stub" : r.id))).toEqual(["stub", "b", "c"]);
  });

  it("M2: an OpenAI-compatible duplicate id gets a wire-safe salted id", () => {
    const wire = (id: string) => ({
      id,
      type: "function",
      function: { name: "forensic_lookup", arguments: "{}" },
    });
    const t = parseOpenAiTurn({ tool_calls: [wire("call_1"), wire("call_1")] }, "openrouter", "m", "t4");
    expect(t.calls.map((c) => c.id)).toEqual(["call_1", "call_dfir_t4_1"]);
    for (const c of t.calls) expect(c.id).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it("M4: no tool ran and the 'none' send calls tools with no text → no 'after 0 lookups'", async () => {
    const p = new Scripted([calls(call("nope", {})), calls(call("nope", {}))]);
    const chat = await (await toolHarness(p, { maxToolCalls: 1 })).run();
    expect(lastTurn(chat).text).toContain("Watson did not answer. Send your message again.");
    expect(lastTurn(chat).text).not.toMatch(/after 0 lookups/);
  });
});
