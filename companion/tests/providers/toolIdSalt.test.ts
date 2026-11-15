import { describe, expect, it } from "vitest";
import { anthropicWith, response, thinking, toolUse, type Body } from "./anthropicToolsHelpers.js";
import { chat, fc, gem, geminiWith, openAiWith, req, turnOf, wireCall } from "./toolAdapterHelpers.js";
import type { ConverseResult, ToolTurn } from "../../src/providers/toolCalling.js";

// Watson phase 5, Task 6 ruling: a provider that sends no call ids gets synthetic ids unique per
// question (the caller's idSalt), wire-safe ([A-Za-z0-9_-]), stored in opaque. Later turns echo them
// unchanged, so the loop never renames an id and signed reasoning is kept.

const WIRE_SAFE = /^[A-Za-z0-9_-]+$/;
const toolTurnFor = (r: ConverseResult): ToolTurn => ({
  role: "tool",
  results: r.calls.map((c) => ({ id: c.id, name: c.name, content: `rows for ${c.id}` })),
});

async function twoTurns(provider: { converse: (q: ReturnType<typeof req>) => Promise<ConverseResult> }) {
  const r1 = await provider.converse(req({ idSalt: "t0" }));
  const t1: ToolTurn[] = [turnOf(r1), toolTurnFor(r1)];
  const r2 = await provider.converse(req({ transcript: t1, idSalt: "t1" }));
  const t2: ToolTurn[] = [...t1, turnOf(r2), toolTurnFor(r2)];
  await provider.converse(req({ transcript: t2, idSalt: "t2" }));
  const ids = [...r1.calls, ...r2.calls].map((c) => c.id);
  expect(new Set(ids).size).toBe(2);
  for (const id of ids) expect(id).toMatch(WIRE_SAFE);
  return ids;
}

describe("synthetic call ids are unique per question and keep signed reasoning", () => {
  it("Anthropic: two turns without ids keep both thinking blocks", async () => {
    const turn = (sig: string) => response([thinking(sig), { ...toolUse("", { text: "a" }), id: undefined }]);
    const env = anthropicWith([turn("s1"), turn("s2"), response([{ type: "text", text: "{}" }], "end_turn")]);
    const ids = await twoTurns(env.provider);
    expect(ids).toEqual(["toolu_dfir_t0_1", "toolu_dfir_t1_1"]);
    const sigs = (env.bodies[2].messages as Body[]).flatMap((m) =>
      Array.isArray(m.content)
        ? m.content.filter((b: Body) => b.type === "thinking").map((b: Body) => b.signature)
        : [],
    );
    expect(sigs).toEqual(["s1", "s2"]);
  });

  it("OpenRouter: two turns without ids keep both reasoning_details", async () => {
    const detail = (sig: string) => [
      { type: "reasoning.text", text: "x", signature: sig, format: "f", index: 0 },
    ];
    const turn = (sig: string) =>
      chat({ reasoning_details: detail(sig), tool_calls: [wireCall(undefined, '{"text":"a"}')] });
    const env = openAiWith("openrouter", [turn("r1"), turn("r2"), chat({ content: "{}" }, "stop")]);
    const ids = await twoTurns(env.provider);
    expect(ids).toEqual(["call_dfir_t0_0", "call_dfir_t1_0"]);
    const kept = (env.bodies[2].messages as Body[])
      .filter((m) => m.reasoning_details)
      .map((m) => m.reasoning_details[0].signature);
    expect(kept).toEqual(["r1", "r2"]);
  });

  it("Gemini: two turns without ids keep both thought signatures", async () => {
    const env = geminiWith([
      gem([fc(undefined, { text: "a" }, "S1")]),
      gem([fc(undefined, { text: "b" }, "S2")]),
      gem([{ text: "{}" }]),
    ]);
    const ids = await twoTurns(env.provider);
    expect(ids).toEqual(["g_t0_0", "g_t1_0"]);
    const sigs = (env.bodies[2].contents as Body[]).flatMap((c) =>
      (c.parts as Body[]).map((p) => p.thoughtSignature).filter(Boolean),
    );
    expect(sigs).toEqual(["S1", "S2"]);
  });

  it("a provider-given id passes through unchanged", async () => {
    const env = geminiWith([gem([fc("vendor-1", { text: "a" }, "S1")])]);
    const r = await env.provider.converse(req({ idSalt: "t0" }));
    expect(r.calls[0].id).toBe("vendor-1");
  });
});
