// Thinking blocks are bound to everything sent before them (the vendor's prefix check). When D6
// re-masking changes the masked transcript at or before a block, that block and every later one is
// dropped; text, tool_use and tool results still go, masked. Nothing changed means nothing dropped.
import { describe, it, expect } from "vitest";
import {
  anthropicWith,
  req,
  response,
  text,
  thinking,
  toolTurn,
  toolUse,
  turnOf,
  type Body,
} from "./anthropicToolsHelpers.js";
import type { ToolTurn } from "../../src/providers/toolCalling.js";

const T1 = [thinking("s1"), text("First look."), toolUse("tuA", { text: "ANON_HOST_1" })];
const T2 = [thinking("s2"), toolUse("tuB", { text: "ANON_USER_1" })];
const FINAL = response([text("{}")], "end_turn");
const isThinking = (b: { type: string }) => b.type === "thinking" || b.type === "redacted_thinking";

async function twoTurns() {
  const env = anthropicWith([response(T1), response(T2), FINAL, FINAL, FINAL]);
  const r1 = await env.provider.converse(req());
  const tA = toolTurn("tuA");
  const r2 = await env.provider.converse(req({ transcript: [turnOf(r1), tA] }));
  return { ...env, r1, r2, tA };
}

function withoutThinking(content: Body[]) {
  return content.filter((b) => !isThinking(b));
}

describe("Anthropic echo — prefix fingerprint", () => {
  it("no re-mask: every block is echoed byte-identical across sends", async () => {
    const { provider, bodies, r1, r2, tA } = await twoTurns();
    await provider.converse(req({ transcript: [turnOf(r1), tA, turnOf(r2), toolTurn("tuB")] }));
    expect(bodies[1].messages[1].content).toEqual(T1);
    expect(bodies[2].messages[1].content).toEqual(T1);
    expect(bodies[2].messages[3].content).toEqual(T2);
  });

  it("a re-mask before a thinking block drops that block and later ones; the request is otherwise unchanged", async () => {
    const { provider, bodies, r1, r2, tA } = await twoTurns();
    const transcript = [turnOf(r1), tA, turnOf(r2), toolTurn("tuB")];
    await provider.converse(req({ transcript }));
    // D6: a host named after the first send is masked in the prompt on the next send.
    await provider.converse(req({ transcript, userPrompt: "What ran on ANON_HOST_2?" }));
    const same = bodies[2];
    const remasked = bodies[3];
    expect(remasked.messages[0].content[0].text).toBe("What ran on ANON_HOST_2?");
    expect(remasked.messages[1].content).toEqual(withoutThinking(T1));
    expect(remasked.messages[3].content).toEqual(withoutThinking(T2));
    expect(remasked.messages[2]).toEqual(same.messages[2]);
    expect(remasked.messages[4]).toEqual(same.messages[4]);
    for (const k of ["model", "max_tokens", "tools", "tool_choice", "system"])
      expect(remasked[k]).toEqual(same[k]);
  });

  it("a change between two turns keeps the earlier turn's thinking and drops the later turn's", async () => {
    const { provider, bodies, r1, r2 } = await twoTurns();
    const changedResult: ToolTurn = {
      role: "tool",
      results: [{ id: "tuA", name: "forensic_lookup", content: "rows for ANON_HOST_9" }],
    };
    await provider.converse(req({ transcript: [turnOf(r1), changedResult, turnOf(r2), toolTurn("tuB")] }));
    expect(bodies[2].messages[1].content).toEqual(T1);
    expect(bodies[2].messages[3].content).toEqual(withoutThinking(T2));
  });

  it("a re-masked tool argument inside a turn keeps the thinking before it and drops the thinking after it", async () => {
    const content = [
      thinking("s1"),
      toolUse("tuA", { text: "ws-01" }),
      thinking("s2", "next"),
      toolUse("tuB", { text: "b" }),
    ];
    const { provider, bodies } = anthropicWith([response(content), FINAL]);
    const r1 = await provider.converse(req());
    const masked: ToolTurn = {
      role: "assistant",
      text: r1.text,
      calls: [{ ...r1.calls[0], input: { text: "ANON_HOST_3" } }, r1.calls[1]],
      opaque: r1.opaque,
    };
    await provider.converse(req({ transcript: [masked, toolTurn("tuA", "tuB")] }));
    expect(bodies[1].messages[1].content).toEqual([
      thinking("s1"),
      toolUse("tuA", { text: "ANON_HOST_3" }),
      toolUse("tuB", { text: "b" }),
    ]);
    expect(JSON.stringify(bodies[1])).not.toContain("ws-01");
  });

  it("re-masked assistant text replaces the original text and drops the thinking after it", async () => {
    const content = [thinking("s1"), text("ws-01 looks odd."), thinking("s2"), toolUse("tuA", {})];
    const { provider, bodies } = anthropicWith([response(content), FINAL]);
    const r1 = await provider.converse(req());
    const masked: ToolTurn = { ...turnOf(r1), text: "ANON_HOST_3 looks odd." } as ToolTurn;
    await provider.converse(req({ transcript: [masked, toolTurn("tuA")] }));
    expect(bodies[1].messages[1].content).toEqual([
      thinking("s1"),
      text("ANON_HOST_3 looks odd."),
      toolUse("tuA", {}),
    ]);
  });

  it("a malformed opaque value is ignored: the turn is sent from its text and calls", async () => {
    const { provider, bodies } = anthropicWith([FINAL]);
    const turn: ToolTurn = {
      role: "assistant",
      text: "Looking.",
      calls: [{ id: "tu0", name: "forensic_lookup", input: {} }],
      opaque: { blocks: "nope" },
    };
    await provider.converse(req({ transcript: [turn, toolTurn("tu0")] }));
    expect(bodies[0].messages[1].content).toEqual([text("Looking."), toolUse("tu0", {})]);
  });
});
