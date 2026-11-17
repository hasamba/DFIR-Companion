import { describe, expect, it } from "vitest";
import { Scripted, calls, final, forensic, toolHarness } from "./roundToolsFixtures.js";

// #2663: a Watson round counts what its own model calls read — every send of the round, counted as it
// happens — and stores it on the reply, with the part the provider served from its cache.

const watsonTurn = (chat: {
  turns: Array<{ role: string; inputTokens?: number; cacheReadTokens?: number }>;
}) => chat.turns.filter((t) => t.role === "watson").at(-1)!;

describe("Watson round usage (#2663)", () => {
  it("sums every send of the round: a lookup step and the answer", async () => {
    const p = new Scripted([calls(forensic({ text: "rclone" })), final()], { tokens: 100, cacheRead: 900 });
    const h = await toolHarness(p);
    const turn = watsonTurn(await h.run());
    expect(turn.inputTokens).toBe(2000); // 2 sends × (100 uncached + 900 from cache)
    expect(turn.cacheReadTokens).toBe(1800);
  });

  it("a provider that reports no cache: input counted, no cache figure invented", async () => {
    const p = new Scripted([final()], { tokens: 70 });
    const turn = watsonTurn(await (await toolHarness(p)).run());
    expect(turn.inputTokens).toBe(70);
    expect(turn.cacheReadTokens).toBe(0);
  });
});
