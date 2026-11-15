import { describe, expect, it } from "vitest";
import { runAiPreview } from "../../../src/analysis/ai/aiPreviewScope.js";
import { previewWatsonRound } from "../../../src/analysis/ai/watson/preview.js";
import { CASE, Scripted, toolHarness } from "./roundToolsFixtures.js";

// Watson phase 5, Task 8: the AI preview follows the round's mode and says how many lookups it allows.

async function capture(maxToolCalls: number) {
  const p = new Scripted([]);
  const h = await toolHarness(p, { maxToolCalls });
  const before = await h.chatStore.load(CASE);
  const res = await runAiPreview(() => previewWatsonRound(h.ctx, CASE, "where did rclone run?"));
  return { p, h, res, before };
}

describe("Watson preview in tool mode", () => {
  it("shows the first request with the addendum and says up to 4 lookups", async () => {
    const { res } = await capture(4);
    expect(res.outcome).toBe("captured");
    if (res.outcome !== "captured") return;
    expect(res.call.systemPrompt).toContain("You can make up to 4 lookups for this question");
    expect(res.call.notes).toContainEqual(
      expect.stringMatching(/^Watson can make up to 4 lookups before it answers/),
    );
  });

  it("makes no provider call and saves nothing", async () => {
    const { p, h, before } = await capture(4);
    expect(p.sent).toHaveLength(0);
    expect(p.analyzed).toHaveLength(0);
    expect(await h.chatStore.load(CASE)).toEqual(before);
  });
});

describe("Watson preview in hop mode", () => {
  it("says one lookup and shows no tool addendum", async () => {
    const { res } = await capture(0);
    expect(res.outcome).toBe("captured");
    if (res.outcome !== "captured") return;
    expect(res.call.systemPrompt).not.toContain("lookups for this question");
    expect(res.call.notes).toContainEqual(
      expect.stringMatching(/^Watson makes one lookup before it answers/),
    );
  });
});
