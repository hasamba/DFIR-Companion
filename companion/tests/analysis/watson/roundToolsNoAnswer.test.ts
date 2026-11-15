import { describe, expect, it } from "vitest";
import { Scripted, calls, final, forensic, lastTurn, toolHarness } from "./roundToolsFixtures.js";

// Final review F6: a "none" send that still returns tool calls and no text gets one finalization
// send while the question has sends left, instead of failing the whole question at once. A second
// no-answer still fails: roundTools.test.ts.

const both = () => calls(forensic({ text: "a" }), forensic({ text: "b" }));

describe("a 'none' send with tool calls and no text (F6)", () => {
  it("cap 2, both lookups in one batch: the 'none' send gives calls only → one finalization send answers", async () => {
    const p = new Scripted([both(), calls(forensic({ text: "c" })), final()]);
    const chat = await (await toolHarness(p, { maxToolCalls: 2 })).run();
    expect(p.sent).toHaveLength(3);
    expect(p.sent.slice(1).map((r) => r.toolChoice)).toEqual(["none", "none"]);
    expect(lastTurn(chat).role).toBe("watson");
  });
});
