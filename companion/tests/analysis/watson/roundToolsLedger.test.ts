import { describe, expect, it } from "vitest";
import { lookupKey } from "../../../src/analysis/ai/watson/autoProgress.js";
import { ThinkingBindingError } from "../../../src/providers/toolCalling.js";
import { CASE, Scripted, calls, final, forensic, reply, toolHarness } from "./roundToolsFixtures.js";

// #2652: Auto's progress ledger (chat.autoSearchesRun) keys every search and lookup a round ran. Tool
// mode must record the same structured key the one-step hop records, exactly once per lookup — also when
// tool mode falls back to the hop, and when a later (hop-mode) reaction round runs the same query.

const refused = () => new ThinkingBindingError("must start with a thinking block");
const keyOf = (text: string) => lookupKey({ text }); // no source: forensic;

/** The tool harness with Auto on and able to continue, so the round's progress is counted. */
async function autoHarness(p: Scripted, maxToolCalls = 4) {
  const h = await toolHarness(p, { mode: "auto", maxToolCalls });
  h.ctx.auto = { ...h.ctx.auto!, continueLater: () => undefined };
  const ledger = async () => {
    await h.run();
    return (await h.chatStore.load(CASE)).autoSearchesRun ?? [];
  };
  return { ...h, ledger };
}

describe("Auto's progress ledger in tool mode (#2652)", () => {
  it("one tool lookup leaves exactly one key: the lookup's structured key", async () => {
    const p = new Scripted([calls(forensic({ text: "rclone" })), final()]);
    const h = await autoHarness(p);
    expect(await h.ledger()).toEqual([keyOf("rclone")]);
  });

  it("the same lookup in other case and spacing is the same key", async () => {
    const p = new Scripted([calls(forensic({ text: "rclone" }), forensic({ text: "  RClone " })), final()]);
    const h = await autoHarness(p);
    expect(await h.ledger()).toEqual([keyOf("rclone")]);
  });

  it("a tool lookup, a fallback, then a hop lookup: two keys, one per lookup", async () => {
    const hopAsk = reply({ lookup: { source: "forensic", text: "mimikatz" } });
    const p = new Scripted([calls(forensic({ text: "rclone" })), refused()], { hop: [hopAsk, reply()] });
    const h = await autoHarness(p);
    expect([...(await h.ledger())].sort()).toEqual([keyOf("mimikatz"), keyOf("rclone")].sort());
  });
});
