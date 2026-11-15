import { describe, expect, it } from "vitest";
import { Scripted, lastTurn, reply, toolHarness } from "./roundToolsFixtures.js";
import { superLookup } from "./superPromoteFixtures.js";

// Codex P2 #4: masking and Presidio run before each one-step send and can take a while. AI switched
// off, or the case closed, in that time stops the send. Only the new `beforeSend` check can do it:
// the guard's own pre-check has already passed when the stop is armed.

type Stop = "off" | "frozen";

/** A one-step harness. Once the guard's pre-check ran (`armed`), the next store read flips the state. */
async function stopDuringPrep(stop: Stop, p: Scripted, armWhen: () => boolean = () => true, retries = 0) {
  let armed = false;
  let state: Stop | null = null;
  const checks = { n: 0 };
  const h = await toolHarness(p, {
    anonymize: true,
    maxToolCalls: 0,
    retries,
    ctx: {
      canContinue: async () => {
        checks.n++;
        if (armWhen()) armed = true;
        return state;
      },
    },
  });
  const store = h.ctx.opts.anonStore!;
  const load = store.load.bind(store);
  store.load = async (caseId: string) => {
    if (armed) state = stop;
    return load(caseId);
  };
  return { ...h, checks };
}

describe("a stop during one-step send preparation prevents the send (Codex P2 #4)", () => {
  it("AI switched off while the one-step call is prepared → no send", async () => {
    const p = new Scripted([]);
    const h = await stopDuringPrep("off", p);
    const chat = await h.run();
    expect(p.analyzed).toHaveLength(0);
    expect(lastTurn(chat).text).toContain("AI is off for this case");
  });

  it("the case closed while the one-step call is prepared → no send", async () => {
    const p = new Scripted([]);
    const h = await stopDuringPrep("frozen", p);
    const chat = await h.run();
    expect(p.analyzed).toHaveLength(0);
    expect(lastTurn(chat).text).toContain("The case was closed or archived");
  });

  it("the hop's call: AI off during its preparation → exactly one send", async () => {
    const p = new Scripted([], { hop: [reply(superLookup())] });
    const h = await stopDuringPrep("off", p, () => p.analyzed.length >= 1);
    const chat = await h.run();
    expect(p.analyzed).toHaveLength(1); // the first call only: the gate refused the hop's send
    expect(lastTurn(chat).text).toContain("AI is off for this case");
  });

  it("a stop is never retried: the check runs once more, not once per retry", async () => {
    const p = new Scripted([]);
    const h = await stopDuringPrep("off", p, () => true, 3);
    await h.run();
    expect(p.analyzed).toHaveLength(0);
    expect(h.checks.n).toBe(2); // the guard's pre-check, then beforeSend
  });

  it("a reaction round: AI off during preparation → no send", async () => {
    const p = new Scripted([]);
    const h = await stopDuringPrep("off", p);
    await h.ctx.chatStore.update("c1", (c) => ({
      ...c,
      pendingCaseEvents: [{ kind: "notebook" as const, text: "n", at: new Date().toISOString() }],
    }));
    await h.run("", { reaction: true });
    expect(p.analyzed).toHaveLength(0);
  });
});
