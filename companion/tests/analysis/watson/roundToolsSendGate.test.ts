import { describe, expect, it } from "vitest";
import { Scripted, calls, final, forensic, lastTurn, toolHarness } from "./roundToolsFixtures.js";

// Final review F4: masking and Presidio run before each send and can take a while. AI switched off,
// or the case closed, in that time stops the send: the provider is never called.

/** A harness whose anonymization store read, after the first send, makes `canContinue` say `stop`. */
async function stopDuringPrep(stop: "off" | "frozen") {
  let armed = false;
  let state: "off" | "frozen" | null = null;
  const p = new Scripted([calls(forensic({ text: "a" })), final()], {
    onSend: (n) => {
      if (n === 1) armed = true;
    },
  });
  const h = await toolHarness(p, { anonymize: true, ctx: { canContinue: async () => state } });
  const store = h.ctx.opts.anonStore!;
  const load = store.load.bind(store);
  store.load = async (caseId: string) => {
    if (armed) state = stop; // the continuation send is being prepared now
    return load(caseId);
  };
  return { p, h };
}

describe("a stop during send preparation prevents the send (F4)", () => {
  it("AI switched off while the continuation send is prepared → no second send", async () => {
    const { p, h } = await stopDuringPrep("off");
    const chat = await h.run();
    expect(p.sent).toHaveLength(1);
    expect(lastTurn(chat)).toMatchObject({ role: "system", error: true });
    expect(lastTurn(chat).text).toContain("AI is off for this case");
  });

  it("the case closed while the continuation send is prepared → no second send", async () => {
    const { p, h } = await stopDuringPrep("frozen");
    const chat = await h.run();
    expect(p.sent).toHaveLength(1);
    expect(lastTurn(chat).text).toContain("The case was closed or archived");
  });
});
