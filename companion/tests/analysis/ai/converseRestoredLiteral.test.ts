import { describe, expect, it } from "vitest";
import { converseRestored } from "../../../src/analysis/ai/converseRestored.js";
import { FakeConverser, HOST, final, newSession, req, setup, tokenFor } from "./converseFixtures.js";

// #3001: a literal equal to a token an earlier send minted goes out escaped, and comes back as itself.
// converseRestored restores each piece ONCE (restore() is not idempotent after #3001): a second restore
// would turn the planted literal into the real host.

async function firstRound() {
  const h = await setup();
  const one = await converseRestored(
    h.ctx,
    h.caseId,
    h.st,
    new FakeConverser([final()]),
    req(),
    newSession(),
  );
  const token = tokenFor(one.session, HOST)!;
  return { h, one, token, escaped: `ANON-LITERAL_${token.slice("ANON_".length)}` };
}

describe("converseRestored restores a planted literal once (#3001)", () => {
  it("the answer and the assistant text hold the literal, never the real host in its place", async () => {
    const { h, one, token, escaped } = await firstRound();
    const p = new FakeConverser([final(JSON.stringify({ note: `${escaped} on ${token}` }))]);
    const two = await converseRestored(h.ctx, h.caseId, h.st, p, req([], `cmd ${token} ran`), one.session);
    expect(p.sent[0].userPrompt).toBe(`cmd ${escaped} ran`);
    expect(two.result.answer).toEqual({ note: `${token} on ${HOST}` });
    expect(two.result.assistant.text).toBe(JSON.stringify({ note: `${token} on ${HOST}` }));
  });

  it("tool-call inputs restore the literal once", async () => {
    const { h, one, token, escaped } = await firstRound();
    const call = { id: "c1", name: "lookup", input: { q: escaped, host: token } };
    const p = new FakeConverser([{ text: "", calls: [call] }]);
    const two = await converseRestored(h.ctx, h.caseId, h.st, p, req([], `cmd ${token}`), one.session);
    expect(two.result.calls[0].input).toEqual({ q: token, host: HOST });
  });
});
