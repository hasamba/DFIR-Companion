import { describe, expect, it } from "vitest";
import { converseRestored } from "../../../src/analysis/ai/converseRestored.js";
import { AnonMapStore } from "../../../src/analysis/anonMap.js";
import { createAnonymizer, type AnonPolicy } from "../../../src/analysis/anonymize.js";
import { FakeConverser, final, newSession, req, setup, tokenFor } from "./converseFixtures.js";

// #2657: a Watson tool-mode round saves what it masks to the case's map, and another call growing the
// map between two of its sends neither renumbers its tokens nor stops it (no "masking changed").

const POLICY = { enabled: true, redactSecrets: false, maskPublicIps: true } as AnonPolicy;

describe("Watson tool mode and the case's masking map (#2657)", () => {
  it("the round's tokens are saved, and survive the map growing between sends", async () => {
    const h = await setup({ anonMap: true });
    const store = h.ctx.opts.anonMapStore as AnonMapStore;
    const p = new FakeConverser([final(), final()]);
    const ask = {
      ...req([], "Seen beacon-srv-77"),
      promptEntities: { hosts: ["beacon-srv-77"], usernames: [] },
    };
    const one = await converseRestored(h.ctx, h.caseId, h.st, p, ask, newSession());
    const token = tokenFor(one.session, "beacon-srv-77")!;
    expect((await store.load(h.caseId)).pairs.map((x) => x.token)).toContain(token);

    // Another AI call on the case mints a new host token in between.
    await store.withAnonMap(h.caseId, async (identity) => {
      const anon = createAnonymizer(
        { ...POLICY, categories: { HOST: true } as AnonPolicy["categories"] },
        { hosts: ["other-host-1"], accounts: [], internalDomains: [] },
        [],
        identity,
      );
      anon.apply("other-host-1");
      return { anon, result: undefined };
    });

    await converseRestored(h.ctx, h.caseId, h.st, p, req([], "Seen beacon-srv-77"), one.session);
    expect(p.sent[1].userPrompt).toBe(`Seen ${token}`);
  });
});
