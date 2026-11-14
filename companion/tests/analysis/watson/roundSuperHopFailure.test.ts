import { describe, expect, it } from "vitest";
import { harness, lastWatsonTurn, reply, superLookup } from "./superPromoteFixtures.js";

// Final review M2: when the super-timeline search's second call fails, the turn still records the
// search that ran (the rows went to the provider), so the card can disclose it.

describe("a failed second call still records the search (M2)", () => {
  it("keeps lookedUp and shownIds on the turn", async () => {
    const h = await harness([reply({ message: "FIRST", ...superLookup() })]);
    h.provider.analyze = (() => {
      const real = h.provider.analyze.bind(h.provider);
      return async (req) => {
        if (h.provider.calls >= 1) {
          h.provider.calls++;
          throw new Error("boom");
        }
        return real(req);
      };
    })();
    const chat = await h.run();
    const turn = lastWatsonTurn(chat);
    expect(turn.text).toMatch(/FIRST[\s\S]*could not search the super-timeline.*boom/i);
    expect(turn.lookedUp).toMatchObject({ source: "supertimeline", shownIds: ["raw1", "raw2"] });
  });
});
