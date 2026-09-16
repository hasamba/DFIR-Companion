import { describe, it, expect } from "vitest";
import { withAdversaryHintsCaveat } from "../../src/analysis/attributionCaveatEnvelope.js";
import { ADVERSARY_HINTS_CAVEAT } from "../../src/analysis/adversaryHints.js";
import type { AdversaryHint } from "../../src/analysis/adversaryTechniques.js";

function hint(over: Partial<AdversaryHint> = {}): AdversaryHint {
  return {
    id: "G0016",
    name: "APT29",
    aliases: [],
    description: "",
    url: "",
    overlapCount: 4,
    exactCount: 2,
    overlapTechniques: [],
    ...over,
  };
}

describe("withAdversaryHintsCaveat", () => {
  it("bundles the imported caveat constant with the hints — never a copy of the string", () => {
    const envelope = withAdversaryHintsCaveat([hint()]);
    expect(envelope.caveat).toBe(ADVERSARY_HINTS_CAVEAT);
  });

  it("carries the hints through unchanged", () => {
    const hints = [hint({ id: "G0016" }), hint({ id: "G0007" })];
    const envelope = withAdversaryHintsCaveat(hints);
    expect(envelope.hints).toBe(hints);
  });

  it("still carries the caveat even when there are no hints to show", () => {
    const envelope = withAdversaryHintsCaveat([]);
    expect(envelope.caveat).toBe(ADVERSARY_HINTS_CAVEAT);
    expect(envelope.hints).toEqual([]);
  });
});
