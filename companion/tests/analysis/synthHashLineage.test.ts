import { describe, it, expect } from "vitest";
import { computeSynthHash, type SynthHashInput } from "../../src/analysis/ai/synthesisInputs.js";
import type { IocEnrichment } from "../../src/analysis/stateTypes.js";

// #933 item 18: lineage rides in the prompt tag and the grounding gates, so a forced re-check that
// records a creator on an otherwise-unchanged verdict must re-synthesize — the skip-if-unchanged
// hash used to read only the verdict strings and would have returned the stale run.
function input(enrichments: IocEnrichment[]): SynthHashInput {
  return {
    scopedEvents: [],
    iocs: [{ id: "i1", type: "domain", value: "evil.example", firstSeen: "", enrichments }],
    scope: { mode: "all" } as never,
    markers: [],
    blocks: {} as never,
    observationsBlock: "",
  };
}

describe("computeSynthHash — intel lineage", () => {
  it("changes when a hit gains a recorded creator, and when creators are cut", () => {
    const legacy = input([{ source: "MISP", verdict: "malicious", fetchedAt: "" }]);
    const recorded = input([
      { source: "MISP", verdict: "malicious", fetchedAt: "", originKind: "relay", origins: ["abuse.ch"] },
    ]);
    const nobody = input([
      { source: "MISP", verdict: "malicious", fetchedAt: "", originKind: "relay", origins: [] },
    ]);
    const cut = input([
      {
        source: "MISP",
        verdict: "malicious",
        fetchedAt: "",
        originKind: "relay",
        origins: ["abuse.ch"],
        moreOrigins: 2,
      },
    ]);
    const hashes = [legacy, recorded, nobody, cut].map(computeSynthHash);
    expect(new Set(hashes).size).toBe(4);
    expect(computeSynthHash(recorded)).toBe(computeSynthHash(input(recorded.iocs[0].enrichments!))); // stable
  });
});
