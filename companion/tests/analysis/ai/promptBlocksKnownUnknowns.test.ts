// #1069: DFIR_SYNTH_KNOWN_UNKNOWNS_MAX=0 must disable the known-unknowns block, per its own
// documented "0 = disable" contract in .env.example and the dashboard settings hint.
import { describe, it, expect, afterEach } from "vitest";
import { knownUnknownsBlock, type PromptBlockContext } from "../../../src/analysis/ai/promptBlocks.js";
import { emptyState, type Finding, type InvestigationState } from "../../../src/analysis/stateTypes.js";

function finding(id: string, severity: Finding["severity"], mitreTechniques: string[]): Finding {
  return {
    id,
    severity,
    title: id,
    description: "",
    relatedIocs: [],
    sourceScreenshots: [],
    mitreTechniques,
    firstSeen: "2026-01-01T00:00:00Z",
    lastUpdated: "2026-01-01T00:00:00Z",
    status: "open",
  };
}

// Only Impact (T1486) is covered -> the other core ATT&CK phases render as gaps, so the block is
// non-empty at the default cap and we can tell a real cap of 0 apart from "nothing to show".
const stateWithGaps: InvestigationState = {
  ...emptyState("c"),
  findings: [finding("f1", "Critical", ["T1486"])],
};

const ctx = { opts: {} } as PromptBlockContext;

afterEach(() => {
  delete process.env.DFIR_SYNTH_KNOWN_UNKNOWNS_MAX;
});

describe("knownUnknownsBlock", () => {
  it("renders the default cap when the env var is unset", async () => {
    const block = await knownUnknownsBlock(ctx, stateWithGaps, [], "c1");
    expect(block).not.toBe("");
  });

  it("DFIR_SYNTH_KNOWN_UNKNOWNS_MAX=0 disables the block", async () => {
    process.env.DFIR_SYNTH_KNOWN_UNKNOWNS_MAX = "0";
    const block = await knownUnknownsBlock(ctx, stateWithGaps, [], "c1");
    expect(block).toBe("");
  });

  it("an unset/empty/non-numeric env var falls back to the default, never to 0", async () => {
    process.env.DFIR_SYNTH_KNOWN_UNKNOWNS_MAX = "not-a-number";
    const block = await knownUnknownsBlock(ctx, stateWithGaps, [], "c1");
    expect(block).not.toBe("");
  });
});
