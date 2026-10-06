import { describe, it, expect } from "vitest";
import {
  buildHostSpikeBlock,
  HOST_SPIKE_BLOCK_HEADER,
  HOST_SPIKE_MAX_LINES,
} from "../../src/analysis/hostSpikeLeads.js";
import {
  assembleUserPrompt,
  overheadSourceText,
  type SynthesisBlocks,
  type TimelineSection,
} from "../../src/analysis/ai/synthesisPromptBlocks.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// The host-activity-spike detector (timelineAnomalies.ts) only ever fed the report. These tests pin
// the synthesis side: the same spikes, read from the FORENSIC timeline the AI is already given, as a
// bounded lead block — never a verdict.

function ev(id: string, asset: string | undefined, timestamp: string): ForensicEvent {
  return {
    id,
    timestamp,
    asset,
    description: `row ${id}`,
    severity: "Medium",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
  };
}

const T0 = Date.parse("2026-10-05T10:00:00Z");
const at = (ms: number): string => new Date(T0 + ms).toISOString();

// Three quiet hosts with one row per 15-minute bucket, and WS-02 bursting 12 more rows into the
// 10:30 bucket.
function burstCase(): ForensicEvent[] {
  const rows: ForensicEvent[] = [];
  for (const host of ["WS-01", "WS-02", "WS-03"]) {
    for (let b = 0; b < 4; b++) rows.push(ev(`${host}-q${b}`, host, at(b * 900_000)));
  }
  for (let i = 0; i < 12; i++) rows.push(ev(`burst${i}`, "WS-02", at(1_800_000 + 60_000 + i * 1000)));
  return rows;
}

describe("buildHostSpikeBlock", () => {
  it("names the bursting host, its window and ratio, and cites row ids", () => {
    const block = buildHostSpikeBlock(burstCase());
    expect(block.startsWith(HOST_SPIKE_BLOCK_HEADER)).toBe(true);
    expect(block).toContain("WS-02");
    expect(block).toContain("10:30–10:45");
    expect(block).toMatch(/13 events/);
    expect(block).toMatch(/\d+(?:\.\d)?× /);
    expect(block).toContain("[WS-02-q2, burst0, burst1");
    expect(block).not.toContain("WS-01");
    expect(block).not.toContain("WS-03");
  });

  it("says plainly that a spike is a lead, not a verdict", () => {
    const block = buildHostSpikeBlock(burstCase());
    expect(block).toMatch(/lead/i);
    expect(block).toMatch(/not (?:evidence|a verdict|proof)/i);
  });

  it("measures a lone host against its own usual rate when it has no peers", () => {
    const rows = burstCase().filter((e) => e.asset === "WS-02");
    const block = buildHostSpikeBlock(rows);
    const line = block.split("\n").find((l) => l.startsWith("- WS-02")) ?? "";
    expect(line).toMatch(/× its own usual rate \[/);
    expect(line).not.toContain("peers");
  });

  // The prompt shows a budget-trimmed selection of the timeline. A citation the model cannot find in
  // that selection is a row it cannot read, so the citations are limited to the rows actually shown.
  it("cites only rows the prompt actually shows", () => {
    const shown = new Set(["burst5", "burst7", "WS-01-q0"]);
    const line = buildHostSpikeBlock(burstCase(), undefined, shown)
      .split("\n")
      .find((l) => l.startsWith("- WS-02"));
    expect(line).toMatch(/\[burst5, burst7\]$/);
  });

  it("says so when none of a spike's rows made it into the prompt", () => {
    const line = buildHostSpikeBlock(burstCase(), undefined, new Set(["WS-01-q0"]))
      .split("\n")
      .find((l) => l.startsWith("- WS-02"));
    expect(line).toBeDefined();
    expect(line).not.toMatch(/\[[^\]]*burst/);
    expect(line).toMatch(/none of its rows is in the timeline below/);
  });

  it("returns '' when nothing spikes", () => {
    const flat = burstCase().filter((e) => !e.id.startsWith("burst"));
    expect(buildHostSpikeBlock(flat)).toBe("");
    expect(buildHostSpikeBlock([])).toBe("");
  });

  it("drops spikes on rows with no host — '(unknown)' is not a machine to look at", () => {
    const rows = burstCase().map((e) => (e.asset === "WS-02" ? ev(e.id, undefined, e.timestamp) : e));
    expect(buildHostSpikeBlock(rows)).not.toContain("(unknown)");
  });

  it(`caps the list at ${HOST_SPIKE_MAX_LINES} lines and says how many were left out`, () => {
    const rows: ForensicEvent[] = [];
    const bursting = HOST_SPIKE_MAX_LINES + 3;
    // Many quiet peers keep the per-bucket median at 1, so each bursting host stands out.
    for (let h = 0; h < bursting * 4; h++) {
      const host = `H-${h}`;
      for (let b = 0; b < 4; b++) rows.push(ev(`${host}-q${b}`, host, at(b * 900_000)));
      if (h < bursting) {
        for (let i = 0; i < 10; i++) rows.push(ev(`${host}-b${i}`, host, at(1_800_000 + 60_000 + i * 1000)));
      }
    }
    const block = buildHostSpikeBlock(rows);
    const lines = block.split("\n").filter((l) => l.startsWith("- "));
    expect(lines).toHaveLength(HOST_SPIKE_MAX_LINES);
    expect(block).toMatch(/3 more/);
  });
});

describe("synthesis prompt carries the host-spike block", () => {
  const empty: SynthesisBlocks = {
    incidentTypeBlock: "",
    scopeNote: "",
    contextBlock: "",
    graphBlock: "",
    beaconBlock: "",
    hostSpikeBlock: "SPIKE-MARKER\n\n",
    attackPhaseBlock: "",
    unknownsBlock: "",
    collectionInventoryBlock: "",
    cloudCoverageBlock: "",
    adversaryBlock: "",
    notebookBlock: "",
    analystHypothesesBlock: "",
    refutedHypothesesBlock: "",
    priorHuntsBlock: "",
    playbookProgressBlock: "",
    satisfiedBlock: "",
    pinnedBlock: "",
    reanswerBlock: "",
    observationsBlock: "",
    existingFindings: "",
    openThreads: "",
    falsePositiveBlock: "",
    authorizedContextBlock: "",
    emulationAgentBlock: "",
    entryCandidatesBlock: "",
    learnedPatternsBlock: "",
  };
  const section: TimelineSection = {
    timelineText: "",
    scopedCount: 0,
    truncatedNote: "",
    contextLegend: "",
    lastSummary: "",
  };

  it("puts it in the prompt sent AND in the overhead the budget is measured against", () => {
    expect(assembleUserPrompt(empty, section)).toContain("SPIKE-MARKER");
    expect(overheadSourceText(empty, "")).toContain("SPIKE-MARKER");
  });

  it("places it right after the beacon leads, before the timeline", () => {
    const prompt = assembleUserPrompt({ ...empty, beaconBlock: "BEACON-MARKER\n\n" }, section);
    expect(prompt.indexOf("BEACON-MARKER")).toBeLessThan(prompt.indexOf("SPIKE-MARKER"));
    expect(prompt.indexOf("SPIKE-MARKER")).toBeLessThan(prompt.indexOf("FORENSIC TIMELINE"));
  });
});
