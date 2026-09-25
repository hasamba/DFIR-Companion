import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SynthMetaStore } from "../../src/analysis/synthMeta.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import type { AIProvider, AnalyzeResult } from "../../src/providers/provider.js";

// #1595 end to end: a real synthesis whose own findings conclude "authorized simulation" persists
// the capped attack findings and the raised verdict — and honours the analyst's override.

const VERDICT =
  "Strong indicators this activity is a scripted attack-simulation exercise rather than an intrusion";

function delta(): string {
  return JSON.stringify({
    findings: [
      {
        id: "f1",
        severity: "Critical",
        confidence: 95,
        title: "Mimikatz executed against LSASS",
        description: "sekurlsa::logonpasswords",
        relatedIocs: [],
        mitreTechniques: ["T1003.001"],
        relatedEventIds: ["e1"],
        status: "confirmed",
      },
      {
        id: "f14",
        severity: "Info",
        confidence: 85,
        title: VERDICT,
        description: "Invoke-LabSimulation.ps1 and an answer-key file",
        relatedIocs: [],
        mitreTechniques: [],
        relatedEventIds: ["e2"],
        status: "open",
      },
    ],
    iocs: [],
    mitreTechniques: [],
    attackerPath: "p",
    summary: "s",
    forensicEvents: [],
    threadsOpened: [],
    threadsClosed: [],
    timelineNote: "",
  });
}

class FixedProvider implements AIProvider {
  readonly name = "fixed";
  readonly model = "fixed-model";
  async analyze(): Promise<AnalyzeResult> {
    return { rawText: delta() };
  }
}

const ev = (id: string, description: string): ForensicEvent => ({
  id,
  timestamp: "2026-09-24T09:04:00Z",
  description,
  severity: "Medium",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
  asset: "ws-01.example.com",
  sources: ["Velociraptor"],
});

async function setup() {
  const cases = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-sim-synth-")));
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(cases);
  const state = emptyState("c1");
  state.forensicTimeline = [
    ev("e1", "mimikatz.exe sekurlsa::logonpasswords"),
    ev("e2", "C:\\Users\\lab\\Desktop\\Invoke-LabSimulation.ps1"),
  ];
  await stateStore.save(state);
  const synthMetaStore = new SynthMetaStore(cases);
  const provider = new FixedProvider();
  const pipeline = new AnalysisPipeline({
    provider,
    synthesisProvider: provider,
    stateStore,
    synthMetaStore,
    imageLoader: async () => ({ base64: "", mimeType: "image/webp" }),
  });
  return { pipeline, stateStore, synthMetaStore };
}

const byId = async (s: StateStore) =>
  Object.fromEntries((await s.load("c1")).findings.map((f) => [f.id, f] as const));

describe("simulation verdict through a real synthesis (#1595)", () => {
  it("caps the attack finding and raises the verdict, even after grading capped the verdict's confidence", async () => {
    const { pipeline, stateStore } = await setup();
    await pipeline.synthesize("c1", { force: true });
    const f = await byId(stateStore);
    expect(f.f14.confidence).toBeLessThan(80); // single-tool, single-host: grading capped it
    expect(f.f14.severity).toBe("Critical");
    expect(f.f1.severity).toBe("Medium");
    expect(f.f1.simulation).toMatchObject({ role: "simulated", originalSeverity: "Critical" });
  });

  it("honours the analyst's override on the next synthesis", async () => {
    const { pipeline, stateStore, synthMetaStore } = await setup();
    await synthMetaStore.setSimulationOverride("c1", true);
    await pipeline.synthesize("c1", { force: true });
    const f = await byId(stateStore);
    expect(f.f1.severity).toBe("Critical");
    expect(f.f14.simulation).toMatchObject({ role: "verdict", overridden: true });
    expect((await synthMetaStore.load("c1")).simulationOverride?.treatAsReal).toBe(true);
  });
});
