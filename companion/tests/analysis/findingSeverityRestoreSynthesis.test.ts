import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SynthMetaStore } from "../../src/analysis/synthMeta.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { emptyState, type Finding, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import {
  FindingSeverityRestoreStore,
  severityCapOf,
  severityRestoredOf,
} from "../../src/analysis/findingSeverityRestore.js";
import type { AIProvider, AnalyzeResult } from "../../src/providers/provider.js";

// #1973 end to end: a real synthesis caps a finding through a grading gate, the analyst restores it,
// and the restore survives the next synthesis. The case-wide simulation cap still applies after it.

const VERDICT =
  "Strong indicators this activity is a scripted attack-simulation exercise rather than an intrusion";

const raw = (id: string, severity: string, title: string, description: string, eventId: string) => ({
  id,
  severity,
  confidence: 90,
  title,
  description,
  relatedIocs: [],
  mitreTechniques: [],
  relatedEventIds: [eventId],
  status: "open",
});

// f2 says its own subject is not in the evidence and guesses at it: the self-disclaimed gate caps it.
const CAPPED = raw(
  "f2",
  "High",
  "Ransomware encryption of the file server",
  "Ransomware may have encrypted the file server. The file server is not in the evidence.",
  "e1",
);
const SIM = raw("f14", "Info", VERDICT, "Invoke-LabSimulation.ps1 and an answer-key file", "e2");

class FixedProvider implements AIProvider {
  readonly name = "fixed";
  readonly model = "fixed-model";
  constructor(private readonly findings: unknown[]) {}
  async analyze(): Promise<AnalyzeResult> {
    return {
      rawText: JSON.stringify({
        findings: this.findings,
        iocs: [],
        mitreTechniques: [],
        attackerPath: "p",
        summary: "s",
        forensicEvents: [],
        threadsOpened: [],
        threadsClosed: [],
        timelineNote: "",
      }),
    };
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

async function setup(findings: unknown[]) {
  const cases = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-sev-restore-synth-")));
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(cases);
  const state = emptyState("c1");
  state.forensicTimeline = [
    ev("e1", "vssadmin delete shadows /all"),
    ev("e2", "C:\\Users\\lab\\Desktop\\Invoke-LabSimulation.ps1"),
  ];
  await stateStore.save(state);
  const restoreStore = new FindingSeverityRestoreStore(cases);
  const provider = new FixedProvider(findings);
  const pipeline = new AnalysisPipeline({
    provider,
    synthesisProvider: provider,
    stateStore,
    synthMetaStore: new SynthMetaStore(cases),
    findingSeverityRestoreStore: restoreStore,
    imageLoader: async () => ({ base64: "", mimeType: "image/webp" }),
  });
  const find = async (id: string): Promise<Finding> =>
    (await stateStore.load("c1")).findings.find((x) => x.id === id) as Finding;
  return { pipeline, restoreStore, find };
}

describe("analyst severity restore through a real synthesis (#1973)", () => {
  it("records the cap, lifts it once restored, and keeps the restore on the next synthesis", async () => {
    const { pipeline, restoreStore, find } = await setup([CAPPED]);
    await pipeline.synthesize("c1", { force: true });
    const capped = await find("f2");
    expect(capped.severity).toBe("Medium");
    expect(severityCapOf(capped)).toEqual({ from: "High", to: "Medium", gates: ["self-disclaimed"] });

    await restoreStore.restore("c1", "f2", { semanticKey: capped.semanticKey ?? "", by: "Alice" });
    await pipeline.synthesize("c1", { force: true });
    const restored = await find("f2");
    expect(restored.severity).toBe("High");
    expect(severityRestoredOf(restored)?.by).toBe("Alice");
    expect(restored.confidenceReason).toMatch(/not in the evidence/); // the cap reason stays

    await pipeline.synthesize("c1", { force: true });
    expect((await find("f2")).severity).toBe("High");

    await restoreStore.clear("c1", "f2");
    await pipeline.synthesize("c1", { force: true });
    const recapped = await find("f2");
    expect(recapped.severity).toBe("Medium");
    expect(severityRestoredOf(recapped)).toBeUndefined();
  });

  it("still applies the case-wide simulation cap after a restore", async () => {
    const { pipeline, restoreStore, find } = await setup([CAPPED, SIM]);
    await pipeline.synthesize("c1", { force: true });
    const key = (await find("f2")).semanticKey ?? "";
    await restoreStore.restore("c1", "f2", { semanticKey: key, by: "Alice" });
    await pipeline.synthesize("c1", { force: true });
    const f2 = await find("f2");
    expect(f2.severity).toBe("Medium");
    expect(f2.simulation).toMatchObject({ role: "simulated", originalSeverity: "High" });
    expect(severityRestoredOf(f2)?.by).toBe("Alice");
  });
});
