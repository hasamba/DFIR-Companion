import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SynthMetaStore } from "../../src/analysis/synthMeta.js";
import { SecondOpinionStore } from "../../src/analysis/secondOpinionStore.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import {
  FindingSeverityRestoreStore,
  severityRestoredOf,
} from "../../src/analysis/findingSeverityRestore.js";
import { markReopenedDecisions, primaryCallOf } from "../../src/analysis/secondOpinionReopen.js";
import type { SecondOpinion, SecondOpinionDelta } from "../../src/analysis/secondOpinion.js";
import { emptyState, type Finding, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import type { AIProvider, AnalyzeResult } from "../../src/providers/provider.js";

// #1972 end to end: a real synthesis keeps the primary model's own graded call on a finding that an
// accepted second-opinion decision overrides, the panel record shows the decision as reopened when
// that call is new, and Keep / Drop act on it.

const PLAIN = { title: "Advanced IP Scanner executed", description: "advanced_ip_scanner.exe ran on ws-01" };
// Says its own subject is not in the evidence: the self-disclaimed gate caps a High to Medium.
const CAPPED = {
  title: "Ransomware encryption of the file server",
  description: "Ransomware may have encrypted the file server. The file server is not in the evidence.",
};

class MutableProvider implements AIProvider {
  readonly name = "fixed";
  readonly model = "fixed-model";
  severity = "High";
  constructor(private readonly shape: { title: string; description: string }) {}
  async analyze(): Promise<AnalyzeResult> {
    const finding = {
      id: "f1",
      severity: this.severity,
      confidence: 90,
      ...this.shape,
      relatedIocs: [],
      mitreTechniques: [],
      relatedEventIds: ["e1"],
      status: "open",
    };
    return {
      rawText: JSON.stringify({
        findings: [finding],
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

const ev: ForensicEvent = {
  id: "e1",
  timestamp: "2026-09-24T09:04:00Z",
  description: "advanced_ip_scanner.exe ran on ws-01, then vssadmin delete shadows /all",
  severity: "Medium",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
  asset: "ws-01.example.com",
  sources: ["Velociraptor"],
};

function decision(shape: { title: string }, aSeverity: string, bSeverity: string): SecondOpinionDelta {
  return {
    id: "severity:f1",
    kind: "severity",
    title: shape.title,
    aSeverity,
    bSeverity,
    finding: {
      id: "f1",
      severity: aSeverity,
      title: shape.title,
      description: "",
      relatedIocs: [],
      sourceScreenshots: [],
      mitreTechniques: [],
      firstSeen: "",
      lastUpdated: "",
      status: "open",
      relatedEventIds: ["e1"],
    } as Finding,
    rationale: "",
    recommendation: "review",
    status: "accepted",
  } as SecondOpinionDelta;
}

async function setup(shape: { title: string; description: string }, d: SecondOpinionDelta) {
  const cases = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-so-reopen-")));
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(cases);
  const state = emptyState("c1");
  state.forensicTimeline = [ev];
  await stateStore.save(state);
  const soStore = new SecondOpinionStore(cases);
  const rec: SecondOpinion = {
    generatedAt: "2026-10-06T09:00:00.000Z",
    modelA: "a",
    modelB: "b",
    referee: "",
    summary: "",
    agreementCount: 0,
    deltas: [d],
  };
  await soStore.save("c1", rec);
  const restoreStore = new FindingSeverityRestoreStore(cases);
  const provider = new MutableProvider(shape);
  const pipeline = new AnalysisPipeline({
    provider,
    synthesisProvider: provider,
    stateStore,
    synthMetaStore: new SynthMetaStore(cases),
    secondOpinionStore: soStore,
    findingSeverityRestoreStore: restoreStore,
    imageLoader: async () => ({ base64: "", mimeType: "image/webp" }),
  });
  const finding = async (): Promise<Finding> =>
    (await stateStore.load("c1")).findings.find((x) => x.id === "f1") as Finding;
  const panel = async () =>
    markReopenedDecisions((await soStore.load("c1")) as SecondOpinion, (await stateStore.load("c1")).findings)
      .deltas[0];
  return { pipeline, provider, finding, panel, soStore, restoreStore };
}

describe("reopen through a real synthesis (#1972)", () => {
  it("keeps the analyst's value, and reopens only on a genuinely new primary call", async () => {
    const h = await setup(PLAIN, decision(PLAIN, "High", "Medium"));
    h.provider.severity = "High"; // the primary repeats its overruled call
    await h.pipeline.synthesize("c1", { force: true });
    expect((await h.finding()).severity).toBe("Medium");
    expect(primaryCallOf(await h.finding())?.severity).toBe("High");
    expect((await h.panel()).reopened).toBeUndefined();

    h.provider.severity = "Critical"; // new evidence, new call
    await h.pipeline.synthesize("c1", { force: true });
    expect((await h.finding()).severity).toBe("Medium"); // still applied until Keep or Drop
    expect((await h.panel()).reopened).toBe("Critical");
  });

  it("compares the GRADED call: a raw High that a gate caps back to the original is no reopen", async () => {
    const h = await setup(CAPPED, decision(CAPPED, "Medium", "Low"));
    h.provider.severity = "High";
    await h.pipeline.synthesize("c1", { force: true });
    expect(primaryCallOf(await h.finding())?.severity).toBe("Medium");
    expect((await h.panel()).reopened).toBeUndefined();
  });

  it("Keep closes the reopen and leaves the case as it is", async () => {
    const h = await setup(PLAIN, decision(PLAIN, "High", "Medium"));
    h.provider.severity = "Critical";
    await h.pipeline.synthesize("c1", { force: true });
    const { record } = await h.pipeline.resolveReopenedSecondOpinion("c1", "severity:f1", true);
    expect(record.deltas[0]).toMatchObject({ status: "accepted", aSeverity: "Critical" });
    expect((await h.finding()).severity).toBe("Medium");
    expect((await h.panel()).reopened).toBeUndefined();
  });

  it("Drop rejects the decision and restores the primary's call, durably", async () => {
    const h = await setup(PLAIN, decision(PLAIN, "High", "Medium"));
    h.provider.severity = "Critical";
    await h.pipeline.synthesize("c1", { force: true });
    const { record, state } = await h.pipeline.resolveReopenedSecondOpinion("c1", "severity:f1", false);
    expect(record.deltas[0].status).toBe("rejected");
    expect(state.findings.find((f) => f.id === "f1")?.severity).toBe("Critical");
    await h.pipeline.synthesize("c1", { force: true });
    expect((await h.finding()).severity).toBe("Critical");
  });

  it("refuses Keep and Drop on a decision that is not reopened", async () => {
    const h = await setup(PLAIN, decision(PLAIN, "High", "Medium"));
    await h.pipeline.synthesize("c1", { force: true });
    await expect(h.pipeline.resolveReopenedSecondOpinion("c1", "severity:f1", false)).rejects.toThrow(
      /not reopened/,
    );
    await expect(h.pipeline.resolveReopenedSecondOpinion("c1", "nope", true)).rejects.toThrow(
      /unknown second-opinion delta/,
    );
  });

  it("Drop with a #1973 restore on the finding: the restore lifts the primary's cap", async () => {
    const h = await setup(CAPPED, decision(CAPPED, "Low", "Info"));
    h.provider.severity = "High"; // graded to Medium: new against both Low and Info
    await h.pipeline.synthesize("c1", { force: true });
    expect((await h.panel()).reopened).toBe("Medium");
    await h.restoreStore.restore("c1", "f1", {
      semanticKey: (await h.finding()).semanticKey ?? "",
      by: "Alice",
    });
    const { state } = await h.pipeline.resolveReopenedSecondOpinion("c1", "severity:f1", false);
    const f1 = state.findings.find((f) => f.id === "f1") as Finding;
    expect(f1.severity).toBe("High");
    expect(severityRestoredOf(f1)?.by).toBe("Alice");
  });
});
