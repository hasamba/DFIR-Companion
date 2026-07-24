import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { CrossCaseStore } from "../../src/storage/crossCaseStore.js";
import type { InvestigationState, IOC, Technique } from "../../src/analysis/stateTypes.js";

let root: string;
let store: CaseStore;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "dfir-crosscase-"));
  store = new CaseStore(root);
});

afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

function state(caseId: string, iocs: IOC[], techniques: Technique[] = []): InvestigationState {
  return {
    caseId,
    findings: [],
    iocs,
    openThreads: [],
    timeline: [],
    forensicTimeline: [],
    mitreTechniques: techniques,
    keyQuestions: [],
    nextSteps: [],
    uncertainties: [],
    lastSummary: "",
    attackerPath: "",
    narrativeTimeline: "",
    iocExcludeRules: [],
    updatedAt: new Date().toISOString(),
  } as InvestigationState;
}

function ioc(value: string, verdict?: string): IOC {
  return {
    id: `ioc-${value}`,
    type: "ip",
    value,
    firstSeen: "2026-01-01T00:00:00Z",
    ...(verdict ? { enrichments: [{ source: "VT", verdict, fetchedAt: "2026-01-01T00:00:00Z" }] } : {}),
  } as IOC;
}

describe("CrossCaseStore", () => {
  it("indexes IOCs from a case", async () => {
    const kb = new CrossCaseStore(store);
    await kb.indexCase(state("case-a", [ioc("1.2.3.4", "malicious")]), "Ransomware A");
    const entry = await kb.lookupIoc("1.2.3.4");
    expect(entry).not.toBeNull();
    expect(entry!.cases).toHaveLength(1);
    expect(entry!.cases[0].caseId).toBe("case-a");
    expect(entry!.cases[0].verdict).toBe("malicious");
  });

  it("aggregates the same IOC across multiple cases", async () => {
    const kb = new CrossCaseStore(store);
    await kb.indexCase(state("case-a", [ioc("1.2.3.4", "malicious")]), "A");
    await kb.indexCase(state("case-b", [ioc("1.2.3.4", "suspicious")]), "B");
    const entry = await kb.lookupIoc("1.2.3.4");
    expect(entry!.cases).toHaveLength(2);
    expect(entry!.cases.map((c) => c.caseId)).toContain("case-a");
    expect(entry!.cases.map((c) => c.caseId)).toContain("case-b");
  });

  it("updates existing case ref on re-index without duplicating", async () => {
    const kb = new CrossCaseStore(store);
    await kb.indexCase(state("case-a", [ioc("1.2.3.4", "suspicious")]), "A");
    await kb.indexCase(state("case-a", [ioc("1.2.3.4", "malicious")]), "A");
    const entry = await kb.lookupIoc("1.2.3.4");
    expect(entry!.cases).toHaveLength(1);
    expect(entry!.cases[0].verdict).toBe("malicious");
  });

  it("indexes MITRE techniques across cases", async () => {
    const kb = new CrossCaseStore(store);
    await kb.indexCase(
      state("case-a", [], [{ id: "T1059.001", name: "PowerShell", findingIds: [] }]),
      "A",
    );
    const entry = await kb.lookupTechnique("T1059.001");
    expect(entry).not.toBeNull();
    expect(entry!.cases).toHaveLength(1);
  });

  it("marks an IOC as benign in a case and propagates", async () => {
    const kb = new CrossCaseStore(store);
    await kb.indexCase(state("case-a", [ioc("10.0.0.1")]), "A");
    await kb.markBenign("case-a", "10.0.0.1");
    const entry = await kb.lookupIoc("10.0.0.1");
    expect(entry!.benignCases).toContain("case-a");
  });

  it("returns KB stats", async () => {
    const kb = new CrossCaseStore(store);
    await kb.indexCase(state("case-a", [ioc("1.2.3.4"), ioc("5.6.7.8")]), "A");
    await kb.indexCase(state("case-b", [ioc("1.2.3.4")]), "B");
    const stats = await kb.stats();
    expect(stats.totalIocs).toBeGreaterThanOrEqual(2);
    expect(stats.casesCovered).toBe(2);
    expect(stats.lastIndexedAt).toBeTruthy();
  });

  it("persists across store instances (file-backed)", async () => {
    const kb1 = new CrossCaseStore(store);
    await kb1.indexCase(state("case-a", [ioc("1.2.3.4")]), "A");
    const kb2 = new CrossCaseStore(store);
    const entry = await kb2.lookupIoc("1.2.3.4");
    expect(entry).not.toBeNull();
  });
});