import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import {
  applySeverityRestores,
  FindingSeverityRestoreStore,
  severityCapOf,
  severityRestoredOf,
  type SeverityRestoreRecord,
} from "../../src/analysis/findingSeverityRestore.js";
import { groundAndScoreFindings } from "../../src/analysis/findingGrounding.js";
import { emptyState, type Finding, type InvestigationState } from "../../src/analysis/stateTypes.js";

// #1973: the analyst lifts one deterministic severity cap on one finding. The record lives in a side
// store keyed like the outcome store (findingId + semanticKey) and is applied after grading.

const CAP = { from: "High", to: "Medium", gates: ["tamper-timing"] };

function f(p: Partial<Finding> & Record<string, unknown> = {}): Finding {
  return {
    id: "f1",
    severity: "Medium",
    title: "Microsoft Defender real-time protection disabled",
    description: "",
    relatedIocs: [],
    sourceScreenshots: [],
    mitreTechniques: ["T1562.001"],
    firstSeen: "",
    lastUpdated: "",
    status: "open",
    semanticKey: "k1",
    severityCap: CAP,
    ...p,
  } as Finding;
}

const rec = (p: Partial<SeverityRestoreRecord> = {}): SeverityRestoreRecord => ({
  findingId: "f1",
  semanticKey: "k1",
  restoredBy: "Alice",
  restoredAt: "2026-10-06T10:00:00.000Z",
  ...p,
});

const withFindings = (findings: Finding[]): InvestigationState => ({ ...emptyState("c1"), findings });

describe("applySeverityRestores", () => {
  it("lifts the cap on the restored finding and marks it", () => {
    const out = applySeverityRestores(withFindings([f()]), [rec()]).findings[0];
    expect(out.severity).toBe("High");
    expect(severityRestoredOf(out)).toEqual({ by: "Alice", at: "2026-10-06T10:00:00.000Z" });
    expect(severityCapOf(out)).toEqual(CAP); // the cap stays recorded, so Undo knows where to go back
  });

  it("does not apply a record whose claim key no longer matches", () => {
    const out = applySeverityRestores(withFindings([f()]), [rec({ semanticKey: "other" })]).findings[0];
    expect(out.severity).toBe("Medium");
    expect(severityRestoredOf(out)).toBeUndefined();
  });

  it("does not let a blank-key record restore a finding that has a claim key (#1991)", () => {
    const out = applySeverityRestores(withFindings([f()]), [rec({ semanticKey: "" })]).findings[0];
    expect(out.severity).toBe("Medium");
    expect(severityRestoredOf(out)).toBeUndefined();
  });

  it("still lets a blank-key record restore a finding whose key is also blank (#1991)", () => {
    const keyless = f({ semanticKey: "", title: "!!!", mitreTechniques: [] });
    const out = applySeverityRestores(withFindings([keyless]), [rec({ semanticKey: "" })]).findings[0];
    expect(out.severity).toBe("High");
    expect(severityRestoredOf(out)).toBeDefined();
  });

  it("does nothing to a finding with no cap", () => {
    const plain = f({ severityCap: undefined, severity: "High" });
    const state = withFindings([plain]);
    expect(applySeverityRestores(state, [rec()])).toBe(state);
  });

  it("puts the cap back when the record is gone", () => {
    const restored = f({ severity: "High", severityRestored: { by: "Alice", at: "t" } });
    const out = applySeverityRestores(withFindings([restored]), []).findings[0];
    expect(out.severity).toBe("Medium");
    expect(severityRestoredOf(out)).toBeUndefined();
  });

  it("restores the live-intrusion severity under a simulation cap, leaving the cap to the simulation step", () => {
    const simulated = f({
      simulation: {
        role: "simulated",
        originalSeverity: "Medium",
        appliedSeverity: "Medium",
        verdictId: "v",
      },
    });
    const out = applySeverityRestores(withFindings([simulated]), [rec()]).findings[0];
    expect(out.severity).toBe("Medium");
    expect(out.simulation?.originalSeverity).toBe("High");
  });

  it("never mutates its input", () => {
    const input = f();
    applySeverityRestores(withFindings([input]), [rec()]);
    expect(input.severity).toBe("Medium");
  });
});

describe("grading keeps the restore honest", () => {
  it("strips a stale restore mark so only the restore step can set it", () => {
    const stale = f({ severity: "High", severityCap: undefined, severityRestored: { by: "x", at: "t" } });
    const out = groundAndScoreFindings({
      findings: [stale],
      scopedEvents: [],
      iocs: [],
      graphLinkedEventIds: new Set(),
    });
    expect(severityRestoredOf(out[0])).toBeUndefined();
  });

  it("keeps a recorded cap when a re-grade finds the finding already at the capped severity", () => {
    const out = groundAndScoreFindings({
      findings: [f()],
      scopedEvents: [],
      iocs: [],
      graphLinkedEventIds: new Set(),
    });
    expect(out[0].severity).toBe("Medium");
    expect(severityCapOf(out[0])).toEqual(CAP);
  });
});

describe("FindingSeverityRestoreStore", () => {
  it("stores, replaces and clears one record per finding", async () => {
    const cases = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-sev-restore-")));
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const store = new FindingSeverityRestoreStore(cases);
    expect(await store.load("c1")).toEqual([]);
    await store.restore("c1", "f1", { semanticKey: "k1", by: "Alice" });
    await store.restore("c1", "f1", { semanticKey: "k1", by: "Bob" });
    await store.restore("c1", "f2", { semanticKey: "k2", by: "Alice" });
    const all = await store.load("c1");
    expect(all.map((r) => [r.findingId, r.restoredBy])).toEqual([
      ["f1", "Bob"],
      ["f2", "Alice"],
    ]);
    expect(await store.clear("c1", "f1")).toBe(true);
    expect(await store.clear("c1", "f1")).toBe(false);
    expect((await store.load("c1")).map((r) => r.findingId)).toEqual(["f2"]);
  });

  it("refuses a blank finding id", async () => {
    const cases = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-sev-restore-")));
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    await expect(
      new FindingSeverityRestoreStore(cases).restore("c1", " ", { semanticKey: "", by: "" }),
    ).rejects.toThrow(/findingId/);
  });
});
