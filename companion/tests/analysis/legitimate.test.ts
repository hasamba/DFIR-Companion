import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { applyLegitimate, buildLegitimateContext, markerId, LegitimateStore, type LegitimateMarker } from "../../src/analysis/legitimate.js";
import { emptyState } from "../../src/analysis/stateTypes.js";

function marker(kind: "finding" | "ioc", ref: string, note = ""): LegitimateMarker {
  return { id: markerId(kind, ref), kind, ref, note, markedAt: "2026-05-28T10:00:00Z" };
}

describe("applyLegitimate", () => {
  it("removes IOCs by exact value and findings by title match", () => {
    const state = emptyState("c1");
    state.iocs.push(
      { id: "i1", type: "process", value: "SharpHound.exe", firstSeen: "" },
      { id: "i2", type: "ip", value: "10.0.0.5", firstSeen: "" },
    );
    state.findings.push(
      { id: "f1", severity: "High", title: "SharpHound AD reconnaissance", description: "", relatedIocs: [],
        mitreTechniques: [], sourceScreenshots: [], firstSeen: "", lastUpdated: "", status: "open" },
      { id: "f2", severity: "Critical", title: "Mimikatz credential dumping", description: "", relatedIocs: [],
        mitreTechniques: [], sourceScreenshots: [], firstSeen: "", lastUpdated: "", status: "open" },
    );

    const filtered = applyLegitimate(state, [
      marker("ioc", "sharphound.exe", "ran by client red team"),
      marker("finding", "SharpHound AD reconnaissance", "authorized pentest"),
    ]);

    expect(filtered.iocs.map((i) => i.value)).toEqual(["10.0.0.5"]);
    expect(filtered.findings.map((f) => f.title)).toEqual(["Mimikatz credential dumping"]);
  });

  it("buildLegitimateContext lists markers for the prompt, empty when none", () => {
    expect(buildLegitimateContext([])).toBe("");
    const ctx = buildLegitimateContext([marker("finding", "SharpHound recon", "authorized")]);
    expect(ctx).toContain("CONFIRMED LEGITIMATE");
    expect(ctx).toContain("SharpHound recon");
  });
});

describe("LegitimateStore", () => {
  let store: LegitimateStore;
  let caseId = "c1";
  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-legit-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId, name: "n", investigator: "i", aiProvider: null });
    store = new LegitimateStore(cases);
  });

  it("returns [] when none saved and round-trips markers", async () => {
    expect(await store.load(caseId)).toEqual([]);
    const markers = [marker("ioc", "evil.exe", "benign tool")];
    await store.save(caseId, markers);
    expect(await store.load(caseId)).toEqual(markers);
  });
});
