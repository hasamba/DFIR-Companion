import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { applyLegitimate, buildLegitimateContext, filterLegitimateEvents, legitimateEventIds, markerId, LegitimateStore, type LegitimateKind, type LegitimateMarker } from "../../src/analysis/legitimate.js";
import { emptyState } from "../../src/analysis/stateTypes.js";

function marker(kind: LegitimateKind, ref: string, note = ""): LegitimateMarker {
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

  it("buildLegitimateContext lists finding/ioc markers, empty when none", () => {
    expect(buildLegitimateContext([])).toBe("");
    const ctx = buildLegitimateContext([marker("finding", "SharpHound recon", "authorized")]);
    expect(ctx).toContain("CONFIRMED LEGITIMATE");
    expect(ctx).toContain("SharpHound recon");
  });

  it("buildLegitimateContext omits event markers (their events are already removed from the prompt)", () => {
    const ctx = buildLegitimateContext([marker("event", "m1e5", "client's own admin action")]);
    expect(ctx).toBe("");
    const mixed = buildLegitimateContext([
      marker("event", "m1e5"),
      marker("ioc", "10.0.0.5", "client jump box"),
    ]);
    expect(mixed).toContain("10.0.0.5");
    expect(mixed).not.toContain("m1e5");
  });

  it("leaves the forensic timeline untouched (events are filtered separately, not stripped from state)", () => {
    const state = emptyState("c1");
    state.forensicTimeline.push(
      { id: "e1", timestamp: "2026-05-28T09:00:00Z", description: "a", severity: "High", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [] },
    );
    const filtered = applyLegitimate(state, [marker("event", "e1")]);
    expect(filtered.forensicTimeline).toHaveLength(1); // preserved — evidence is never deleted here
  });
});

describe("filterLegitimateEvents / legitimateEventIds", () => {
  const events = [
    { id: "e1", description: "logon" },
    { id: "e2", description: "process create" },
    { id: "e3", description: "file write" },
  ];

  it("removes events whose id is marked legitimate, case-insensitively", () => {
    const out = filterLegitimateEvents(events, [marker("event", "E2"), marker("ioc", "x")]);
    expect(out.map((e) => e.id)).toEqual(["e1", "e3"]);
  });

  it("returns a copy unchanged when there are no event markers", () => {
    const out = filterLegitimateEvents(events, [marker("finding", "foo")]);
    expect(out).toEqual(events);
    expect(out).not.toBe(events); // copy, not the same reference
  });

  it("legitimateEventIds collects only event-kind refs, lowercased", () => {
    const ids = legitimateEventIds([marker("event", "E1"), marker("event", "e2"), marker("ioc", "e3")]);
    expect(ids).toEqual(new Set(["e1", "e2"]));
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
