import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, writeFile, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import {
  applyFalsePositive,
  buildFalsePositiveContext,
  filterFalsePositiveEvents,
  falsePositiveEventIds,
  markerId,
  FalsePositiveStore,
  type FalsePositiveKind,
  type FalsePositiveMarker,
} from "../../src/analysis/falsePositive.js";
import { emptyState } from "../../src/analysis/stateTypes.js";

function marker(
  kind: FalsePositiveKind,
  ref: string,
  reason: FalsePositiveMarker["reason"] = "other",
  note = "",
): FalsePositiveMarker {
  return { id: markerId(kind, ref), kind, ref, reason, note, markedAt: "2026-05-28T10:00:00Z", markedBy: "anonymous" };
}

describe("applyFalsePositive", () => {
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

    const filtered = applyFalsePositive(state, [
      marker("ioc", "sharphound.exe", "authorized-test", "ran by client red team"),
      marker("finding", "SharpHound AD reconnaissance", "authorized-test", "authorized pentest"),
    ]);

    expect(filtered.iocs.map((i) => i.value)).toEqual(["10.0.0.5"]);
    expect(filtered.findings.map((f) => f.title)).toEqual(["Mimikatz credential dumping"]);
  });

  it("buildFalsePositiveContext lists finding/ioc markers with their reason, empty when none", () => {
    expect(buildFalsePositiveContext([])).toBe("");
    const ctx = buildFalsePositiveContext([marker("finding", "SharpHound recon", "authorized-test", "authorized")]);
    expect(ctx).toContain("CONFIRMED");
    expect(ctx).toContain("SharpHound recon");
    expect(ctx).toContain("authorized-test");
  });

  it("buildFalsePositiveContext omits event markers (their events are already removed from the prompt)", () => {
    const ctx = buildFalsePositiveContext([marker("event", "m1e5")]);
    expect(ctx).toBe("");
    const mixed = buildFalsePositiveContext([
      marker("event", "m1e5"),
      marker("ioc", "10.0.0.5", "known-good-tool", "client jump box"),
    ]);
    expect(mixed).toContain("10.0.0.5");
    expect(mixed).not.toContain("m1e5");
  });

  it("leaves the forensic timeline untouched (events are filtered separately, not stripped from state)", () => {
    const state = emptyState("c1");
    state.forensicTimeline.push(
      { id: "e1", timestamp: "2026-05-28T09:00:00Z", description: "a", severity: "High", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [] },
    );
    const filtered = applyFalsePositive(state, [marker("event", "e1")]);
    expect(filtered.forensicTimeline).toHaveLength(1); // preserved — evidence is never deleted here
  });

  it("filterFalsePositiveEvents drops marked event ids from a copy, case-insensitively", () => {
    const events = [
      { id: "E1", timestamp: "", description: "", severity: "Low" as const, mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [] },
      { id: "e2", timestamp: "", description: "", severity: "Low" as const, mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [] },
    ];
    const out = filterFalsePositiveEvents(events, [marker("event", "e1")]);
    expect(out.map((e) => e.id)).toEqual(["e2"]);
  });

  it("falsePositiveEventIds returns the lowercased set of event-kind marker refs", () => {
    const ids = falsePositiveEventIds([marker("event", "E1"), marker("ioc", "10.0.0.5")]);
    expect(ids).toEqual(new Set(["e1"]));
  });
});

describe("FalsePositiveStore", () => {
  let dir: string;
  let store: CaseStore;
  const caseId = "c1";

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "dfir-fp-"));
    store = new CaseStore(dir);
    await store.createCase({ caseId, name: "c1", investigator: "i", aiProvider: null });
  });

  it("round-trips markers with reason + markedBy", async () => {
    const fp = new FalsePositiveStore(store);
    const m = marker("finding", "SharpHound recon", "detection-misfire", "sensor false alarm");
    await fp.save(caseId, [m]);
    expect(await fp.load(caseId)).toEqual([m]);
  });

  it("migrates a legacy legitimate.json (no reason field) on first load, mapping reason to 'other'", async () => {
    const legacyDir = store.stateDir(caseId);
    await writeFile(
      join(legacyDir, "legitimate.json"),
      JSON.stringify([{ id: "ioc:10.0.0.5", kind: "ioc", ref: "10.0.0.5", note: "jump box", markedAt: "2026-01-01T00:00:00Z" }]),
    );
    const fp = new FalsePositiveStore(store);
    const loaded = await fp.load(caseId);
    expect(loaded).toEqual([
      { id: "ioc:10.0.0.5", kind: "ioc", ref: "10.0.0.5", reason: "other", note: "jump box", markedAt: "2026-01-01T00:00:00Z", markedBy: "anonymous" },
    ]);
    // migration persisted the new file, and left the legacy file untouched
    const migrated = JSON.parse(await readFile(join(legacyDir, "false-positive.json"), "utf8"));
    expect(migrated).toEqual(loaded);
    const legacyStillThere = JSON.parse(await readFile(join(legacyDir, "legitimate.json"), "utf8"));
    expect(legacyStillThere).toHaveLength(1);
  });

  it("prefers false-positive.json over a legacy legitimate.json when both exist", async () => {
    const legacyDir = store.stateDir(caseId);
    await writeFile(join(legacyDir, "legitimate.json"), JSON.stringify([{ id: "x", kind: "ioc", ref: "x", note: "", markedAt: "" }]));
    await writeFile(join(legacyDir, "false-positive.json"), JSON.stringify([]));
    const fp = new FalsePositiveStore(store);
    expect(await fp.load(caseId)).toEqual([]);
  });
});
