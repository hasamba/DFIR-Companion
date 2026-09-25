// #1595: the analyst's "treat as real intrusion" answer lives in synth-meta. record() REPLACES that
// document on every real synthesis, so it must carry the override over, or a re-synthesis would
// silently undo the analyst's decision.
import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { SynthMetaStore } from "../../src/analysis/synthMeta.js";
import type { FindingsDiff } from "../../src/analysis/findingsDiff.js";

const DIFF: FindingsDiff = { added: [], removed: [], severityChanged: [] };

describe("SynthMetaStore — simulation override (#1595)", () => {
  let cases: CaseStore;
  let store: SynthMetaStore;
  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-synthmeta-sim-"));
    cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    store = new SynthMetaStore(cases);
  });

  it("defaults to not overridden", async () => {
    expect(await store.treatAsReal("c1")).toBe(false);
  });

  it("stores the override and survives a synthesis record()", async () => {
    await store.setSimulationOverride("c1", true, "analyst-a", "2026-09-25T10:00:00.000Z");
    await store.record("c1", DIFF, "2026-09-25T10:05:00.000Z");
    const meta = await store.load("c1");
    expect(meta.simulationOverride).toEqual({
      treatAsReal: true,
      at: "2026-09-25T10:00:00.000Z",
      by: "analyst-a",
    });
    expect(meta.lastSynthesizedAt).toBe("2026-09-25T10:05:00.000Z");
    expect(await store.treatAsReal("c1")).toBe(true);
  });

  it("merges onto the rest of the card", async () => {
    await store.record("c1", DIFF, "2026-09-25T10:05:00.000Z");
    await store.setSimulationOverride("c1", false);
    const meta = await store.load("c1");
    expect(meta.lastSynthesizedAt).toBe("2026-09-25T10:05:00.000Z");
    expect(meta.simulationOverride?.treatAsReal).toBe(false);
  });

  it("answers treat-as-real when the file cannot be read", async () => {
    await writeFile(join(cases.stateDir("c1"), "synth-meta.json"), "{ not json");
    expect(await store.treatAsReal("c1")).toBe(true);
  });
});
