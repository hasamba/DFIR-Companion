import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { emptyState } from "../../src/analysis/stateTypes.js";

let caseStore: CaseStore;
let stateStore: StateStore;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-state-"));
  caseStore = new CaseStore(root);
  await caseStore.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(caseStore);
});

describe("StateStore", () => {
  it("returns empty state when none saved", async () => {
    const state = await stateStore.load("c1");
    expect(state.findings).toEqual([]);
    expect(state.caseId).toBe("c1");
  });

  it("round-trips a saved state", async () => {
    const state = emptyState("c1");
    state.lastSummary = "initial recon of host WIN-01";
    await stateStore.save(state);

    const loaded = await stateStore.load("c1");
    expect(loaded.lastSummary).toBe("initial recon of host WIN-01");
  });
});
