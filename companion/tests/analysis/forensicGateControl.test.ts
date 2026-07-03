import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { ForensicGateControlStore } from "../../src/analysis/forensicGateControl.js";

describe("ForensicGateControlStore", () => {
  let cases: CaseStore;
  let store: ForensicGateControlStore;
  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-forensic-gate-"));
    cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    store = new ForensicGateControlStore(cases);
  });

  it("returns {} for a fresh case (file absent, ENOENT default)", async () => {
    expect(await store.load("c1")).toEqual({});
  });

  it("persists and reloads a valid minSeverity", async () => {
    await store.set("c1", { minSeverity: "Medium" });
    expect(await store.load("c1")).toEqual({ minSeverity: "Medium" });
  });

  it("parses a bogus persisted value back to the default", async () => {
    const path = join(cases.stateDir("c1"), "forensic-gate.json");
    await writeFile(path, JSON.stringify({ minSeverity: "Bogus" }), "utf8");
    expect(await store.load("c1")).toEqual({});
  });
});
