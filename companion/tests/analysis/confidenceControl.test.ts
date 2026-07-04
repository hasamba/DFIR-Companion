import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { ConfidenceControlStore } from "../../src/analysis/confidenceControl.js";

describe("ConfidenceControlStore", () => {
  let cases: CaseStore;
  let store: ConfidenceControlStore;
  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-confidence-control-"));
    cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    store = new ConfidenceControlStore(cases);
  });

  it("returns {} for a fresh case (file absent, ENOENT default)", async () => {
    expect(await store.load("c1")).toEqual({});
  });

  it("persists and reloads a valid minConfidence", async () => {
    await store.set("c1", { minConfidence: 60 });
    expect(await store.load("c1")).toEqual({ minConfidence: 60 });
  });

  it("clears minConfidence when set to undefined", async () => {
    await store.set("c1", { minConfidence: 60 });
    await store.set("c1", { minConfidence: undefined });
    expect(await store.load("c1")).toEqual({});
  });

  it("parses a bogus persisted value back to the default", async () => {
    const path = join(cases.stateDir("c1"), "confidence-control.json");
    await writeFile(path, JSON.stringify({ minConfidence: 500 }), "utf8");
    expect(await store.load("c1")).toEqual({});
  });
});
