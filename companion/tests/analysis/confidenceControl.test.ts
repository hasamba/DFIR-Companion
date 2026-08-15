import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { ConfidenceControlStore, type ConfidenceControl } from "../../src/analysis/confidenceControl.js";

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

  it("persists and reloads both origin lenses", async () => {
    await store.set("c1", { hideAutoFindings: true, hideGapFindings: true });
    expect(await store.load("c1")).toEqual({ hideAutoFindings: true, hideGapFindings: true });
  });

  // The reason `set` patches key by key. The dashboard writes the confidence floor (debounced) and
  // the lenses (immediate) from two independent code paths; neither may erase the other's value.
  it("patches one field without disturbing the others", async () => {
    await store.set("c1", { minConfidence: 60, hideGapFindings: true });
    await store.set("c1", { hideAutoFindings: true });
    expect(await store.load("c1")).toEqual({
      minConfidence: 60,
      hideGapFindings: true,
      hideAutoFindings: true,
    });
  });

  it("clears a lens when set to undefined", async () => {
    await store.set("c1", { hideAutoFindings: true });
    expect(await store.load("c1")).toEqual({ hideAutoFindings: true }); // prove it was actually set
    await store.set("c1", { hideAutoFindings: undefined });
    expect(await store.load("c1")).toEqual({});
  });

  it("parses a bogus persisted lens back to the default", async () => {
    const path = join(cases.stateDir("c1"), "confidence-control.json");
    await writeFile(path, JSON.stringify({ hideAutoFindings: "yes" }), "utf8");
    expect(await store.load("c1")).toEqual({});
  });

  it("drops patch keys outside the known three, unlike a spread would", async () => {
    const patch = { minConfidence: 60, bogus: "nope" } as ConfidenceControl;
    const result = await store.set("c1", patch);
    expect(result).not.toHaveProperty("bogus");
  });
});
