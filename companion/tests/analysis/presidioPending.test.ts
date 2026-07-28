import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { PresidioPendingStore } from "../../src/analysis/presidioPending.js";

let cases: CaseStore;
let store: PresidioPendingStore;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-presidiopending-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  store = new PresidioPendingStore(cases);
});

describe("PresidioPendingStore", () => {
  it("returns an empty list for a case with no pending file", async () => {
    expect(await store.load("c1")).toEqual([]);
  });

  it("round-trips findings", async () => {
    await store.save("c1", [{ value: "Jane Doe", category: "PERSON" }]);
    expect(await store.load("c1")).toEqual([{ value: "Jane Doe", category: "PERSON" }]);
  });

  it("sanitizes on save, coercing an unknown category to OTHER", async () => {
    await store.save("c1", [{ value: "x", category: "NOPE" } as never]);
    expect(await store.load("c1")).toEqual([{ value: "x", category: "OTHER" }]);
  });

  it("clear empties the list", async () => {
    await store.save("c1", [{ value: "Jane Doe", category: "PERSON" }]);
    await store.clear("c1");
    expect(await store.load("c1")).toEqual([]);
  });
});
