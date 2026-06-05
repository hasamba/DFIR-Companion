import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { CustomEntitiesStore, sanitizeCustomEntities } from "../../src/analysis/anonEntities.js";

let cases: CaseStore;
let store: CustomEntitiesStore;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-anonent-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  store = new CustomEntitiesStore(cases);
});

describe("sanitizeCustomEntities", () => {
  it("drops blanks, coerces unknown category to OTHER, dedupes case-insensitively", () => {
    const out = sanitizeCustomEntities([
      { value: "Host1", category: "HOST" },
      { value: "  ", category: "HOST" },          // blank → dropped
      { value: "host1", category: "USER" },        // dup of Host1 (ci) → dropped
      { value: "Falcon", category: "bogus" },      // unknown cat → OTHER
      { value: "x" },                              // missing cat → OTHER
    ]);
    expect(out).toEqual([
      { value: "Host1", category: "HOST" },
      { value: "Falcon", category: "OTHER" },
      { value: "x", category: "OTHER" },
    ]);
  });
  it("non-array → []", () => {
    expect(sanitizeCustomEntities(null)).toEqual([]);
  });
});

describe("CustomEntitiesStore", () => {
  it("returns [] when never saved", async () => {
    expect(await store.load("c1")).toEqual([]);
  });
  it("round-trips a saved (sanitized) list", async () => {
    await store.save("c1", [{ value: "DC02", category: "HOST" }, { value: "ProjectX", category: "OTHER" }]);
    expect(await store.load("c1")).toEqual([{ value: "DC02", category: "HOST" }, { value: "ProjectX", category: "OTHER" }]);
  });
});
