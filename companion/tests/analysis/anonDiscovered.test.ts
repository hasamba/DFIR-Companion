import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import {
  DiscoveredEntitiesStore,
  mergeDiscovered,
  suppressValue,
  unsuppressValue,
  sanitizeDiscovered,
  emptyDiscovered,
} from "../../src/analysis/anonDiscovered.js";

describe("anonDiscovered pure helpers", () => {
  it("mergeDiscovered dedupes case-insensitively and skips suppressed", () => {
    const prev = { discovered: [{ value: "WIN11", category: "HOST" as const }], suppressed: ["config\\powershellinfo.log"] };
    const next = mergeDiscovered(prev, [
      { value: "win11", category: "HOST" },                       // dup (ci) → skipped
      { value: "vagrant", category: "USER" },                     // new
      { value: "config\\PowershellInfo.log", category: "USER" },  // suppressed → skipped
    ]);
    expect(next.discovered.map((e) => e.value)).toEqual(["WIN11", "vagrant"]);
    expect(next.suppressed).toEqual(["config\\powershellinfo.log"]);
  });

  it("suppressValue removes from discovered and records the veto (lowercased)", () => {
    const prev = { discovered: [{ value: "config\\PowershellInfo.log", category: "USER" as const }, { value: "WIN11", category: "HOST" as const }], suppressed: [] };
    const next = suppressValue(prev, "config\\PowershellInfo.log");
    expect(next.discovered.map((e) => e.value)).toEqual(["WIN11"]);
    expect(next.suppressed).toEqual(["config\\powershellinfo.log"]);
  });

  it("unsuppressValue lifts the veto", () => {
    const next = unsuppressValue({ discovered: [], suppressed: ["win11", "x"] }, "WIN11");
    expect(next.suppressed).toEqual(["x"]);
  });

  it("sanitizeDiscovered drops suppressed entries from the discovered list and lowercases the veto", () => {
    const s = sanitizeDiscovered({ discovered: [{ value: "WIN11", category: "HOST" }, { value: "bad", category: "USER" }], suppressed: ["BAD"] });
    expect(s.discovered.map((e) => e.value)).toEqual(["WIN11"]);
    expect(s.suppressed).toEqual(["bad"]);
  });
});

describe("DiscoveredEntitiesStore", () => {
  let cases: CaseStore;
  let store: DiscoveredEntitiesStore;
  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-disc-"));
    cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    store = new DiscoveredEntitiesStore(cases);
  });

  it("returns empty for a fresh case", async () => {
    expect(await store.load("c1")).toEqual(emptyDiscovered());
  });

  it("adds, suppresses (removes + vetoes), and restores — round-tripping to disk", async () => {
    await store.addDiscovered("c1", [{ value: "WIN11", category: "HOST" }, { value: "config\\PowershellInfo.log", category: "USER" }]);
    expect((await store.load("c1")).discovered).toHaveLength(2);

    await store.suppress("c1", "config\\PowershellInfo.log");
    let cur = await store.load("c1");
    expect(cur.discovered.map((e) => e.value)).toEqual(["WIN11"]);
    expect(cur.suppressed).toEqual(["config\\powershellinfo.log"]);

    // A suppressed value is not re-added by a later discovery.
    await store.addDiscovered("c1", [{ value: "config\\PowershellInfo.log", category: "USER" }]);
    expect((await store.load("c1")).discovered.map((e) => e.value)).toEqual(["WIN11"]);

    await store.unsuppress("c1", "config\\PowershellInfo.log");
    expect((await store.load("c1")).suppressed).toEqual([]);
  });
});
