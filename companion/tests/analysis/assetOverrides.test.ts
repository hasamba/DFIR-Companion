import { describe, it, expect } from "vitest";
import { applyAssetOverrides, emptyOverrides } from "../../src/analysis/assetOverrides.js";
import { buildAssetGraph } from "../../src/analysis/assetGraph.js";
import { emptyState } from "../../src/analysis/stateTypes.js";

const HASH = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

function baseGraph() {
  const s = emptyState("c1");
  s.iocs.push(
    { id: "i1", type: "hash", value: HASH, firstSeen: "" },
    { id: "i2", type: "ip", value: "10.0.0.5", firstSeen: "" },
  );
  s.forensicTimeline.push(
    { id: "e1", timestamp: "2026-01-01T00:00:00Z", description: "malware on WIN-01", severity: "Critical",
      mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], asset: "WIN-01", sha256: HASH },
    { id: "e2", timestamp: "2026-01-01T00:05:00Z", description: "beacon to 10.0.0.5", severity: "High",
      mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], asset: "WIN-02" },
  );
  return buildAssetGraph(s);
}

describe("applyAssetOverrides", () => {
  it("returns the graph unchanged when overrides are empty", () => {
    const g = baseGraph();
    const result = applyAssetOverrides(g, emptyOverrides());
    expect(result.assets.map((a) => a.name).sort()).toEqual(["WIN-01", "WIN-02"]);
    expect(result.iocs.length).toBe(2);
    expect(result.edges.length).toBe(2);
  });

  it("renames an asset by its id", () => {
    const g = baseGraph();
    const win01 = g.assets.find((a) => a.name === "WIN-01")!;
    const result = applyAssetOverrides(g, { ...emptyOverrides(), renames: { [win01.id]: "CORP-WS-01" } });
    const names = result.assets.map((a) => a.name);
    expect(names).toContain("CORP-WS-01");
    expect(names).not.toContain("WIN-01");
  });

  it("clears a rename when the override name is empty", () => {
    const g = baseGraph();
    const win01 = g.assets.find((a) => a.name === "WIN-01")!;
    // First apply rename
    const renamed = applyAssetOverrides(g, { ...emptyOverrides(), renames: { [win01.id]: "CORP-WS-01" } });
    expect(renamed.assets.map((a) => a.name)).toContain("CORP-WS-01");
    // Then clear the rename (empty renames object)
    const cleared = applyAssetOverrides(g, emptyOverrides());
    expect(cleared.assets.map((a) => a.name)).toContain("WIN-01");
    expect(cleared.assets.map((a) => a.name)).not.toContain("CORP-WS-01");
  });

  it("suppresses an auto-derived asset and its edges", () => {
    const g = baseGraph();
    const win01 = g.assets.find((a) => a.name === "WIN-01")!;
    const result = applyAssetOverrides(g, { ...emptyOverrides(), removed: [win01.id] });
    expect(result.assets.map((a) => a.name)).not.toContain("WIN-01");
    // i1 (linked only to WIN-01) should disappear from graph; i2 (linked to WIN-02) stays
    expect(result.iocs.some((i) => i.id === "i1")).toBe(false);
    expect(result.iocs.some((i) => i.id === "i2")).toBe(true);
    // No edges for the suppressed asset
    expect(result.edges.some((e) => e.asset === win01.id)).toBe(false);
  });

  it("adds a manual asset", () => {
    const g = baseGraph();
    const manual = { id: "manual:pivot", name: "JUMP-SERVER", type: "host" as const };
    const result = applyAssetOverrides(g, { ...emptyOverrides(), added: [manual] });
    const added = result.assets.find((a) => a.id === "manual:pivot");
    expect(added).toBeDefined();
    expect(added!.name).toBe("JUMP-SERVER");
    expect(added!.type).toBe("host");
    expect(added!.compromised).toBe(false);
    expect(added!.iocIds).toEqual([]);
  });

  it("adds a manual link between an existing asset and IoC", () => {
    const g = baseGraph();
    const win02 = g.assets.find((a) => a.name === "WIN-02")!;
    // WIN-02 is currently linked to i2; manually link it to i1 as well
    const result = applyAssetOverrides(g, { ...emptyOverrides(), addedLinks: [{ asset: win02.id, ioc: "i1" }] });
    expect(result.edges.some((e) => e.asset === win02.id && e.ioc === "i1")).toBe(true);
    const win02out = result.assets.find((a) => a.id === win02.id)!;
    expect(win02out.iocIds).toContain("i1");
    const i1out = result.iocs.find((i) => i.id === "i1")!;
    expect(i1out.assetIds).toContain(win02.id);
  });

  it("ignores an added link whose IoC does not exist in the graph", () => {
    const g = baseGraph();
    const win01 = g.assets.find((a) => a.name === "WIN-01")!;
    const result = applyAssetOverrides(g, { ...emptyOverrides(), addedLinks: [{ asset: win01.id, ioc: "nonexistent" }] });
    expect(result.edges.every((e) => e.ioc !== "nonexistent")).toBe(true);
  });

  it("suppresses an auto-derived link", () => {
    const g = baseGraph();
    const win01 = g.assets.find((a) => a.name === "WIN-01")!;
    // WIN-01 → i1 (hash field). Suppress this edge.
    const result = applyAssetOverrides(g, { ...emptyOverrides(), removedLinks: [{ asset: win01.id, ioc: "i1" }] });
    expect(result.edges.some((e) => e.asset === win01.id && e.ioc === "i1")).toBe(false);
    const win01out = result.assets.find((a) => a.id === win01.id)!;
    expect(win01out.iocIds).not.toContain("i1");
  });

  it("removes an IoC from the graph when its last asset link is suppressed", () => {
    const g = baseGraph();
    const win01 = g.assets.find((a) => a.name === "WIN-01")!;
    // i1 is only linked to WIN-01 via sha256. Suppress that link → i1 disappears.
    const result = applyAssetOverrides(g, { ...emptyOverrides(), removedLinks: [{ asset: win01.id, ioc: "i1" }] });
    expect(result.iocs.find((i) => i.id === "i1")).toBeUndefined();
  });

  it("does not add a manual asset whose id is already in the auto-derived graph", () => {
    const g = baseGraph();
    const win01 = g.assets.find((a) => a.name === "WIN-01")!;
    // Try to add a manual asset with the same id — it should be ignored
    const manual = { id: win01.id, name: "OVERRIDE", type: "host" as const };
    const result = applyAssetOverrides(g, { ...emptyOverrides(), added: [manual] });
    // The original WIN-01 should still be there (auto-derived takes precedence)
    const node = result.assets.find((a) => a.id === win01.id);
    expect(node?.name).not.toBe("OVERRIDE");
  });

  it("combined: rename + add manual asset + suppress link", () => {
    const g = baseGraph();
    const win01 = g.assets.find((a) => a.name === "WIN-01")!;
    const win02 = g.assets.find((a) => a.name === "WIN-02")!;
    const result = applyAssetOverrides(g, {
      renames: { [win01.id]: "CORP-WS-01" },
      added: [{ id: "manual:pivot", name: "JUMP-SERVER", type: "host" }],
      removed: [],
      addedLinks: [],
      removedLinks: [{ asset: win02.id, ioc: "i2" }],
    });
    expect(result.assets.map((a) => a.name)).toContain("CORP-WS-01");
    expect(result.assets.map((a) => a.name)).toContain("JUMP-SERVER");
    expect(result.edges.some((e) => e.asset === win02.id && e.ioc === "i2")).toBe(false);
  });
});
