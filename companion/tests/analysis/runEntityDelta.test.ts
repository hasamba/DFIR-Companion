import { describe, expect, it } from "vitest";
import { entityDelta, findingClaims, importReceipt } from "../../src/analysis/runEntityDelta.js";
import { claimSnapshot } from "../../src/analysis/analysisRunHash.js";
import type { Finding } from "../../src/analysis/stateTypes.js";

describe("entityDelta (#1887)", () => {
  it("lists the ids the import added and removed, in their own order", () => {
    expect(entityDelta(["a", "b", "c"], ["b", "d", "c", "e"])).toEqual({
      added: ["d", "e"],
      removed: ["a"],
      beforeCount: 3,
      afterCount: 4,
    });
  });

  it("treats the ids as a multiset: a second row with an existing id is added", () => {
    expect(entityDelta(["a"], ["a", "a"])).toMatchObject({ added: ["a"], removed: [] });
  });

  it("treats the ids as a multiset: one of two duplicates removed is removed", () => {
    expect(entityDelta(["a", "b", "a"], ["b", "a"])).toMatchObject({ added: [], removed: ["a"] });
  });

  it("leaves non-string ids out of the lists but counts them", () => {
    const delta = entityDelta(["a", null, 7], [null, "b", undefined, { x: 1 }]);
    expect(delta).toEqual({ added: ["b"], removed: ["a"], beforeCount: 3, afterCount: 4 });
  });

  it("reads an empty baseline as every id added", () => {
    expect(entityDelta([], ["x", "y"])).toEqual({
      added: ["x", "y"],
      removed: [],
      beforeCount: 0,
      afterCount: 2,
    });
  });

  it("does not match a string id to a non-string of the same text", () => {
    expect(entityDelta([1], ["1"])).toMatchObject({ added: ["1"], removed: [] });
  });
});

describe("importReceipt (#1887)", () => {
  const findings = [
    { id: "f1", title: "T", severity: "High", description: "d", relatedEventIds: ["e2", "e1"] },
  ] as unknown as Finding[];

  it("records only the change plus counts, never the full id lists", () => {
    const before = Array.from({ length: 50 }, (_, i) => `e${i}`);
    const after = [...before.slice(1), "new"];
    const receipt = importReceipt(
      before,
      after,
      [{ id: "investigation-state/v3", sha256: "a".repeat(64) }],
      findings,
    );
    expect(receipt.input).toEqual({ eventIds: [], entityIds: [], entityCount: 50 });
    expect(receipt.output).toEqual({
      entityIds: ["new"],
      removedEntityIds: ["e0"],
      entityCount: 50,
      hashes: [{ id: "investigation-state/v3", sha256: "a".repeat(64) }],
      claims: findingClaims(findings),
    });
  });

  it("builds a claim per finding the same way every run recorder does", () => {
    expect(findingClaims(findings)).toEqual([
      claimSnapshot("f1", { title: "T", severity: "High", description: "d", evidenceEventIds: ["e2", "e1"] }),
    ]);
  });
});
