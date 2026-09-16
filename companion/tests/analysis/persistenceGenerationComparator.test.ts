// #1128: the persistence-domain orchestrator over #1108's own already-shipped ledger.
import { describe, it, expect } from "vitest";
import { comparePersistenceGenerations } from "../../src/analysis/persistenceGenerationComparator.js";
import { buildHostAliasIndex, type HostAliasIndex } from "../../src/analysis/hostAlias.js";
import type { CollectionGeneration } from "../../src/analysis/canonicalCollectionGeneration.js";

const HASH_A = "a".repeat(64);
const EMPTY_INDEX: HostAliasIndex = buildHostAliasIndex([], {});

let seq = 0;
function generation(overrides: Partial<CollectionGeneration> = {}): CollectionGeneration {
  seq += 1;
  return {
    generationId: `00000000-0000-4000-8000-${String(seq).padStart(12, "0")}`,
    rawHost: "WS-01",
    domain: "persistence",
    completenessState: "complete",
    filtersApplied: [],
    order: { kind: "captured", capturedAt: "2026-01-12T10:00:00Z" },
    artifactRef: { importSeq: seq, artifactHash: HASH_A },
    inventory: [{ technique: "Run Key", path: "HKCU\\Run\\Updater", value: "C:\\x.exe" }],
    recordedBy: { id: "u1", displayName: "J. Analyst" },
    recordedAt: "2026-01-12T10:05:00Z",
    ...overrides,
  };
}

describe("comparePersistenceGenerations", () => {
  it("returns no cohorts when there are no persistence generations", () => {
    expect(comparePersistenceGenerations([], EMPTY_INDEX)).toEqual([]);
  });

  it("groups by resolved host and reports zero pairs for a single-generation cohort", () => {
    const result = comparePersistenceGenerations([generation()], EMPTY_INDEX);
    expect(result).toHaveLength(1);
    expect(result[0].resolvedHost).toBe("ws-01");
    expect(result[0].eligibleCount).toBe(1);
    expect(result[0].pairs).toEqual([]);
    expect(result[0].excluded).toEqual([]);
  });

  it("diffs two adjacent generations: present-only-in-earlier, present-only-in-later, changed", () => {
    const earlier = generation({
      order: { kind: "captured", capturedAt: "2026-01-12T10:00:00Z" },
      inventory: [
        { technique: "Run Key", path: "HKCU\\Run\\A", value: "old.exe" },
        { technique: "Run Key", path: "HKCU\\Run\\Gone", value: "gone.exe" },
      ],
    });
    const later = generation({
      order: { kind: "captured", capturedAt: "2026-01-13T10:00:00Z" },
      inventory: [
        { technique: "Run Key", path: "HKCU\\Run\\A", value: "new.exe" },
        { technique: "Run Key", path: "HKCU\\Run\\New", value: "new2.exe" },
      ],
    });
    const [cohort] = comparePersistenceGenerations([earlier, later], EMPTY_INDEX);
    expect(cohort.pairs).toHaveLength(1);
    const directions = cohort.pairs[0].changes.map((c) => c.direction).sort();
    expect(directions).toEqual(["changed", "present-only-in-earlier", "present-only-in-later"]);
  });

  it("never uses added/removed/deleted labels", () => {
    const earlier = generation({ order: { kind: "captured", capturedAt: "2026-01-12T10:00:00Z" } });
    const later = generation({
      order: { kind: "captured", capturedAt: "2026-01-13T10:00:00Z" },
      inventory: [{ technique: "Run Key", path: "HKCU\\Run\\New", value: "x.exe" }],
    });
    const [cohort] = comparePersistenceGenerations([earlier, later], EMPTY_INDEX);
    const serialized = JSON.stringify(cohort.pairs[0].changes);
    expect(serialized).not.toMatch(/added|removed|deleted/i);
  });

  it("excludes a partial generation and does not pair it", () => {
    const complete = generation();
    const partial = generation({ completenessState: "partial" });
    const [cohort] = comparePersistenceGenerations([complete, partial], EMPTY_INDEX);
    expect(cohort.eligibleCount).toBe(1);
    expect(cohort.excluded).toEqual([{ generationId: partial.generationId, reason: "partial" }]);
    expect(cohort.pairs).toEqual([]);
  });

  it("excludes a filtered generation", () => {
    const complete = generation();
    const filtered = generation({ filtersApplied: ["event-cap"] });
    const [cohort] = comparePersistenceGenerations([complete, filtered], EMPTY_INDEX);
    expect(cohort.excluded).toEqual([{ generationId: filtered.generationId, reason: "filtered" }]);
  });

  it("quarantines a generation whose own inventory has an ambiguous (technique,path) identity", () => {
    const ambiguous = generation({
      inventory: [
        { technique: "Run Key", path: "HKCU\\Run\\A", value: "one.exe" },
        { technique: "Run Key", path: "HKCU\\Run\\A", value: "two.exe" },
      ],
    });
    const [cohort] = comparePersistenceGenerations([ambiguous], EMPTY_INDEX);
    expect(cohort.excluded).toEqual([{ generationId: ambiguous.generationId, reason: "ambiguous-identity" }]);
    expect(cohort.eligibleCount).toBe(0);
  });

  it("does not collide (technique='a|b', path='c') with (technique='a', path='b|c')", () => {
    const earlier = generation({
      inventory: [{ technique: "a|b", path: "c", value: "v1" }],
    });
    const later = generation({
      order: { kind: "captured", capturedAt: "2026-01-13T10:00:00Z" },
      inventory: [{ technique: "a", path: "b|c", value: "v2" }],
    });
    const [cohort] = comparePersistenceGenerations([earlier, later], EMPTY_INDEX);
    const directions = cohort.pairs[0].changes.map((c) => c.direction).sort();
    expect(directions).toEqual(["present-only-in-earlier", "present-only-in-later"]);
  });

  it("quarantines two generations sharing an identical capturedAt order key from any pair", () => {
    const a = generation({ order: { kind: "captured", capturedAt: "2026-01-12T10:00:00Z" } });
    const b = generation({ order: { kind: "captured", capturedAt: "2026-01-12T10:00:00Z" } });
    const [cohort] = comparePersistenceGenerations([a, b], EMPTY_INDEX);
    expect(cohort.pairs).toEqual([]);
    expect(cohort.ambiguousOrder.map((x) => x.generationId).sort()).toEqual(
      [a.generationId, b.generationId].sort(),
    );
  });

  it("quarantines two generations sharing an identical declared sequence from any pair", () => {
    const a = generation({ order: { kind: "declared", sequence: 1 } });
    const b = generation({ order: { kind: "declared", sequence: 1 } });
    const [cohort] = comparePersistenceGenerations([a, b], EMPTY_INDEX);
    expect(cohort.pairs).toEqual([]);
    expect(cohort.ambiguousOrder).toHaveLength(2);
  });

  it("never invents a cross-mode order — captured and declared generations never pair", () => {
    const captured = generation({ order: { kind: "captured", capturedAt: "2026-01-12T10:00:00Z" } });
    const declared = generation({ order: { kind: "declared", sequence: 1 } });
    const [cohort] = comparePersistenceGenerations([captured, declared], EMPTY_INDEX);
    expect(cohort.pairs).toEqual([]);
    expect(cohort.eligibleCount).toBe(2);
  });

  it("diffs adjacent pairs only across three generations, never first-to-last", () => {
    const g1 = generation({ order: { kind: "declared", sequence: 1 } });
    const g2 = generation({ order: { kind: "declared", sequence: 2 } });
    const g3 = generation({ order: { kind: "declared", sequence: 3 } });
    const [cohort] = comparePersistenceGenerations([g1, g2, g3], EMPTY_INDEX);
    expect(cohort.pairs).toHaveLength(2);
    expect(cohort.pairs[0].earlier.generationId).toBe(g1.generationId);
    expect(cohort.pairs[0].later.generationId).toBe(g2.generationId);
    expect(cohort.pairs[1].earlier.generationId).toBe(g2.generationId);
    expect(cohort.pairs[1].later.generationId).toBe(g3.generationId);
  });

  it("counts an excluded generation strictly between a pair's own two endpoints", () => {
    const g1 = generation({ order: { kind: "declared", sequence: 1 } });
    const excludedMid = generation({
      order: { kind: "declared", sequence: 2 },
      completenessState: "partial",
    });
    const g3 = generation({ order: { kind: "declared", sequence: 3 } });
    const [cohort] = comparePersistenceGenerations([g1, excludedMid, g3], EMPTY_INDEX);
    expect(cohort.pairs).toHaveLength(1);
    expect(cohort.pairs[0].interveningExcludedCount).toBe(1);
  });

  it("resolves aliased host spellings into one cohort", () => {
    const index = buildHostAliasIndex([{ hostname: "ws-01", fqdn: "ws-01.corp.local" }], {});
    const a = generation({ rawHost: "ws-01" });
    const b = generation({
      rawHost: "WS-01.corp.local",
      order: { kind: "captured", capturedAt: "2026-01-13T10:00:00Z" },
    });
    const result = comparePersistenceGenerations([a, b], index);
    expect(result).toHaveLength(1);
    expect(result[0].pairs).toHaveLength(1);
  });

  it("keeps different hosts in separate cohorts", () => {
    const a = generation({ rawHost: "WS-01" });
    const b = generation({ rawHost: "WS-02" });
    const result = comparePersistenceGenerations([a, b], EMPTY_INDEX);
    expect(result.map((c) => c.resolvedHost).sort()).toEqual(["ws-01", "ws-02"]);
    expect(result.every((c) => c.pairs.length === 0)).toBe(true);
  });

  it("sorts changes deterministically regardless of inventory order", () => {
    const earlier = generation({
      inventory: [
        { technique: "Run Key", path: "HKCU\\Run\\Z", value: "z" },
        { technique: "Run Key", path: "HKCU\\Run\\A", value: "a" },
      ],
    });
    const later = generation({
      order: { kind: "captured", capturedAt: "2026-01-13T10:00:00Z" },
      inventory: [
        { technique: "Run Key", path: "HKCU\\Run\\A", value: "a2" },
        { technique: "Run Key", path: "HKCU\\Run\\Z", value: "z2" },
      ],
    });
    const [cohort] = comparePersistenceGenerations([earlier, later], EMPTY_INDEX);
    const keys = cohort.pairs[0].changes.map((c) => c.key);
    expect(keys).toEqual([...keys].sort());
  });

  it("truncates changes past the per-pair cap and marks truncated", () => {
    const bigInventory = (offset: number) =>
      Array.from({ length: 510 }, (_, i) => ({
        technique: "Run Key",
        path: `HKCU\\Run\\Item${i}`,
        value: `v${i + offset}`,
      }));
    const earlier = generation({ inventory: bigInventory(0) });
    const later = generation({
      order: { kind: "captured", capturedAt: "2026-01-13T10:00:00Z" },
      inventory: bigInventory(1),
    });
    const [cohort] = comparePersistenceGenerations([earlier, later], EMPTY_INDEX);
    expect(cohort.pairs[0].truncated).toBe(true);
    expect(cohort.pairs[0].changes.length).toBe(500);
  });
});
