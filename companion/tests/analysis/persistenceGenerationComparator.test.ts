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

function cohortsOf(generations: CollectionGeneration[], index: HostAliasIndex = EMPTY_INDEX) {
  return comparePersistenceGenerations(generations, index).cohorts;
}

describe("comparePersistenceGenerations", () => {
  it("returns no cohorts when there are no persistence generations", () => {
    const result = comparePersistenceGenerations([], EMPTY_INDEX);
    expect(result.cohorts).toEqual([]);
    expect(result.truncatedCohorts).toBe(false);
  });

  it("groups by resolved host and reports zero pairs for a single-generation cohort", () => {
    const result = cohortsOf([generation()]);
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
    const [cohort] = cohortsOf([earlier, later]);
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
    const [cohort] = cohortsOf([earlier, later]);
    const serialized = JSON.stringify(cohort.pairs[0].changes);
    expect(serialized).not.toMatch(/added|removed|deleted/i);
  });

  it("excludes a partial generation and does not pair it", () => {
    const complete = generation();
    const partial = generation({ completenessState: "partial" });
    const [cohort] = cohortsOf([complete, partial]);
    expect(cohort.eligibleCount).toBe(1);
    expect(cohort.excluded).toEqual([{ generationId: partial.generationId, reason: "partial" }]);
    expect(cohort.pairs).toEqual([]);
  });

  it("excludes a filtered generation", () => {
    const complete = generation();
    const filtered = generation({ filtersApplied: ["event-cap"] });
    const [cohort] = cohortsOf([complete, filtered]);
    expect(cohort.excluded).toEqual([{ generationId: filtered.generationId, reason: "filtered" }]);
  });

  it("quarantines a generation whose own inventory has an ambiguous (technique,path) identity", () => {
    const ambiguous = generation({
      inventory: [
        { technique: "Run Key", path: "HKCU\\Run\\A", value: "one.exe" },
        { technique: "Run Key", path: "HKCU\\Run\\A", value: "two.exe" },
      ],
    });
    const [cohort] = cohortsOf([ambiguous]);
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
    const [cohort] = cohortsOf([earlier, later]);
    const directions = cohort.pairs[0].changes.map((c) => c.direction).sort();
    expect(directions).toEqual(["present-only-in-earlier", "present-only-in-later"]);
  });

  it("quarantines two generations sharing an identical capturedAt order key from any pair", () => {
    const a = generation({ order: { kind: "captured", capturedAt: "2026-01-12T10:00:00Z" } });
    const b = generation({ order: { kind: "captured", capturedAt: "2026-01-12T10:00:00Z" } });
    const [cohort] = cohortsOf([a, b]);
    expect(cohort.pairs).toEqual([]);
    expect(cohort.ambiguousOrder.map((x) => x.generationId).sort()).toEqual(
      [a.generationId, b.generationId].sort(),
    );
  });

  it("quarantines two generations sharing an identical declared sequence from any pair", () => {
    const a = generation({ order: { kind: "declared", sequence: 1 } });
    const b = generation({ order: { kind: "declared", sequence: 1 } });
    const [cohort] = cohortsOf([a, b]);
    expect(cohort.pairs).toEqual([]);
    expect(cohort.ambiguousOrder).toHaveLength(2);
  });

  it("never invents a cross-mode order — captured and declared generations never pair", () => {
    const captured = generation({ order: { kind: "captured", capturedAt: "2026-01-12T10:00:00Z" } });
    const declared = generation({ order: { kind: "declared", sequence: 1 } });
    const [cohort] = cohortsOf([captured, declared]);
    expect(cohort.pairs).toEqual([]);
    expect(cohort.eligibleCount).toBe(2);
  });

  it("diffs adjacent pairs only across three generations, never first-to-last", () => {
    const g1 = generation({ order: { kind: "declared", sequence: 1 } });
    const g2 = generation({ order: { kind: "declared", sequence: 2 } });
    const g3 = generation({ order: { kind: "declared", sequence: 3 } });
    const [cohort] = cohortsOf([g1, g2, g3]);
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
    const [cohort] = cohortsOf([g1, excludedMid, g3]);
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
    const result = cohortsOf([a, b], index);
    expect(result).toHaveLength(1);
    expect(result[0].pairs).toHaveLength(1);
  });

  it("keeps different hosts in separate cohorts", () => {
    const a = generation({ rawHost: "WS-01" });
    const b = generation({ rawHost: "WS-02" });
    const result = cohortsOf([a, b]);
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
    const [cohort] = cohortsOf([earlier, later]);
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
    const [cohort] = cohortsOf([earlier, later]);
    expect(cohort.pairs[0].truncated).toBe(true);
    expect(cohort.pairs[0].changes.length).toBe(500);
  });

  // Codex code-review finding (High): ordering captured timestamps by string representation
  // instead of parsed instant can reverse or fabricate a directional diff.
  describe("captured-time ordering by real instant, not string representation (code-review fix)", () => {
    it("orders two offset-bearing timestamps by real instant even though their strings sort the other way", () => {
      // "01:00+02:00" names 23:00 UTC the PREVIOUS day — an earlier instant than "00:30Z" the next
      // day, even though the raw string "2026-01-02T01:00:00+02:00" > "2026-01-02T00:30:00Z"
      // lexicographically.
      const earlierByInstant = generation({
        order: { kind: "captured", capturedAt: "2026-01-02T01:00:00+02:00" }, // 2026-01-01T23:00:00Z
        inventory: [{ technique: "Run Key", path: "HKCU\\Run\\A", value: "old.exe" }],
      });
      const laterByInstant = generation({
        order: { kind: "captured", capturedAt: "2026-01-02T00:30:00Z" }, // 2026-01-02T00:30:00Z
        inventory: [{ technique: "Run Key", path: "HKCU\\Run\\A", value: "new.exe" }],
      });
      const [cohort] = cohortsOf([earlierByInstant, laterByInstant]);
      expect(cohort.pairs).toHaveLength(1);
      expect(cohort.pairs[0].earlier.generationId).toBe(earlierByInstant.generationId);
      expect(cohort.pairs[0].later.generationId).toBe(laterByInstant.generationId);
      expect(cohort.pairs[0].changes).toEqual([
        {
          direction: "changed",
          key: JSON.stringify(["Run Key", "HKCU\\Run\\A"]),
          earlierValue: "old.exe",
          laterValue: "new.exe",
        },
      ]);
    });

    it("quarantines two different offset-bearing strings that name the SAME real instant", () => {
      const a = generation({ order: { kind: "captured", capturedAt: "2026-01-01T00:00:00Z" } });
      const b = generation({ order: { kind: "captured", capturedAt: "2026-01-01T01:00:00+01:00" } }); // same instant
      const [cohort] = cohortsOf([a, b]);
      expect(cohort.pairs).toEqual([]);
      expect(cohort.ambiguousOrder).toHaveLength(2);
    });

    it("computes interveningExcludedCount by real instant, not string order, across offsets", () => {
      // Real instants, earliest to latest: 22:00Z, 23:00Z, 00:30Z(+1 day). As raw STRINGS,
      // "...T01:00:00+02:00" (23:00Z) sorts AFTER "...T00:30:00Z" (00:30Z the next day) because
      // string comparison never looks at the offset — exactly Codex's own code-review example.
      const earliest = generation({
        order: { kind: "captured", capturedAt: "2025-12-31T22:00:00Z" },
      });
      const middleByInstant = generation({
        order: { kind: "captured", capturedAt: "2026-01-01T01:00:00+02:00" }, // = 2025-12-31T23:00:00Z
        completenessState: "partial",
      });
      const latest = generation({
        order: { kind: "captured", capturedAt: "2026-01-01T00:30:00Z" },
      });
      const [cohort] = cohortsOf([earliest, middleByInstant, latest]);
      expect(cohort.pairs).toHaveLength(1);
      expect(cohort.pairs[0].earlier.generationId).toBe(earliest.generationId);
      expect(cohort.pairs[0].later.generationId).toBe(latest.generationId);
      expect(cohort.pairs[0].interveningExcludedCount).toBe(1);
    });
  });

  // Codex code-review finding (Medium): resource caps must bound work, not just output size.
  describe("resource bounds (code-review fix)", () => {
    it("truncates a single generation's own envelope past MAX_ENTRIES_PER_ENVELOPE rather than growing it unbounded", () => {
      const bigInventory = Array.from({ length: 10_010 }, (_, i) => ({
        technique: "Run Key",
        path: `HKCU\\Run\\Item${i}`,
        value: "v",
      }));
      const earlier = generation({ inventory: bigInventory });
      const later = generation({
        order: { kind: "captured", capturedAt: "2026-01-13T10:00:00Z" },
        inventory: [{ technique: "Run Key", path: "HKCU\\Run\\Item0", value: "v" }],
      });
      const [cohort] = cohortsOf([earlier, later]);
      // The earlier envelope was truncated to 10,000 of its 10,010 entries, so at least the 10
      // dropped keys show up as present-only-in-earlier being LOST (not present at all) is wrong —
      // what matters here is the comparison completed without building an unbounded structure.
      expect(cohort.pairs).toHaveLength(1);
      expect(cohort.pairs[0].truncated).toBe(true);
    });

    // #1138: truncatedEntries was computed by generationToEnvelope() and silently discarded by
    // its own caller — never reaching the API response.
    it("discloses inventoryTruncated on a pair when either side's own envelope was capped (#1138)", () => {
      const bigInventory = Array.from({ length: 10_010 }, (_, i) => ({
        technique: "Run Key",
        path: `HKCU\\Run\\Item${i}`,
        value: "v",
      }));
      const earlier = generation({ inventory: bigInventory });
      const later = generation({
        order: { kind: "captured", capturedAt: "2026-01-13T10:00:00Z" },
        inventory: [{ technique: "Run Key", path: "HKCU\\Run\\Item0", value: "v" }],
      });
      const [cohort] = cohortsOf([earlier, later]);
      expect(cohort.pairs[0].inventoryTruncated).toBe(true);
    });

    it("inventoryTruncated is false when neither side's envelope was capped", () => {
      const earlier = generation();
      const later = generation({ order: { kind: "captured", capturedAt: "2026-01-13T10:00:00Z" } });
      const [cohort] = cohortsOf([earlier, later]);
      expect(cohort.pairs[0].inventoryTruncated).toBe(false);
    });

    it("discloses truncatedCohorts when more than MAX_COHORTS resolved hosts exist", () => {
      const many = Array.from({ length: 205 }, (_, i) => generation({ rawHost: `WS-${i}` }));
      const result = comparePersistenceGenerations(many, EMPTY_INDEX);
      expect(result.truncatedCohorts).toBe(true);
      expect(result.cohorts).toHaveLength(200);
    });

    it("does not set truncatedCohorts when at or under the cap", () => {
      const some = Array.from({ length: 5 }, (_, i) => generation({ rawHost: `WS-${i}` }));
      const result = comparePersistenceGenerations(some, EMPTY_INDEX);
      expect(result.truncatedCohorts).toBe(false);
    });
  });
});
