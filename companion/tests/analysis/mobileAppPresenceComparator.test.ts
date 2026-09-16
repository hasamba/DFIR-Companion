// #1132: the mobile-app-presence orchestrator over the examiner-attested backup-pairing ledger.
import { describe, it, expect } from "vitest";
import { compareMobileGenerations } from "../../src/analysis/mobileAppPresenceComparator.js";
import type { MobileBackupGeneration } from "../../src/analysis/canonicalMobileBackupGeneration.js";

const HASH_A = "a".repeat(64);

let seq = 0;
function generation(overrides: Partial<MobileBackupGeneration> = {}): MobileBackupGeneration {
  seq += 1;
  return {
    generationId: `00000000-0000-4000-8000-${String(seq).padStart(12, "0")}`,
    deviceIdentity: { kind: "serial-number", value: "F2LN12ABCDEF" },
    domain: "mobile-app-presence",
    completenessState: "complete",
    filtersApplied: [],
    order: { kind: "captured", capturedAt: "2026-01-12T10:00:00Z" },
    backupInfoRef: {
      importSeq: seq * 2,
      artifactHash: HASH_A,
      originalName: "backup.tsv",
      importedAt: "2026-01-12T09:00:00Z",
    },
    installedAppsRef: {
      importSeq: seq * 2 + 1,
      artifactHash: HASH_A,
      originalName: "apps.tsv",
      importedAt: "2026-01-12T09:01:00Z",
    },
    attestedSameBackup: true,
    inventory: [{ bundleId: "com.example.app", itemName: "Example", version: "1.0" }],
    recordedBy: { id: "u1", displayName: "J. Analyst" },
    recordedAt: "2026-01-12T10:05:00Z",
    ...overrides,
  };
}

function cohortsOf(generations: MobileBackupGeneration[]) {
  return compareMobileGenerations(generations).cohorts;
}

describe("compareMobileGenerations", () => {
  it("returns no cohorts when there are no mobile generations", () => {
    const result = compareMobileGenerations([]);
    expect(result.cohorts).toEqual([]);
    expect(result.truncatedCohorts).toBe(false);
  });

  it("groups by device identity and reports zero pairs for a single-generation cohort", () => {
    const result = cohortsOf([generation()]);
    expect(result).toHaveLength(1);
    expect(result[0].resolvedDevice).toEqual({ kind: "serial-number", value: "F2LN12ABCDEF" });
    expect(result[0].eligibleCount).toBe(1);
    expect(result[0].pairs).toEqual([]);
  });

  it("diffs two adjacent generations: present-only-in-earlier, present-only-in-later, changed", () => {
    const earlier = generation({
      inventory: [
        { bundleId: "com.example.a", itemName: "A", version: "1.0" },
        { bundleId: "com.example.gone", itemName: "Gone", version: "1.0" },
      ],
    });
    const later = generation({
      order: { kind: "captured", capturedAt: "2026-01-13T10:00:00Z" },
      inventory: [
        { bundleId: "com.example.a", itemName: "A", version: "2.0" },
        { bundleId: "com.example.new", itemName: "New", version: "1.0" },
      ],
    });
    const [cohort] = cohortsOf([earlier, later]);
    expect(cohort.pairs).toHaveLength(1);
    const directions = cohort.pairs[0].changes.map((c) => c.direction).sort();
    expect(directions).toEqual(["changed", "present-only-in-earlier", "present-only-in-later"]);
  });

  it("treats an identical {itemName, version} object as unchanged (structural equality, not ===)", () => {
    const earlier = generation({ inventory: [{ bundleId: "com.example.a", itemName: "A", version: "1.0" }] });
    const later = generation({
      order: { kind: "captured", capturedAt: "2026-01-13T10:00:00Z" },
      inventory: [{ bundleId: "com.example.a", itemName: "A", version: "1.0" }], // a DIFFERENT object, same fields
    });
    const [cohort] = cohortsOf([earlier, later]);
    expect(cohort.pairs[0].changes).toEqual([]);
  });

  it("never uses added/removed/deleted labels", () => {
    const earlier = generation();
    const later = generation({
      order: { kind: "captured", capturedAt: "2026-01-13T10:00:00Z" },
      inventory: [{ bundleId: "com.example.new", itemName: "New", version: "1.0" }],
    });
    const [cohort] = cohortsOf([earlier, later]);
    expect(JSON.stringify(cohort.pairs[0].changes)).not.toMatch(/added|removed|deleted/i);
  });

  it("excludes a partial generation and does not pair it", () => {
    const complete = generation();
    const partial = generation({ completenessState: "partial" });
    const [cohort] = cohortsOf([complete, partial]);
    expect(cohort.eligibleCount).toBe(1);
    expect(cohort.excluded).toEqual([{ generationId: partial.generationId, reason: "partial" }]);
  });

  it("quarantines a generation whose own inventory has an ambiguous bundleId identity", () => {
    const ambiguous = generation({
      inventory: [
        { bundleId: "com.example.a", itemName: "A", version: "1.0" },
        { bundleId: "com.example.a", itemName: "A", version: "2.0" },
      ],
    });
    const [cohort] = cohortsOf([ambiguous]);
    expect(cohort.excluded).toEqual([{ generationId: ambiguous.generationId, reason: "ambiguous-identity" }]);
    expect(cohort.eligibleCount).toBe(0);
  });

  it("quarantines two generations sharing an identical capturedAt order key from any pair", () => {
    const a = generation();
    const b = generation();
    const [cohort] = cohortsOf([a, b]);
    expect(cohort.pairs).toEqual([]);
    expect(cohort.ambiguousOrder).toHaveLength(2);
  });

  it("never invents a cross-mode order — captured and declared generations never pair", () => {
    const captured = generation();
    const declared = generation({
      order: { kind: "declared", sequence: 1 },
      dateUnavailableReason: "no date",
    });
    const [cohort] = cohortsOf([captured, declared]);
    expect(cohort.pairs).toEqual([]);
    expect(cohort.eligibleCount).toBe(2);
  });

  it("diffs adjacent pairs only across three generations, never first-to-last", () => {
    const g1 = generation({ order: { kind: "declared", sequence: 1 }, dateUnavailableReason: "x" });
    const g2 = generation({ order: { kind: "declared", sequence: 2 }, dateUnavailableReason: "x" });
    const g3 = generation({ order: { kind: "declared", sequence: 3 }, dateUnavailableReason: "x" });
    const [cohort] = cohortsOf([g1, g2, g3]);
    expect(cohort.pairs).toHaveLength(2);
    expect(cohort.pairs[0].earlier.generationId).toBe(g1.generationId);
    expect(cohort.pairs[0].later.generationId).toBe(g2.generationId);
    expect(cohort.pairs[1].earlier.generationId).toBe(g2.generationId);
    expect(cohort.pairs[1].later.generationId).toBe(g3.generationId);
  });

  it("keeps different devices in separate cohorts, even sharing the same identity VALUE across kinds", () => {
    const a = generation({ deviceIdentity: { kind: "serial-number", value: "ABC123" } });
    const b = generation({ deviceIdentity: { kind: "unique-identifier", value: "ABC123" } });
    const result = cohortsOf([a, b]);
    expect(result).toHaveLength(2);
  });

  it("resolves device identity value case-insensitively into one cohort", () => {
    const a = generation({ deviceIdentity: { kind: "serial-number", value: "abc123" } });
    const b = generation({
      deviceIdentity: { kind: "serial-number", value: "ABC123" },
      order: { kind: "captured", capturedAt: "2026-01-13T10:00:00Z" },
    });
    const result = cohortsOf([a, b]);
    expect(result).toHaveLength(1);
    expect(result[0].pairs).toHaveLength(1);
  });

  it("discloses truncatedCohorts when more than MAX_COHORTS distinct devices exist", () => {
    const many = Array.from({ length: 205 }, (_, i) =>
      generation({ deviceIdentity: { kind: "serial-number", value: `SN-${i}` } }),
    );
    const result = compareMobileGenerations(many);
    expect(result.truncatedCohorts).toBe(true);
    expect(result.cohorts).toHaveLength(200);
  });

  it("truncates changes past the per-pair cap and marks truncated", () => {
    const bigInventory = (offset: number) =>
      Array.from({ length: 510 }, (_, i) => ({
        bundleId: `com.example.item${i}`,
        itemName: "Item",
        version: `${i + offset}`,
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

  it("discloses inventoryTruncated on a pair when either side's own envelope was capped", () => {
    const bigInventory = Array.from({ length: 10_010 }, (_, i) => ({
      bundleId: `com.example.item${i}`,
      itemName: "Item",
      version: "1.0",
    }));
    const earlier = generation({ inventory: bigInventory });
    const later = generation({
      order: { kind: "captured", capturedAt: "2026-01-13T10:00:00Z" },
      inventory: [{ bundleId: "com.example.item0", itemName: "Item", version: "1.0" }],
    });
    const [cohort] = cohortsOf([earlier, later]);
    expect(cohort.pairs[0].inventoryTruncated).toBe(true);
  });

  it("counts an excluded generation strictly between a pair's own two endpoints", () => {
    const g1 = generation({ order: { kind: "declared", sequence: 1 }, dateUnavailableReason: "x" });
    const excludedMid = generation({
      order: { kind: "declared", sequence: 2 },
      dateUnavailableReason: "x",
      completenessState: "partial",
    });
    const g3 = generation({ order: { kind: "declared", sequence: 3 }, dateUnavailableReason: "x" });
    const [cohort] = cohortsOf([g1, excludedMid, g3]);
    expect(cohort.pairs).toHaveLength(1);
    expect(cohort.pairs[0].interveningExcludedCount).toBe(1);
  });
});
