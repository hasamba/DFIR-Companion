// #1132: the mobile-backup-generation schema and its own eligibility predicate.
import { describe, it, expect } from "vitest";
import {
  mobileBackupGenerationSchema,
  generationEligible,
  type MobileBackupGeneration,
} from "../../src/analysis/canonicalMobileBackupGeneration.js";

const HASH_A = "a".repeat(64);

function generation(overrides: Partial<MobileBackupGeneration> = {}): MobileBackupGeneration {
  return {
    generationId: "00000000-0000-4000-8000-000000000001",
    deviceIdentity: { kind: "serial-number", value: "F2LN12ABCDEF" },
    domain: "mobile-app-presence",
    completenessState: "complete",
    filtersApplied: [],
    order: { kind: "captured", capturedAt: "2026-01-12T10:00:00Z" },
    backupInfoRef: {
      importSeq: 1,
      artifactHash: HASH_A,
      originalName: "Info.plist backup info.tsv",
      importedAt: "2026-01-12T09:00:00Z",
    },
    installedAppsRef: {
      importSeq: 2,
      artifactHash: HASH_A,
      originalName: "Installed Apps.tsv",
      importedAt: "2026-01-12T09:01:00Z",
    },
    attestedSameBackup: true,
    inventory: [{ bundleId: "com.example.app", itemName: "Example", version: "1.0" }],
    recordedBy: { id: "u1", displayName: "J. Analyst" },
    recordedAt: "2026-01-12T10:05:00Z",
    ...overrides,
  };
}

describe("mobileBackupGenerationSchema", () => {
  it("parses a well-formed generation", () => {
    expect(() => mobileBackupGenerationSchema.parse(generation())).not.toThrow();
  });

  it("rejects an empty inventory", () => {
    expect(() => mobileBackupGenerationSchema.parse(generation({ inventory: [] }))).toThrow();
  });

  it("rejects a non-hex or wrong-length artifactHash on either ref", () => {
    expect(() =>
      mobileBackupGenerationSchema.parse(
        generation({ backupInfoRef: { ...generation().backupInfoRef, artifactHash: "not-a-hash" } }),
      ),
    ).toThrow();
  });

  it("rejects attestedSameBackup: false", () => {
    expect(() =>
      mobileBackupGenerationSchema.parse({ ...generation(), attestedSameBackup: false }),
    ).toThrow();
  });

  it("rejects backupInfoRef and installedAppsRef naming the SAME import sequence", () => {
    const g = generation();
    expect(() =>
      mobileBackupGenerationSchema.parse({
        ...g,
        installedAppsRef: { ...g.installedAppsRef, importSeq: g.backupInfoRef.importSeq },
      }),
    ).toThrow(/two different imports/);
  });

  it("rejects a declared order with no dateUnavailableReason", () => {
    expect(() =>
      mobileBackupGenerationSchema.parse(generation({ order: { kind: "declared", sequence: 1 } })),
    ).toThrow(/dateUnavailableReason/);
  });

  it("accepts a declared order WITH a dateUnavailableReason", () => {
    expect(() =>
      mobileBackupGenerationSchema.parse(
        generation({
          order: { kind: "declared", sequence: 1 },
          dateUnavailableReason: "Last Backup Date was absent from the export",
        }),
      ),
    ).not.toThrow();
  });

  it("rejects an unknown deviceIdentity.kind", () => {
    expect(() =>
      mobileBackupGenerationSchema.parse(
        generation({ deviceIdentity: { kind: "imei" as never, value: "123" } }),
      ),
    ).toThrow();
  });

  it("defaults filtersApplied to an empty array when omitted", () => {
    const { filtersApplied: _drop, ...rest } = generation();
    const parsed = mobileBackupGenerationSchema.parse(rest);
    expect(parsed.filtersApplied).toEqual([]);
  });
});

describe("generationEligible", () => {
  it("a complete, unfiltered generation is eligible", () => {
    expect(generationEligible(generation())).toBe(true);
  });

  it("a partial generation is not eligible", () => {
    expect(generationEligible(generation({ completenessState: "partial" }))).toBe(false);
  });

  it("a generation with any filter applied is not eligible", () => {
    expect(generationEligible(generation({ filtersApplied: ["some-filter"] }))).toBe(false);
  });
});
