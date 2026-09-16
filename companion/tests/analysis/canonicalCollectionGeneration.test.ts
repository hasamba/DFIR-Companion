// #1108: the collection-generation schema and its own comparability predicate.
import { describe, it, expect } from "vitest";
import {
  collectionGenerationSchema,
  generationsComparable,
  type CollectionGeneration,
} from "../../src/analysis/canonicalCollectionGeneration.js";

const HASH_A = "a".repeat(64);

function generation(overrides: Partial<CollectionGeneration> = {}): CollectionGeneration {
  return {
    generationId: "00000000-0000-4000-8000-000000000001",
    rawHost: "WS-01",
    domain: "persistence",
    completenessState: "complete",
    filtersApplied: [],
    order: { kind: "captured", capturedAt: "2026-01-12T10:00:00Z" },
    artifactRef: { importSeq: 1, artifactHash: HASH_A },
    inventory: [{ technique: "Run Key", path: "HKCU\\Run\\Updater", value: "C:\\x.exe" }],
    recordedBy: { id: "u1", displayName: "J. Analyst" },
    recordedAt: "2026-01-12T10:05:00Z",
    ...overrides,
  };
}

describe("collectionGenerationSchema", () => {
  it("parses a well-formed generation", () => {
    expect(() => collectionGenerationSchema.parse(generation())).not.toThrow();
  });

  it("rejects an empty inventory — a generation with nothing matched is never stored", () => {
    expect(() => collectionGenerationSchema.parse(generation({ inventory: [] }))).toThrow();
  });

  it("rejects a non-hex or wrong-length artifactHash", () => {
    expect(() =>
      collectionGenerationSchema.parse(
        generation({ artifactRef: { importSeq: 1, artifactHash: "not-a-hash" } }),
      ),
    ).toThrow();
  });

  it("rejects a capturedAt that is not a real timezone-bearing instant", () => {
    expect(() =>
      collectionGenerationSchema.parse(
        generation({ order: { kind: "captured", capturedAt: "not-a-date" } as never }),
      ),
    ).toThrow();
  });

  it("rejects a non-positive declared sequence", () => {
    expect(() =>
      collectionGenerationSchema.parse(generation({ order: { kind: "declared", sequence: 0 } })),
    ).toThrow();
  });

  it("defaults filtersApplied to an empty array when omitted", () => {
    const { filtersApplied: _drop, ...rest } = generation();
    const parsed = collectionGenerationSchema.parse(rest);
    expect(parsed.filtersApplied).toEqual([]);
  });
});

describe("generationsComparable", () => {
  it("two complete, unfiltered generations of the same domain and order kind are comparable", () => {
    expect(
      generationsComparable(
        generation(),
        generation({ generationId: "00000000-0000-4000-8000-000000000002" }),
      ),
    ).toBe(true);
  });

  it("not comparable when either is partial", () => {
    expect(generationsComparable(generation(), generation({ completenessState: "partial" }))).toBe(false);
  });

  it("not comparable when either has a filter applied", () => {
    expect(generationsComparable(generation(), generation({ filtersApplied: ["event-cap"] }))).toBe(false);
  });

  it("not comparable across mixed order kinds — never inferred into one total order", () => {
    const declared = generation({ order: { kind: "declared", sequence: 1 } });
    expect(generationsComparable(generation(), declared)).toBe(false);
  });

  it("not comparable across different domains (guards the check even though v1 has only one domain)", () => {
    const otherDomain = generation({ domain: "other-future-domain" as never });
    expect(generationsComparable(generation(), otherDomain)).toBe(false);
  });
});
