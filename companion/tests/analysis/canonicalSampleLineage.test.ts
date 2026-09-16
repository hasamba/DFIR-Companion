// #932.8: the sample-lineage schema. See canonicalSampleLineage.ts's own header for why this is
// an ASSOCIATION fact, never a parent/child descent claim.
import { describe, it, expect } from "vitest";
import {
  sampleAssociationFactSchema,
  sampleLineageBlockSchema,
} from "../../src/analysis/canonicalSampleLineage.js";

const SHA256_A = "a".repeat(64);
const SHA256_B = "b".repeat(64);

function fact(overrides: Record<string, unknown> = {}) {
  return {
    targetHashes: { sha256: SHA256_A },
    objectHashes: { sha256: SHA256_B },
    reportedIn: ["dropped"],
    relationship: "listed-during-analysis-of",
    ...overrides,
  };
}

describe("sampleAssociationFactSchema", () => {
  it("parses a well-formed fact", () => {
    expect(() => sampleAssociationFactSchema.parse(fact())).not.toThrow();
  });

  it("rejects an objectHashes with no valid hash at all", () => {
    expect(() => sampleAssociationFactSchema.parse(fact({ objectHashes: {} }))).toThrow();
  });

  it("rejects a malformed (wrong-length) hash rather than accepting any hex-looking string", () => {
    expect(() => sampleAssociationFactSchema.parse(fact({ objectHashes: { sha256: "abc123" } }))).toThrow();
  });

  it("accepts an MD5-only or SHA1-only object hash", () => {
    expect(() =>
      sampleAssociationFactSchema.parse(fact({ objectHashes: { md5: "d".repeat(32) } })),
    ).not.toThrow();
    expect(() =>
      sampleAssociationFactSchema.parse(fact({ objectHashes: { sha1: "e".repeat(40) } })),
    ).not.toThrow();
  });

  it("allows targetHashes to be entirely absent (a missing target.file, e.g. a URL-target report)", () => {
    const { targetHashes: _drop, ...rest } = fact();
    expect(() => sampleAssociationFactSchema.parse(rest)).not.toThrow();
  });

  it("accepts objectNames as a list (CAPE's own real shape) and objectGuestPaths separately", () => {
    const parsed = sampleAssociationFactSchema.parse(
      fact({ objectNames: ["a.exe", "b.exe"], objectGuestPaths: ["C:\\Users\\a\\a.exe"] }),
    );
    expect(parsed.objectNames).toEqual(["a.exe", "b.exe"]);
    expect(parsed.objectGuestPaths).toEqual(["C:\\Users\\a\\a.exe"]);
  });

  it("reportedIn accepts BOTH memberships at once — never mutually exclusive", () => {
    const parsed = sampleAssociationFactSchema.parse(fact({ reportedIn: ["dropped", "cape-payloads"] }));
    expect(parsed.reportedIn).toEqual(["dropped", "cape-payloads"]);
  });

  it("requires at least one membership", () => {
    expect(() => sampleAssociationFactSchema.parse(fact({ reportedIn: [] }))).toThrow();
  });

  it("relationship is locked to the single neutral literal — never 'parent'/'child' wording", () => {
    expect(() => sampleAssociationFactSchema.parse(fact({ relationship: "parent-of" }))).toThrow();
  });
});

describe("sampleLineageBlockSchema", () => {
  it("parses a well-formed block", () => {
    const block = {
      reportLocator: "abc123",
      facts: [fact()],
      notCited: 0,
      malformed: 0,
      basis:
        "objects this SAME sandbox report listed together during one analysis — never a claim of direct production or descent, never inferred across separate reports, and never a claim about an incident endpoint",
    };
    expect(() => sampleLineageBlockSchema.parse(block)).not.toThrow();
  });

  it("caps facts at 256", () => {
    const block = {
      reportLocator: "abc123",
      facts: Array.from({ length: 257 }, () => fact()),
      notCited: 0,
      malformed: 0,
      basis:
        "objects this SAME sandbox report listed together during one analysis — never a claim of direct production or descent, never inferred across separate reports, and never a claim about an incident endpoint",
    };
    expect(() => sampleLineageBlockSchema.parse(block)).toThrow();
  });
});
