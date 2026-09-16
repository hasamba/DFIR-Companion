// #1128: the generic, domain-blind snapshot-comparison kernel.
import { describe, it, expect } from "vitest";
import { diffEnvelopes, type SnapshotEnvelope } from "../../src/analysis/snapshotComparisonKernel.js";

function envelope(
  entries: Record<string, string>,
  overrides: Partial<SnapshotEnvelope<string>> = {},
): SnapshotEnvelope<string> {
  return {
    version: 1,
    snapshotId: "g1",
    subject: "ws-01",
    domain: "persistence",
    order: { kind: "captured", capturedAt: "2026-01-12T10:00:00Z" },
    entries: new Map(Object.entries(entries)),
    provenance: [{ importSeq: 1, artifactHash: "a".repeat(64) }],
    ...overrides,
  };
}

const eq = (a: string, b: string) => a === b;

describe("diffEnvelopes", () => {
  it("finds no changes between identical envelopes", () => {
    const a = envelope({ k1: "v1", k2: "v2" });
    const b = envelope({ k1: "v1", k2: "v2" }, { snapshotId: "g2" });
    expect(diffEnvelopes(a, b, eq)).toEqual([]);
  });

  it("reports a key present only in the earlier envelope", () => {
    const a = envelope({ k1: "v1" });
    const b = envelope({});
    expect(diffEnvelopes(a, b, eq)).toEqual([
      { direction: "present-only-in-earlier", key: "k1", earlierValue: "v1" },
    ]);
  });

  it("reports a key present only in the later envelope", () => {
    const a = envelope({});
    const b = envelope({ k1: "v1" });
    expect(diffEnvelopes(a, b, eq)).toEqual([
      { direction: "present-only-in-later", key: "k1", laterValue: "v1" },
    ]);
  });

  it("reports a changed value for a key present in both", () => {
    const a = envelope({ k1: "old" });
    const b = envelope({ k1: "new" });
    expect(diffEnvelopes(a, b, eq)).toEqual([
      { direction: "changed", key: "k1", earlierValue: "old", laterValue: "new" },
    ]);
  });

  it("never labels a change 'added'/'removed'/'deleted' — direction values are the neutral literals only", () => {
    const a = envelope({ k1: "v1" });
    const b = envelope({ k2: "v2" });
    const directions = diffEnvelopes(a, b, eq).map((c) => c.direction);
    expect(directions.sort()).toEqual(["present-only-in-earlier", "present-only-in-later"]);
  });

  it("sorts deterministically by key then direction, regardless of Map insertion order", () => {
    const a1 = envelope({ zzz: "1", aaa: "2" });
    const b1 = envelope({ mmm: "3" });
    const a2 = envelope({ aaa: "2", zzz: "1" });
    const b2 = envelope({ mmm: "3" });
    expect(diffEnvelopes(a1, b1, eq)).toEqual(diffEnvelopes(a2, b2, eq));
  });

  it("uses the caller-supplied equality function, not ===", () => {
    const a = envelope({ k1: "V1" });
    const b = envelope({ k1: "v1" });
    const caseInsensitiveEq = (x: string, y: string) => x.toLowerCase() === y.toLowerCase();
    expect(diffEnvelopes(a, b, caseInsensitiveEq)).toEqual([]);
    expect(diffEnvelopes(a, b, eq)).toEqual([
      { direction: "changed", key: "k1", earlierValue: "V1", laterValue: "v1" },
    ]);
  });
});
