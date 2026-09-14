import { describe, it, expect } from "vitest";
import { mergeEnrichedSubset } from "../../src/analysis/iocBulkOps.js";
import type { IOC } from "../../src/analysis/stateTypes.js";

const base = (overrides: Partial<IOC> & Pick<IOC, "id" | "value">): IOC => ({
  type: "ip",
  firstSeen: "2024-01-01T00:00:00Z",
  ...overrides,
});

describe("mergeEnrichedSubset", () => {
  it("returns allIocs unchanged when enrichedSubset is empty", () => {
    const all = [base({ id: "a", value: "1.2.3.4" }), base({ id: "b", value: "5.6.7.8" })];
    expect(mergeEnrichedSubset(all, [])).toEqual(all);
  });

  it("replaces enriched IOCs in allIocs while preserving order", () => {
    const iocA = base({ id: "a", value: "1.2.3.4" });
    const iocB = base({ id: "b", value: "5.6.7.8" });
    const iocC = base({ id: "c", value: "evil.com" });
    const all = [iocA, iocB, iocC];
    const enriched: IOC = {
      ...iocB,
      enrichments: [{ source: "VirusTotal", verdict: "malicious", fetchedAt: "t", status: "live" }],
      enrichedBy: ["VirusTotal"],
    };
    const result = mergeEnrichedSubset(all, [enriched]);
    expect(result).toHaveLength(3);
    expect(result[0]).toBe(iocA); // unchanged reference
    // Merged by assertion (#1024), never a whole-object swap: the enriched fields arrive, the rest stays.
    expect(result[1]).toMatchObject({ id: "b", enrichedBy: ["VirusTotal"] });
    expect(result[1].enrichments).toHaveLength(1);
    expect(result[1].enrichments![0]).toMatchObject({
      source: "VirusTotal",
      verdict: "malicious",
      status: "live",
    });
    expect(result[2]).toBe(iocC); // unchanged reference
  });

  it("handles multiple updated IOCs in the subset", () => {
    const iocA = base({ id: "a", value: "1.2.3.4" });
    const iocB = base({ id: "b", value: "5.6.7.8" });
    const enrichedA: IOC = { ...iocA, enrichedBy: ["MISP"] };
    const enrichedB: IOC = { ...iocB, enrichedBy: ["MISP"] };
    const result = mergeEnrichedSubset([iocA, iocB], [enrichedA, enrichedB]);
    expect(result[0]).toMatchObject({ id: "a", enrichedBy: ["MISP"] });
    expect(result[1]).toMatchObject({ id: "b", enrichedBy: ["MISP"] });
  });

  it("ignores subset IDs that are not in allIocs", () => {
    const iocA = base({ id: "a", value: "1.2.3.4" });
    const ghost: IOC = { ...iocA, id: "ghost", value: "9.9.9.9" };
    const result = mergeEnrichedSubset([iocA], [ghost]);
    expect(result).toHaveLength(1);
    expect(result[0]).toBe(iocA);
  });

  it("preserves allIocs order regardless of subset order", () => {
    const a = base({ id: "a", value: "1" });
    const b = base({ id: "b", value: "2" });
    const c = base({ id: "c", value: "3" });
    const enrichedC: IOC = { ...c, enrichedBy: ["VT"] };
    const enrichedA: IOC = { ...a, enrichedBy: ["VT"] };
    // subset order is c, a — allIocs order is a, b, c → result should be a, b, c
    const result = mergeEnrichedSubset([a, b, c], [enrichedC, enrichedA]);
    expect(result[0].id).toBe("a");
    expect(result[1].id).toBe("b");
    expect(result[2].id).toBe("c");
    expect(result[0]).toMatchObject({ id: "a", enrichedBy: ["VT"] });
    expect(result[2]).toMatchObject({ id: "c", enrichedBy: ["VT"] });
  });
});

// #1024: a stale completion of one re-check must not erase the history a faster one appended.
describe("mergeEnrichedSubset keeps the newest assertion state", () => {
  it("a later revoked state wins over a stale live copy; histories union", () => {
    const current: IOC = {
      ...base({ id: "a", value: "1.2.3.4" }),
      enrichments: [
        {
          source: "OpenCTI",
          verdict: "malicious",
          fetchedAt: "2026-06-02T00:00:00Z",
          assertionId: "x",
          status: "revoked",
          revoked: true,
        },
      ],
      intelHistory: [
        {
          assertionId: "x",
          provider: "OpenCTI",
          source: "OpenCTI",
          verdict: "malicious",
          status: "live",
          fingerprint: "f1",
          firstCheckedAt: "2026-06-01T00:00:00Z",
          lastCheckedAt: "2026-06-01T00:00:00Z",
          checkCount: 1,
        },
        {
          assertionId: "x",
          provider: "OpenCTI",
          source: "OpenCTI",
          verdict: "malicious",
          status: "revoked",
          fingerprint: "f2",
          firstCheckedAt: "2026-06-02T00:00:00Z",
          lastCheckedAt: "2026-06-02T00:00:00Z",
          checkCount: 1,
        },
      ],
      enrichedBy: ["OpenCTI"],
    };
    const stale: IOC = {
      ...base({ id: "a", value: "1.2.3.4" }),
      enrichments: [
        {
          source: "OpenCTI",
          verdict: "malicious",
          fetchedAt: "2026-06-01T00:00:00Z",
          assertionId: "x",
          status: "live",
        },
      ],
      intelHistory: [
        {
          assertionId: "x",
          provider: "OpenCTI",
          source: "OpenCTI",
          verdict: "malicious",
          status: "live",
          fingerprint: "f1",
          firstCheckedAt: "2026-06-01T00:00:00Z",
          lastCheckedAt: "2026-06-01T00:00:00Z",
          checkCount: 1,
        },
      ],
      enrichedBy: ["OpenCTI"],
    };
    const [merged] = mergeEnrichedSubset([current], [stale]);
    expect(merged.enrichments![0].status).toBe("revoked");
    expect(merged.intelHistory).toHaveLength(2);
  });
});
