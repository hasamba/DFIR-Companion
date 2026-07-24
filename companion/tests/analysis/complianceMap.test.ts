import { describe, it, expect, beforeEach } from "vitest";
import {
  mapFindings,
  loadComplianceMap,
  _resetComplianceMapCache,
} from "../../src/analysis/complianceMap.js";
import type { Finding } from "../../src/analysis/stateTypes.js";

function makeFinding(overrides: Partial<Finding>): Finding {
  return {
    id: "f1",
    severity: "High",
    title: "test finding",
    description: "desc",
    relatedIocs: [],
    sourceScreenshots: [],
    mitreTechniques: [],
    firstSeen: "2026-01-01T00:00:00.000Z",
    lastUpdated: "2026-01-01T00:00:00.000Z",
    status: "confirmed",
    ...overrides,
  };
}

describe("complianceMap", () => {
  beforeEach(() => {
    _resetComplianceMapCache();
  });

  it("loads the bundled compliance-map.json with the 10 mapped techniques", () => {
    const ds = loadComplianceMap();
    expect(ds.source.length).toBeGreaterThan(0);
    expect(ds.techniqueCount).toBe(10);
    const expected = [
      "T1566.001", "T1059.001", "T1003.001", "T1486", "T1021.002",
      "T1071.001", "T1562.001", "T1070.001", "T1048.002", "T1053.005",
    ];
    for (const t of expected) {
      expect(ds.map[t]).toBeDefined();
      expect(ds.map[t].length).toBeGreaterThan(0);
    }
  });

  it("maps a confirmed finding's MITRE techniques to control failures + obligations", () => {
    const results = mapFindings([
      makeFinding({ id: "f1", mitreTechniques: ["T1486"], status: "confirmed" }),
    ]);
    expect(results).toHaveLength(1);
    expect(results[0].technique).toBe("T1486");
    expect(results[0].findingId).toBe("f1");
    const frameworks = results[0].frameworks.map((f) => f.framework);
    expect(frameworks).toEqual(
      expect.arrayContaining(["NIST 800-53", "PCI-DSS", "HIPAA", "GDPR", "SEC", "ISO 27001"]),
    );
    const gdpr = results[0].frameworks.find((f) => f.framework === "GDPR");
    expect(gdpr?.control).toBe("Art. 33");
    expect(gdpr?.deadline).toBe("P72H");
    expect(gdpr?.obligation.length).toBeGreaterThan(0);
  });

  it("skips findings that are not confirmed (open/dismissed)", () => {
    const findings: Finding[] = [
      makeFinding({ id: "f-open", mitreTechniques: ["T1486"], status: "open" }),
      makeFinding({ id: "f-dismissed", mitreTechniques: ["T1486"], status: "dismissed" }),
      makeFinding({ id: "f-confirmed", mitreTechniques: ["T1486"], status: "confirmed" }),
    ];
    const results = mapFindings(findings);
    expect(results).toHaveLength(1);
    expect(results[0].findingId).toBe("f-confirmed");
  });

  it("skips findings with no MITRE techniques and techniques with no mapping", () => {
    const results = mapFindings([
      makeFinding({ id: "f-no-mitre", mitreTechniques: [], status: "confirmed" }),
      makeFinding({ id: "f-unmapped", mitreTechniques: ["T9999"], status: "confirmed" }),
      makeFinding({ id: "f-mapped", mitreTechniques: ["T1059.001"], status: "confirmed" }),
    ]);
    expect(results).toHaveLength(1);
    expect(results[0].findingId).toBe("f-mapped");
    expect(results[0].technique).toBe("T1059.001");
  });

  it("emits one ComplianceResult per distinct technique across a multi-technique finding", () => {
    const results = mapFindings([
      makeFinding({
        id: "f-multi",
        mitreTechniques: ["T1566.001", "T1059.001", "T1003.001"],
        status: "confirmed",
      }),
    ]);
    expect(results).toHaveLength(3);
    const techniques = results.map((r) => r.technique);
    expect(techniques).toEqual(["T1566.001", "T1059.001", "T1003.001"]);
    for (const r of results) expect(r.findingId).toBe("f-multi");
    for (const r of results) expect(r.frameworks.length).toBeGreaterThan(0);
  });

  it("caches the loaded dataset — repeated calls return the same instance", () => {
    const a = loadComplianceMap();
    const b = loadComplianceMap();
    expect(b).toBe(a);
    _resetComplianceMapCache();
    const c = loadComplianceMap();
    expect(c).not.toBe(a);
  });
});