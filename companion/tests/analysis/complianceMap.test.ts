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
      "T1566.001",
      "T1059.001",
      "T1003.001",
      "T1486",
      "T1021.002",
      "T1071.001",
      "T1562.001",
      "T1070.001",
      "T1048.002",
      "T1053.005",
    ];
    for (const t of expected) {
      expect(ds.map[t]).toBeDefined();
      expect(ds.map[t].length).toBeGreaterThan(0);
    }
  });

  it("derives techniqueCount from the parsed map rather than trusting the file", () => {
    // The count used to be a hand-maintained field in the JSON, which goes stale the first time a
    // technique is added without bumping it. It is now computed, so the two can never disagree.
    const ds = loadComplianceMap();
    expect(ds.techniqueCount).toBe(Object.keys(ds.map).length);
  });

  it("carries the not-legal-advice disclaimer and an edition per framework", () => {
    const ds = loadComplianceMap();
    expect(ds.note).toMatch(/not legal advice/i);

    // Every framework named in the data must declare which edition its control ids came from.
    const used = new Set(Object.values(ds.map).flatMap((rows) => rows.map((r) => String(r.framework))));
    for (const framework of used) {
      expect(ds.frameworkVersions[framework], `${framework} has no declared edition`).toBeTruthy();
    }
  });

  it("uses ISO 27001:2022 Annex A numbering throughout, not the 2013 edition", () => {
    // The 2022 Annex A has exactly four themes: A.5 organizational, A.6 people, A.7 physical,
    // A.8 technological. A stray A.9/A.12/A.13 is a 2013 control id, and mixing the two editions
    // in one dataset is what made the original draft untrustworthy.
    const ds = loadComplianceMap();
    const iso = Object.values(ds.map)
      .flat()
      .filter((r) => r.framework === "ISO 27001");
    expect(iso.length).toBeGreaterThan(0);
    for (const row of iso) {
      expect(row.control, `${row.control} is not 2022 Annex A numbering`).toMatch(/^A\.[5-8]\.\d+$/);
    }
    expect(ds.frameworkVersions["ISO 27001"]).toContain("2022");
  });

  it("attaches notification clocks only to real breach-notification obligations", () => {
    const ds = loadComplianceMap();
    const withClocks = Object.values(ds.map)
      .flat()
      .filter((r) => r.notification);
    expect(withClocks.length).toBeGreaterThan(0);

    for (const row of withClocks) {
      // A clock is only actionable with all three parts: how long, in what kind of days, from what.
      expect(row.notification!.within).toMatch(/^P/);
      expect(["calendar", "business"]).toContain(row.notification!.unit);
      expect(row.notification!.from.length).toBeGreaterThan(0);
    }

    // Control cadences (back up every N days, train every N days) must NOT carry a clock — a
    // dashboard countdown built on those would look regulatory and would not be.
    const cadences = Object.values(ds.map)
      .flat()
      .filter((r) => ["CP-9", "AT-2"].includes(r.control));
    expect(cadences.length).toBeGreaterThan(0);
    for (const row of cadences) expect(row.notification).toBeUndefined();
  });

  it("maps a confirmed finding's MITRE techniques to control failures + obligations", () => {
    const results = mapFindings([makeFinding({ id: "f1", mitreTechniques: ["T1486"], status: "confirmed" })]);
    expect(results).toHaveLength(1);
    expect(results[0].technique).toBe("T1486");
    expect(results[0].findingId).toBe("f1");
    const frameworks = results[0].frameworks.map((f) => f.framework);
    expect(frameworks).toEqual(
      expect.arrayContaining(["NIST 800-53", "PCI-DSS", "HIPAA", "GDPR", "SEC", "ISO 27001"]),
    );

    // GDPR Art. 33: 72 calendar hours from awareness of the breach.
    const gdpr = results[0].frameworks.find((f) => f.framework === "GDPR");
    expect(gdpr?.control).toBe("Art. 33");
    expect(gdpr?.notification).toEqual({
      within: "PT72H",
      unit: "calendar",
      from: "becoming aware of the personal data breach",
    });
    expect(gdpr?.obligation.length).toBeGreaterThan(0);

    // Form 8-K Item 1.05 runs in BUSINESS days, from a materiality determination — the distinction
    // the single free-text `deadline` field could not express.
    const sec = results[0].frameworks.find((f) => f.framework === "SEC");
    expect(sec?.control).toContain("Item 1.05");
    expect(sec?.notification?.within).toBe("P4D");
    expect(sec?.notification?.unit).toBe("business");
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
        mitreTechniques: ["T1566.001", "T1059.001", "T1003.001", "T1566.001"],
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
