// #2604 item 2 — Remove-DlpCompliancePolicy. A Security & Compliance cmdlet record (RecordType 18,
// Workload SecurityComplianceCenter) carries `Parameters` as ONE command-line string, not the
// Exchange Name/Value pairs, so the dry-run switch is read from that string. Synthetic records.
import { describe, expect, it } from "vitest";
import { parseM365Audit } from "../../src/analysis/m365Import.js";

const rec = (params: unknown, over: Record<string, unknown> = {}) => ({
  CreationTime: "2026-06-04T06:17:25",
  Id: "00000000-0000-4000-8000-00000000d001",
  Operation: "Remove-DlpCompliancePolicy",
  OrganizationId: "00000000-0000-4000-8000-0000000000aa",
  RecordType: 18,
  ResultStatus: "Success",
  UserKey: "operator@example.test",
  UserType: 2,
  Version: 1,
  Workload: "SecurityComplianceCenter",
  ObjectId: "",
  UserId: "operator@example.test",
  SecurityComplianceCenterEventType: 0,
  ClientApplication: "EMC",
  EffectiveOrganization: "example.test",
  NonPIIParameters: '-Identity "<SNIP-PII>"',
  Parameters: params,
  StartTime: "2026-06-04T06:17:25",
  ...over,
});

/** The record as the UAL CSV export carries it: the JSON in AuditData. */
const csvShaped = (r: Record<string, unknown>) => ({
  RecordType: "SecurityComplianceCenterEOPCmdlet",
  CreationDate: "2026-06-04T06:17:25Z",
  UserIds: "operator@example.test",
  Operations: "Remove-DlpCompliancePolicy",
  AuditData: JSON.stringify(r),
});

const rows = (records: Record<string, unknown>[]) => parseM365Audit(JSON.stringify(records)).events;

describe("Remove-DlpCompliancePolicy (#2604 item 2)", () => {
  it("a completed removal is Medium + T1562.001 and names the policy", () => {
    const [e] = rows([rec('-Identity "Finance DLP"')]);
    expect(e.severity).toBe("Medium");
    expect(e.mitreTechniques).toEqual(["T1562.001"]);
    expect(e.description).toContain("Remove-DlpCompliancePolicy");
    expect(e.description).toContain("Finance DLP");
  });

  it("the CSV-export shape grades the same", () => {
    const [e] = rows([csvShaped(rec('-Identity "Finance DLP"'))]);
    expect(e.severity).toBe("Medium");
    expect(e.mitreTechniques).toEqual(["T1562.001"]);
  });

  it("a -WhatIf removal is a dry run: Low, no technique, said on the row", () => {
    for (const p of ['-Identity "Finance DLP" -WhatIf', '-Identity "Finance DLP" -WhatIf:$true']) {
      const [e] = rows([rec(p)]);
      expect(e.severity).toBe("Low");
      expect(e.mitreTechniques ?? []).toEqual([]);
      expect(e.description).toMatch(/dry run/);
    }
  });

  it("-WhatIf:$false is a real removal", () => {
    const [e] = rows([rec('-Identity "Finance DLP" -WhatIf:$false')]);
    expect(e.severity).toBe("Medium");
  });

  it("the Exchange-style Name/Value pairs are read too", () => {
    const [e] = rows([
      rec([
        { Name: "Identity", Value: "Finance DLP" },
        { Name: "WhatIf", Value: "True" },
      ]),
    ]);
    expect(e.severity).toBe("Low");
  });

  it("a failed or unknown removal is an attempt: Medium, no technique", () => {
    for (const status of ["Failed", "False", ""]) {
      const [e] = rows([rec('-Identity "Finance DLP"', { ResultStatus: status })]);
      expect(e.severity).toBe("Medium");
      expect(e.mitreTechniques ?? []).toEqual([]);
      expect(e.description).toMatch(/FAILED|failed|result unknown/);
    }
  });

  it("a completed, a dry-run and a failed removal never fold into one row, in either order", () => {
    const done = rec('-Identity "Finance DLP"');
    const dry = rec('-Identity "Finance DLP" -WhatIf');
    const failed = rec('-Identity "Finance DLP"', { ResultStatus: "Failed" });
    for (const order of [
      [done, dry, failed],
      [failed, dry, done],
    ]) {
      const out = rows(order);
      expect(out).toHaveLength(3);
      expect(out.filter((e) => (e.mitreTechniques ?? []).includes("T1562.001"))).toHaveLength(1);
    }
  });

  it("another compliance cmdlet is untouched", () => {
    const [e] = rows([rec('-Identity "Finance DLP"', { Operation: "Get-DlpCompliancePolicy" })]);
    expect(e.severity).toBe("Info");
  });
});
