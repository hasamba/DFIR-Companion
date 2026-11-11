// #2549 — Set-AdminAuditLogConfig is graded by what it set, not by its name. Turning admin audit
// logging or unified audit ingestion OFF is the anti-forensics action (High, T1562.008) whoever
// does it; Exchange's own service host turning it ON is upkeep (Info); a person turning it on is
// Low; any other change of the audit configuration by a person is Medium with no technique.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { decodeExchangeRecord, type ExchangeChange } from "../../src/analysis/exchangeAudit.js";
import { parseM365Audit } from "../../src/analysis/m365Import.js";
import { loadBundledSigmaRuleSet } from "../../src/analysis/sigmaBundledRules.js";
import { createSigmaImportGrader } from "../../src/analysis/sigmaImportGrade.js";
import { compileText } from "../../src/analysis/taggerStore.js";
import { runTagger } from "../../src/analysis/tagger.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

const SYSTEM = "NT AUTHORITY\\SYSTEM (Microsoft.Exchange.ServiceHost)";
const PERSON = "admin@example.test";

const rec = (params: Record<string, string>, over: Record<string, unknown> = {}) => ({
  Id: "00000000-0000-0000-0000-0000000000c9",
  CreationTime: "2026-03-01T10:00:00",
  Workload: "Exchange",
  RecordType: 1,
  Operation: "Set-AdminAuditLogConfig",
  OrganizationId: "00000000-0000-0000-0000-0000000000aa",
  ObjectId: "example.test\\Admin Audit Log Settings",
  UserType: 2,
  UserId: PERSON,
  ResultStatus: "True",
  ClientIP: "198.51.100.7",
  Parameters: Object.entries(params).map(([Name, Value]) => ({ Name, Value })),
  ...over,
});
// The housekeeping parameters Exchange's own host writes on every one of its records.
const HOUSEKEEPING = { DomainController: "DC1.example.test", Identity: "x", IgnoreDehydratedFlag: "True" };
const bySystem = (params: Record<string, string>, userType = 3) =>
  rec({ ...HOUSEKEEPING, ...params }, { UserId: SYSTEM, UserType: userType });

const one = (r: Record<string, unknown>): ExchangeChange => {
  const c = decodeExchangeRecord(r, 0);
  if (!c) throw new Error("not decoded");
  return c;
};

describe("Set-AdminAuditLogConfig decoder (#2549)", () => {
  it("SYSTEM turning admin audit logging ON is Info with no technique, both host spellings", () => {
    for (const actor of [SYSTEM, "NT AUTHORITY\\SYSTEM (Microsoft.Exchange.Servicehost)"]) {
      const c = one(rec({ ...HOUSEKEEPING, AdminAuditLogEnabled: "True" }, { UserId: actor, UserType: 3 }));
      expect(c.kind).toBe("config");
      expect(c.severity).toBe("Info");
      expect(c.mitre).toEqual([]);
      expect(c.posture).toContain("AdminAuditLogEnabled on");
    }
  });

  it("a person turning logging ON is Low", () => {
    const c = one(rec({ AdminAuditLogEnabled: "$true" }));
    expect(c.severity).toBe("Low");
    expect(c.mitre).toEqual([]);
  });

  it("a person turning admin audit logging OFF is High + T1562.008", () => {
    const c = one(rec({ AdminAuditLogEnabled: "False" }));
    expect(c.severity).toBe("High");
    expect(c.mitre).toEqual(["T1562.008"]);
    expect(c.posture).toContain("AdminAuditLogEnabled off");
  });

  it("turning unified audit ingestion OFF is High, even by a system actor", () => {
    expect(one(rec({ UnifiedAuditLogIngestionEnabled: "$false" })).severity).toBe("High");
    const sys = one(bySystem({ UnifiedAuditLogIngestionEnabled: "False" }));
    expect(sys.severity).toBe("High");
    expect(sys.mitre).toEqual(["T1562.008"]);
  });

  it("an OFF mixed with an ON is still High", () => {
    const c = one(rec({ AdminAuditLogEnabled: "True", UnifiedAuditLogIngestionEnabled: "False" }));
    expect(c.severity).toBe("High");
  });

  it("any other change by a person is Medium with no technique and names the setting", () => {
    const c = one(rec({ AdminAuditLogAgeLimit: "7.00:00:00" }));
    expect(c.severity).toBe("Medium");
    expect(c.mitre).toEqual([]);
    expect(c.posture).toContain("AdminAuditLogAgeLimit");
    expect(one(rec({})).severity).toBe("Medium");
  });

  it("the same other change by the service host is Low", () => {
    expect(one(bySystem({ AdminAuditLogAgeLimit: "90.00:00:00" })).severity).toBe("Low");
  });

  it("a dry run makes no change: Low, no technique", () => {
    const c = one(rec({ AdminAuditLogEnabled: "False", WhatIf: "True" }));
    expect(c.severity).toBe("Low");
    expect(c.mitre).toEqual([]);
    expect(c.qualifiers.join(" ")).toMatch(/dry run/);
  });

  it("a failed disable is an attempt: Medium, no technique", () => {
    const c = one(rec({ AdminAuditLogEnabled: "False" }, { ResultStatus: "False" }));
    expect(c.attempted).toBe(true);
    expect(c.severity).toBe("Medium");
    expect(c.mitre).toEqual([]);
  });

  it("other cmdlets are not decoded by it", () => {
    expect(decodeExchangeRecord(rec({}, { Operation: "Get-AdminAuditLogConfig" }), 0)).toBeNull();
    expect(decodeExchangeRecord(rec({}, { Operation: "Install-AdminAuditLogConfig" }), 0)).toBeNull();
  });
});

const TAGS = compileText(
  readFileSync(fileURLToPath(new URL("../../data/tags.yaml", import.meta.url)), "utf8"),
);
const { set } = loadBundledSigmaRuleSet();
const sigma = createSigmaImportGrader(set).snapshot();

/** Import → Sigma (optional) → shipped tagger; the row's final grade, techniques and rule ids. */
function graded(r: Record<string, unknown>, withSigma: boolean) {
  const res = parseM365Audit(JSON.stringify([r]), {
    aggregate: false,
    ...(withSigma ? { sigma } : {}),
  });
  expect(res.events).toHaveLength(1);
  const e = res.events[0];
  const event = { ...e, id: "e0", relatedFindingIds: [], sourceScreenshots: [] } as unknown as ForensicEvent;
  const t = runTagger([event], TAGS).perEvent[0];
  return { row: e, ruleIds: t?.ruleIds ?? [], taggerSeverity: t?.severity };
}

describe("Set-AdminAuditLogConfig through the importer and the shipped rules (#2549)", () => {
  it("SYSTEM turning logging on is not High anywhere, and stays tag-searchable", () => {
    for (const withSigma of [false, true]) {
      const g = graded(bySystem({ AdminAuditLogEnabled: "True" }), withSigma);
      expect(g.row.severity).toBe("Info");
      expect(g.ruleIds).toContain("mas_operation_audit_config_changed");
      expect(g.taggerSeverity ?? "Info").toBe("Info");
    }
  });

  it("a user turning logging off is High with T1562.008, with and without the Suzaku rule", () => {
    const offs: Record<string, string>[] = [
      { AdminAuditLogEnabled: "False" },
      { UnifiedAuditLogIngestionEnabled: "$false" },
    ];
    for (const withSigma of [false, true]) {
      for (const p of offs) {
        const g = graded(rec(p), withSigma);
        expect(g.row.severity).toBe("High");
        expect(g.row.mitreTechniques).toContain("T1562.008");
      }
    }
  });
});
