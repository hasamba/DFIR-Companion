// #2605 — Set-Mailbox audit settings are read for what they set. A record whose only setting is
// AuditLogAgeLimit used to render as a plain "Set-Mailbox by … → <mailbox>", and the AI then wrote
// that the changed parameters were not in the record. A zero age limit or AuditEnabled false is the
// anti-forensics action (High, T1562.008); any other audit setting change by a person is Medium.
// Record shape copied from the Suzaku det-eng sample (values replaced with synthetic ones).
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { decodeExchangeRecord, type ExchangeChange } from "../../src/analysis/exchangeAudit.js";
import { isZeroTimeSpan } from "../../src/analysis/exchangeMailboxAudit.js";
import { parseM365Audit } from "../../src/analysis/m365Import.js";
import { loadBundledSigmaRuleSet } from "../../src/analysis/sigmaBundledRules.js";
import { createSigmaImportGrader } from "../../src/analysis/sigmaImportGrade.js";
import { compileText } from "../../src/analysis/taggerStore.js";
import { runTagger } from "../../src/analysis/tagger.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

const SYSTEM = "NT AUTHORITY\\SYSTEM (Microsoft.Exchange.ServiceHost)";

const rec = (params: Record<string, string>, over: Record<string, unknown> = {}) => ({
  CreationTime: "2026-03-01T11:01:07",
  Id: "00000000-0000-4000-8000-0000000026a5",
  Operation: "Set-Mailbox",
  OrganizationId: "00000000-0000-0000-0000-0000000000aa",
  RecordType: 1,
  ResultStatus: "True",
  UserKey: "1003000000000000",
  UserType: 2,
  Version: 1,
  Workload: "Exchange",
  ClientIP: "198.51.100.7:9257",
  ObjectId: "00000000-0000-4000-8000-00000000b0b0",
  UserId: "operator@example.test",
  AppId: "00000000-0000-4000-8000-00000000a99a",
  ClientAppId: "",
  ExternalAccess: false,
  OrganizationName: "example.test",
  Parameters: [
    { Name: "Identity", Value: "victim@example.test" },
    ...Object.entries(params).map(([Name, Value]) => ({ Name, Value })),
  ],
  SessionId: "00000000-0000-4000-8000-000000005e55",
  ...over,
});

const one = (r: Record<string, unknown>): ExchangeChange => {
  const c = decodeExchangeRecord(r, 0);
  if (!c) throw new Error("not decoded");
  return c;
};

describe("isZeroTimeSpan (#2605)", () => {
  it("is true only when every component is zero", () => {
    for (const v of ["00:00:00", "0", "0.00:00:00", "0:0:0", " 00:00:00.000 "])
      expect(isZeroTimeSpan(v)).toBe(true);
    for (const v of ["1.00:00:00", "00:00:01", "90", "", "unlimited", "-00:00:00x"])
      expect(isZeroTimeSpan(v)).toBe(false);
  });
});

describe("Set-Mailbox audit settings (#2605)", () => {
  it("a zero AuditLogAgeLimit is High, T1562.008, a config row that states the value", () => {
    const c = one(rec({ AuditLogAgeLimit: "00:00:00" }));
    expect(c.kind).toBe("config");
    expect(c.severity).toBe("High");
    expect(c.mitre).toEqual(["T1562.008"]);
    expect(c.polarity).toBe("removes");
    expect(c.posture).toContain("AuditLogAgeLimit to 00:00:00");
    expect(c.posture).toMatch(/zero/);
  });

  it("a non-zero age limit is Medium with no technique and says the prior value is not in the record", () => {
    const c = one(rec({ AuditLogAgeLimit: "1.00:00:00" }));
    expect(c.kind).toBe("config");
    expect(c.severity).toBe("Medium");
    expect(c.mitre).toEqual([]);
    expect(c.posture).toContain("AuditLogAgeLimit to 1.00:00:00");
    expect(c.qualifiers.join(" ")).toMatch(/prior value/);
  });

  it("the one-day and zero records do not fold into one row", () => {
    expect(one(rec({ AuditLogAgeLimit: "1.00:00:00" })).key).not.toBe(
      one(rec({ AuditLogAgeLimit: "00:00:00" })).key,
    );
  });

  it("AuditEnabled false is High, even with another setting turned on in the same record", () => {
    for (const v of ["False", "$false"]) {
      const c = one(rec({ AuditEnabled: v }));
      expect(c.severity).toBe("High");
      expect(c.mitre).toEqual(["T1562.008"]);
      expect(c.posture).toMatch(/mailbox auditing off/);
    }
    expect(one(rec({ AuditEnabled: "False", AuditOwner: "MailboxLogin" })).severity).toBe("High");
  });

  it("AuditEnabled true is Low for a person and Info for the service host", () => {
    expect(one(rec({ AuditEnabled: "True" })).severity).toBe("Low");
    expect(one(rec({ AuditEnabled: "True" }, { UserId: SYSTEM, UserType: 3 })).severity).toBe("Info");
  });

  it("an unreadable AuditEnabled value is a change of unknown effect: Medium", () => {
    expect(one(rec({ AuditEnabled: "maybe" })).severity).toBe("Medium");
  });

  it("an audited-actions change is Medium and names the setting", () => {
    const c = one(rec({ AuditOwner: "MailboxLogin,HardDelete" }));
    expect(c.severity).toBe("Medium");
    expect(c.posture).toContain("AuditOwner");
  });

  it("an unreadable age limit is Medium and the value is shown, bounded", () => {
    const c = one(rec({ AuditLogAgeLimit: `x${"y".repeat(200)}` }));
    expect(c.severity).toBe("Medium");
    expect(c.posture.length).toBeLessThan(200);
  });

  it("a dry run of an audit change is a config row that simulates, Low, no technique", () => {
    const c = one(rec({ AuditLogAgeLimit: "00:00:00", WhatIf: "True" }));
    expect(c.kind).toBe("config");
    expect(c.polarity).toBe("simulates");
    expect(c.severity).toBe("Low");
    expect(c.mitre).toEqual([]);
    expect(c.qualifiers.join(" ")).toMatch(/dry run/);
  });

  it("a failed zero age limit is an attempt: Medium, no technique", () => {
    const c = one(rec({ AuditLogAgeLimit: "00:00:00" }, { ResultStatus: "False" }));
    expect(c.attempted).toBe(true);
    expect(c.severity).toBe("Medium");
    expect(c.mitre).toEqual([]);
  });

  it("a record that sets forwarding AND a zero age limit shows both and keeps the worst grade", () => {
    const c = one(rec({ ForwardingSmtpAddress: "smtp:drop@example.test", AuditLogAgeLimit: "00:00:00" }));
    expect(c.kind).toBe("forwarding");
    expect(c.posture).toContain("SMTP forwarding");
    expect(c.words).toContain("AuditLogAgeLimit to 00:00:00");
    expect(c.severity).toBe("High");
    expect(c.mitre).toContain("T1562.008");
  });

  it("a Set-Mailbox with neither forwarding nor audit settings is not decoded by it", () => {
    expect(decodeExchangeRecord(rec({ HiddenFromAddressListsEnabled: "True" }), 0)).toBeNull();
  });
});

const TAGS = compileText(
  readFileSync(fileURLToPath(new URL("../../data/tags.yaml", import.meta.url)), "utf8"),
);
const sigma = createSigmaImportGrader(loadBundledSigmaRuleSet().set).snapshot();

function graded(r: Record<string, unknown>, withSigma: boolean) {
  const res = parseM365Audit(JSON.stringify([r]), { aggregate: false, ...(withSigma ? { sigma } : {}) });
  expect(res.events).toHaveLength(1);
  const e = res.events[0];
  const event = { ...e, id: "e0", relatedFindingIds: [], sourceScreenshots: [] } as unknown as ForensicEvent;
  const t = runTagger([event], TAGS).perEvent[0];
  return { row: e, ruleIds: t?.ruleIds ?? [] };
}

describe("Set-Mailbox audit settings through the importer and the shipped rules (#2605)", () => {
  it("a zero age limit is High with T1562.008, with and without Sigma, and stays tagged as a mailbox change", () => {
    for (const withSigma of [false, true]) {
      const g = graded(rec({ AuditLogAgeLimit: "00:00:00" }), withSigma);
      expect(g.row.severity).toBe("High");
      expect(g.row.mitreTechniques).toContain("T1562.008");
      expect(g.row.description).toMatch(/^M365 Exchange: Set-Mailbox\b/);
      expect(g.row.description).toContain("AuditLogAgeLimit to 00:00:00");
      expect(g.ruleIds).toContain("ts_m365_set_mailbox");
    }
  });

  it("the one-day then zero sequence stays two rows under aggregation", () => {
    const res = parseM365Audit(
      JSON.stringify([
        rec({ AuditLogAgeLimit: "1.00:00:00" }, { Id: "00000000-0000-4000-8000-0000000026a6" }),
        rec({ AuditLogAgeLimit: "00:00:00" }),
      ]),
      { aggregate: true },
    );
    expect(res.events).toHaveLength(2);
  });
});
