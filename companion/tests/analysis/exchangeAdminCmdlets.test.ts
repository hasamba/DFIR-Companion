// #2604 — Exchange admin cmdlets graded by the parameter that decides them: the mailbox audit
// bypass, POP/IMAP enabled on a mailbox, and the ApplicationImpersonation role. Records keep the
// real Unified Audit Log shape (an ExchangeAdmin record, `Parameters` as Name/Value pairs) and are
// synthetic: example.test names, documentation IPs, invented ids.
import { describe, expect, it } from "vitest";
import { decodeExchangeRecord, type ExchangeChange } from "../../src/analysis/exchangeAudit.js";
import { parseM365Audit } from "../../src/analysis/m365Import.js";

const ADMIN = "operator@example.test";

const rec = (operation: string, params: Record<string, string>, over: Record<string, unknown> = {}) => ({
  CreationTime: "2026-05-20T11:07:00",
  Id: "00000000-0000-4000-8000-00000000e001",
  Operation: operation,
  OrganizationId: "00000000-0000-4000-8000-0000000000aa",
  RecordType: 1,
  ResultStatus: "True",
  UserKey: "1000000000000001",
  UserType: 2,
  Version: 1,
  Workload: "Exchange",
  ClientIP: "203.0.113.40:56806",
  ObjectId: "11111111-2222-4333-8444-555555555555",
  UserId: ADMIN,
  AppId: "00000000-0000-4000-8000-0000000000a1",
  ClientAppId: "",
  ExternalAccess: false,
  OrganizationName: "example.test",
  OriginatingServer: "EX01 (15.20.0000.000)",
  Parameters: Object.entries(params).map(([Name, Value]) => ({ Name, Value })),
  SessionId: "00000000-0000-4000-8000-0000000000s1",
  ...over,
});

const one = (r: Record<string, unknown>): ExchangeChange => {
  const c = decodeExchangeRecord(r, 0);
  if (!c) throw new Error("not decoded");
  return c;
};

/** Through the public import path, aggregation on (the default). */
const imported = (records: Record<string, unknown>[]) => parseM365Audit(JSON.stringify(records)).events;

describe("Set-MailboxAuditBypassAssociation (#2604 item 1)", () => {
  const bypass = (value: string, over: Record<string, unknown> = {}) =>
    rec(
      "Set-MailboxAuditBypassAssociation",
      { AuditBypassEnabled: value, Identity: "alex@example.test" },
      over,
    );

  it("AuditBypassEnabled True is High + T1562.008 and the row names the value", () => {
    const c = one(bypass("True"));
    expect(c.severity).toBe("High");
    expect(c.mitre).toEqual(["T1562.008"]);
    expect(c.posture).toContain("AuditBypassEnabled True");
    expect(c.words).toContain("alex@example.test");
  });

  it("AuditBypassEnabled False requests the bypass off: Low, no technique", () => {
    const c = one(bypass("False"));
    expect(c.severity).toBe("Low");
    expect(c.mitre).toEqual([]);
    expect(c.posture).toMatch(/requests the mailbox audit bypass off/);
  });

  it("a failed bypass is an attempt: Medium, no technique, never the completed verb", () => {
    const c = one(bypass("True", { ResultStatus: "False" }));
    expect(c.attempted).toBe(true);
    expect(c.severity).toBe("Medium");
    expect(c.mitre).toEqual([]);
    expect(c.posture).toMatch(/^attempted to /);
  });

  it("a WhatIf bypass is a dry run: Low, no technique", () => {
    const r = rec("Set-MailboxAuditBypassAssociation", {
      AuditBypassEnabled: "True",
      Identity: "alex@example.test",
      WhatIf: "True",
    });
    const c = one(r);
    expect(c.severity).toBe("Low");
    expect(c.mitre).toEqual([]);
    expect(c.qualifiers.join(" ")).toMatch(/dry run/);
  });
});

describe("Set-CASMailbox (#2604 item 3)", () => {
  const cas = (params: Record<string, string>, over: Record<string, unknown> = {}) =>
    rec("Set-CASMailbox", { Identity: "lee@example.test", ...params }, over);

  it("POP and IMAP enabled is Medium + T1114.002 and names the protocols", () => {
    const c = one(cas({ ImapEnabled: "True", PopEnabled: "True", OWAEnabled: "True" }));
    expect(c.severity).toBe("Medium");
    expect(c.mitre).toEqual(["T1114.002"]);
    expect(c.posture).toMatch(/enables POP and IMAP/);
    expect(c.posture).not.toMatch(/collect/i);
    expect(c.words).toContain("lee@example.test");
  });

  it("IMAP alone is enough", () => {
    const c = one(cas({ ImapEnabled: "$true" }));
    expect(c.severity).toBe("Medium");
    expect(c.posture).toMatch(/enables IMAP/);
  });

  it("OWAEnabled alone, or POP/IMAP turned off, keeps the plain row", () => {
    expect(decodeExchangeRecord(cas({ OWAEnabled: "True" }), 0)).toBeNull();
    expect(decodeExchangeRecord(cas({ PopEnabled: "False", ImapEnabled: "False" }), 0)).toBeNull();
  });

  it("a failed enable is an attempt, a WhatIf a dry run", () => {
    const failed = one(cas({ PopEnabled: "True" }, { ResultStatus: "False" }));
    expect(failed.attempted).toBe(true);
    expect(failed.mitre).toEqual([]);
    const dry = one(cas({ PopEnabled: "True", WhatIf: "" }));
    expect(dry.severity).toBe("Low");
    expect(dry.polarity).toBe("simulates");
  });
});

describe("ApplicationImpersonation role (#2604 item 4)", () => {
  it("New-RoleGroup with Roles ApplicationImpersonation is High + T1098.002", () => {
    const c = one(
      rec(
        "New-RoleGroup",
        {
          Name: "ImpersonationGroup",
          Roles: "ApplicationImpersonation",
          Members: "22222222-3333-4444-8555-666666666666",
        },
        { ObjectId: "EX01/Microsoft Exchange Hosted Organizations/example.test/ImpersonationGroup" },
      ),
    );
    expect(c.severity).toBe("High");
    expect(c.mitre).toEqual(["T1098.002"]);
    expect(c.posture).toContain("ApplicationImpersonation");
    expect(c.posture).toContain("ImpersonationGroup");
  });

  it("the role is matched as a list element, never as a substring", () => {
    const listed = one(
      rec("New-RoleGroup", { Name: "G", Roles: "Mail Recipients, ApplicationImpersonation" }),
    );
    expect(listed.severity).toBe("High");
    expect(decodeExchangeRecord(rec("New-RoleGroup", { Name: "G", Roles: "Mail Recipients" }), 0)).toBeNull();
    expect(
      decodeExchangeRecord(rec("New-RoleGroup", { Name: "G", Roles: "NotApplicationImpersonationX" }), 0),
    ).toBeNull();
  });

  it("New-ManagementRoleAssignment of ApplicationImpersonation is High and names the assignee", () => {
    const c = one(
      rec("New-ManagementRoleAssignment", {
        Name: "Impersonate-svc",
        Role: "ApplicationImpersonation",
        User: "svc@example.test",
      }),
    );
    expect(c.severity).toBe("High");
    expect(c.mitre).toEqual(["T1098.002"]);
    expect(c.posture).toContain("svc@example.test");
  });

  it("another role assignment keeps the plain row; a failed one is an attempt", () => {
    expect(
      decodeExchangeRecord(rec("New-ManagementRoleAssignment", { Role: "Mail Recipients", User: "a" }), 0),
    ).toBeNull();
    const failed = one(
      rec("New-RoleGroup", { Name: "G", Roles: "ApplicationImpersonation" }, { ResultStatus: "False" }),
    );
    expect(failed.attempted).toBe(true);
    expect(failed.severity).toBe("Medium");
    expect(failed.mitre).toEqual([]);
  });
});

describe("the public import path with aggregation on (#2604 R2)", () => {
  it("a routine Set-CASMailbox and a POP/IMAP enable never fold into one row, in either order", () => {
    const routine = rec("Set-CASMailbox", { Identity: "lee@example.test", OWAEnabled: "True" });
    const signal = rec("Set-CASMailbox", { Identity: "lee@example.test", PopEnabled: "True" });
    for (const order of [
      [routine, signal],
      [signal, routine],
    ]) {
      const rows = imported(order);
      expect(rows).toHaveLength(2);
      const graded = rows.filter((e) => e.severity === "Medium");
      expect(graded).toHaveLength(1);
      expect(graded[0].description).toMatch(/enables POP/);
      expect(graded[0].mitreTechniques).toContain("T1114.002");
      expect(rows.find((e) => e !== graded[0])?.severity).toBe("Info");
    }
  });

  it("a bypass on and a bypass off by the same admin are two rows with their own grades", () => {
    const on = rec("Set-MailboxAuditBypassAssociation", {
      AuditBypassEnabled: "True",
      Identity: "a@example.test",
    });
    const off = rec("Set-MailboxAuditBypassAssociation", {
      AuditBypassEnabled: "False",
      Identity: "a@example.test",
    });
    for (const order of [
      [on, off],
      [off, on],
    ]) {
      const rows = imported(order);
      expect(rows.map((e) => e.severity).sort()).toEqual(["High", "Low"]);
    }
  });

  it("a role group without ApplicationImpersonation stays Info and apart from the graded one", () => {
    const plain = rec("New-RoleGroup", { Name: "Helpdesk", Roles: "Mail Recipients" });
    const graded = rec("New-RoleGroup", { Name: "Imp", Roles: "ApplicationImpersonation" });
    for (const order of [
      [plain, graded],
      [graded, plain],
    ]) {
      const rows = imported(order);
      expect(rows.map((e) => e.severity).sort()).toEqual(["High", "Info"]);
    }
  });
});
