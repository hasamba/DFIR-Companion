// #2550 — BEC grading in the Exchange audit decoder: the owner's domain when the mailbox is an
// alias, mailbox permission grants graded by who made them, and an owner's hard delete.
import { describe, expect, it } from "vitest";
import { decodeExchangeRecord, type ExchangeChange } from "../../src/analysis/exchangeAudit.js";

const OWNER = "alice@example.invalid";
const base = (over: Record<string, unknown>) => ({
  Id: "rec-1",
  CreationTime: "2024-05-01T10:00:00Z",
  Workload: "Exchange",
  OrganizationId: "tenant-1",
  UserType: 0,
  UserId: "helpdesk@example.invalid",
  ResultStatus: "True",
  ClientIP: "203.0.113.9",
  ...over,
});
const admin = (op: string, params: Record<string, string>, over: Record<string, unknown> = {}) =>
  base({
    RecordType: 1,
    Operation: op,
    ObjectId: OWNER,
    Parameters: Object.entries(params).map(([Name, Value]) => ({ Name, Value })),
    ...over,
  });
const one = (rec: Record<string, unknown>): ExchangeChange => {
  const c = decodeExchangeRecord(rec, 0);
  if (!c) throw new Error("not decoded");
  return c;
};
const DN = (tenant: string, name: string) =>
  `NAMPR01A001.PROD.OUTLOOK.COM/Microsoft Exchange Hosted Organizations/${tenant}/${name}`;
const SYSTEM = "NT AUTHORITY\\SYSTEM (Microsoft.Exchange.ServiceHost)";

describe("owner domain when the mailbox is an alias (#2550)", () => {
  it("the actor's UPN domain classes a forward from an alias mailbox: outside is High", () => {
    const c = one(
      admin(
        "New-InboxRule",
        { Name: "Fin", BodyContainsWords: "Invoice;Payments", ForwardTo: "drop@outside.invalid" },
        { ObjectId: "alice\\Fin", UserType: 2, UserId: "alice@tenant.invalid" },
      ),
    );
    expect(c.mailbox).toBe("alice");
    expect(c.words).toContain("drop@outside.invalid (outside the tenant domains this record names)");
    expect(c.severity).toBe("High");
    expect(c.forwardsOutside).toBe(true);
  });
  it("the tenant segment of the Exchange path classes an SMTP forward: outside High, the tenant's own domain Medium", () => {
    const rec = (to: string) =>
      admin(
        "Set-Mailbox",
        { Identity: DN("tenant.onmicrosoft.invalid", "Bob"), ForwardingSmtpAddress: `smtp:${to}` },
        { ObjectId: "Bob", UserType: 5, UserId: "app-1" },
      );
    const out = one(rec("ex@outside.invalid"));
    expect(out.severity).toBe("High");
    expect(out.posture).toContain("(outside the tenant domains this record names)");
    const inside = one(rec("bob@tenant.onmicrosoft.invalid"));
    expect(inside.severity).toBe("Medium");
    expect(inside.posture).toContain("(inside the tenant domains this record names)");
  });
  it("an address inside ANY proven domain is inside: the path's domain and the actor's own domain", () => {
    const c = one(
      admin(
        "New-InboxRule",
        { Name: "r", ForwardTo: "bob@tenant.invalid;carol@tenant.onmicrosoft.invalid" },
        {
          ObjectId: `${DN("tenant.onmicrosoft.invalid", "alice")}\\r`,
          UserType: 0,
          UserId: "admin@tenant.invalid",
        },
      ),
    );
    expect(c.severity).toBe("Medium");
    expect(c.forwardsOutside).toBe(false);
  });
  it("a system actor proves no domain: an alias mailbox stays unclassed", () => {
    const c = one(
      admin(
        "New-InboxRule",
        { Name: "r", ForwardTo: "x@outside.invalid" },
        { ObjectId: "alice\\r", UserType: 3, UserId: SYSTEM },
      ),
    );
    expect(c.words).not.toContain("domain");
    expect(c.severity).toBe("Medium");
  });
  it("a UPN mailbox keeps the mailbox's own domain and wording", () => {
    const c = one(admin("New-InboxRule", { Name: "r", ForwardTo: "x@helpdesk.invalid" }));
    expect(c.words).toContain("(outside the mailbox's domain)");
  });
});

describe("mailbox permission grants by who made them (#2550)", () => {
  const grant = (op: string, params: Record<string, string>, over: Record<string, unknown> = {}) =>
    one(admin(op, params, { ObjectId: "Carol", UserType: 2, UserId: "admin@tenant.invalid", ...over }));
  it("FullAccess and SendAs to another account by a person are High", () => {
    const fa = grant("Add-MailboxPermission", {
      Identity: DN("tenant.invalid", "Carol"),
      User: DN("tenant.invalid", "Attacker"),
      AccessRights: "FullAccess",
    });
    expect(fa.severity).toBe("High");
    expect(fa.mitre).toEqual(["T1098.002"]);
    const sa = grant("Add-RecipientPermission", {
      Identity: DN("tenant.invalid", "Carol"),
      Trustee: DN("tenant.invalid", "Attacker"),
      AccessRights: "SendAs",
    });
    expect(sa.severity).toBe("High");
    // An admin granting THEMSELVES access to someone else's mailbox is the core case.
    expect(
      grant("Add-MailboxPermission", {
        Identity: "Carol",
        User: "admin@tenant.invalid",
        AccessRights: "FullAccess",
      }).severity,
    ).toBe("High");
  });
  it("the same grant by a system or application actor is Low", () => {
    const params = {
      Identity: DN("tenant.invalid", "DiscoverySearchMailbox"),
      User: "Discovery Management",
      AccessRights: "FullAccess",
    };
    expect(grant("Add-MailboxPermission", params, { UserType: 3, UserId: SYSTEM }).severity).toBe("Low");
    expect(
      grant("Add-MailboxPermission", params, { UserType: 0, UserId: "NT AUTHORITY\\SYSTEM" }).severity,
    ).toBe("Low");
    expect(grant("Add-MailboxPermission", params, { UserType: 5, UserId: "app-1" }).severity).toBe("Low");
  });
  it("a self-grant (the trustee is the mailbox itself) stays Medium; a Deny entry is unchanged", () => {
    expect(
      grant("Add-MailboxPermission", {
        Identity: DN("tenant.invalid", "Carol"),
        User: DN("tenant.invalid", "carol"),
        AccessRights: "FullAccess",
      }).severity,
    ).toBe("Medium");
    expect(
      grant("Add-MailboxPermission", {
        Identity: "carol@tenant.invalid",
        User: "Carol",
        AccessRights: "FullAccess",
      }).severity,
    ).toBe("Medium");
    const deny = { Identity: "Carol", User: "x", AccessRights: "FullAccess", Deny: "True" };
    expect(grant("Add-MailboxPermission", deny).severity).toBe("Low");
    expect(grant("Remove-MailboxPermission", deny).severity).toBe("Medium");
  });
  it("other rights stay Medium", () => {
    expect(
      grant("Add-MailboxFolderPermission", {
        Identity: "Carol:\\Inbox",
        User: "x",
        AccessRights: "Reviewer",
      }).severity,
    ).toBe("Medium");
  });
});

describe("an owner's hard delete (#2550)", () => {
  const item = (op: string, logon: number) =>
    one(
      base({
        RecordType: 3,
        Operation: op,
        LogonType: logon,
        MailboxOwnerUPN: OWNER,
        UserId: OWNER,
        AffectedItems: [{ Id: "i1", Subject: "s" }],
      }),
    );
  it("HardDelete by the owner is Low; MoveToDeletedItems by the owner stays Info", () => {
    expect(item("HardDelete", 0).severity).toBe("Low");
    expect(item("MoveToDeletedItems", 0).severity).toBe("Info");
    expect(item("HardDelete", 1).severity).toBe("Medium");
  });
});

describe("self-grant test keeps the domain when both sides are UPNs (#2550 review)", () => {
  it("treats alice@one and alice@two as different accounts", async () => {
    const { permissionSeverity, samePrincipal } = await import("../../src/analysis/exchangeAuditValues.js");
    expect(samePrincipal("alice@one.example", "alice@two.example")).toBe(false);
    expect(samePrincipal("alice@one.example", "ALICE@one.example")).toBe(true);
    expect(samePrincipal("alice", "alice@one.example")).toBe(true);
    expect(samePrincipal("ORG/Users/alice", "alice")).toBe(true);
    const g = { widens: true, deny: false, rights: "FullAccess", byService: false };
    expect(permissionSeverity({ ...g, trustee: "alice@two.example", mailbox: "alice@one.example" })).toBe(
      "High",
    );
    expect(permissionSeverity({ ...g, trustee: "alice@one.example", mailbox: "alice@one.example" })).toBe(
      "Medium",
    );
  });
});
