// #2550 — the BEC post-passes over one M365 export: a hiding rule next to a forward-out rule by the
// same actor on the same mailbox (Critical), and a privileged role granted to a user created in the
// last 24 hours (High). Plus the two table grades the issue named: AnonymousLinkCreated and HardDelete.
import { describe, expect, it } from "vitest";
import { parseM365Audit } from "../../src/analysis/m365Import.js";

type Rec = Record<string, unknown>;
const T0 = Date.parse("2024-05-01T10:00:00Z");
const at = (minutes: number) => new Date(T0 + minutes * 60_000).toISOString().replace(".000Z", "");
let seq = 0;
const ex = (op: string, params: Record<string, string>, minutes: number, over: Rec = {}): Rec => ({
  Id: `ex-${++seq}`,
  CreationTime: at(minutes),
  Workload: "Exchange",
  RecordType: 1,
  Operation: op,
  OrganizationId: "tenant-1",
  UserType: 2,
  UserId: "alice@tenant.invalid",
  ObjectId: `alice\\${params.Name ?? ""}`,
  ResultStatus: "True",
  ClientIP: "203.0.113.9",
  Parameters: Object.entries(params).map(([Name, Value]) => ({ Name, Value })),
  ...over,
});
const forwardOut = (minutes: number, over: Rec = {}) =>
  ex(
    "New-InboxRule",
    { Name: "Fin", BodyContainsWords: "Invoice", ForwardTo: "drop@outside.invalid" },
    minutes,
    over,
  );
const deleter = (minutes: number, over: Rec = {}) =>
  ex("New-InboxRule", { Name: "", BodyContainsWords: "drop", DeleteMessage: "True" }, minutes, over);

const rows = (recs: Rec[]) => parseM365Audit(JSON.stringify(recs), { aggregate: false }).events;
const ruleRow = (recs: Rec[], name: string) => {
  const r = rows(recs).find((e) => e.description.includes(`creates inbox rule "${name}"`));
  if (!r) throw new Error(`no row for rule ${name}`);
  return r;
};

describe("hiding rule paired with a forward-out rule (#2550)", () => {
  it("a delete rule 2 minutes after a forward-out rule by the same actor is Critical and says why", () => {
    const recs = [forwardOut(0), deleter(2)];
    const del = ruleRow(recs, "");
    expect(del.severity).toBe("Critical");
    expect(del.description).toMatch(/forward-out rule .*within 10 minutes/);
    expect(ruleRow(recs, "Fin").severity).toBe("High");
  });
  it("one mailbox written as an Exchange path and as an alias still pairs", () => {
    const path = "NAMPR01A001.PROD.OUTLOOK.COM/Microsoft Exchange Hosted Organizations/tenant.invalid/alice";
    expect(ruleRow([forwardOut(0, { ObjectId: `${path}\\Fin` }), deleter(2)], "").severity).toBe("Critical");
  });
  it("the delete rule may come first", () => {
    expect(ruleRow([deleter(0), forwardOut(9)], "").severity).toBe("Critical");
  });
  it("30 minutes apart the delete rule stays High", () => {
    const del = ruleRow([forwardOut(0), deleter(30)], "");
    expect(del.severity).toBe("High");
    expect(del.description).not.toContain("forward-out rule");
  });
  it("a different actor, a different mailbox, or a failed forward rule is no pair", () => {
    expect(ruleRow([forwardOut(0, { UserId: "bob@tenant.invalid" }), deleter(2)], "").severity).toBe("High");
    expect(ruleRow([forwardOut(0, { ObjectId: "carol\\Fin" }), deleter(2)], "").severity).toBe("High");
    expect(ruleRow([forwardOut(0, { ResultStatus: "False" }), deleter(2)], "").severity).toBe("High");
  });
  it("a forward rule that stays inside the tenant is no pair", () => {
    const inside = ex("New-InboxRule", { Name: "In", ForwardTo: "bob@tenant.invalid" }, 0);
    expect(ruleRow([inside, deleter(2)], "").severity).toBe("High");
  });
});

// Entra directory changes exported through the UAL (RecordType 8).
const aad = (op: string, minutes: number, target: { id: string; upn: string }, props: Rec[] = []): Rec => ({
  Id: `aad-${++seq}`,
  CreationTime: at(minutes),
  Workload: "AzureActiveDirectory",
  RecordType: 8,
  Operation: op,
  ResultStatus: "Success",
  OrganizationId: "tenant-1",
  UserType: 0,
  UserId: "admin@tenant.invalid",
  ObjectId: target.upn,
  Actor: [
    { ID: "admin@tenant.invalid", Type: 5 },
    { ID: "User", Type: 2 },
  ],
  Target: [
    { ID: `User_${target.id}`, Type: 2 },
    { ID: target.id, Type: 2 },
    { ID: "User", Type: 2 },
    { ID: target.upn, Type: 5 },
  ],
  ModifiedProperties: props,
});
const NEW_USER = { id: "11111111-2222-4333-8444-555555555555", upn: "newbie@tenant.invalid" };
const OLD_USER = { id: "99999999-2222-4333-8444-555555555555", upn: "veteran@tenant.invalid" };
const role = (name: string, templateId: string): Rec[] => [
  { Name: "Role.DisplayName", NewValue: name, OldValue: "" },
  { Name: "Role.TemplateId", NewValue: templateId, OldValue: "" },
];
const EXCHANGE_ADMIN = role("Exchange Administrator", "29232cdf-9323-42fd-ade2-1d097af3e4de");
const DIRECTORY_READERS = role("Directory Readers", "88d8e3e3-8f55-4a1e-953a-9b9898b8876b");
const grantRow = (recs: Rec[], upn: string) => {
  const r = rows(recs).find(
    (e) => /assigns directory role/.test(e.description) && e.description.includes(upn),
  );
  if (!r) throw new Error("no grant row");
  return r;
};

describe("privileged role granted to a newly created user (#2550)", () => {
  it("Exchange Administrator to a user created a minute earlier is High and says why", () => {
    const recs = [aad("Add user.", 0, NEW_USER), aad("Add member to role.", 1, NEW_USER, EXCHANGE_ADMIN)];
    const g = grantRow(recs, NEW_USER.upn);
    expect(g.severity).toBe("High");
    expect(g.description).toMatch(/created .*in this export/);
    const created = rows(recs).find((e) => /Add user/.test(e.description));
    expect(created?.severity).toBe("Medium");
  });
  it("the same grant with no creation in the export, or more than 24 h later, stays Medium", () => {
    expect(grantRow([aad("Add member to role.", 1, OLD_USER, EXCHANGE_ADMIN)], OLD_USER.upn).severity).toBe(
      "Medium",
    );
    const late = [
      aad("Add user.", 0, NEW_USER),
      aad("Add member to role.", 25 * 60, NEW_USER, EXCHANGE_ADMIN),
    ];
    expect(grantRow(late, NEW_USER.upn).severity).toBe("Medium");
  });
  it("a grant BEFORE the creation, or a non-privileged role, is no pair", () => {
    const before = [aad("Add member to role.", 0, NEW_USER, EXCHANGE_ADMIN), aad("Add user.", 5, NEW_USER)];
    expect(grantRow(before, NEW_USER.upn).severity).toBe("Medium");
    const reader = [
      aad("Add user.", 0, NEW_USER),
      aad("Add member to role.", 1, NEW_USER, DIRECTORY_READERS),
    ];
    expect(grantRow(reader, NEW_USER.upn).severity).toBe("Medium");
  });
});

// The Graph directory-audit shape of the same two records.
const graphAudit = (activity: string, minutes: number, target: Rec): Rec => ({
  id: `g-${++seq}`,
  activityDateTime: new Date(T0 + minutes * 60_000).toISOString(),
  activityDisplayName: activity,
  category: "UserManagement",
  result: "success",
  loggedByService: "Core Directory",
  initiatedBy: { user: { id: "a-1", userPrincipalName: "admin@tenant.invalid", ipAddress: "203.0.113.5" } },
  targetResources: [target],
});
const graphUser = (props: Rec[] = []): Rec => ({
  type: "User",
  id: NEW_USER.id,
  userPrincipalName: NEW_USER.upn,
  modifiedProperties: props.map((p) => ({ displayName: p.Name, oldValue: null, newValue: p.NewValue })),
});

describe("privileged role granted to a newly created user — Graph shape (#2550)", () => {
  it("Add user then Exchange Administrator a minute later: the grant is High", () => {
    const recs = [
      graphAudit("Add user", 0, graphUser()),
      graphAudit("Add member to role", 1, graphUser(EXCHANGE_ADMIN)),
    ];
    expect(grantRow(recs, NEW_USER.upn).severity).toBe("High");
    expect(grantRow([recs[1]], NEW_USER.upn).severity).toBe("Medium");
  });
});

describe("table grades (#2550)", () => {
  it("AnonymousLinkCreated is Low", () => {
    const e = rows([
      {
        Id: "sp-1",
        CreationTime: at(0),
        Workload: "OneDrive",
        RecordType: 14,
        Operation: "AnonymousLinkCreated",
        UserType: 0,
        UserId: "alice@tenant.invalid",
        ObjectId: "https://tenant-my.sharepoint.invalid/personal/alice/Documents/a.docx",
        ClientIP: "203.0.113.9",
      },
    ]);
    expect(e[0]?.severity).toBe("Low");
  });
  it("HardDelete by the mailbox owner is Low", () => {
    const e = rows([
      {
        Id: "hd-1",
        CreationTime: at(0),
        Workload: "Exchange",
        RecordType: 3,
        Operation: "HardDelete",
        LogonType: 0,
        UserType: 0,
        UserId: "alice@tenant.invalid",
        MailboxOwnerUPN: "alice@tenant.invalid",
        ResultStatus: "Succeeded",
        ClientIP: "203.0.113.9",
        AffectedItems: [{ Id: "i1", Subject: "s" }],
      },
    ]);
    expect(e[0]?.severity).toBe("Low");
  });
});
