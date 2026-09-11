// The Exchange Online audit decoder (#931 item 2): what ONE Unified Audit Log record establishes
// — the rule actions it supplied, the forwarding parameter it set, the items it lists, who
// reached which mailbox and how — and nothing it does not: no effective state from an absent
// parameter, no completed verb on a failed command, no "read" from a bind, no count invented.
import { describe, expect, it } from "vitest";
import { decodeExchangeRecord, type ExchangeChange } from "../../src/analysis/exchangeAudit.js";

const OWNER = "alice@example.invalid";
const ACTOR = "helpdesk@example.invalid";
const base = (over: Record<string, unknown>) => ({
  Id: "rec-1",
  CreationTime: "2024-05-01T10:00:00Z",
  Workload: "Exchange",
  OrganizationId: "tenant-1",
  UserType: 0,
  UserId: ACTOR,
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
const one = (rec: Record<string, unknown>, index = 0): ExchangeChange => {
  const c = decodeExchangeRecord(rec, index);
  if (!c) throw new Error("not decoded");
  return c;
};

describe("inbox rules — admin cmdlets", () => {
  it("New-InboxRule forwarding outside the mailbox's domain and deleting is High with both actions and the class", () => {
    const c = one(
      admin("New-InboxRule", {
        Name: "..",
        ForwardTo: "drop@attacker.invalid",
        DeleteMessage: "True",
        SubjectContainsWords: "invoice;payment;wire;urgent",
      }),
    );
    expect(c.kind).toBe("rule");
    expect(c.posture).toBe('creates inbox rule ".."');
    expect(c.words).toContain("forwards to drop@attacker.invalid (outside the mailbox's domain)");
    expect(c.words).toContain("deletes the message");
    expect(c.words).toContain("when subject contains invoice, payment, wire (+1 more)");
    expect(c.severity).toBe("High");
    expect(c.mitre).toEqual(expect.arrayContaining(["T1114.003", "T1564.008"]));
    expect(c.attempted).toBe(false);
  });
  it("forwarding inside the domain, or hiding without forwarding, is Medium; other actions only are Low", () => {
    expect(one(admin("New-InboxRule", { Name: "r", RedirectTo: "bob@example.invalid" })).severity).toBe(
      "Medium",
    );
    const hide = one(admin("New-InboxRule", { Name: "r", MoveToFolder: "RSS Feeds", MarkAsRead: "True" }));
    expect(hide.severity).toBe("Medium");
    expect(hide.words).toContain('moves to "RSS Feeds"');
    expect(hide.words).toContain("marks as read");
    expect(hide.mitre).toEqual(["T1564.008"]);
    const other = one(admin("New-InboxRule", { Name: "r", ApplyCategory: "Blue" }));
    expect(other.severity).toBe("Low");
    expect(other.mitre).toEqual([]);
  });
  it("'on every message' only for a successful New-InboxRule with no condition parameter", () => {
    expect(one(admin("New-InboxRule", { Name: "r", ForwardTo: "x@attacker.invalid" })).words).toContain(
      "on every message",
    );
    expect(
      one(
        admin("New-InboxRule", { Name: "r", ForwardTo: "x@attacker.invalid", From: "boss@example.invalid" }),
      ).words,
    ).not.toContain("on every message");
  });
  it("Set-InboxRule reports only the supplied deltas and never an effective state", () => {
    const rename = one(admin("Set-InboxRule", { Identity: "r", Name: "quiet" }));
    expect(rename.posture).toBe('changes inbox rule "r"');
    expect(rename.words).toContain('renamed to "quiet"');
    expect(rename.words).not.toContain("on every message");
    expect(rename.qualifiers).toContain("effective conditions and actions not in this record");
    expect(rename.severity).toBe("Medium");
    const fwd = one(admin("Set-InboxRule", { Identity: "r", ForwardTo: "x@attacker.invalid" }));
    expect(fwd.words).toContain("now forwards to x@attacker.invalid (outside the mailbox's domain)");
    expect(fwd.severity).toBe("High");
    const enable = one(admin("Set-InboxRule", { Identity: "r", Enabled: "True" }));
    expect(enable.words).toContain("now enabled");
  });
  it("a failed New-InboxRule is an attempt: no completed verb, Medium, no technique, its own key", () => {
    const ok = one(admin("New-InboxRule", { Name: "r", ForwardTo: "x@attacker.invalid" }));
    const failed = one(
      admin("New-InboxRule", { Name: "r", ForwardTo: "x@attacker.invalid" }, { ResultStatus: "False" }),
    );
    expect(failed.attempted).toBe(true);
    expect(failed.posture).toBe('attempted to create inbox rule "r"');
    expect(failed.severity).toBe("Medium");
    expect(failed.mitre).toEqual([]);
    expect(failed.key).not.toBe(ok.key);
    const unknown = one(admin("New-InboxRule", { Name: "r" }, { ResultStatus: "" }));
    expect(unknown.attempted).toBe(true);
    expect(unknown.outcome).toBe("unknown");
  });
  it("Disable/Remove are posture only, Low, no persistence words, the name kept", () => {
    const rm = one(admin("Remove-InboxRule", { Identity: "quiet" }));
    expect(rm.posture).toBe('removes inbox rule "quiet"');
    expect(rm.severity).toBe("Low");
    expect(rm.mitre).toEqual([]);
    expect(rm.words).toBe("");
    expect(one(admin("Disable-InboxRule", { Identity: "quiet" })).posture).toBe(
      'disables inbox rule "quiet"',
    );
  });
  it("a forwarding target that is not an SMTP address gets no domain class", () => {
    const c = one(admin("New-InboxRule", { Name: "r", ForwardTo: "Bob Smith" }));
    expect(c.words).toContain("forwards to Bob Smith");
    expect(c.words).not.toContain("domain");
    expect(c.severity).toBe("Medium");
  });
});

describe("inbox rules — the mailbox-audit UpdateInboxRules form (RecordType 2)", () => {
  it("reads RuleOperation, RuleName, RuleCondition and the JSON RuleActions, naming a forwarding recipient", () => {
    const c = one(
      base({
        RecordType: 2,
        Operation: "UpdateInboxRules",
        LogonType: 0,
        MailboxOwnerUPN: OWNER,
        UserId: OWNER,
        ClientInfoString: "Client=OWA;Action=ViaProxy",
        OperationProperties: [
          { Name: "RuleOperation", Value: "AddMailboxRule" },
          { Name: "RuleName", Value: "." },
          { Name: "RuleCondition", Value: "SubjectContains: invoice" },
          {
            Name: "RuleActions",
            Value: JSON.stringify([
              { ActionType: "ForwardToRecipients", Recipients: ["drop@attacker.invalid"] },
              { ActionType: "Delete" },
            ]),
          },
        ],
      }),
    );
    expect(c.kind).toBe("rule");
    expect(c.posture).toBe('creates inbox rule "."');
    expect(c.words).toContain("forwards to drop@attacker.invalid (outside the mailbox's domain)");
    expect(c.words).toContain("deletes the message");
    expect(c.words).toContain("when SubjectContains: invoice");
    expect(c.severity).toBe("High");
  });
  it("an unparsable RuleActions value is shown bounded, never dropped", () => {
    const c = one(
      base({
        RecordType: 2,
        Operation: "UpdateInboxRules",
        MailboxOwnerUPN: OWNER,
        OperationProperties: [
          { Name: "RuleOperation", Value: "ModifyMailboxRule" },
          { Name: "RuleName", Value: "x" },
          { Name: "RuleActions", Value: "{not json" },
        ],
      }),
    );
    expect(c.posture).toBe('changes inbox rule "x"');
    expect(c.words).toContain("actions: {not json");
    expect(c.severity).toBe("Medium");
  });
});

describe("mailbox forwarding and permissions", () => {
  it("Set-Mailbox ForwardingSmtpAddress outside the domain is High; a copy claim needs DeliverToMailboxAndForward", () => {
    const c = one(
      admin("Set-Mailbox", {
        Identity: OWNER,
        ForwardingSmtpAddress: "smtp:drop@attacker.invalid",
        DeliverToMailboxAndForward: "False",
      }),
    );
    expect(c.kind).toBe("forwarding");
    expect(c.posture).toBe("sets SMTP forwarding to drop@attacker.invalid (outside the mailbox's domain)");
    expect(c.words).toContain("no copy stays in the mailbox");
    expect(c.severity).toBe("High");
    expect(c.mitre).toEqual(["T1114.003"]);
    const noCopyClaim = one(
      admin("Set-Mailbox", { Identity: OWNER, ForwardingSmtpAddress: "smtp:drop@attacker.invalid" }),
    );
    expect(noCopyClaim.words).not.toMatch(/copy/);
    expect(noCopyClaim.qualifiers).toContain("effective forwarding state not in this record");
  });
  it("ForwardingAddress is an in-organization recipient with no domain class; both set → precedence stated", () => {
    const c = one(admin("Set-Mailbox", { Identity: OWNER, ForwardingAddress: "CN=Shared,OU=x" }));
    expect(c.posture).toBe("sets forwarding to in-organization recipient CN=Shared,OU=x");
    expect(c.posture).not.toContain("domain");
    expect(c.severity).toBe("Medium");
    const both = one(
      admin("Set-Mailbox", {
        Identity: OWNER,
        ForwardingAddress: "shared",
        ForwardingSmtpAddress: "smtp:x@attacker.invalid",
      }),
    );
    expect(both.words).toContain("ForwardingAddress takes precedence");
  });
  it("clearing one address clears that one only, Low", () => {
    const c = one(admin("Set-Mailbox", { Identity: OWNER, ForwardingSmtpAddress: "" }));
    expect(c.posture).toBe("clears SMTP forwarding");
    expect(c.severity).toBe("Low");
    expect(c.words).not.toContain("in-organization");
  });
  it("Add-MailboxPermission names User and AccessRights; Add-RecipientPermission names Trustee", () => {
    const m = one(
      admin("Add-MailboxPermission", {
        Identity: OWNER,
        User: "helper@attacker.invalid",
        AccessRights: "FullAccess",
      }),
    );
    expect(m.posture).toBe(
      "grants FullAccess on alice@example.invalid to helper@attacker.invalid (outside the mailbox's domain)",
    );
    expect(m.severity).toBe("Medium");
    expect(m.mitre).toEqual(["T1098.002"]);
    const r = one(
      admin("Add-RecipientPermission", {
        Identity: OWNER,
        Trustee: "bob@example.invalid",
        AccessRights: "SendAs",
      }),
    );
    expect(r.posture).toContain(
      "grants SendAs on alice@example.invalid to bob@example.invalid (inside the mailbox's domain)",
    );
    expect(
      one(
        admin("Remove-MailboxPermission", {
          Identity: OWNER,
          User: "helper@attacker.invalid",
          AccessRights: "FullAccess",
        }),
      ).severity,
    ).toBe("Low");
  });
});

const access = (over: Record<string, unknown>) =>
  base({
    RecordType: 50,
    Operation: "MailItemsAccessed",
    ResultStatus: "Succeeded",
    LogonType: 2,
    MailboxOwnerUPN: OWNER,
    MailboxGuid: "aaaaaaaa-0000-0000-0000-000000000001",
    ClientInfoString: "Client=REST;;",
    ClientIPAddress: "203.0.113.9",
    SessionId: "sess-1111-2222",
    OperationCount: 7,
    OperationProperties: [
      { Name: "MailAccessType", Value: "Bind" },
      { Name: "IsThrottled", Value: "False" },
    ],
    Folders: [
      {
        Id: "f1",
        Path: "\\Inbox",
        FolderItems: [
          { InternetMessageId: "<m1@x>" },
          { InternetMessageId: "<m2@x>" },
          { InternetMessageId: "<m3@x>" },
        ],
      },
      {
        Id: "f2",
        Path: "\\Sent Items",
        FolderItems: [{ InternetMessageId: "<m4@x>" }, { InternetMessageId: "<m5@x>" }],
      },
    ],
    ...over,
  });

describe("MailItemsAccessed (RecordType 50)", () => {
  it("a delegate Bind counts the items listed, never OperationCount; Low; the qualifier; no technique", () => {
    const c = one(access({}));
    expect(c.kind).toBe("access");
    expect(c.posture).toBe("binds 5 items in 2 folders (7 operations)");
    expect(c.object).toBe("on alice@example.invalid as delegate via REST session sess-1111-2222");
    expect(c.qualifiers).toContain("item access; whether a person read the content is not established");
    expect(c.severity).toBe("Low");
    expect(c.mitre).toEqual([]);
  });
  it("LogonType 1 (Admin) is Medium; the owner's own access is Info", () => {
    expect(one(access({ LogonType: 1 })).severity).toBe("Medium");
    expect(one(access({ LogonType: 1 })).object).toContain("as admin");
    expect(one(access({ LogonType: 0, UserId: OWNER })).severity).toBe("Info");
    expect(one(access({ LogonType: 7 })).object).toContain("as logon type 7");
  });
  it("Sync is folder scope with the offline qualifier; throttled says what the gap can mean", () => {
    const s = one(
      access({
        OperationProperties: [{ Name: "MailAccessType", Value: "Sync" }],
        Folders: [{ Id: "f1", Path: "\\Inbox" }],
      }),
    );
    expect(s.posture).toBe('syncs folder "\\Inbox"');
    expect(s.qualifiers).toContain("possible offline copy after sync");
    const t = one(
      access({
        OperationProperties: [
          { Name: "MailAccessType", Value: "Bind" },
          { Name: "IsThrottled", Value: "True" },
        ],
      }),
    );
    expect(t.qualifiers.join(" ")).toContain("throttled — the item list is incomplete");
    expect(t.qualifiers.join(" ")).toContain("depends on the service behaviour at the time of the event");
  });
  it("a RecordType 19 aggregate says operations, never items", () => {
    const c = one(
      base({
        RecordType: 19,
        Operation: "MailItemsAccessed",
        MailboxOwnerUPN: OWNER,
        LogonType: 2,
        OperationCount: 40,
        AggregateDurationInSeconds: 3600,
      }),
    );
    expect(c.kind).toBe("aggregate");
    expect(c.posture).toBe("40 operations over 3600 s, items not listed");
    expect(c.posture).not.toContain("40 items");
  });
  it("AppId/ClientAppId is client context, not the actor, unless UserType says the actor is an application", () => {
    const u = one(access({ ClientAppId: "app-9", AppId: "app-9" }));
    expect(u.actorIsApp).toBe(false);
    expect(u.object).toContain("client app app-9");
    const a = one(access({ UserType: 6, UserId: "app-9", ClientAppId: "app-9" }));
    expect(a.actorIsApp).toBe(true);
  });
  it("ClientInfoString is parsed for OWA, REST, RPC and IMAP4", () => {
    expect(one(access({ ClientInfoString: "Client=OWA;Action=ViaProxy" })).object).toContain("via OWA");
    expect(one(access({ ClientInfoString: "Client=MSExchangeRPC" })).object).toContain("via MSExchangeRPC");
    expect(one(access({ ClientInfoString: "Client=POP3/IMAP4;Protocol=IMAP4" })).object).toContain(
      "via POP3/IMAP4 (IMAP4)",
    );
    expect(one(access({ ClientInfoString: "Client=WebServices;ExchangeWebServices/1.0" })).object).toContain(
      "via WebServices",
    );
  });
  it("keys: two mailboxes, owner sync vs delegate bind, two addresses, and two id-less binds are distinct; one session one mailbox one access type folds", () => {
    const k = (over: Record<string, unknown>, i = 0) => one(access(over), i).key;
    expect(k({})).not.toBe(
      k({ MailboxOwnerUPN: "carol@example.invalid", MailboxGuid: "bbbbbbbb-0000-0000-0000-000000000002" }),
    );
    expect(k({})).not.toBe(
      k({ LogonType: 0, UserId: OWNER, OperationProperties: [{ Name: "MailAccessType", Value: "Sync" }] }),
    );
    expect(k({})).not.toBe(k({ ClientIPAddress: "203.0.113.10" }));
    expect(k({})).toBe(k({}));
    const noIds = (id: string, i: number) =>
      k({ Id: id, Folders: [{ Path: "\\Inbox", FolderItems: [{ SizeInBytes: 10 }] }] }, i);
    expect(noIds("r1", 1)).not.toBe(noIds("r2", 2));
    const im = (x: string) =>
      k({ Folders: [{ Id: "f1", Path: "\\Inbox", FolderItems: [{ ImmutableId: x }] }] });
    expect(im("A")).not.toBe(im("B"));
    const agg = (n: number) =>
      one(
        base({
          Id: `a${n}`,
          RecordType: 19,
          Operation: "MailItemsAccessed",
          MailboxOwnerUPN: OWNER,
          OperationCount: n,
        }),
      ).key;
    expect(agg(40)).not.toBe(agg(41));
  });
});

describe("item operations (RecordType 2 and 3)", () => {
  it("SendAs by a non-owner is Low with a bounded subject and no technique", () => {
    const c = one(
      base({
        RecordType: 2,
        Operation: "SendAs",
        LogonType: 2,
        MailboxOwnerUPN: OWNER,
        Item: { Id: "i1", Subject: "S".repeat(100), InternetMessageId: "<s1@x>" },
      }),
    );
    expect(c.kind).toBe("item");
    expect(c.posture).toBe("sends as alice@example.invalid");
    expect(c.words).toMatch(/^subject "S{60}…"$/);
    expect(c.severity).toBe("Low");
    expect(c.mitre).toEqual([]);
  });
  it("a RecordType 2 delete narrates its one Item; a RecordType 3 delete counts AffectedItems", () => {
    const single = one(
      base({
        RecordType: 2,
        Operation: "HardDelete",
        LogonType: 0,
        UserId: OWNER,
        MailboxOwnerUPN: OWNER,
        Item: { Id: "i1", ParentFolder: { Path: "\\Inbox" } },
      }),
    );
    expect(single.posture).toBe('hard-deletes 1 item from "\\Inbox"');
    const group = one(
      base({
        RecordType: 3,
        Operation: "HardDelete",
        LogonType: 2,
        MailboxOwnerUPN: OWNER,
        Folder: { Path: "\\Deleted Items" },
        AffectedItems: [{ Id: "a" }, { Id: "b" }, { Id: "c" }],
      }),
    );
    expect(group.posture).toBe('hard-deletes 3 items from "\\Deleted Items"');
    expect(
      one(
        base({
          RecordType: 2,
          Operation: "Send",
          LogonType: 0,
          UserId: OWNER,
          MailboxOwnerUPN: OWNER,
          Item: { Id: "i1" },
        }),
      ).severity,
    ).toBe("Info");
  });
  it("an operation the decoder does not narrate yields null", () => {
    expect(
      decodeExchangeRecord(base({ RecordType: 1, Operation: "Get-Mailbox", Parameters: [] }), 0),
    ).toBeNull();
    expect(
      decodeExchangeRecord(base({ Workload: "SharePoint", RecordType: 4, Operation: "FileAccessed" }), 0),
    ).toBeNull();
  });
});
