// #931 item 2, chain half (#975): the mailbox-compromise chain built over one m365 export —
// sign-in → access → rule/forwarding → send/delete, joined by session (or by actor + address,
// said), with every claim backed by the records it cites and nothing the records do not say.
import { describe, expect, it } from "vitest";
import { parseM365Audit } from "../../src/analysis/m365Import.js";
import {
  mailboxChains,
  MAILBOX_CHAIN_WINDOW_HOURS,
  MAILBOX_CHAINS_MAX,
  STEPS_PER_STAGE_MAX,
} from "../../src/analysis/mailboxChain.js";
import { readUalLogon, readEntraSignIn } from "../../src/analysis/ualLogon.js";
import { canonicalEventEnvelopeSchema } from "../../src/analysis/canonicalEvent.js";
import { correlateEvents } from "../../src/analysis/correlate.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

const OWNER = "alice@example.invalid";
const GUID = "aaaaaaaa-0000-0000-0000-000000000001";
const ACTOR = "helpdesk@example.invalid";
const TENANT = "6f1b7a5e-5555-4eee-8fff-000000000006";
const IP = "203.0.113.9";
const SESSION = "3f2a1b0c-1111-2222-3333-444444444444";
const T = "2024-05-01T10:00:00Z";
const at = (s: number) => new Date(Date.parse(T) + s * 1000).toISOString();
let n = 0;
const base = (over: Record<string, unknown>) => ({
  Id: `rec-${++n}`,
  CreationTime: T,
  Workload: "Exchange",
  OrganizationId: TENANT,
  UserType: 0,
  UserId: ACTOR,
  ResultStatus: "Succeeded",
  ClientIPAddress: IP,
  ...over,
});
const logon = (over: Record<string, unknown> = {}) => ({
  Id: `rec-${++n}`,
  CreationTime: T,
  Workload: "AzureActiveDirectory",
  RecordType: 15,
  Operation: "UserLoggedIn",
  OrganizationId: TENANT,
  UserId: ACTOR,
  ClientIP: IP,
  ResultStatus: "Succeeded",
  ExtendedProperties: [
    { Name: "UserAgent", Value: "Mozilla/5.0 (Windows NT 10.0) Chrome/120" },
    { Name: "RequestType", Value: "OAuth2:Authorize" },
  ],
  DeviceProperties: [
    { Name: "OS", Value: "Windows" },
    { Name: "SessionId", Value: SESSION },
  ],
  ...over,
});
const access = (over: Record<string, unknown> = {}) =>
  base({
    RecordType: 50,
    Operation: "MailItemsAccessed",
    CreationTime: at(180),
    LogonType: 2,
    MailboxOwnerUPN: OWNER,
    MailboxGuid: GUID,
    ClientInfoString: "Client=REST;;",
    SessionId: SESSION,
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
const rule = (over: Record<string, unknown> = {}, actions?: unknown[]) =>
  base({
    RecordType: 2,
    Operation: "UpdateInboxRules",
    CreationTime: at(300),
    LogonType: 2,
    MailboxOwnerUPN: OWNER,
    MailboxGuid: GUID,
    SessionId: SESSION,
    ClientInfoString: "Client=OWA;Action=ViaProxy",
    OperationProperties: [
      { Name: "RuleOperation", Value: "AddMailboxRule" },
      { Name: "RuleName", Value: "." },
      {
        Name: "RuleActions",
        Value: JSON.stringify(
          actions ?? [
            { ActionType: "ForwardToRecipients", Recipients: ["drop@attacker.invalid"] },
            { ActionType: "Delete" },
          ],
        ),
      },
    ],
    ...over,
  });
const cmdletRule = (over: Record<string, unknown> = {}, params: Record<string, string> = {}) =>
  base({
    RecordType: 1,
    Operation: "New-InboxRule",
    CreationTime: at(300),
    ObjectId: OWNER,
    ClientIP: IP,
    ClientIPAddress: undefined,
    Parameters: Object.entries({
      Name: "..",
      ForwardTo: "drop@attacker.invalid",
      DeleteMessage: "True",
      ...params,
    }).map(([Name, Value]) => ({ Name, Value })),
    ...over,
  });
const send = (over: Record<string, unknown> = {}) =>
  base({
    RecordType: 2,
    Operation: "SendAs",
    CreationTime: at(480),
    LogonType: 2,
    MailboxOwnerUPN: OWNER,
    MailboxGuid: GUID,
    SessionId: SESSION,
    SendAsUserSmtp: OWNER,
    Item: { Id: "i1", Subject: "Re: wire" },
    recipientList: [{ Address: "cfo@example.invalid" }],
    recipientCount: 1,
    ...over,
  });
const hardDelete = (over: Record<string, unknown> = {}) =>
  base({
    RecordType: 2,
    Operation: "HardDelete",
    CreationTime: at(540),
    LogonType: 2,
    MailboxOwnerUPN: OWNER,
    MailboxGuid: GUID,
    SessionId: SESSION,
    AffectedItems: [{ Id: "d1" }, { Id: "d2" }, { Id: "d3" }, { Id: "d4" }],
    ...over,
  });
const signIn = (over: Record<string, unknown> = {}) => ({
  id: `si-${++n}`,
  createdDateTime: at(-60),
  userPrincipalName: ACTOR,
  appDisplayName: "OfficeHome",
  ipAddress: IP,
  clientAppUsed: "Browser",
  isInteractive: true,
  riskState: "atRisk",
  riskLevelDuringSignIn: "medium",
  resourceTenantId: TENANT,
  status: { errorCode: 0 },
  ...over,
});
const chains = (records: Record<string, unknown>[]) => mailboxChains(records);
const importChains = (records: Record<string, unknown>[], opts: Record<string, unknown> = {}) =>
  parseM365Audit(JSON.stringify(records), { aggregate: false, ...opts }).events.filter((e) =>
    e.description.startsWith("Mailbox chain:"),
  );

describe("the full chain by session", () => {
  it("sign-in → access → configured rule → send: High, every step named with its time, actor, address and record; join: session", () => {
    const rows = chains([logon(), access(), rule(), send(), hardDelete()]);
    expect(rows).toHaveLength(1);
    const r = rows[0];
    expect(r.severity).toBe("High");
    expect(r.description).toContain(`Mailbox chain: ${OWNER} (join: session 3f2a1b0c-1111-2…)`);
    expect(r.description).toContain(
      `${T.replace("Z", ".000Z")} signed in from ${IP} (Mozilla/5.0 (Windows NT 10.0) Chrome/120) OAuth2:Authorize`,
    );
    expect(r.description).toContain(
      "accessed: binds 5 items in 2 folders (7 operations) as delegate via REST",
    );
    expect(r.description).toContain(
      'configured: creates inbox rule "." forwards to drop@attacker.invalid (outside the mailbox\'s domain), deletes the message',
    );
    expect(r.description).toContain("delivery through the forwarding is not in this evidence");
    expect(r.description).toContain("sends as alice@example.invalid to cfo@example.invalid");
    expect(r.description).toContain("hard-deletes 4 items");
    expect(r.description).toContain("items listed: 10 across the joined records");
    expect(r.description).toContain("four stages in order]");
    expect(r.description).not.toMatch(/forwarded|\bread\b|suspicious|compromised|attacker\b(?!\.invalid)/);
    expect(r.mitre).toEqual(expect.arrayContaining(["T1114.003", "T1564.008"]));
    expect(canonicalEventEnvelopeSchema.safeParse(r.canonical).success).toBe(true);
    expect(r.canonical?.mailboxChain).toMatchObject({
      mailbox: GUID,
      mailboxIdKind: "guid",
      tenant: TENANT.toLowerCase(),
      join: { kind: "session", key: SESSION },
      windowHours: MAILBOX_CHAIN_WINDOW_HOURS,
      stages: 4,
      itemsListed: 10,
      operationsUnlisted: 0,
    });
    expect(r.canonical?.mailboxChain?.steps.map((s) => s.stage)).toEqual([
      "sign-in",
      "access",
      "persistence",
      "consequence",
    ]);
    expect(r.canonical?.evidence.rawRecords.map((x) => x.locator)).toEqual([
      "record:0",
      "record:1",
      "record:2",
      "record:3",
    ]);
  });

  it("two sessions on one mailbox are two chains; the same session on two mailboxes is two chains", () => {
    const S2 = "9e8d7c6b-1111-2222-3333-444444444444";
    const two = chains([
      logon(),
      access(),
      rule(),
      logon({ CreationTime: at(3600), DeviceProperties: [{ Name: "SessionId", Value: S2 }] }),
      access({ CreationTime: at(3700), SessionId: S2 }),
      hardDelete({ CreationTime: at(3800), SessionId: S2 }),
    ]);
    expect(two).toHaveLength(2);
    expect(two.map((r) => r.canonical?.mailboxChain?.join.key).sort()).toEqual([SESSION, S2].sort());
    expect(new Set(two.map((r) => r.aggKey)).size).toBe(2);
    const OTHER = "bbbbbbbb-0000-0000-0000-000000000002";
    const mailboxes = chains([
      logon(),
      access(),
      rule(),
      access({ MailboxOwnerUPN: "carol@example.invalid", MailboxGuid: OTHER }),
      hardDelete({ MailboxOwnerUPN: "carol@example.invalid", MailboxGuid: OTHER }),
    ]);
    expect(mailboxes).toHaveLength(2);
    expect(mailboxes.map((r) => r.canonical?.mailboxChain?.mailbox).sort()).toEqual([GUID, OTHER]);
  });
});

describe("the join is said, never assumed", () => {
  it("a cmdlet rule carries no session: it joins the ONE session sharing its actor and address, and the row says so", () => {
    const rows = chains([logon(), access(), cmdletRule(), send()]);
    expect(rows).toHaveLength(1);
    expect(rows[0].description).toContain("join: session");
    expect(rows[0].description).toContain(
      'configured: creates inbox rule ".." forwards to drop@attacker.invalid (outside the mailbox\'s domain), deletes the message on every message — delivery through the forwarding is not in this evidence (joined by actor + address, not by session)',
    );
    expect(rows[0].canonical?.mailboxChain?.steps.find((s) => s.stage === "persistence")?.joinedBy).toBe(
      "actor-address",
    );
  });

  it("two sessions of the same actor and address inside the window: the sessionless rule joins neither and is counted", () => {
    const S2 = "9e8d7c6b-1111-2222-3333-444444444444";
    const rows = chains([
      logon(),
      access(),
      logon({ CreationTime: at(3600), DeviceProperties: [{ Name: "SessionId", Value: S2 }] }),
      access({ CreationTime: at(3700), SessionId: S2 }),
      cmdletRule({ CreationTime: at(3900) }),
    ]);
    expect(rows).toHaveLength(2);
    for (const r of rows) {
      expect(r.severity).toBe("Low");
      expect(r.description).not.toContain("configured:");
      expect(r.description).toContain(
        "1 record by this actor from this address inside the window matches two or more sessions — not joined",
      );
      expect(r.canonical?.mailboxChain?.ambiguous).toBe(1);
    }
  });

  it("sessionless records alone form an actor + address chain with the window stated; a record sharing neither actor nor address is not joined", () => {
    const rows = chains([
      logon({ DeviceProperties: [] }),
      cmdletRule(),
      cmdletRule({ CreationTime: at(400), UserId: "other@example.invalid", ClientIP: "198.51.100.1" }),
    ]);
    expect(rows).toHaveLength(1);
    expect(rows[0].description).toContain(`join: actor + address, ${MAILBOX_CHAIN_WINDOW_HOURS}-hour window`);
    expect(rows[0].description).toContain("two of four stages");
    expect(rows[0].canonical?.mailboxChain?.join.kind).toBe("actor-address");
    expect(rows[0].description).not.toContain("other@example.invalid");
  });

  it("a cmdlet naming the mailbox by an alias joins nothing and is counted; a UPN joins; a GUID learned beside a UPN resolves it", () => {
    const rows = chains([logon(), access(), cmdletRule({ ObjectId: "alice\\.." }), send()]);
    expect(rows[0].description).not.toContain("configured:");
    expect(rows[0].description).toContain(
      "1 change names a mailbox by an alias or name no record of this export links — not joined",
    );
    const byUpn = chains([logon(), access({ MailboxGuid: undefined }), cmdletRule()]);
    expect(byUpn[0].canonical?.mailboxChain).toMatchObject({ mailbox: `upn:${OWNER}`, mailboxIdKind: "upn" });
    expect(byUpn[0].description).toContain("configured:");
    const learned = chains([logon(), access(), cmdletRule()]);
    expect(learned[0].canonical?.mailboxChain?.mailbox).toBe(GUID);
    expect(learned[0].canonical?.mailboxChain?.steps).toHaveLength(3);
  });
});

describe("what is never claimed", () => {
  it("a failed rule, a dry run, a removal and a partial success are listed as non-steps, never counted", () => {
    const failed = chains([logon(), access(), rule({ ResultStatus: "Failed" })]);
    expect(failed[0].severity).toBe("Low");
    expect(failed[0].description).toContain("attempt: attempted to create inbox rule");
    expect(failed[0].description).toContain(
      "no rule, forwarding or permission change for this mailbox among the 2 supplied Exchange mailbox-audit records",
    );
    const dry = chains([logon(), access(), cmdletRule({}, { WhatIf: "True" })]);
    expect(dry[0].description).toContain("simulation: simulates creating inbox rule");
    expect(dry[0].description).not.toContain("configured:");
    const removed = chains([
      logon(),
      access(),
      base({
        RecordType: 1,
        Operation: "Remove-InboxRule",
        CreationTime: at(300),
        ObjectId: OWNER,
        ClientIP: IP,
        Parameters: [{ Name: "Identity", Value: ".." }],
      }),
    ]);
    expect(removed[0].description).toContain("reversal: removes inbox rule");
    expect(removed[0].description).not.toContain("configured:");
    const partial = chains([logon(), access(), rule({ ResultStatus: "PartiallySucceeded" })]);
    expect(partial[0].description).toContain("attempt:");
    expect(partial[0].description).not.toContain("configured:");
  });

  it("a UAL logon is a sign-in only when every outcome field says so; UserLoginFailed never is", () => {
    const bad = chains([
      logon({ ErrorNumber: "50133", LogonError: "FaultDomainRedirect" }),
      access(),
      rule(),
    ]);
    expect(bad[0].description).toContain("logon record — outcome not established (ErrorNumber 50133)");
    expect(bad[0].description).toContain(
      "no established logon record for this actor among the 1 supplied UAL logon records",
    );
    expect(bad[0].description).toContain("two of four stages");
    const failedOp = chains([logon({ Operation: "UserLoginFailed" }), access(), rule()]);
    expect(failedOp[0].description).toContain("two of four stages");
    expect(readUalLogon(logon()).established).toBe(true);
    expect(readUalLogon(logon({ ResultStatus: "Failed" })).established).toBe(false);
    expect(readUalLogon(logon({ ErrorCode: 0 })).established).toBe(true);
  });

  it("forwarding is configured, never forwarded; Set-Mailbox forwarding outside the domain is High; clearing it is a reversal", () => {
    const fwd = base({
      RecordType: 1,
      Operation: "Set-Mailbox",
      CreationTime: at(300),
      ObjectId: OWNER,
      ClientIP: IP,
      Parameters: [
        { Name: "Identity", Value: OWNER },
        { Name: "ForwardingSmtpAddress", Value: "smtp:drop@attacker.invalid" },
        { Name: "DeliverToMailboxAndForward", Value: "False" },
      ],
    });
    const rows = chains([logon(), access(), fwd]);
    expect(rows[0].severity).toBe("High");
    expect(rows[0].description).toContain("configured: sets SMTP forwarding to");
    expect(rows[0].description).toContain("delivery through the forwarding is not in this evidence");
    expect(rows[0].description).not.toMatch(/forwarded/);
    const cleared = chains([
      logon(),
      access(),
      {
        ...fwd,
        Parameters: [
          { Name: "Identity", Value: OWNER },
          { Name: "ForwardingSmtpAddress", Value: "$null" },
        ],
      },
    ]);
    expect(cleared[0].description).toContain("reversal: clears SMTP forwarding");
    expect(cleared[0].severity).toBe("Low");
  });

  it("absence rests on the supplied records and never claims coverage; no records of a kind → 'not in this export'", () => {
    const rows = chains([logon(), access()]);
    expect(rows[0].description).toContain(
      "no rule, forwarding or permission change for this mailbox among the 1 supplied Exchange mailbox-audit records (earliest 2024-05-01, latest 2024-05-01)",
    );
    expect(rows[0].description).toContain("no send, move or deletion for this mailbox among the 1 supplied");
    expect(rows[0].description).toContain(
      "continuous coverage of the window is not established by this export; licence, audit configuration and retention are not in this evidence",
    );
    expect(rows[0].description).not.toContain("inside the window among");
    const noLogon = chains([access(), rule()]);
    expect(noLogon[0].description).toContain("UAL logon log not in this export");
    expect(noLogon[0].canonical?.mailboxChain?.coverage.logons).toBeUndefined();
    expect(noLogon[0].canonical?.mailboxChain?.coverage.mailboxAudit).toMatchObject({ records: 2 });
  });

  it("counts are the items the records list; an aggregated record contributes operations, items not listed", () => {
    const aggregate = base({
      RecordType: 19,
      Operation: "MailItemsAccessed",
      CreationTime: at(200),
      LogonType: 2,
      MailboxOwnerUPN: OWNER,
      MailboxGuid: GUID,
      SessionId: SESSION,
      OperationCount: 40,
      AggregateDurationInSeconds: "3600",
    });
    const rows = chains([logon(), access(), aggregate, rule()]);
    expect(rows[0].description).toContain(
      "items listed: 5 across the joined records; 40 operations in aggregated records, items not listed",
    );
    expect(rows[0].canonical?.mailboxChain).toMatchObject({ itemsListed: 5, operationsUnlisted: 40 });
  });

  it("a folder sync says 'possible offline copy — inferred'; a delegate access is never 'read'", () => {
    const sync = access({
      OperationProperties: [{ Name: "MailAccessType", Value: "Sync" }],
      Folders: [{ Id: "f1", Path: "\\Inbox" }],
    });
    const rows = chains([logon(), sync, rule()]);
    expect(rows[0].description).toContain(
      "possible offline copy after a folder sync — inferred, not observed",
    );
    expect(rows[0].description).not.toMatch(/\bread\b/);
  });
});

describe("risk, order, grading", () => {
  it("a contemporaneous interactive sign-in of the same user, address and tenant carries its risk verdict, said as contemporaneous", () => {
    const rows = chains([signIn(), logon(), access(), rule()]);
    expect(rows[0].description).toContain(
      "a contemporaneous sign-in in the sign-in log (1 min apart) carries risk: atRisk, medium — not established as the same sign-in",
    );
    // Another tenant, a non-interactive sign-in, another address, or outside ±10 minutes: no verdict.
    for (const over of [
      { resourceTenantId: "00000000-0000-0000-0000-00000000dead" },
      { isInteractive: false },
      { ipAddress: "198.51.100.1" },
      { createdDateTime: at(-1200) },
    ]) {
      expect(chains([signIn(over), logon(), access(), rule()])[0].description).not.toContain("carries risk");
    }
    expect(readEntraSignIn(signIn()).interactive).toBe(true);
    expect(readEntraSignIn(signIn({ isInteractive: "false" })).interactive).toBe(false);
  });

  it("stages count only in order: a rule before the access is listed as out of order, not counted", () => {
    const rows = chains([logon(), rule({ CreationTime: at(60) }), access({ CreationTime: at(180) }), send()]);
    expect(rows[0].description).toContain("before the stage it would follow, not counted:");
    expect(rows[0].description).toContain("three of four stages");
    expect(rows[0].canonical?.mailboxChain?.steps.map((s) => s.stage)).toEqual([
      "sign-in",
      "access",
      "consequence",
    ]);
  });

  it("grading only raises: an owner's own routine (all Info) is no row; a delegate access + logon is Low; three stages with an outside rule is High, with an inside rule Medium", () => {
    expect(
      chains([
        logon({ UserId: OWNER }),
        access({ UserId: OWNER, LogonType: 0 }),
        send({ UserId: OWNER, LogonType: 0 }),
      ]),
    ).toHaveLength(0);
    expect(chains([logon(), access()])[0].severity).toBe("Low");
    expect(chains([logon(), access(), rule()])[0].severity).toBe("High");
    const inside = chains([
      logon(),
      access(),
      rule({}, [{ ActionType: "ForwardToRecipients", Recipients: ["bob@example.invalid"] }]),
    ]);
    expect(inside[0].severity).toBe("Medium");
    expect(chains([logon(), access(), send()])[0].severity).toBe("Medium");
    expect(chains([access()])).toHaveLength(0);
  });
});

describe("identity, bounds, the importer", () => {
  it("the row's identity is (tenant, mailbox, join); a re-import folds at merge; the importer appends after the cap and counts source rows alone", () => {
    const records = [logon(), access(), rule(), send()];
    const a = importChains(records);
    const b = importChains(records);
    expect(a).toHaveLength(1);
    expect(a[0].aggKey).toBe(b[0].aggKey);
    expect(a[0].aggKey).toMatch(/^mailbox-chain\|[0-9a-f]{32}$/);
    const asEvents = (tag: string): ForensicEvent[] =>
      importChains(records).map((e, i) => ({
        ...e,
        id: `${tag}-${i}`,
        relatedFindingIds: [],
        sourceScreenshots: [],
        sources: ["Microsoft 365"],
      }));
    expect(correlateEvents([...asEvents("a"), ...asEvents("b")])).toHaveLength(1);
    const r = parseM365Audit(JSON.stringify(records), { aggregate: false, maxEvents: 1 });
    const summaries = r.events.filter((e) => e.description.startsWith("Mailbox chain:"));
    expect(summaries).toHaveLength(1);
    expect(r.kept).toBe(1);
    expect(r.dropped).toBe(3);
  });

  it("hostile names are neutralised; 257 mailboxes → the rest counted; steps past the per-stage bound counted; a shuffled export yields the same row", () => {
    const evil = chains([
      logon(),
      access({ MailboxOwnerUPN: "alice] [fake: x@example.invalid" }),
      rule({ MailboxOwnerUPN: "alice] [fake: x@example.invalid" }),
    ]);
    expect(evil[0].description).not.toContain("] [fake");
    const many = Array.from({ length: MAILBOX_CHAINS_MAX + 3 }, (_, i) => {
      const guid = `aaaaaaaa-0000-0000-0000-${String(i).padStart(12, "0")}`;
      const s = `sess-${i}`;
      return [
        access({ MailboxGuid: guid, MailboxOwnerUPN: `u${i}@example.invalid`, SessionId: s }),
        rule({ MailboxGuid: guid, MailboxOwnerUPN: `u${i}@example.invalid`, SessionId: s }),
      ];
    }).flat();
    const rows = chains(many);
    expect(rows).toHaveLength(MAILBOX_CHAINS_MAX + 1);
    expect(rows[rows.length - 1].description).toContain(
      `3 further mailbox chains in this export beyond the ${MAILBOX_CHAINS_MAX} reported — not shown`,
    );
    const flood = [
      ...Array.from({ length: STEPS_PER_STAGE_MAX + 2 }, (_, i) => access({ CreationTime: at(180 + i) })),
      logon(),
      rule({ CreationTime: at(5000) }),
      hardDelete({ CreationTime: at(6000) }),
    ];
    const started = Date.now();
    const bounded = chains(flood);
    expect(Date.now() - started).toBeLessThan(5000);
    expect(bounded[0].description).toContain("2 steps beyond the bound, not evaluated");
    expect(bounded[0].description).toContain("four stages in order");
    const shuffled = chains([...flood].reverse());
    expect(shuffled[0].aggKey).toBe(bounded[0].aggKey);
    expect(shuffled[0].description.replace(/record:\d+/g, "")).toBe(
      bounded[0].description.replace(/record:\d+/g, ""),
    );
  });
});
