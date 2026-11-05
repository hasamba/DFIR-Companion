import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { compileText } from "../../src/analysis/taggerStore.js";
import { runTagger, applyToForensicEvent } from "../../src/analysis/tagger.js";
import { parseM365Audit } from "../../src/analysis/m365Import.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// Graph auditLogRecord parity (#2304). MES `Get-UALGraph` (and the Graph AuditLogQuery API that
// live collection will use) returns `security.auditLogRecord` objects — `id, createdDateTime,
// auditLogRecordType, operation, service, userPrincipalName, clientIp, auditData` — instead of the
// Search-UnifiedAuditLog shape. The SAME action given either way must come out of the importer and
// the SHIPPED tags.yaml identically: the rules match on the description's prefix AND wording, so a
// Graph record that renders "M365 audit:" instead of "M365 Exchange:" silently loses its rules.
const RULES = compileText(
  readFileSync(fileURLToPath(new URL("../../data/tags.yaml", import.meta.url)), "utf8"),
);

interface Outcome {
  ruleIds: string[];
  severity: string;
  mitre: string[];
  timestamp: string;
  description: string;
}

function outcomes(records: unknown[]): Outcome[] {
  const parsed = parseM365Audit(JSON.stringify(records), { aggregate: false });
  return parsed.events
    .filter((e) => !/summary|chain|path/i.test(e.sources?.join(" ") ?? ""))
    .map((m, i) => {
      const event = {
        ...m,
        id: `e${i}`,
        relatedFindingIds: [],
        sourceScreenshots: [],
        mitreTechniques: m.mitreTechniques ?? [],
      } as unknown as ForensicEvent;
      const proposal = runTagger([event], RULES).perEvent[0];
      const after = proposal ? applyToForensicEvent(event, proposal) : event;
      return {
        ruleIds: [...(proposal?.ruleIds ?? [])].sort(),
        severity: after.severity,
        mitre: [...after.mitreTechniques].sort(),
        timestamp: after.timestamp,
        description: after.description,
      };
    });
}

const TENANT = "00000000-0000-4000-8000-000000000001";

interface Action {
  name: string;
  /** The AuditData object Microsoft records for the action (the UAL record proper). */
  auditData: Record<string, unknown>;
  /** The Graph `auditLogRecordType` name for its RecordType. */
  graphType: string;
  graphService: string;
}

const envelope = (over: Record<string, unknown>) => ({
  CreationTime: "2026-11-01T10:01:00",
  OrganizationId: TENANT,
  ResultStatus: "Succeeded",
  UserType: 0,
  Version: 1,
  ...over,
});

const ACTIONS: Action[] = [
  {
    name: "New-InboxRule forwarding to an external address",
    graphType: "ExchangeAdmin",
    graphService: "Exchange",
    auditData: envelope({
      Id: "00000000-0000-4000-8000-000000000a01",
      Operation: "New-InboxRule",
      RecordType: 1,
      Workload: "Exchange",
      ClientIP: "203.0.113.10:51000",
      UserId: "user1@example.com",
      ObjectId: "user1@example.com\\rule1",
      Parameters: [
        { Name: "Name", Value: "rule1" },
        { Name: "ForwardTo", Value: "drop@external.example.net" },
      ],
    }),
  },
  {
    name: "UserLoginFailed (wrong password)",
    graphType: "AzureActiveDirectoryStsLogon",
    graphService: "AzureActiveDirectory",
    auditData: envelope({
      Id: "00000000-0000-4000-8000-000000000a02",
      Operation: "UserLoginFailed",
      RecordType: 15,
      Workload: "AzureActiveDirectory",
      ResultStatus: "Failed",
      ClientIP: "198.51.100.20",
      UserId: "user2@example.com",
      LogonError: "InvalidUserNameOrPassword",
      ErrorNumber: "50126",
    }),
  },
  {
    name: "Consent to application",
    graphType: "AzureActiveDirectory",
    graphService: "AzureActiveDirectory",
    auditData: envelope({
      Id: "00000000-0000-4000-8000-000000000a03",
      Operation: "Consent to application.",
      RecordType: 8,
      Workload: "AzureActiveDirectory",
      ResultStatus: "Success",
      ClientIP: "203.0.113.30",
      UserId: "user3@example.com",
      ObjectId: "00000000-0000-4000-8000-000000000b03",
      Target: [
        { ID: "00000000-0000-4000-8000-000000000b03", Type: 2 },
        { ID: "Example App", Type: 1 },
      ],
      ModifiedProperties: [
        { Name: "ConsentContext.IsAdminConsent", NewValue: "False", OldValue: "" },
        { Name: "ConsentAction.Permissions", NewValue: "Scope: Mail.Read offline_access", OldValue: "" },
      ],
    }),
  },
  {
    name: "Add service principal",
    graphType: "AzureActiveDirectory",
    graphService: "AzureActiveDirectory",
    auditData: envelope({
      Id: "00000000-0000-4000-8000-000000000a04",
      Operation: "Add service principal.",
      RecordType: 8,
      Workload: "AzureActiveDirectory",
      ResultStatus: "Success",
      ClientIP: "203.0.113.31",
      UserId: "admin@example.com",
      ObjectId: "00000000-0000-4000-8000-000000000b04",
      Target: [
        { ID: "00000000-0000-4000-8000-000000000b04", Type: 2 },
        { ID: "Example App", Type: 1 },
      ],
      ModifiedProperties: [{ Name: "DisplayName", NewValue: '["Example App"]', OldValue: "[]" }],
    }),
  },
  {
    name: "Set-Mailbox forwarding",
    graphType: "ExchangeAdmin",
    graphService: "Exchange",
    auditData: envelope({
      Id: "00000000-0000-4000-8000-000000000a05",
      Operation: "Set-Mailbox",
      RecordType: 1,
      Workload: "Exchange",
      ClientIP: "203.0.113.10",
      UserId: "user1@example.com",
      ObjectId: "user1@example.com",
      Parameters: [
        { Name: "Identity", Value: "user1@example.com" },
        { Name: "ForwardingSmtpAddress", Value: "smtp:drop@external.example.net" },
        { Name: "DeliverToMailboxAndForward", Value: "False" },
      ],
    }),
  },
];

// Search-UnifiedAuditLog | ConvertTo-Json: the outer columns plus AuditData as a JSON string.
function legacy(a: Action): Record<string, unknown> {
  return {
    RecordType: a.graphType,
    CreationDate: "2026-11-01T10:01:00",
    UserIds: a.auditData.UserId,
    Operations: a.auditData.Operation,
    AuditData: JSON.stringify(a.auditData),
  };
}

// Graph security.auditLogRecord, as Get-UALGraph and the AuditLogQuery API return it.
function graphOuter(a: Action): Record<string, unknown> {
  return {
    id: a.auditData.Id,
    createdDateTime: "2026-11-01T10:01:00Z",
    auditLogRecordType: a.graphType,
    operation: a.auditData.Operation,
    organizationId: TENANT,
    userType: "regular",
    userId: a.auditData.UserId,
    service: a.graphService,
    objectId: a.auditData.ObjectId ?? "",
    userPrincipalName: a.auditData.UserId,
    clientIp: a.auditData.ClientIP,
    administrativeUnits: [],
  };
}

const ENVELOPE_KEYS = new Set([
  "CreationTime",
  "Id",
  "Operation",
  "RecordType",
  "Workload",
  "ClientIP",
  "UserId",
]);

/** The auditData with only the action's detail — the envelope comes from the Graph fields alone. */
function detailOnly(a: Action): Record<string, unknown> {
  return {
    "@odata.type": "#microsoft.graph.security.defaultAuditData",
    ...Object.fromEntries(Object.entries(a.auditData).filter(([k]) => !ENVELOPE_KEYS.has(k))),
  };
}

const VARIANTS: Array<[string, (a: Action) => Record<string, unknown>]> = [
  ["Graph, nested auditData object", (a) => ({ ...graphOuter(a), auditData: a.auditData })],
  [
    "Graph, auditData as a JSON string",
    (a) => ({ ...graphOuter(a), auditData: JSON.stringify(a.auditData) }),
  ],
  ["Graph, envelope only in the Graph fields", (a) => ({ ...graphOuter(a), auditData: detailOnly(a) })],
];

describe("Graph auditLogRecord grades exactly like the legacy UAL record (#2304)", () => {
  for (const action of ACTIONS) {
    describe(action.name, () => {
      const expected = outcomes([legacy(action)]);

      it("the legacy record maps to one event", () => {
        expect(expected).toHaveLength(1);
      });

      it.each(VARIANTS)("%s: same rules, severity, MITRE, time, user, IP and detail", (_v, build) => {
        expect(outcomes([build(action)])).toEqual(expected);
      });
    });
  }

  // The outcomes themselves, pinned: parity with a legacy row that graded nothing would prove nothing.
  it("forwarding inbox rule: the inbox-rule and forwarding rules fire, High, with the forwarding target", () => {
    const [o] = outcomes([legacy(ACTIONS[0])]);
    expect(o.ruleIds).toEqual(expect.arrayContaining(["ts_m365_inbox_rule", "ts_m365_mailbox_forwarding"]));
    expect(o.severity).toBe("High");
    expect(o.mitre).toContain("T1114.003");
    expect(o.timestamp).toBe("2026-11-01T10:01:00Z");
    expect(o.description).toMatch(/^M365 Exchange: New-InboxRule\b/);
    expect(o.description).toContain("user1@example.com");
    expect(o.description).toContain("drop@external.example.net");
  });

  it("failed sign-in: the UserLoginFailed rule fires with the user and source IP", () => {
    const [o] = outcomes([legacy(ACTIONS[1])]);
    expect(o.ruleIds).toContain("ts_m365_signin_failed");
    expect(o.severity).toBe("Medium");
    expect(o.mitre).toContain("T1110");
    expect(o.description).toContain("user2@example.com");
    expect(o.description).toContain("198.51.100.20");
  });

  it("consent and service principal: the OAuth rules fire", () => {
    expect(outcomes([legacy(ACTIONS[2])])[0].ruleIds.join(" ")).toMatch(/consent/);
    expect(outcomes([legacy(ACTIONS[3])])[0].ruleIds.join(" ")).toMatch(/service_principal/);
  });

  it("Set-Mailbox forwarding: the set-mailbox rule fires and names the forwarding address", () => {
    const [o] = outcomes([legacy(ACTIONS[4])]);
    expect(o.ruleIds).toContain("ts_m365_set_mailbox");
    expect(o.description).toContain("drop@external.example.net");
  });

  it("an auditData field spelled in another case still beats the Graph field", () => {
    const a = ACTIONS[0];
    const { ClientIP: _ip, ...ad } = a.auditData;
    const rec = {
      ...graphOuter(a),
      clientIp: "198.51.100.99",
      auditData: { ...ad, clientIP: "203.0.113.10" },
    };
    const [o] = outcomes([rec]);
    expect(o.description).toContain("203.0.113.10");
    expect(o.description).not.toContain("198.51.100.99");
  });
});
