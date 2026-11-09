// Entra audit rows: the agent-type marker is not a name, an app's empty refresh of its own service
// principal is not graded as credential tampering, and every row carries what the record changed in
// its `message` — the text the dashboard's [details] panel shows.
import { describe, expect, it } from "vitest";
import { learnApiResolver, mapEntraAuditRows } from "../../src/analysis/entraAuditImport.js";
import { readEntraAuditRecord } from "../../src/analysis/entraAuditRecord.js";
import type { Severity } from "../../src/analysis/stateTypes.js";

const noResolve = learnApiResolver([]);
// The production table's grade for service-principal operations (m365Import.ts opSeverity).
const table = (op: string): { severity: Severity; mitre?: string[] } =>
  /service principal/i.test(op) ? { severity: "High", mitre: ["T1098.001"] } : { severity: "Info" };

const INTUNE_SP = "12345678-1234-4123-8123-123456789abc";
const INTUNE_APP = "0000000a-0000-0000-c000-000000000000";
const OTHER_SP = "22222222-3333-4444-8555-666666666666";
const USER = "33333333-4444-4555-8666-777777777777";
const EMPTY_INCLUDED = { displayName: "Included Updated Properties", oldValue: null, newValue: '""' };

const graphUpdate = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
  id: "Directory_1",
  activityDisplayName: "Update service principal",
  activityDateTime: "2026-11-08T03:10:52.206863Z",
  result: "success",
  initiatedBy: {
    user: null,
    app: { appId: null, displayName: "Microsoft Intune", servicePrincipalId: INTUNE_SP },
  },
  targetResources: [
    {
      id: INTUNE_SP,
      displayName: "Microsoft Intune",
      type: "ServicePrincipal",
      modifiedProperties: [EMPTY_INCLUDED],
    },
  ],
  ...over,
});

// The Unified Audit Log copy of the same event, as Microsoft writes it (agentType pair included).
const ualUpdate = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
  Workload: "AzureActiveDirectory",
  RecordType: 8,
  CreationTime: "2026-11-08T03:10:52Z",
  Id: "ual-1",
  Operation: "Update service principal.",
  ResultStatus: "Success",
  UserId: `ServicePrincipal_${INTUNE_SP}`,
  UserType: 4,
  Actor: [
    { ID: "Microsoft Intune", Type: 1 },
    { ID: INTUNE_APP, Type: 2 },
    { ID: `ServicePrincipal_${INTUNE_SP}`, Type: 2 },
    { ID: INTUNE_SP, Type: 2 },
    { ID: "ServicePrincipal", Type: 2 },
    { ID: "NotAgentic", Type: 2 },
  ],
  Target: [
    { ID: `ServicePrincipal_${INTUNE_SP}`, Type: 2 },
    { ID: INTUNE_SP, Type: 2 },
    { ID: "ServicePrincipal", Type: 2 },
    { ID: "NotAgentic", Type: 2 },
    { ID: "Microsoft Intune", Type: 1 },
    { ID: INTUNE_APP, Type: 2 },
    { ID: "Other", Type: 2 },
  ],
  ModifiedProperties: [{ Name: "Included Updated Properties", NewValue: "", OldValue: "" }],
  ...over,
});

describe("UAL identity arrays — the agentType marker", () => {
  it("a target's NotAgentic pair is not its display name", () => {
    const r = readEntraAuditRecord(ualUpdate())!;
    expect(r.targets[0]).toMatchObject({ id: INTUNE_SP, name: "Microsoft Intune" });
  });

  it.each([
    "notAgentic",
    "agenticApp",
    "agenticAppInstance",
    "agentIdentityBlueprintPrincipal",
    "agentIDuser",
    "unknownFutureValue",
  ])("%s is never read as a name", (marker) => {
    const r = readEntraAuditRecord(
      ualUpdate({
        Target: [
          { ID: `User_${USER}`, Type: 2 },
          { ID: USER, Type: 2 },
          { ID: "User", Type: 2 },
          { ID: marker, Type: 2 },
        ],
      }),
    )!;
    expect(r.targets[0].name).toBe("");
  });

  it("the plain row names the real target, not the marker", () => {
    const [row] = mapEntraAuditRows(ualUpdate(), new Map(), 0, noResolve, table);
    expect(row.description).toContain("→ Microsoft Intune");
    expect(row.description).not.toMatch(/NotAgentic/i);
  });
});

describe("an app's empty update of its own service principal", () => {
  it.each([
    ["Graph", graphUpdate()],
    ["UAL", ualUpdate()],
  ])("is Low with no technique (%s shape)", (_shape, rec) => {
    const [row] = mapEntraAuditRows(rec, new Map(), 0, noResolve, table);
    expect(row.severity).toBe("Low");
    expect(row.mitre).toEqual([]);
  });

  it("a user's empty update keeps the table's grade", () => {
    const rec = graphUpdate({
      initiatedBy: { user: { id: USER, userPrincipalName: "admin@example.com", ipAddress: "203.0.113.9" } },
      targetResources: [
        {
          id: OTHER_SP,
          displayName: "Collector",
          type: "ServicePrincipal",
          modifiedProperties: [EMPTY_INCLUDED],
        },
      ],
    });
    const [row] = mapEntraAuditRows(rec, new Map(), 0, noResolve, table);
    expect(row.severity).toBe("High");
    expect(row.mitre).toEqual(["T1098.001"]);
  });

  it("an app's empty update of ANOTHER service principal keeps the table's grade", () => {
    const rec = graphUpdate({
      targetResources: [
        {
          id: OTHER_SP,
          displayName: "Collector",
          type: "ServicePrincipal",
          modifiedProperties: [EMPTY_INCLUDED],
        },
      ],
    });
    const [row] = mapEntraAuditRows(rec, new Map(), 0, noResolve, table);
    expect(row.severity).toBe("High");
  });

  it("an app's self-update that names a changed property keeps the table's grade", () => {
    const rec = graphUpdate({
      targetResources: [
        {
          id: INTUNE_SP,
          displayName: "Microsoft Intune",
          type: "ServicePrincipal",
          modifiedProperties: [
            {
              displayName: "ReplyUrls",
              oldValue: '["https://a.example.com"]',
              newValue: '["https://b.example.com"]',
            },
            { displayName: "Included Updated Properties", oldValue: null, newValue: '"ReplyUrls"' },
          ],
        },
      ],
    });
    const [row] = mapEntraAuditRows(rec, new Map(), 0, noResolve, table);
    expect(row.severity).toBe("High");
  });
});

describe("the row's details (message)", () => {
  it("says Microsoft recorded no changed property when the list is empty", () => {
    const [row] = mapEntraAuditRows(graphUpdate(), new Map(), 0, noResolve, table);
    expect(row.message).toMatch(/no changed propert/i);
    expect(row.message).toContain("Microsoft Intune");
  });

  it("lists every changed property with its old and new value, and drops the redundant name list", () => {
    const rec = graphUpdate({
      activityDisplayName: "Add service principal",
      initiatedBy: { user: { id: USER, userPrincipalName: "admin@example.com", ipAddress: "203.0.113.9" } },
      targetResources: [
        {
          id: OTHER_SP,
          displayName: "Collector",
          type: "ServicePrincipal",
          modifiedProperties: [
            { displayName: "AccountEnabled", oldValue: "[]", newValue: "[true]" },
            {
              displayName: "Credential",
              oldValue: "[]",
              newValue: '[{"CredentialType":2,"KeyStoreId":"44444444-5555-4666-8777-888888888888"}]',
            },
            {
              displayName: "Included Updated Properties",
              oldValue: null,
              newValue: '"AccountEnabled, Credential"',
            },
          ],
        },
      ],
    });
    const rows = mapEntraAuditRows(rec, new Map(), 0, noResolve, table);
    const msg = rows.map((r) => r.message ?? "").join("\n");
    expect(msg).toContain("Collector");
    expect(msg).toMatch(/AccountEnabled: \[\] → \[true\]/);
    expect(msg).toContain("Credential:");
    expect(msg).toContain("44444444-5555-4666-8777-888888888888");
    expect(msg).not.toContain("Included Updated Properties");
  });

  it("bounds a long value and a long property list", () => {
    const many = Array.from({ length: 80 }, (_, i) => ({
      displayName: `P${i}`,
      oldValue: null,
      newValue: JSON.stringify("x".repeat(2000)),
    }));
    const rec = graphUpdate({
      targetResources: [
        { id: OTHER_SP, displayName: "C", type: "ServicePrincipal", modifiedProperties: many },
      ],
    });
    const [row] = mapEntraAuditRows(rec, new Map(), 0, noResolve, table);
    expect(row.message!.length).toBeLessThan(8000);
    expect(row.message).toMatch(/more propert/i);
  });
});
