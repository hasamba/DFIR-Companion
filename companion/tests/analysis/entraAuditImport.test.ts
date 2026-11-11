// entraAuditImport — direct tests for mapEntraAuditRows and the service-principal sign-in path
// (#2170). Indirect coverage lives in m365Import.test.ts through parseM365Audit; these pin the
// exported functions themselves, including their behaviour on malformed records.
import { describe, expect, it } from "vitest";
import {
  isServicePrincipalSignIn,
  learnApiResolver,
  mapEntraAuditRows,
  mapSpSignIn,
  readSpSignIn,
} from "../../src/analysis/entraAuditImport.js";
import { parseM365Audit } from "../../src/analysis/m365Import.js";
import type { SiemIoc } from "../../src/analysis/siemImport.js";
import type { Severity } from "../../src/analysis/stateTypes.js";

const plain = (activity: string): { severity: Severity; mitre?: string[] } =>
  /role/i.test(activity) ? { severity: "High", mitre: ["T1098.003"] } : { severity: "Info" };
const noResolve = learnApiResolver([]);

const roleAssignment = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
  id: "audit-1",
  activityDateTime: "2023-05-02T09:00:00Z",
  activityDisplayName: "Add member to role",
  result: "success",
  initiatedBy: {
    user: { id: "u-admin", userPrincipalName: "admin@example.invalid", ipAddress: "203.0.113.60" },
  },
  targetResources: [{ type: "User", id: "u-target", userPrincipalName: "attacker@example.invalid" }],
  ...over,
});

const SP_ID = "11111111-1111-1111-1111-111111111111";
const APP_ID = "22222222-2222-2222-2222-222222222222";

const spSignIn = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
  id: "signin-1",
  createdDateTime: "2023-05-03T08:00:00Z",
  servicePrincipalId: SP_ID,
  servicePrincipalName: "Backup App",
  appId: APP_ID,
  resourceDisplayName: "Microsoft Graph",
  ipAddress: "198.51.100.7",
  clientCredentialType: "clientSecret",
  status: { errorCode: 0 },
  ...over,
});

describe("mapEntraAuditRows — happy path", () => {
  it("maps a role assignment to one row with the table's grade, the target and an IP IOC", () => {
    const sink = new Map<string, SiemIoc>();
    const rows = mapEntraAuditRows(roleAssignment(), sink, 2, noResolve, plain);
    expect(rows).toHaveLength(1);
    const [e] = rows;
    expect(e.description).toContain(
      "Entra audit: Add member to role by admin@example.invalid from 203.0.113.60",
    );
    expect(e.description).toContain("→ attacker@example.invalid");
    expect(e.severity).toBe("High");
    expect(e.mitre).toEqual(["T1098.003"]);
    expect(e.sources).toEqual(["Entra ID"]);
    expect(e.timestamp).toContain("2023-05-02T09:00:00");
    expect(e.canonical?.target).toMatchObject({ kind: "account", id: "u-target" });
    expect(e.canonical?.evidence?.rawRecords?.[0]).toMatchObject({
      source: "entra-audit",
      locator: "record:2",
    });
    expect([...sink.values()].some((i) => i.type === "ip" && i.value === "203.0.113.60")).toBe(true);
  });

  it("tags a failed record with its outcome", () => {
    const [e] = mapEntraAuditRows(roleAssignment({ result: "failure" }), new Map(), 0, noResolve, plain);
    expect(e.description).toContain("[failure]");
  });

  it("summarises extra targets as '+n more'", () => {
    const rec = roleAssignment({
      targetResources: [
        { type: "User", id: "a", userPrincipalName: "a@example.invalid" },
        { type: "User", id: "b", userPrincipalName: "b@example.invalid" },
      ],
    });
    const [e] = mapEntraAuditRows(rec, new Map(), 0, noResolve, plain);
    expect(e.description).toContain("→ a@example.invalid +1 more");
  });
});

describe("mapEntraAuditRows — UAL NotAgentic flag (#2484)", () => {
  const TARGET = "33333333-3333-4333-8333-333333333333";
  const ual = (Target: unknown[]): Record<string, unknown> => ({
    Id: "ual-2484",
    CreationTime: "2023-05-02T09:00:00Z",
    Workload: "AzureActiveDirectory",
    RecordType: 8,
    Operation: "Update user.",
    ResultStatus: "Success",
    OrganizationId: "tenant-1",
    UserId: "admin@example.invalid",
    UserType: 2,
    Actor: [{ ID: "admin@example.invalid", Type: 5 }],
    Target,
    ModifiedProperties: [],
  });

  it("shows the target's display name, never the NotAgentic flag", () => {
    const rec = ual([
      { ID: `User_${TARGET}`, Type: 2 },
      { ID: "NotAgentic", Type: 2 },
      { ID: "Jane Analyst", Type: 1 },
    ]);
    const [e] = mapEntraAuditRows(rec, new Map(), 0, noResolve, plain);
    expect(e.description).toContain("→ Jane Analyst");
    expect(e.description).not.toContain("NotAgentic");
    expect(e.canonical?.target).toMatchObject({ name: "Jane Analyst" });
  });

  it("with no display name, the flag word never appears in the row", () => {
    const rec = ual([
      { ID: `User_${TARGET}`, Type: 2 },
      { ID: "NotAgentic", Type: 2 },
    ]);
    const [e] = mapEntraAuditRows(rec, new Map(), 0, noResolve, plain);
    expect(e.description).not.toContain("NotAgentic");
    expect(JSON.stringify(e.canonical ?? {})).not.toContain("NotAgentic");
  });
});

describe("mapEntraAuditRows — malformed records", () => {
  it("returns no rows for a record that is neither export shape", () => {
    const sink = new Map<string, SiemIoc>();
    expect(mapEntraAuditRows({}, sink, 0, noResolve, plain)).toEqual([]);
    expect(sink.size).toBe(0);
  });

  it.each([
    ["targetResources as a string", roleAssignment({ targetResources: "not-an-array" })],
    ["targetResources with null entries", roleAssignment({ targetResources: [null, 7] })],
    [
      "modifiedProperties not an array",
      roleAssignment({ targetResources: [{ id: "x", modifiedProperties: "x" }] }),
    ],
    ["initiatedBy as null", roleAssignment({ initiatedBy: null })],
    ["an empty activity name", roleAssignment({ activityDisplayName: "" })],
  ])("does not throw on %s", (_name, rec) => {
    expect(() => mapEntraAuditRows(rec, new Map(), 0, noResolve, plain)).not.toThrow();
  });

  it("does not throw on a UAL record whose AuditData-style fields are the wrong type", () => {
    const ual = {
      Workload: "AzureActiveDirectory",
      RecordType: 8,
      Operation: "Add member to role.",
      ModifiedProperties: "not-an-array",
      Target: { not: "an array" },
      Actor: "nope",
    };
    expect(() => mapEntraAuditRows(ual, new Map(), 0, noResolve, plain)).not.toThrow();
  });

  it("does not throw on a UAL record with an unparseable AuditData string", () => {
    const ual = {
      Workload: "AzureActiveDirectory",
      RecordType: 8,
      Operation: "Add member to role.",
      AuditData: "{trunc",
    };
    expect(() => mapEntraAuditRows(ual, new Map(), 0, noResolve, plain)).not.toThrow();
  });
});

describe("isServicePrincipalSignIn", () => {
  it("is true for a sign-in with a service principal and no user", () => {
    expect(isServicePrincipalSignIn(spSignIn())).toBe(true);
  });

  it.each([
    ["a user sign-in", spSignIn({ userPrincipalName: "bob@example.invalid" })],
    ["no service principal id or name", spSignIn({ servicePrincipalId: "", servicePrincipalName: "" })],
    ["no status, resource or appId", { servicePrincipalId: SP_ID }],
    ["an empty record", {}],
  ])("is false for %s", (_name, rec) => {
    expect(isServicePrincipalSignIn(rec)).toBe(false);
  });
});

describe("readSpSignIn / mapSpSignIn", () => {
  it("reads the sign-in's identity, resource, credential and outcome", () => {
    const s = readSpSignIn(spSignIn());
    expect(s).toMatchObject({
      spId: SP_ID,
      appId: APP_ID,
      name: "Backup App",
      resourceName: "Microsoft Graph",
      ip: "198.51.100.7",
      credType: "clientSecret",
      code: 0,
      rejected: false,
      outcome: "success",
    });
  });

  it("maps a successful client-secret token issue to Low with an IP IOC", () => {
    const sink = new Map<string, SiemIoc>();
    const e = mapSpSignIn(spSignIn(), sink, 1);
    expect(e.severity).toBe("Low");
    expect(e.mitre).toEqual([]);
    expect(e.description).toContain(`Entra sign-in: application Backup App (${APP_ID})`);
    expect(e.description).toContain("token issued");
    expect(e.canonical?.event).toMatchObject({ category: "authentication", outcome: "success" });
    expect([...sink.values()].some((i) => i.type === "ip" && i.value === "198.51.100.7")).toBe(true);
  });

  it("grades a rejected workload credential Medium with T1078.004", () => {
    const e = mapSpSignIn(spSignIn({ status: { errorCode: 7000215 } }), new Map(), 0);
    expect(e.severity).toBe("Medium");
    expect(e.mitre).toEqual(["T1078.004"]);
    expect(e.description).toContain("invalid client secret");
  });

  it("grades any other failure Low and a missing status Info", () => {
    expect(mapSpSignIn(spSignIn({ status: { errorCode: "53003" } }), new Map(), 0).severity).toBe("Low");
    expect(mapSpSignIn(spSignIn({ status: undefined }), new Map(), 0).severity).toBe("Info");
  });

  it.each([
    ["an empty record", {}],
    ["status as a string", spSignIn({ status: "failed" })],
    ["a non-numeric errorCode", spSignIn({ status: { errorCode: "abc" } })],
  ])("does not throw on %s and reports an unknown outcome as Info", (_name, rec) => {
    expect(readSpSignIn(rec).outcome).toBe("unknown");
    expect(mapSpSignIn(rec, new Map(), 0).severity).toBe("Info");
  });

  it("drops a garbage IP rather than recording it as an IOC", () => {
    const sink = new Map<string, SiemIoc>();
    const e = mapSpSignIn(spSignIn({ ipAddress: "not-an-ip" }), sink, 0);
    expect(readSpSignIn(spSignIn({ ipAddress: "not-an-ip" })).ip).toBe("");
    expect(e.description).not.toContain("not-an-ip");
    expect(sink.size).toBe(0);
  });
});

// #2549 — Microsoft's own backend services provisioning service principals (app-only, UserType 4)
// are upkeep: Low, still in the forensic timeline. Keyed on the immutable app id or Microsoft's
// internal certificate actor shape — never the display name, never a public client, never a
// credential add, never a person.
describe("parseM365Audit — Microsoft first-party service principal provisioning (#2549)", () => {
  const SERVICE_MGMT_APP = "797f4846-ba00-4fd7-ba43-dac1f8f63013"; // Windows Azure Service Management API
  const AZURE_CLI = "04b07795-8ddb-461a-bbee-02f9e1bf7b46";
  const THIRD_PARTY = "33333333-3333-4333-8333-333333333333";
  const SP_OBJECT = "44444444-4444-4444-8444-444444444444";
  const appActor = (name: string, appId: string) => [
    { ID: name, Type: 1 },
    { ID: appId, Type: 2 },
    { ID: `ServicePrincipal_${SP_OBJECT}`, Type: 2 },
    { ID: SP_OBJECT, Type: 2 },
    { ID: "ServicePrincipal", Type: 2 },
  ];
  const ual = (op: string, over: Record<string, unknown>) => ({
    CreationTime: "2026-03-01T10:00:00",
    Id: "00000000-0000-0000-0000-0000000000d1",
    Operation: op,
    OrganizationId: "00000000-0000-0000-0000-0000000000aa",
    RecordType: 8,
    ResultStatus: "Success",
    Workload: "AzureActiveDirectory",
    UserType: 4,
    UserId: `ServicePrincipal_${SP_OBJECT}`,
    Target: [
      { ID: "ServicePrincipal_55555555-5555-4555-8555-555555555555", Type: 2 },
      { ID: "Some App", Type: 1 },
    ],
    ...over,
  });
  const grade = (rec: Record<string, unknown>) => {
    const r = parseM365Audit(JSON.stringify([rec]), { aggregate: false });
    expect(r.events).toHaveLength(1);
    return r.events[0];
  };

  it("a listed Microsoft backend service adding or updating a service principal is Low with no technique", () => {
    for (const op of ["Add service principal.", "Update service principal."]) {
      const e = grade(ual(op, { Actor: appActor("Windows Azure Service Management API", SERVICE_MGMT_APP) }));
      expect(e.severity).toBe("Low");
      expect(e.mitreTechniques).toEqual([]);
    }
  });

  it("Microsoft's internal certificate actor (UserId Certificate, type Other) is Low", () => {
    const e = grade(
      ual("Add service principal.", {
        UserId: "Certificate",
        Actor: [
          { ID: "Microsoft Azure AD Internal - Jit Provisioning", Type: 1 },
          { ID: "Certificate", Type: 2 },
          { ID: "Other", Type: 2 },
        ],
      }),
    );
    expect(e.severity).toBe("Low");
  });

  it("a third-party app named like a Microsoft service stays High (the display name is never read)", () => {
    const e = grade(
      ual("Add service principal.", { Actor: appActor("Microsoft Online Services", THIRD_PARTY) }),
    );
    expect(e.severity).toBe("High");
    expect(e.mitreTechniques).toContain("T1098.001");
  });

  it("a public client (Azure CLI) acting app-only stays High", () => {
    const e = grade(ual("Add service principal.", { Actor: appActor("Microsoft Azure CLI", AZURE_CLI) }));
    expect(e.severity).toBe("High");
  });

  it("a credential add by a first-party service stays High", () => {
    const e = grade(
      ual("Add service principal credentials.", {
        Actor: appActor("Windows Azure Service Management API", SERVICE_MGMT_APP),
      }),
    );
    expect(e.severity).toBe("High");
  });

  it("a person (UPN actor) adding a service principal stays High, whatever client they used", () => {
    const e = grade(
      ual("Add service principal.", {
        UserType: 0,
        UserId: "admin@example.test",
        Actor: [
          { ID: "admin@example.test", Type: 5 },
          { ID: SERVICE_MGMT_APP, Type: 2 },
          { ID: "User_66666666-6666-4666-8666-666666666666", Type: 2 },
          { ID: "User", Type: 2 },
        ],
      }),
    );
    expect(e.severity).toBe("High");
  });
});
