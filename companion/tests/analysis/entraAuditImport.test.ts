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
