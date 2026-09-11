// The two Entra audit shapes read into one view (#931 item 1): identities by shape, values
// JSON-first and bounded, the credential and consent composites parsed into fields.
import { describe, expect, it } from "vitest";
import {
  isEntraUalRecord,
  normalizeOperation,
  parseAuditValue,
  parseConsentPermissions,
  parseKeyDescriptions,
  readEntraAuditRecord,
} from "../../src/analysis/entraAuditRecord.js";

const SP = "2b7f3c1a-1111-4aaa-8bbb-000000000001";
const GRAPH_SP = "3c8e4d2b-2222-4bbb-9ccc-000000000002";
const USER = "4d9f5e3c-3333-4ccc-addd-000000000003";

describe("normalizeOperation", () => {
  it("maps every dash variant to the ASCII hyphen, collapses whitespace, strips the trailing period", () => {
    for (const dash of ["-", "–", "—", "−"]) {
      expect(normalizeOperation(`Update application ${dash}  Certificates and secrets management.`)).toBe(
        "Update application - Certificates and secrets management",
      );
    }
  });
});

describe("parseAuditValue", () => {
  it("reads JSON-encoded, plain and over-bound values", () => {
    expect(parseAuditValue('["Directory.ReadWrite.All"]').value).toEqual(["Directory.ReadWrite.All"]);
    expect(parseAuditValue('"AppRoleAssignment.ReadWrite.All"').value).toBe(
      "AppRoleAssignment.ReadWrite.All",
    );
    expect(parseAuditValue("true").value).toBe(true);
    expect(parseAuditValue("plain text").value).toBe("plain text");
    const big = parseAuditValue("x".repeat(5000));
    expect(big.unreadable).toBe(true);
    expect(big.rawDigest).toMatch(/^[0-9a-f]{16}$/);
    expect(parseAuditValue("a").rawDigest).not.toBe(parseAuditValue("b").rawDigest);
  });
});

describe("parseKeyDescriptions", () => {
  it("reads the four named fields of each bracketed credential and drops anything else", () => {
    const list = parseKeyDescriptions([
      "[KeyIdentifier=9c1d2e3f-0000-4000-8000-000000000001,KeyType=Password,KeyUsage=Verify,DisplayName=deploy]",
      "[KeyIdentifier=9c1d2e3f-0000-4000-8000-000000000002,KeyType=AsymmetricX509Cert,KeyUsage=Verify,DisplayName=CN=x,Value=SHOULD-NOT-SURVIVE]",
      "not a credential",
    ]);
    expect(list).toHaveLength(2);
    expect(list[0]).toEqual({
      keyId: "9c1d2e3f-0000-4000-8000-000000000001",
      keyType: "Password",
      usage: "Verify",
      displayName: "deploy",
    });
    expect(list[1].keyType).toBe("AsymmetricX509Cert");
    expect(JSON.stringify(list)).not.toContain("SHOULD-NOT-SURVIVE");
  });
});

describe("parseConsentPermissions", () => {
  it("parses the composite '[] => [[…]]' form into entries with split scopes", () => {
    const v = `[] => [[Id: abc-1, ClientId: ${SP}, PrincipalId: ${USER}, ResourceId: ${GRAPH_SP}, ConsentType: Principal, Scope: Mail.Read openid profile, CreatedDateTime: 2024-01-01, ExpiryTime: ], [Id: abc-2, ClientId: ${SP}, PrincipalId: , ResourceId: ${GRAPH_SP}, ConsentType: AllPrincipals, Scope: User.Read.All]]`;
    const entries = parseConsentPermissions(v);
    expect(entries).toHaveLength(2);
    expect(entries[0]).toMatchObject({
      id: "abc-1",
      clientId: SP,
      principalId: USER,
      resourceId: GRAPH_SP,
      consentType: "Principal",
      scopes: ["Mail.Read", "openid", "profile"],
    });
    expect(entries[1]).toMatchObject({
      consentType: "AllPrincipals",
      principalId: "",
      scopes: ["User.Read.All"],
    });
  });
  it("returns nothing for text without consent entries", () => {
    expect(parseConsentPermissions("[] => []")).toEqual([]);
    expect(parseConsentPermissions(42)).toEqual([]);
  });
});

describe("readEntraAuditRecord — Graph shape", () => {
  it("reads the initiator, every target, and every target's properties with their index", () => {
    const r = readEntraAuditRecord({
      id: "rec-1",
      activityDateTime: "2024-05-01T10:00:00Z",
      activityDisplayName: "Add app role assignment to service principal",
      result: "success",
      initiatedBy: {
        user: { id: USER, userPrincipalName: "admin@example.invalid", ipAddress: "203.0.113.5" },
      },
      targetResources: [
        {
          id: GRAPH_SP,
          displayName: "Microsoft Graph",
          type: "ServicePrincipal",
          modifiedProperties: [
            { displayName: "AppRole.Value", oldValue: null, newValue: '"Mail.Read"' },
            { displayName: "ServicePrincipal.ObjectID", oldValue: null, newValue: `"${SP}"` },
          ],
        },
      ],
    })!;
    expect(r.shape).toBe("graph");
    expect(r.initiator).toMatchObject({
      kind: "user",
      id: USER,
      upn: "admin@example.invalid",
      ip: "203.0.113.5",
    });
    expect(r.targets[0]).toMatchObject({ type: "ServicePrincipal", id: GRAPH_SP, name: "Microsoft Graph" });
    expect(r.props.map((p) => [p.name, p.newValue, p.targetIndex])).toEqual([
      ["AppRole.Value", "Mail.Read", 0],
      ["ServicePrincipal.ObjectID", SP, 0],
    ]);
    expect(r.outcome).toBe("success");
  });
  it("an app initiator is read by its service principal id", () => {
    const r = readEntraAuditRecord({
      activityDisplayName: "Add service principal credentials",
      result: "failure",
      initiatedBy: { app: { appId: "app-1", servicePrincipalId: SP, displayName: "Sync" } },
      targetResources: [],
    })!;
    expect(r.initiator).toMatchObject({ kind: "app", id: SP, appId: "app-1", name: "Sync" });
    expect(r.outcome).toBe("failure");
  });
});

describe("readEntraAuditRecord — UAL shape", () => {
  it("groups Actor/Target entries by shape — GUID, UPN, type label — and ignores the numeric Type", () => {
    const r = readEntraAuditRecord({
      Id: "ual-1",
      CreationTime: "2024-05-01T10:00:00Z",
      Workload: "AzureActiveDirectory",
      Operation: "Add member to role.",
      ResultStatus: "Success",
      OrganizationId: "tenant-1",
      ActorIpAddress: "203.0.113.9",
      Actor: [
        { ID: "admin@example.invalid", Type: 5 },
        { ID: "User", Type: 2 },
        { ID: USER, Type: 3 },
      ],
      Target: [
        { ID: "svc-sync", Type: 1 },
        { ID: "ServicePrincipal", Type: 2 },
        { ID: SP, Type: 3 },
      ],
      ModifiedProperties: [
        { Name: "Role.DisplayName", NewValue: "Global Administrator", OldValue: "" },
        { Name: "Role.TemplateId", NewValue: "62e90394-69f5-4237-9190-012177145e10", OldValue: "" },
      ],
    })!;
    expect(r.shape).toBe("ual");
    expect(r.operation).toBe("Add member to role");
    expect(r.tenant).toBe("tenant-1");
    expect(r.initiator).toMatchObject({
      kind: "user",
      id: USER,
      upn: "admin@example.invalid",
      ip: "203.0.113.9",
    });
    expect(r.targets).toEqual([{ type: "ServicePrincipal", id: SP, name: "svc-sync", upn: "" }]);
    expect(r.props.map((p) => [p.name, p.newValue, p.targetIndex])).toEqual([
      ["Role.DisplayName", "Global Administrator", -1],
      ["Role.TemplateId", "62e90394-69f5-4237-9190-012177145e10", -1],
    ]);
  });
  it("an Actor typed ServicePrincipal is an app initiator", () => {
    const r = readEntraAuditRecord({
      Workload: "AzureActiveDirectory",
      Operation: "Add app role assignment to service principal.",
      ResultStatus: "Success",
      Actor: [
        { ID: "Sync", Type: 1 },
        { ID: "ServicePrincipal", Type: 2 },
        { ID: SP, Type: 3 },
      ],
      Target: [],
      ModifiedProperties: [],
    })!;
    expect(r.initiator).toMatchObject({ kind: "app", id: SP, name: "Sync" });
  });
  it("recognises only AzureActiveDirectory records with identity or property arrays", () => {
    expect(isEntraUalRecord({ Workload: "AzureActiveDirectory", Target: [] })).toBe(true);
    expect(isEntraUalRecord({ Workload: "Exchange", Operation: "Set-InboxRule" })).toBe(false);
    expect(readEntraAuditRecord({ Workload: "Exchange", Operation: "Set-InboxRule" })).toBeNull();
  });
});
