// The Entra application-change decoder (#931 item 1): what ONE audit record establishes — the
// credential added (both lists are in the record), the permission granted and on which API, the
// consent's scope, the role assigned — and nothing it does not: no "used", no API from a name.
import { describe, expect, it } from "vitest";
import { decodeEntraAppChanges, type EntraAppChange } from "../../src/analysis/entraAppChange.js";
import { readEntraAuditRecord } from "../../src/analysis/entraAuditRecord.js";

const SP = "2b7f3c1a-1111-4aaa-8bbb-000000000001";
const GRAPH_SP = "3c8e4d2b-2222-4bbb-9ccc-000000000002";
const USER = "4d9f5e3c-3333-4ccc-addd-000000000003";
const USER2 = "5e0a6f4d-4444-4ddd-beee-000000000004";
const GRAPH_APP = "00000003-0000-0000-c000-000000000000";
const GA = "62e90394-69f5-4237-9190-012177145e10";
const key = (k: string, t: string, d: string) =>
  `[KeyIdentifier=${k},KeyType=${t},KeyUsage=Verify,DisplayName=${d}]`;

type Prop = { displayName: string; oldValue: unknown; newValue: unknown };
const graph = (
  activity: string,
  targets: Array<{
    type: string;
    id: string;
    displayName?: string;
    userPrincipalName?: string;
    modifiedProperties?: Prop[];
  }>,
  over: Record<string, unknown> = {},
) =>
  readEntraAuditRecord({
    id: "rec-1",
    activityDateTime: "2024-05-01T10:00:00Z",
    activityDisplayName: activity,
    result: "success",
    initiatedBy: { user: { id: USER, userPrincipalName: "admin@example.invalid", ipAddress: "203.0.113.5" } },
    targetResources: targets,
    ...over,
  })!;
const one = (changes: EntraAppChange[]): EntraAppChange => {
  expect(changes).toHaveLength(1);
  return changes[0];
};
const P = (name: string, newValue: unknown, oldValue: unknown = null): Prop => ({
  displayName: name,
  oldValue,
  newValue,
});

describe("credentials", () => {
  it("the ADDED credential is the new list minus the old, by key id; one change per credential", () => {
    const r = graph("Add service principal credentials", [
      {
        type: "ServicePrincipal",
        id: SP,
        displayName: "svc-sync",
        modifiedProperties: [
          P(
            "KeyDescription",
            JSON.stringify([
              key("k-old", "Password", "old"),
              key("k-new1", "Password", "deploy"),
              key("k-new2", "AsymmetricX509Cert", "CN=x"),
            ]),
            JSON.stringify([key("k-old", "Password", "old")]),
          ),
        ],
      },
    ]);
    const changes = decodeEntraAppChanges(r);
    expect(changes).toHaveLength(2);
    expect(changes[0].kind).toBe("credential-added");
    expect(changes[0].posture).toBe('adds Password credential k-new1 "deploy" (3 now)');
    expect(changes[1].posture).toBe('adds AsymmetricX509Cert credential k-new2 "CN=x" (3 now)');
    expect(changes[0].subject).toMatchObject({ id: SP, name: "svc-sync" });
    expect(changes[0].severity).toBe("High");
    expect(changes[0].mitre).toContain("T1098.001");
    expect(changes[0].aggKey).not.toBe(changes[1].aggKey);
  });
  it("the ASCII-hyphen literal and a dash variant both dispatch as a credential change", () => {
    for (const op of [
      "Update application - Certificates and secrets management",
      "Update application – Certificates and secrets management",
    ]) {
      const r = graph(op, [
        {
          type: "Application",
          id: SP,
          displayName: "app",
          modifiedProperties: [
            P("KeyDescription", JSON.stringify([key("k1", "Password", "s")]), JSON.stringify([])),
          ],
        },
      ]);
      expect(one(decodeEntraAppChanges(r)).kind).toBe("credential-added");
    }
  });
  it("no added credential → no change; an unparsable list → one unreadable change keyed on the raw digest; a fifth field never survives", () => {
    const none = graph("Add service principal credentials", [
      {
        type: "ServicePrincipal",
        id: SP,
        modifiedProperties: [
          P(
            "KeyDescription",
            JSON.stringify([key("k1", "Password", "s")]),
            JSON.stringify([key("k1", "Password", "s")]),
          ),
        ],
      },
    ]);
    expect(decodeEntraAppChanges(none)).toEqual([]);
    const bad = (text: string) =>
      graph("Add service principal credentials", [
        { type: "ServicePrincipal", id: SP, modifiedProperties: [P("KeyDescription", text, null)] },
      ]);
    const a = one(decodeEntraAppChanges(bad("garbage-a")));
    const b = one(decodeEntraAppChanges(bad("garbage-b")));
    expect(a.posture).toContain("credential list changed (unreadable)");
    expect(a.aggKey).not.toBe(b.aggKey);
    const leak = graph("Add service principal credentials", [
      {
        type: "ServicePrincipal",
        id: SP,
        modifiedProperties: [
          P(
            "KeyDescription",
            JSON.stringify([
              "[KeyIdentifier=k9,KeyType=Password,KeyUsage=Verify,DisplayName=d,Value=SECRET-SHAPED]",
            ]),
            JSON.stringify([]),
          ),
        ],
      },
    ]);
    expect(JSON.stringify(decodeEntraAppChanges(leak))).not.toContain("SECRET-SHAPED");
  });
  it("a removal keeps its verb and is Low", () => {
    const r = graph("Remove service principal credentials", [
      {
        type: "ServicePrincipal",
        id: SP,
        modifiedProperties: [
          P("KeyDescription", JSON.stringify([]), JSON.stringify([key("k1", "Password", "s")])),
        ],
      },
    ]);
    const c = one(decodeEntraAppChanges(r));
    expect(c.kind).toBe("credential-removed");
    expect(c.posture).toContain("removes Password credential k1");
    expect(c.severity).toBe("Low");
  });
});

describe("application permissions", () => {
  const grant = (
    value: string,
    names: unknown = [GRAPH_APP, "https://graph.microsoft.com"],
    over: Record<string, unknown> = {},
  ) =>
    graph(
      "Add app role assignment to service principal",
      [
        {
          type: "ServicePrincipal",
          id: GRAPH_SP,
          displayName: "Microsoft Graph",
          modifiedProperties: [
            P("AppRole.Id", "role-id-1"),
            P("AppRole.Value", value),
            P("ServicePrincipal.AppId", "app-1"),
            P("ServicePrincipal.DisplayName", "svc-sync"),
            P("ServicePrincipal.ObjectID", SP),
            P("TargetId.ServicePrincipalNames", names),
          ],
        },
      ],
      over,
    );
  it("reads the client from ServicePrincipal.ObjectID, the API from its immutable app id, and explains the capability", () => {
    const c = one(decodeEntraAppChanges(grant("RoleManagement.ReadWrite.Directory")));
    expect(c.kind).toBe("app-permission-granted");
    expect(c.subject).toMatchObject({ id: SP, appId: "app-1", name: "svc-sync" });
    expect(c.resource).toMatchObject({ id: GRAPH_SP, api: "Microsoft Graph" });
    expect(c.capability).toMatchObject({
      value: "RoleManagement.ReadWrite.Directory",
      class: "directory RBAC",
      delegated: false,
    });
    expect(c.posture).toBe("grants application permission RoleManagement.ReadWrite.Directory");
    expect(c.object).toBe("on Microsoft Graph for svc-sync");
    expect(c.summary).toContain("on Microsoft Graph for svc-sync");
    expect(c.words).toContain("any directory role, Global Administrator included");
    expect(c.severity).toBe("High");
    expect(c.mitre).toContain("T1098.003");
    expect(c.qualifiers).toContain("assigned, not yet observed in use");
  });
  it("a display name never identifies the API — an unknown app id named 'Microsoft Graph' is unidentified and Medium, whatever the spelling", () => {
    const c = one(
      decodeEntraAppChanges(
        grant("Mail.ReadWrite", ["11111111-2222-3333-4444-555555555555", "https://api.example.invalid"]),
      ),
    );
    expect(c.resource.api).toBe("");
    expect(c.capability?.class).toBe("");
    expect(c.object).toContain("on API Microsoft Graph");
    expect(c.qualifiers).toContain("API not identified in this record");
    expect(c.severity).toBe("Medium");
  });
  it("an 'other' Graph permission is Medium and named", () => {
    const c = one(decodeEntraAppChanges(grant("Tasks.ReadWrite")));
    expect(c.severity).toBe("Medium");
    expect(c.capability?.class).toBe("other");
  });
  it("a self-grant is detected by id, never by name, and is High", () => {
    const self = one(
      decodeEntraAppChanges(
        grant("Tasks.ReadWrite", undefined, {
          initiatedBy: { app: { appId: "app-1", servicePrincipalId: SP, displayName: "Sync" } },
        }),
      ),
    );
    expect(self.selfGrant).toBe(true);
    expect(self.severity).toBe("High");
    expect(self.posture).toMatch(/^self-grant: /);
    const other = one(
      decodeEntraAppChanges(
        grant("Tasks.ReadWrite", undefined, {
          initiatedBy: { app: { appId: "app-2", servicePrincipalId: USER2, displayName: "svc-sync" } },
        }),
      ),
    );
    expect(other.selfGrant).toBe(false);
  });
  it("a failed grant is an attempt: 'attempted to', Medium, the capability shown as requested", () => {
    const c = one(
      decodeEntraAppChanges(grant("RoleManagement.ReadWrite.Directory", undefined, { result: "failure" })),
    );
    expect(c.attempted).toBe(true);
    expect(c.posture).toMatch(/^attempted to grant application permission/);
    expect(c.severity).toBe("Medium");
    expect(c.summary).toContain("requested");
  });
  it("a removal keeps its verb and is Low; two permissions to one app are two keys; the same grant twice is one", () => {
    const rm = graph("Remove app role assignment from service principal", [
      {
        type: "ServicePrincipal",
        id: GRAPH_SP,
        modifiedProperties: [
          P("AppRole.Value", "Mail.Read"),
          P("ServicePrincipal.ObjectID", SP),
          P("TargetId.ServicePrincipalNames", [GRAPH_APP]),
        ],
      },
    ]);
    const c = one(decodeEntraAppChanges(rm));
    expect(c.kind).toBe("app-permission-removed");
    expect(c.severity).toBe("Low");
    expect(one(decodeEntraAppChanges(grant("Mail.Read"))).aggKey).not.toBe(
      one(decodeEntraAppChanges(grant("Mail.Send"))).aggKey,
    );
    expect(one(decodeEntraAppChanges(grant("Mail.Read"))).aggKey).toBe(
      one(decodeEntraAppChanges(grant("Mail.Read"))).aggKey,
    );
  });
});

describe("consent and delegated grants", () => {
  const consent = (permissions: string, ctx: Record<string, unknown> = {}) =>
    graph("Consent to application", [
      {
        type: "ServicePrincipal",
        id: SP,
        displayName: "svc-sync",
        modifiedProperties: [
          P("ConsentContext.IsAdminConsent", String(ctx.admin ?? false)),
          P("ConsentContext.IsAppOnly", String(ctx.appOnly ?? false)),
          P("ConsentContext.OnBehalfOfAll", String(ctx.all ?? false)),
          P("ConsentAction.Permissions", permissions),
        ],
      },
    ]);
  const entry = (id: string, principal: string, type: string, scope: string) =>
    `[Id: ${id}, ClientId: ${SP}, PrincipalId: ${principal}, ResourceId: ${GRAPH_SP}, ConsentType: ${type}, Scope: ${scope}, CreatedDateTime: 2024-05-01, ExpiryTime: ]`;
  it("one change per scope per entry, with the grant's identity (consent type, principal, entry id)", () => {
    const changes = decodeEntraAppChanges(
      consent(
        `[] => [${entry("g1", USER, "Principal", "openid Mail.ReadWrite")}, ${entry("g2", "", "AllPrincipals", "User.Read.All")}]`,
        { admin: true },
      ),
    );
    expect(changes.map((c) => c.capability?.value)).toEqual(["openid", "Mail.ReadWrite", "User.Read.All"]);
    expect(changes[0].consent).toMatchObject({
      admin: true,
      allUsers: false,
      principalId: USER,
      entryId: "g1",
    });
    expect(changes[2].consent).toMatchObject({ allUsers: true, principalId: "", entryId: "g2" });
    expect(changes.every((c) => c.capability?.delegated)).toBe(true);
    expect(changes[1].posture).toContain("grants delegated permission Mail.ReadWrite");
    expect(changes[1].qualifiers).toContain("delegated — as the signed-in user, within that user's access");
  });
  it("the API of a consent entry is only an object id: unidentified, and the grade follows the delegated rules", () => {
    const low = decodeEntraAppChanges(
      consent(`[] => [${entry("g1", USER, "Principal", "openid profile User.Read")}]`),
    );
    expect(low.every((c) => c.severity === "Low")).toBe(true);
    const mid = one(
      decodeEntraAppChanges(consent(`[] => [${entry("g1", USER, "Principal", "Tasks.ReadWrite")}]`)),
    );
    expect(mid.severity).toBe("Medium");
    // The spelling alone never makes it Graph: Medium, with the reason in the words.
    const data = one(
      decodeEntraAppChanges(consent(`[] => [${entry("g1", USER, "Principal", "Mail.ReadWrite")}]`)),
    );
    expect(data.severity).toBe("Medium");
    expect(data.qualifiers).toContain("API not identified in this record");
    // With a tenant-scoped resolution of the resource's object id to Graph's app id (learned from
    // another record of the same export), the class applies and the grade follows it.
    const resolved = one(
      decodeEntraAppChanges(consent(`[] => [${entry("g1", USER, "Principal", "Mail.ReadWrite")}]`), (id) =>
        id === GRAPH_SP ? GRAPH_APP : "",
      ),
    );
    expect(resolved.resource.api).toBe("Microsoft Graph");
    expect(resolved.severity).toBe("High");
    expect(resolved.object).toContain("on Microsoft Graph");
    expect(resolved.qualifiers).not.toContain("API not identified in this record");
  });
  it("two users consenting the same scope to the same app are two rows", () => {
    const a = one(decodeEntraAppChanges(consent(`[] => [${entry("g1", USER, "Principal", "Mail.Read")}]`)));
    const b = one(decodeEntraAppChanges(consent(`[] => [${entry("g2", USER2, "Principal", "Mail.Read")}]`)));
    expect(a.aggKey).not.toBe(b.aggKey);
  });
  it("app-only consent grants APPLICATION permissions; admin consent for all users of a data scope is High", () => {
    const app = one(
      decodeEntraAppChanges(
        consent(`[] => [${entry("g1", "", "AllPrincipals", "Mail.Read")}]`, {
          admin: true,
          appOnly: true,
          all: true,
        }),
      ),
    );
    expect(app.capability?.delegated).toBe(false);
    expect(app.posture).toContain("grants application permission Mail.Read");
    const all = one(
      decodeEntraAppChanges(
        consent(`[] => [${entry("g1", "", "AllPrincipals", "Mail.Read")}]`, { admin: true, all: true }),
        (id) => (id === GRAPH_SP ? GRAPH_APP : ""),
      ),
    );
    expect(all.severity).toBe("High");
    expect(all.summary).toContain("admin consent");
    expect(all.summary).toContain("for all users");
  });
  it("a delegated permission grant record is read the same way", () => {
    const r = graph("Add delegated permission grant", [
      {
        type: "ServicePrincipal",
        id: GRAPH_SP,
        displayName: "Microsoft Graph",
        modifiedProperties: [
          P("DelegatedPermissionGrant.Scope", "Mail.Read Files.Read.All"),
          P("DelegatedPermissionGrant.ConsentType", "AllPrincipals"),
          P("ServicePrincipal.ObjectID", SP),
          P("TargetId.ServicePrincipalNames", [GRAPH_APP]),
        ],
      },
    ]);
    const changes = decodeEntraAppChanges(r);
    expect(changes.map((c) => c.capability?.value)).toEqual(["Mail.Read", "Files.Read.All"]);
    expect(changes[0].resource.api).toBe("Microsoft Graph");
    expect(changes[0].subject.id).toBe(SP);
    expect(changes[0].consent?.allUsers).toBe(true);
  });
});

describe("directory roles", () => {
  const role = (
    activity: string,
    member: { type: string; id: string; displayName?: string; userPrincipalName?: string },
    props: Prop[],
  ) => graph(activity, [{ ...member, modifiedProperties: props }]);
  it("a tier-0 role to a service principal is High and typed in the words", () => {
    const c = one(
      decodeEntraAppChanges(
        role("Add member to role", { type: "ServicePrincipal", id: SP, displayName: "svc-sync" }, [
          P("Role.DisplayName", "Global Administrator"),
          P("Role.TemplateId", GA),
          P("Role.ObjectID", "role-obj-1"),
        ]),
      ),
    );
    expect(c.kind).toBe("role-assigned");
    expect(c.posture).toBe("assigns directory role Global Administrator to service principal svc-sync");
    expect(c.role).toMatchObject({
      tier: "tier-0",
      templateId: GA,
      objectId: "role-obj-1",
      memberType: "ServicePrincipal",
    });
    expect(c.severity).toBe("High");
    expect(c.mitre).toContain("T1098.003");
  });
  it("an admin role is Medium; eligible and activation are kept in the words", () => {
    const admin = one(
      decodeEntraAppChanges(
        role(
          "Add eligible member to role",
          { type: "User", id: USER, userPrincipalName: "u@example.invalid" },
          [
            P("Role.DisplayName", "Exchange Administrator"),
            P("Role.TemplateId", "29232cdf-9323-42fd-ade2-1d097af3e4de"),
          ],
        ),
      ),
    );
    expect(admin.severity).toBe("Medium");
    expect(admin.posture).toContain("eligible");
    const act = one(
      decodeEntraAppChanges(
        role("Add member to role completed (PIM activation)", { type: "User", id: USER }, [
          P("Role.DisplayName", "Global Administrator"),
          P("Role.TemplateId", GA),
        ]),
      ),
    );
    expect(act.posture).toContain("activation");
  });
  it("two custom roles without a template id are two keys; a removal is Low", () => {
    const custom = (name: string, objectId: string) =>
      one(
        decodeEntraAppChanges(
          role("Add member to role", { type: "User", id: USER }, [
            P("Role.DisplayName", name),
            P("Role.ObjectID", objectId),
          ]),
        ),
      );
    expect(custom("Custom A", "obj-a").aggKey).not.toBe(custom("Custom B", "obj-b").aggKey);
    const noIds = (name: string) =>
      one(
        decodeEntraAppChanges(
          role("Add member to role", { type: "User", id: USER }, [P("Role.DisplayName", name)]),
        ),
      );
    expect(noIds("Custom A").aggKey).not.toBe(noIds("Custom B").aggKey);
    expect(
      one(
        decodeEntraAppChanges(
          role("Remove member from role", { type: "User", id: USER }, [
            P("Role.DisplayName", "Global Administrator"),
            P("Role.TemplateId", GA),
          ]),
        ),
      ).severity,
    ).toBe("Low");
  });
});

describe("keys and bounds", () => {
  it("two administrators making the same change are two rows", () => {
    const rec = (upn: string, id: string) =>
      graph(
        "Add member to role",
        [
          {
            type: "User",
            id: USER,
            modifiedProperties: [P("Role.DisplayName", "Global Administrator"), P("Role.TemplateId", GA)],
          },
        ],
        { initiatedBy: { user: { id, userPrincipalName: upn, ipAddress: "203.0.113.5" } } },
      );
    const a = one(decodeEntraAppChanges(rec("a@example.invalid", USER2)));
    const b = one(decodeEntraAppChanges(rec("b@example.invalid", "6f1b7a5e-5555-4eee-bfff-000000000005")));
    expect(a.aggKey).not.toBe(b.aggKey);
  });
  it("a consent with more scopes than the bound keeps the bound and adds one overflow row that says how much was cut", () => {
    const scopes = Array.from({ length: 50 }, (_, i) => `Scope.${i}`).join(" ");
    const r = graph("Consent to application", [
      {
        type: "ServicePrincipal",
        id: SP,
        modifiedProperties: [
          P("ConsentContext.IsAdminConsent", "True"),
          P(
            "ConsentAction.Permissions",
            `[] => [[Id: g1, ClientId: ${SP}, PrincipalId: , ResourceId: ${GRAPH_SP}, ConsentType: AllPrincipals, Scope: ${scopes}, CreatedDateTime: 2024-05-01, ExpiryTime: ]]`,
          ),
        ],
      },
    ]);
    const changes = decodeEntraAppChanges(r);
    expect(changes).toHaveLength(33);
    const overflow = changes[32];
    expect(overflow.posture).toBe("grant lists 18 more scopes than are shown");
    expect(overflow.qualifiers).toContain("truncated — the complete list is in the raw record");
    expect(overflow.severity).toBe("High");
  });
});

describe("credential bound", () => {
  it("an oversized credential list yields the bound plus one overflow row", () => {
    const many = Array.from({ length: 40 }, (_, i) => key(`k-${i}`, "Password", `s${i}`));
    const r = graph("Add service principal credentials", [
      {
        type: "ServicePrincipal",
        id: SP,
        displayName: "svc",
        modifiedProperties: [P("KeyDescription", JSON.stringify(many), JSON.stringify([]))],
      },
    ]);
    const changes = decodeEntraAppChanges(r);
    expect(changes).toHaveLength(17);
    expect(changes[16].posture).toBe("credential list adds 24 more than are shown");
    expect(changes[16].qualifiers).toContain("truncated — the complete list is in the raw record");
  });
});

describe("delegated-grant bound", () => {
  it("a 3,850-character scope string is bounded the same way as a consent, with one overflow row", () => {
    const scopeText = Array.from({ length: 700 }, (_, i) => `s${i}`).join(" ");
    expect(scopeText.length).toBeLessThanOrEqual(3850);
    const r = graph("Add delegated permission grant", [
      {
        type: "ServicePrincipal",
        id: GRAPH_SP,
        modifiedProperties: [
          P("DelegatedPermissionGrant.Scope", scopeText),
          P("DelegatedPermissionGrant.ConsentType", "AllPrincipals"),
          P("ServicePrincipal.ObjectID", SP),
          P("TargetId.ServicePrincipalNames", [GRAPH_APP]),
        ],
      },
    ]);
    const changes = decodeEntraAppChanges(r);
    expect(changes).toHaveLength(33);
    expect(changes[32].posture).toBe("grant lists 668 more scopes than are shown");
  });
});

describe("owners, unknown operations, UAL shape", () => {
  it("an owner added to a service principal names both", () => {
    const c = one(
      decodeEntraAppChanges(
        graph("Add owner to service principal", [
          { type: "User", id: USER, userPrincipalName: "u@example.invalid" },
          { type: "ServicePrincipal", id: SP, displayName: "svc-sync" },
        ]),
      ),
    );
    expect(c.kind).toBe("owner-added");
    expect(c.posture).toBe("adds owner u@example.invalid to service principal svc-sync");
    expect(c.subject.id).toBe(SP);
  });
  it("an operation outside the table yields no change", () => {
    expect(decodeEntraAppChanges(graph("Update user", [{ type: "User", id: USER }]))).toEqual([]);
  });
  it("the UAL shape of a role assignment decodes to the same change and, with a tenant, the same key", () => {
    const ual = readEntraAuditRecord({
      Id: "ual-1",
      CreationTime: "2024-05-01T10:00:00Z",
      Workload: "AzureActiveDirectory",
      Operation: "Add member to role.",
      ResultStatus: "Success",
      OrganizationId: "tenant-1",
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
        { Name: "Role.TemplateId", NewValue: GA, OldValue: "" },
      ],
    })!;
    const g = graph(
      "Add member to role",
      [
        {
          type: "ServicePrincipal",
          id: SP,
          displayName: "svc-sync",
          modifiedProperties: [P("Role.DisplayName", "Global Administrator"), P("Role.TemplateId", GA)],
        },
      ],
      { tenantId: "tenant-1" },
    );
    const a = one(decodeEntraAppChanges(ual));
    const b = one(decodeEntraAppChanges(g));
    expect(a.posture).toBe(b.posture);
    expect(a.aggKey).toBe(b.aggKey);
  });
});
