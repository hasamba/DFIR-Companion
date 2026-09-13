import { describe, it, expect } from "vitest";
import { parseM365Audit } from "../../src/analysis/m365Import.js";
import {
  entraPrivilegePaths,
  learnSubjectResolver,
  OPERATION_PERMISSIONS,
  PRIVILEGE_PATH_WINDOW_DAYS,
  PRIVILEGE_PATHS_MAX,
  STEPS_PER_APP_MAX,
} from "../../src/analysis/entraPrivilegePath.js";
import { correlateEvents } from "../../src/analysis/correlate.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";
import { learnApiResolver } from "../../src/analysis/entraAuditImport.js";
import { canonicalEventEnvelopeSchema } from "../../src/analysis/canonicalEvent.js";

// #931 item 1, second half (#973): the privilege path per application, built over one export.

const SP = "2b7f3c1a-1111-4aaa-8bbb-000000000001";
const SP2 = "2b7f3c1a-1111-4aaa-8bbb-000000000009";
const GRAPH_SP = "3c8e4d2b-2222-4bbb-9ccc-000000000002";
const GRAPH_APP = "00000003-0000-0000-c000-000000000000";
const USER = "4d9f5e3c-3333-4ccc-addd-000000000003";
const GA = "62e90394-69f5-4237-9190-012177145e10";
const APP = "5e0a6f4d-4444-4ddd-beee-000000000004";
const APP2 = "5e0a6f4d-4444-4ddd-beee-000000000005";
const TENANT = "6f1b7a5e-5555-4eee-8fff-000000000006";
const T = "2024-05-01T10:00:00Z";
const at = (s: number) => new Date(Date.parse(T) + s * 1000).toISOString();
const key = (k: string, t: string, d: string) =>
  `[KeyIdentifier=${k},KeyType=${t},KeyUsage=Verify,DisplayName=${d}]`;
type Prop = { displayName: string; oldValue: unknown; newValue: unknown };
const P = (name: string, newValue: unknown, oldValue: unknown = null): Prop => ({
  displayName: name,
  oldValue,
  newValue,
});
let n = 0;
const graph = (activity: string, targets: unknown[], over: Record<string, unknown> = {}) => ({
  id: `rec-${++n}`,
  activityDateTime: T,
  activityDisplayName: activity,
  result: "success",
  initiatedBy: { user: { id: USER, userPrincipalName: "admin@example.invalid", ipAddress: "203.0.113.5" } },
  targetResources: targets,
  tenantId: TENANT,
  ...over,
});
const credential = (over: Record<string, unknown> = {}, sp = SP, k = "k-new") =>
  graph(
    "Add service principal credentials",
    [
      {
        type: "ServicePrincipal",
        id: sp,
        displayName: "Sync",
        modifiedProperties: [
          P(
            "KeyDescription",
            JSON.stringify([key("k-old", "Password", "old"), key(k, "Password", "deploy")]),
            JSON.stringify([key("k-old", "Password", "old")]),
          ),
        ],
      },
    ],
    over,
  );
const grant = (value: string, over: Record<string, unknown> = {}, sp = SP, app = APP) =>
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
          P("ServicePrincipal.AppId", app),
          P("ServicePrincipal.DisplayName", "Sync"),
          P("ServicePrincipal.ObjectID", sp),
          P("TargetId.ServicePrincipalNames", [GRAPH_APP]),
        ],
      },
    ],
    over,
  );
const role = (over: Record<string, unknown> = {}, activity = "Add member to role") =>
  graph(
    activity,
    [
      {
        type: "ServicePrincipal",
        id: SP,
        displayName: "Sync",
        modifiedProperties: [
          P("Role.DisplayName", "Global Administrator"),
          P("Role.TemplateId", GA),
          P("Role.ObjectID", "role-obj-1"),
        ],
      },
    ],
    over,
  );
const signIn = (over: Record<string, unknown> = {}) => ({
  id: `sp-${++n}`,
  createdDateTime: at(300),
  appId: APP,
  servicePrincipalId: SP,
  servicePrincipalName: "Sync",
  resourceDisplayName: "Microsoft Graph",
  resourceServicePrincipalId: GRAPH_SP,
  resourceId: GRAPH_APP,
  ipAddress: "198.51.100.7",
  clientCredentialType: "clientSecret",
  servicePrincipalCredentialKeyId: "k-new",
  resourceTenantId: TENANT,
  status: { errorCode: 0 },
  ...over,
});
const action = (activity = "Add member to role", over: Record<string, unknown> = {}) =>
  graph(
    activity,
    [
      {
        type: "User",
        id: USER,
        userPrincipalName: "victim@example.invalid",
        modifiedProperties: [P("Role.DisplayName", "Global Administrator"), P("Role.TemplateId", GA)],
      },
    ],
    {
      activityDateTime: at(360),
      initiatedBy: { app: { appId: APP, servicePrincipalId: SP, displayName: "Sync" } },
      ...over,
    },
  );
const paths = (records: Record<string, unknown>[]) => entraPrivilegePaths(records, learnApiResolver(records));
const importPaths = (records: Record<string, unknown>[]) =>
  parseM365Audit(JSON.stringify(records), { aggregate: false }).events.filter((e) =>
    e.description.startsWith("Entra privilege path:"),
  );

describe("the full path", () => {
  it("credential → privileged grant → matched successful sign-in → consistent action: High, every stage named with its record", () => {
    const rows = paths([
      credential(),
      grant("RoleManagement.ReadWrite.Directory", { activityDateTime: at(120) }),
      signIn(),
      action(),
    ]);
    expect(rows).toHaveLength(1);
    const r = rows[0];
    expect(r.severity).toBe("High");
    expect(r.mitre).toEqual(["T1098.001"]);
    expect(r.description).toContain(
      `Entra privilege path: Sync (app id ${APP}) [${T.replace("Z", ".000Z")} credential added by admin@example.invalid: Password k-new "deploy"; `,
    );
    expect(r.description).toContain(
      "privileged capability granted by admin@example.invalid: application permission RoleManagement.ReadWrite.Directory on Microsoft Graph (directory RBAC)",
    );
    expect(r.description).toContain(
      "signed in → Microsoft Graph (clientSecret k-new) — with the new credential",
    );
    expect(r.description).toContain(
      "acted: Add member to role — consistent with the granted RoleManagement.ReadWrite.Directory; the authorization the token carried is not in the record",
    );
    expect(r.description).toContain("all four stages in order]");
    expect(r.description).not.toMatch(/exercised|enabled|automation|rotation/);
    expect(canonicalEventEnvelopeSchema.safeParse(r.canonical).success).toBe(true);
    expect(r.canonical?.entra).toMatchObject({
      appId: APP,
      tenant: TENANT,
      stages: 4,
      windowDays: PRIVILEGE_PATH_WINDOW_DAYS,
    });
    expect(r.canonical?.entra?.steps.map((s) => s.stage)).toEqual([
      "credential",
      "grant",
      "sign-in",
      "action",
    ]);
    expect(r.canonical?.evidence.rawRecords.map((x) => x.locator)).toEqual([
      "record:0",
      "record:1",
      "record:2",
      "record:3",
    ]);
  });

  it("a tier-0 directory role is a privileged grant too, with T1098.003; a data-class grant is not privileged", () => {
    const withRole = paths([credential(), role({ activityDateTime: at(120) }), signIn(), action()]);
    expect(withRole[0].severity).toBe("High");
    expect(withRole[0].mitre).toEqual(["T1098.001", "T1098.003"]);
    expect(withRole[0].description).toContain(
      "privileged directory role assigned by admin@example.invalid: Global Administrator (can take over the tenant)",
    );
    expect(withRole[0].description).toContain("consistent with the tier-0 directory role granted");
    const data = paths([credential(), grant("Mail.Read", { activityDateTime: at(120) }), signIn(), action()]);
    expect(data[0].severity).toBe("Medium");
    expect(data[0].description).toContain("no privileged capability granted inside the window");
    expect(data[0].description).toContain(
      "needs RoleManagement.ReadWrite.Directory, not among the permissions live at that time",
    );
  });
});

describe("what is never claimed", () => {
  it("an unmatched key, a rejected matched attempt, an unmapped operation and a mapped-but-not-granted one are each said", () => {
    const unmatched = paths([
      credential(),
      grant("RoleManagement.ReadWrite.Directory", { activityDateTime: at(120) }),
      signIn({ servicePrincipalCredentialKeyId: "k-9" }),
    ]);
    expect(unmatched[0].severity).toBe("Low");
    expect(unmatched[0].description).toContain(
      "no successful sign-in with the new credential inside the window among the 1 sign-in records of this export (2024-05-01 → 2024-05-01)",
    );
    const rejected = paths([
      credential(),
      grant("RoleManagement.ReadWrite.Directory", { activityDateTime: at(120) }),
      signIn({ status: { errorCode: 7000215 } }),
    ]);
    expect(rejected[0].severity).toBe("Low");
    expect(rejected[0].description).not.toContain("signed in");
    const unmapped = paths([
      credential(),
      grant("RoleManagement.ReadWrite.Directory", { activityDateTime: at(120) }),
      signIn(),
      action("Update group"),
    ]);
    expect(unmapped[0].severity).toBe("Medium");
    expect(unmapped[0].description).toContain(
      "acted: Update group — the action's required permission was not mapped",
    );
    const notGranted = paths([
      credential(),
      grant("AppRoleAssignment.ReadWrite.All", { activityDateTime: at(120) }),
      signIn(),
      action(),
    ]);
    expect(notGranted[0].severity).toBe("Medium");
    expect(notGranted[0].description).toContain(
      "needs RoleManagement.ReadWrite.Directory, not among the permissions live at that time",
    );
    expect(OPERATION_PERMISSIONS.get("add app role assignment to service principal")).toEqual([
      ["AppRoleAssignment.ReadWrite.All"],
    ]);
    // Owner operations need the read permission as well as the write: a conjunction, not two alternatives.
    expect(OPERATION_PERMISSIONS.get("add owner to application")).toEqual([
      ["Application.ReadWrite.All", "Directory.Read.All"],
      ["Application.ReadWrite.OwnedBy", "Directory.Read.All"],
    ]);
  });

  it("absence rests on the export: no sign-in records at all → 'sign-in log not in this export'", () => {
    const rows = paths([
      credential(),
      grant("RoleManagement.ReadWrite.Directory", { activityDateTime: at(120) }),
    ]);
    expect(rows[0].severity).toBe("Low");
    expect(rows[0].description).toContain("sign-in log not in this export");
    expect(rows[0].description).toContain("two of four stages");
  });

  it("removals end the interval; an eligible role and a delegated grant are not steps; an attempt is not a step", () => {
    const removed = paths([
      credential(),
      grant("RoleManagement.ReadWrite.Directory", { activityDateTime: at(120) }),
      graph(
        "Remove service principal credentials",
        [
          {
            type: "ServicePrincipal",
            id: SP,
            displayName: "Sync",
            modifiedProperties: [
              P(
                "KeyDescription",
                JSON.stringify([key("k-old", "Password", "old")]),
                JSON.stringify([key("k-old", "Password", "old"), key("k-new", "Password", "deploy")]),
              ),
            ],
          },
        ],
        { activityDateTime: at(200) },
      ),
      signIn(),
    ]);
    expect(removed[0].severity).toBe("Low");
    expect(removed[0].description).toContain("credential k-new removed by admin@example.invalid");
    const eligible = paths([
      credential(),
      role({ activityDateTime: at(120) }, "Add eligible member to role"),
      signIn(),
    ]);
    expect(eligible[0].severity).toBe("Low");
    expect(eligible[0].description).toContain("no capability granted inside the window");
    const failed = paths([credential({ result: "failure" }), grant("RoleManagement.ReadWrite.Directory")]);
    expect(failed).toHaveLength(0);
  });

  it("steps outside the 30-day window are listed, not counted; a lone step is no row", () => {
    const late = paths([
      credential(),
      grant("RoleManagement.ReadWrite.Directory", { activityDateTime: at(40 * 86400) }),
      signIn({ createdDateTime: at(41 * 86400) }),
    ]);
    expect(late).toHaveLength(0);
    const partial = paths([
      credential(),
      grant("RoleManagement.ReadWrite.Directory", { activityDateTime: at(120) }),
      signIn({ createdDateTime: at(40 * 86400) }),
    ]);
    expect(partial[0].severity).toBe("Low");
    expect(partial[0].description).toContain("outside the 30-day window: ");
    expect(paths([credential()])).toHaveLength(0);
    expect(paths([grant("RoleManagement.ReadWrite.Directory")])).toHaveLength(0);
  });
});

describe("identity", () => {
  it("joins through the app id only: two applications named Sync are two findings; a name is never a join", () => {
    const rows = paths([
      credential({}, SP, "k-a"),
      grant("RoleManagement.ReadWrite.Directory", { activityDateTime: at(120) }, SP, APP),
      credential({}, SP2, "k-b"),
      grant("RoleManagement.ReadWrite.Directory", { activityDateTime: at(120) }, SP2, APP2),
      signIn({ servicePrincipalCredentialKeyId: "k-a" }),
    ]);
    expect(rows).toHaveLength(2);
    expect(rows.map((r) => r.severity).sort()).toEqual(["Low", "Medium"]);
    expect(rows.map((r) => r.aggKey)).not.toContain(rows[0].aggKey === rows[1].aggKey ? rows[0].aggKey : "");
  });

  it("an object id links to an app id only through a record that states both; otherwise the change is counted as not joined", () => {
    const resolver = learnSubjectResolver([signIn()], "");
    expect(resolver(SP, TENANT)).toBe(APP);
    expect(resolver(SP2, TENANT)).toBe("");
    const rows = paths([
      credential({}, SP2),
      grant("RoleManagement.ReadWrite.Directory", { activityDateTime: at(120) }, SP, APP),
      credential({ activityDateTime: at(60) }),
      signIn(),
    ]);
    expect(rows).toHaveLength(1);
    expect(rows[0].description).toContain(
      "1 change named an application by an id no record of this export links to an app id — not joined]",
    );
  });

  it("the initiator is named on every step; an application initiator is said to be one", () => {
    const rows = paths([
      credential({
        initiatedBy: { app: { appId: "app-deploy", servicePrincipalId: SP2, displayName: "Deployer" } },
      }),
      grant("RoleManagement.ReadWrite.Directory", { activityDateTime: at(120) }),
    ]);
    expect(rows[0].description).toContain("credential added by Deployer (an application, not a user)");
  });
});

describe("episodes, bounds, identity of the row", () => {
  it("every credential opens an episode; the finding is the best one and names the others", () => {
    const rows = paths([
      credential({}, SP, "k-a"),
      grant("RoleManagement.ReadWrite.Directory", { activityDateTime: at(120) }),
      credential({ activityDateTime: at(45 * 86400) }, SP, "k-b"),
      grant("RoleManagement.ReadWrite.Directory", { activityDateTime: at(45 * 86400 + 60) }),
      signIn({ createdDateTime: at(45 * 86400 + 120), servicePrincipalCredentialKeyId: "k-b" }),
    ]);
    expect(rows).toHaveLength(1);
    expect(rows[0].severity).toBe("Medium");
    expect(rows[0].description).toContain("1 other episode: Low");
  });

  it("the row's identity is the (tenant, app id) tuple; a re-import folds; the importer emits it beside the rows", () => {
    const records = [
      credential(),
      grant("RoleManagement.ReadWrite.Directory", { activityDateTime: at(120) }),
      signIn(),
      action(),
    ];
    const a = importPaths(records);
    const b = importPaths(records);
    expect(a).toHaveLength(1);
    expect(a[0].aggKey).toBe(b[0].aggKey);
    expect(a[0].aggKey).toMatch(/^entra-privilege-path\|[0-9a-f]{32}$/);
    const both = parseM365Audit(JSON.stringify([...records, ...records]), { aggregate: true });
    expect(both.events.filter((e) => e.description.startsWith("Entra privilege path:"))).toHaveLength(1);
  });

  it("hostile names are neutralised; bounds: more than 256 applications → the rest counted", () => {
    const evil = paths([
      credential({
        targetResources: [
          {
            type: "ServicePrincipal",
            id: SP,
            displayName: "Sync] [fake: x",
            modifiedProperties: [P("KeyDescription", JSON.stringify([key("k-new", "Password", "d")]), "[]")],
          },
        ],
      }),
      grant("RoleManagement.ReadWrite.Directory", { activityDateTime: at(120) }),
    ]);
    expect(evil[0].description).not.toContain("] [fake");
    const many = Array.from({ length: PRIVILEGE_PATHS_MAX + 3 }, (_, i) => {
      const sp = `2b7f3c1a-1111-4aaa-8bbb-${String(i).padStart(12, "0")}`;
      return [
        credential({}, sp, `k-${i}`),
        grant(
          "RoleManagement.ReadWrite.Directory",
          { activityDateTime: at(120) },
          sp,
          `5e0a6f4d-4444-4ddd-beee-${String(i).padStart(12, "0")}`,
        ),
      ];
    }).flat();
    const rows = paths(many);
    expect(rows).toHaveLength(PRIVILEGE_PATHS_MAX + 1);
    expect(rows[rows.length - 1].description).toContain(
      "3 further applications with a path in this export beyond the 256 reported — not shown",
    );
  });
});

// Code round 1 (Codex): the cases the review named.
describe("code round 1", () => {
  const TENANT2 = "6f1b7a5e-5555-4eee-8fff-000000000007";
  const removeCredential = (k: string, at_: string, sp = SP) =>
    graph(
      "Remove service principal credentials",
      [
        {
          type: "ServicePrincipal",
          id: sp,
          displayName: "Sync",
          modifiedProperties: [
            P("KeyDescription", JSON.stringify([]), JSON.stringify([key(k, "Password", "deploy")])),
          ],
        },
      ],
      { activityDateTime: at_ },
    );

  it("a failed action is excluded from the stages; a success by the same application counts", () => {
    const failed = paths([
      credential(),
      grant("RoleManagement.ReadWrite.Directory", { activityDateTime: at(120) }),
      signIn(),
      action("Add member to role", { result: "failure" }),
    ]);
    expect(failed[0].severity).toBe("Medium");
    expect(failed[0].description).toContain("three of four stages");
    expect(failed[0].description).not.toContain("all four stages");
  });

  it("two credentials live at once: a sign-in matches only the episode of its own key id", () => {
    const rows = paths([
      credential({}, SP, "k-a"),
      credential({ activityDateTime: at(60) }, SP, "k-b"),
      grant("RoleManagement.ReadWrite.Directory", { activityDateTime: at(120) }),
      signIn({ servicePrincipalCredentialKeyId: "k-b" }),
      action(),
    ]);
    expect(rows).toHaveLength(1);
    expect(rows[0].severity).toBe("High");
    expect(rows[0].description).toContain("Password k-b");
    expect(rows[0].description).toContain("1 other episode: Medium");
    expect(rows[0].canonical?.entra?.steps.find((s) => s.stage === "credential")?.keyId).toBe("k-b");
  });

  it("a thumbprint-only sign-in never matches a key id", () => {
    const rows = paths([
      credential(),
      grant("RoleManagement.ReadWrite.Directory", { activityDateTime: at(120) }),
      signIn({ servicePrincipalCredentialKeyId: undefined, servicePrincipalCredentialThumbprint: "k-new" }),
    ]);
    expect(rows[0].severity).toBe("Low");
    expect(rows[0].description).toContain("identified by thumbprint only, not matched to a key id");
    expect(rows[0].description).not.toContain("— with the new credential");
  });

  it("order is a subsequence: a sign-in before the grant, or an action before the sign-in, is not a stage", () => {
    const early = paths([
      credential(),
      signIn({ createdDateTime: at(60) }),
      grant("RoleManagement.ReadWrite.Directory", { activityDateTime: at(120) }),
      action(),
    ]);
    // credential < grant < action: the action is consistent with the grant, but no sign-in sits between.
    expect(early[0].severity).toBe("Medium");
    expect(early[0].description).toContain("no successful sign-in with the new credential inside the window");
    expect(early[0].description).toContain("— with the new credential, before the grant");
    const before = paths([
      credential(),
      grant("RoleManagement.ReadWrite.Directory", { activityDateTime: at(120) }),
      action("Add member to role", { activityDateTime: at(200) }),
      signIn(),
    ]);
    expect(before[0].severity).toBe("Medium");
    expect(before[0].description).toContain(
      "no consistent directory change by this application inside the window",
    );
  });

  it("a revoked grant is not live for a later action; a re-grant after the revocation is", () => {
    const revoke = graph(
      "Remove app role assignment from service principal",
      [
        {
          type: "ServicePrincipal",
          id: GRAPH_SP,
          displayName: "Microsoft Graph",
          modifiedProperties: [
            P("AppRole.Value", null, "RoleManagement.ReadWrite.Directory"),
            P("ServicePrincipal.AppId", APP),
            P("ServicePrincipal.ObjectID", SP),
          ],
        },
      ],
      { activityDateTime: at(240) },
    );
    const revoked = paths([
      credential(),
      grant("RoleManagement.ReadWrite.Directory", { activityDateTime: at(120) }),
      revoke,
      signIn(),
      action(),
    ]);
    expect(revoked[0].severity).toBe("Medium");
    expect(revoked[0].description).toContain("not among the permissions live at that time");
    const regranted = paths([
      credential(),
      grant("RoleManagement.ReadWrite.Directory", { activityDateTime: at(120) }),
      revoke,
      signIn(),
      grant("RoleManagement.ReadWrite.Directory", { activityDateTime: at(330) }),
      action(),
    ]);
    expect(regranted[0].severity).toBe("High");
    // A credential removed before the sign-in ends its interval: the later sign-in is not a use.
    const removed = paths([
      credential(),
      grant("RoleManagement.ReadWrite.Directory", { activityDateTime: at(120) }),
      removeCredential("k-new", at(200)),
      signIn(),
    ]);
    expect(removed[0].severity).toBe("Low");
  });

  it("the resolver learns only from one target tuple: an object id on one target and an app id on another teach nothing", () => {
    const crossed = graph("Add app role assignment to service principal", [
      { type: "ServicePrincipal", id: GRAPH_SP, modifiedProperties: [P("ServicePrincipal.ObjectID", SP2)] },
      { type: "ServicePrincipal", id: SP, modifiedProperties: [P("ServicePrincipal.AppId", APP2)] },
    ]);
    const resolver = learnSubjectResolver([crossed], "");
    expect(resolver(SP2, TENANT)).toBe("");
    // The second target IS the application the app id is stated on.
    expect(resolver(SP, TENANT)).toBe(APP2.toLowerCase());
    // Two records that disagree on one object id teach nothing for it.
    const conflict = learnSubjectResolver([signIn(), signIn({ appId: APP2 })], "");
    expect(conflict(SP, TENANT)).toBe("");
    // A non-GUID app id is never an identity.
    expect(learnSubjectResolver([signIn({ appId: "Sync" })], "")(SP, TENANT)).toBe("");
  });

  it("Graph directory audits name no tenant: they join the export's sign-ins only when those name one tenant", () => {
    const untagged = (r: Record<string, unknown>) => {
      const { tenantId: _t, ...rest } = r;
      return rest;
    };
    const one = paths([
      untagged(credential()),
      untagged(grant("RoleManagement.ReadWrite.Directory", { activityDateTime: at(120) })),
      signIn(),
      untagged(action()),
    ]);
    expect(one).toHaveLength(1);
    expect(one[0].severity).toBe("High");
    expect(one[0].canonical?.entra?.tenant).toBe(TENANT.toLowerCase());
    const two = paths([
      untagged(credential()),
      untagged(grant("RoleManagement.ReadWrite.Directory", { activityDateTime: at(120) })),
      signIn(),
      signIn({ resourceTenantId: TENANT2, servicePrincipalId: SP2, appId: APP2 }),
      untagged(action()),
    ]);
    // Two tenants among the sign-ins: the tenantless audits join no sign-in, and say so.
    expect(two[0].severity).toBe("Medium");
    expect(two[0].description).toContain(
      "the sign-in records of this export name 2 tenants and the directory-audit records name none — not joined",
    );
    expect(two[0].canonical?.entra?.tenant).toBeUndefined();
  });

  it("owner operations need the read permission as well: the conjunction is checked, an alternative met suffices", () => {
    const owner = (extra: string[]) =>
      paths([
        credential(),
        ...extra.map((v, i) => grant(v, { activityDateTime: at(120 + i) })),
        signIn(),
        action("Add owner to application"),
      ]);
    expect(owner(["Application.ReadWrite.All"])[0].description).toContain(
      "needs Application.ReadWrite.All + Directory.Read.All or Application.ReadWrite.OwnedBy + Directory.Read.All, not among the permissions live at that time",
    );
    expect(owner(["Application.ReadWrite.OwnedBy", "Directory.Read.All"])[0].description).toContain(
      "consistent with the granted Application.ReadWrite.OwnedBy + Directory.Read.All",
    );
  });

  it("the summary rows are appended after the cap: a cap of one keeps the source row AND the path", () => {
    const records = [
      credential(),
      grant("RoleManagement.ReadWrite.Directory", { activityDateTime: at(120) }),
      signIn(),
      action(),
    ];
    const r = parseM365Audit(JSON.stringify(records), { aggregate: false, maxEvents: 1 });
    const summaries = r.events.filter((e) => e.description.startsWith("Entra privilege path:"));
    expect(summaries).toHaveLength(1);
    expect(r.events.length - summaries.length).toBe(1);
  });

  it("a matching record outside the window is listed beside the scoped absence, never contradicted", () => {
    const rows = paths([
      credential(),
      grant("RoleManagement.ReadWrite.Directory", { activityDateTime: at(120) }),
      signIn({ createdDateTime: at(40 * 86400) }),
    ]);
    expect(rows[0].description).toContain(
      "no successful sign-in with the new credential inside the window among the 1 sign-in records",
    );
    expect(rows[0].description).toContain("outside the 30-day window: 2024-06-10");
    expect(rows[0].canonical?.entra?.outsideWindow).toBe(1);
  });

  it("a re-import of the same export folds at merge: two parses, one row", () => {
    const records = [
      credential(),
      grant("RoleManagement.ReadWrite.Directory", { activityDateTime: at(120) }),
      signIn(),
      action(),
    ];
    const asEvents = (tag: string): ForensicEvent[] =>
      importPaths(records).map(
        (e, i) =>
          ({
            ...e,
            id: `${tag}-${i}`,
            relatedFindingIds: [],
            sourceScreenshots: [],
            sources: ["Entra audit"],
          }) as unknown as ForensicEvent,
      );
    expect(correlateEvents([...asEvents("a"), ...asEvents("b")])).toHaveLength(1);
  });

  it("stress: steps past the per-application bound are counted, never read; the pass stays linear", () => {
    const many = [
      credential(),
      grant("RoleManagement.ReadWrite.Directory", { activityDateTime: at(120) }),
      ...Array.from({ length: STEPS_PER_APP_MAX + 5 }, (_, i) => signIn({ createdDateTime: at(300 + i) })),
    ];
    const started = Date.now();
    const rows = paths(many);
    expect(Date.now() - started).toBeLessThan(5000);
    expect(rows).toHaveLength(1);
    expect(rows[0].description).toMatch(/\d+ steps beyond the bound, not evaluated/);
  });
});
