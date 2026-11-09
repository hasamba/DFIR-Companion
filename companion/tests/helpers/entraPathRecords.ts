// Synthetic Entra records that form a full four-stage privilege path (credential → privileged grant
// → matched sign-in → consistent action), the shapes entraPrivilegePath.test.ts uses. Documentation
// GUIDs, example.invalid names and TEST-NET addresses only. Used by the live-collection summary
// tests (#2493), where the directory audits and the sign-ins are saved as separate sources.

const SP = "2b7f3c1a-1111-4aaa-8bbb-000000000001";
const GRAPH_SP = "3c8e4d2b-2222-4bbb-9ccc-000000000002";
const GRAPH_APP = "00000003-0000-0000-c000-000000000000";
const USER = "4d9f5e3c-3333-4ccc-addd-000000000003";
const GA = "62e90394-69f5-4237-9190-012177145e10";
export const PATH_APP = "5e0a6f4d-4444-4ddd-beee-000000000004";
const TENANT = "6f1b7a5e-5555-4eee-8fff-000000000006";
const T = "2024-05-01T10:00:00Z";
const at = (s: number) => new Date(Date.parse(T) + s * 1000).toISOString();
const key = (k: string, t: string, d: string) =>
  `[KeyIdentifier=${k},KeyType=${t},KeyUsage=Verify,DisplayName=${d}]`;
const P = (displayName: string, newValue: unknown, oldValue: unknown = null) => ({
  displayName,
  oldValue,
  newValue,
});
type Row = Record<string, unknown>;

const graph = (id: string, activity: string, targets: unknown[], over: Row = {}): Row => ({
  id,
  activityDateTime: T,
  activityDisplayName: activity,
  result: "success",
  initiatedBy: { user: { id: USER, userPrincipalName: "admin@example.invalid", ipAddress: "203.0.113.5" } },
  targetResources: targets,
  tenantId: TENANT,
  ...over,
});

/** The directory audit that adds the new client secret "k-new" to the app's service principal. */
export const pathCredential = (): Row =>
  graph("rec-cred", "Add service principal credentials", [
    {
      type: "ServicePrincipal",
      id: SP,
      displayName: "Sync",
      modifiedProperties: [
        P(
          "KeyDescription",
          JSON.stringify([key("k-old", "Password", "old"), key("k-new", "Password", "deploy")]),
          JSON.stringify([key("k-old", "Password", "old")]),
        ),
      ],
    },
  ]);

/** The directory audit that grants RoleManagement.ReadWrite.Directory on Microsoft Graph. */
export const pathGrant = (): Row =>
  graph(
    "rec-grant",
    "Add app role assignment to service principal",
    [
      {
        type: "ServicePrincipal",
        id: GRAPH_SP,
        displayName: "Microsoft Graph",
        modifiedProperties: [
          P("AppRole.Id", "role-id-1"),
          P("AppRole.Value", "RoleManagement.ReadWrite.Directory"),
          P("ServicePrincipal.AppId", PATH_APP),
          P("ServicePrincipal.DisplayName", "Sync"),
          P("ServicePrincipal.ObjectID", SP),
          P("TargetId.ServicePrincipalNames", [GRAPH_APP]),
        ],
      },
    ],
    { activityDateTime: at(120) },
  );

/** The app's successful service-principal sign-in with the new credential. */
export const pathSignIn = (): Row => ({
  id: "sp-signin-1",
  createdDateTime: at(300),
  appId: PATH_APP,
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
});

/** The directory audit of the app acting: adding a user to Global Administrator. */
export const pathAction = (): Row =>
  graph(
    "rec-action",
    "Add member to role",
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
      initiatedBy: { app: { appId: PATH_APP, servicePrincipalId: SP, displayName: "Sync" } },
    },
  );

/** A failed Entra user sign-in from one spraying address (the m365 spray fixtures' shape). */
export function spraySignIn(upn: string, minute: number): Row {
  return {
    id: `spray-${upn}`,
    createdDateTime: new Date(Date.parse("2026-06-01T00:00:00Z") + minute * 60_000).toISOString(),
    userPrincipalName: upn,
    appDisplayName: "Azure CLI",
    ipAddress: "198.51.100.9",
    status: { errorCode: 50126 },
    resourceTenantId: "tenant-a",
  };
}
