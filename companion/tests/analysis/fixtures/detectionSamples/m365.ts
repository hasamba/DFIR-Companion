// Microsoft 365 / Entra samples for the detection-overlap check (#2348): UAL records, Entra sign-ins
// and Entra directory-audit records, copied from tagsYamlCloudGaps, tagsYamlTimesketchM365,
// tagsYamlSigmaOverlap and sigmaCloudImport. The originals stay in their tests.
import { sample, type DetectionSample } from "./types.js";

/** An Entra sign-in in the Graph shape — the base for sign-in samples and Sigma-built ones. */
export const signInBase = (o: Record<string, unknown> = {}): Record<string, unknown> => ({
  id: "dddddddd-0000-4000-8000-000000000001",
  createdDateTime: "2026-03-01T10:00:00Z",
  userPrincipalName: "alice@example.test",
  appDisplayName: "Azure Portal",
  ipAddress: "198.51.100.7",
  clientAppUsed: "Browser",
  userAgent: "Mozilla/5.0",
  status: { errorCode: 0 },
  deviceDetail: { isCompliant: true, trustType: "AzureAd" },
  location: { city: "Paris", countryOrRegion: "FR" },
  resourceTenantId: "11111111-1111-4111-8111-111111111111",
  ...o,
});

/** An Entra directory-audit record in the Graph shape — the base for audit samples. */
/** A unified-audit-log record (#2500): an operation the importer does not grade, so a rule's own
 * `Operation` overwrites it. */
export const ualBase = (o: Record<string, unknown> = {}): Record<string, unknown> => ({
  CreationTime: "2026-03-01T10:00:00",
  Id: "00000000-0000-0000-0000-0000000000c1",
  Operation: "MailItemsAccessed",
  OrganizationId: "00000000-0000-0000-0000-0000000000aa",
  RecordType: 2,
  ResultStatus: "Succeeded",
  UserKey: "user@example.com",
  UserType: 0,
  Workload: "Exchange",
  ClientIP: "198.51.100.10",
  UserId: "user@example.com",
  ...o,
});

/** An Azure Activity Log event, REST shape (#2500): a neutral read a rule's operationName overwrites. */
export const azureActivityBase = (o: Record<string, unknown> = {}): Record<string, unknown> => ({
  eventTimestamp: "2026-03-01T10:00:00Z",
  caller: "user@example.com",
  correlationId: "00000000-0000-0000-0000-0000000000c2",
  resourceId: "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg1",
  operationName: { value: "Microsoft.Resources/subscriptions/resourceGroups/read" },
  status: { value: "Succeeded" },
  httpRequest: { clientIpAddress: "198.51.100.10" },
  ...o,
});

export const auditBase = (o: Record<string, unknown> = {}): Record<string, unknown> => ({
  id: "aaaaaaaa-0000-4000-8000-000000000001",
  activityDateTime: "2026-03-01T10:00:00Z",
  activityDisplayName: "Update user",
  category: "UserManagement",
  result: "success",
  loggedByService: "Core Directory",
  initiatedBy: { user: { userPrincipalName: "alice@example.test", ipAddress: "198.51.100.4" } },
  targetResources: [{ id: "t1", displayName: "user1", type: "User" }],
  ...o,
});

/** A flat UAL record (Operation + Workload at the top level). */
const ual = (Workload: string, Operation: string, extra: Record<string, unknown> = {}) => ({
  CreationTime: "2026-01-01T00:00:00",
  Id: "aaaaaaaa-0000-4000-8000-000000000101",
  Operation,
  Workload,
  RecordType: 1,
  UserId: "admin@example.com",
  ClientIP: "198.51.100.4",
  OrganizationId: "11111111-1111-4111-8111-111111111111",
  ResultStatus: "Succeeded",
  ...extra,
});
const exchange = (op: string, params: Array<[string, string]> = []) =>
  ual("Exchange", op, { Parameters: params.map(([Name, Value]) => ({ Name, Value })) });
const aad = (op: string) => ual("AzureActiveDirectory", op, { RecordType: 8 });

const GAPS = "tagsYamlCloudGaps";
const TS = "tagsYamlTimesketchM365";
const SIGMA = "sigmaCloudImport / tagsYamlSigmaOverlap";
const m = (id: string, from: string, record: Record<string, unknown>) => sample("m365", id, from, record);

const BROWSER =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36";
const TEAMFILTRATION =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Teams/1.3.00.30866 Chrome/80.0.3987.165 Electron/8.5.1 Safari/537.36";

export const M365_SAMPLES: readonly DetectionSample[] = [
  // ── UAL (no Sigma path: the bundled rules read Entra sign-in and audit logs only) ──
  m(
    "ual.Set-AdminAuditLogConfig",
    GAPS,
    exchange("Set-AdminAuditLogConfig", [["UnifiedAuditLogIngestionEnabled", "False"]]),
  ),
  m("ual.New-InboundConnector", GAPS, exchange("New-InboundConnector", [["Name", "c1"]])),
  m("ual.Enable-InboxRule", GAPS, exchange("Enable-InboxRule", [["Identity", "r"]])),
  m(
    "ual.Add-RecipientPermission",
    GAPS,
    exchange("Add-RecipientPermission", [
      ["Identity", "ceo"],
      ["Trustee", "x@example.com"],
      ["AccessRights", "SendAs"],
    ]),
  ),
  m("ual.AddOwnerToApplication", GAPS, aad("Add owner to application.")),
  m("ual.UpdateServicePrincipal", GAPS, aad("Update service principal.")),
  m("ual.SearchQueryInitiatedExchange", GAPS, exchange("SearchQueryInitiatedExchange")),
  m(
    "ual.FileSyncDownloadedFull",
    GAPS,
    ual("SharePoint", "FileSyncDownloadedFull", { ObjectId: "https://example.sharepoint.com/a.docx" }),
  ),
  m("ual.AtpDetection", GAPS, ual("ThreatIntelligence", "AtpDetection", { RecordType: 47 })),
  m(
    "ual.New-InboxRule.hidingFolder",
    GAPS,
    exchange("New-InboxRule", [
      ["Name", "r"],
      ["MoveToFolder", "Archiv"],
    ]),
  ),
  m("ual.New-InboxRule.forward", TS, exchange("New-InboxRule", [["ForwardTo", "x@example.net"]])),
  m("ual.AddMemberToRole", TS, aad("Add member to role.")),
  m("ual.RemoveMemberFromRole", TS, aad("Remove member from role.")),
  m("ual.AddAppRoleAssignmentGrant", TS, aad("Add app role assignment grant to user.")),
  m("ual.ConsentToApplication", TS, aad("Consent to application.")),
  m("ual.AddApplication", TS, aad("Add application.")),
  m("ual.AddServicePrincipal", TS, aad("Add service principal.")),
  m("ual.AddServicePrincipalCredentials", TS, aad("Add service principal credentials.")),
  m("ual.New-TransportRule", TS, exchange("New-TransportRule")),
  m("ual.Add-MailboxPermission", TS, exchange("Add-MailboxPermission")),
  m("ual.AddUser", TS, aad("Add user.")),
  m("ual.DeleteUser", TS, aad("Delete user.")),
  m("ual.UpdateUser", TS, aad("Update user.")),
  m("ual.ResetUserPassword", TS, aad("Reset user password.")),
  m("ual.UserLoggedIn", TS, aad("UserLoggedIn")),
  m("ual.UserLoginFailed", TS, aad("UserLoginFailed")),

  // ── Entra sign-in ──
  m("signin.axios", GAPS, signInBase({ userAgent: "axios/1.6.8" })),
  m(
    "signin.nodeFetch.nonInteractive",
    GAPS,
    signInBase({
      userAgent: "node-fetch/1.0",
      signInEventTypes: ["nonInteractiveUser"],
      isInteractive: false,
    }),
  ),
  m("signin.teamFiltration", GAPS, signInBase({ userAgent: TEAMFILTRATION })),
  m("signin.aadInternals", GAPS, signInBase({ userAgent: "AADInternals" })),
  m("signin.pythonRequests", GAPS, signInBase({ userAgent: "python-requests/2.31" })),
  m("signin.browser", GAPS, signInBase({ userAgent: BROWSER })),
  m("signin.azureHound", SIGMA, signInBase({ userAgent: "azurehound/v2.1.0" })),
  m(
    "signin.lockout",
    SIGMA,
    signInBase({ status: { errorCode: 50053, failureReason: "Account is locked" } }),
  ),
  m("signin.riskHigh", TS, signInBase({ riskLevelDuringSignIn: "high" })),
  m("signin.ropc", TS, signInBase({ userAgent: "BAV2ROPC", riskLevelDuringSignIn: "none" })),

  // ── Entra directory audit ──
  m(
    "audit.AddServicePrincipal",
    SIGMA,
    auditBase({
      activityDisplayName: "Add service principal",
      category: "ApplicationManagement",
      targetResources: [{ id: "t1", displayName: "app1", type: "ServicePrincipal" }],
    }),
  ),
  m(
    "audit.SetDeviceRegistrationPolicies",
    SIGMA,
    auditBase({ activityDisplayName: "Set device registration policies", category: "Policy" }),
  ),
  m(
    "audit.AddMemberToRole",
    TS,
    auditBase({ activityDisplayName: "Add member to role", category: "RoleManagement" }),
  ),
  m(
    "audit.CreateConditionalAccessPolicy",
    TS,
    auditBase({ activityDisplayName: "Create conditional access policy", category: "Policy" }),
  ),
  m(
    "audit.UpdateAuthenticationMethodsPolicy",
    TS,
    auditBase({ activityDisplayName: "Update authentication methods policy", category: "Policy" }),
  ),
  m(
    "audit.UpdateAuditLogSettings",
    TS,
    auditBase({ activityDisplayName: "Update auditLogSettings", category: "Policy" }),
  ),
  m(
    "audit.ActivateEligibleRole",
    TS,
    auditBase({ activityDisplayName: "Activate eligible role assignment", category: "RoleManagement" }),
  ),
  m(
    "audit.DismissRiskyUser",
    TS,
    auditBase({ activityDisplayName: "Dismiss risky user", category: "UserManagement" }),
  ),
  m(
    "audit.AddDelegatedPermissionGrant.mailRead",
    GAPS,
    auditBase({
      activityDisplayName: "Add delegated permission grant",
      category: "ApplicationManagement",
      targetResources: [
        {
          type: "ServicePrincipal",
          id: "cccccccc-0000-4000-8000-000000000001",
          displayName: "Sync",
          modifiedProperties: [
            { displayName: "DelegatedPermissionGrant.Scope", oldValue: '""', newValue: '"Mail.Read"' },
          ],
        },
      ],
    }),
  ),
];
