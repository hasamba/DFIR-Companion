import type { Severity } from "./stateTypes.js";

// What an Entra permission or directory role ALLOWS, in exact words (#931 item 1).
//
// A consent row that says "Mail.Read" and one that says "RoleManagement.ReadWrite.Directory" are
// not the same finding, and the record does not explain either. These tables do, keyed on the
// API's immutable application id plus the permission value — never on a display name, which is
// mutable and can be set to "Microsoft Graph" by anyone who owns a custom API. A value on an API
// this table does not identify is reported with its spelling and NO class: a custom API can expose
// a scope called Mail.ReadWrite that reads no mailbox.

export type CapabilityClass =
  | "app-role grant management"
  | "delegated-grant management"
  | "credential management"
  | "directory RBAC"
  | "identity takeover"
  | "data read"
  | "data write/send"
  | "other";

export interface Capability {
  class: CapabilityClass;
  /** Microsoft's nominal description of the APPLICATION permission (the permissions reference). */
  allows: string;
  /** The same scope DELEGATED: what it lets the app do as the signed-in user. */
  delegated: string;
}

/** Immutable application ids of the Microsoft first-party APIs this module identifies. */
export const KNOWN_APIS: Record<string, string> = {
  "00000003-0000-0000-c000-000000000000": "Microsoft Graph",
  "00000002-0000-0000-c000-000000000000": "Azure AD Graph",
  "00000002-0000-0ff1-ce00-000000000000": "Exchange Online",
  "00000003-0000-0ff1-ce00-000000000000": "SharePoint Online",
};
export const GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000";

// Microsoft Graph permissions, in the words of Microsoft's permissions reference — the NOMINAL
// grant. What it reaches in a given tenant (an Exchange application access policy, a
// role-assignable group's extra requirement) is not in the audit record; the row's qualifier says
// so. `delegated` is the same scope as the signed-in user: the intersection of the app's scope and
// that user's own access — never "every mailbox".
const C = (cls: CapabilityClass, allows: string, delegated: string): Capability => ({
  class: cls,
  allows,
  delegated,
});
const GRAPH: Record<string, Capability> = {
  "approleassignment.readwrite.all": C(
    "app-role grant management",
    "manage app permission grants and app role assignments (any app role, Graph application permissions included, to any principal)",
    "manage app role assignments the signed-in user can manage",
  ),
  "delegatedpermissiongrant.readwrite.all": C(
    "delegated-grant management",
    "manage all delegated permission grants",
    "manage delegated permission grants the signed-in user can manage",
  ),
  "application.readwrite.all": C(
    "credential management",
    "read and write all applications (credentials included — then sign in as them)",
    "read and write applications the signed-in user can manage",
  ),
  "application.readwrite.ownedby": C(
    "credential management",
    "manage apps that this app creates or owns (credentials included)",
    "manage owned apps as the signed-in user",
  ),
  "rolemanagement.readwrite.directory": C(
    "directory RBAC",
    "read and write all directory RBAC settings (any directory role, Global Administrator included, to any principal)",
    "read and write directory RBAC settings the signed-in user can manage",
  ),
  "privilegedaccess.readwrite.azuread": C(
    "directory RBAC",
    "read and write privileged access to Microsoft Entra roles",
    "read and write privileged access the signed-in user can manage",
  ),
  "user.readwrite.all": C(
    "identity takeover",
    "read and write all users' full profiles",
    "read and write user profiles the signed-in user can change",
  ),
  "userauthenticationmethod.readwrite.all": C(
    "identity takeover",
    "read and write all users' authentication methods (not use them)",
    "read and write authentication methods the signed-in user can change",
  ),
  "directory.readwrite.all": C(
    "identity takeover",
    "read and write directory data (not role assignments)",
    "read and write directory data the signed-in user can change",
  ),
  "group.readwrite.all": C(
    "identity takeover",
    "read and write all groups (role-assignable groups need RoleManagement too)",
    "read and write groups the signed-in user can change",
  ),
  "groupmember.readwrite.all": C(
    "identity takeover",
    "read and write all group memberships (role-assignable groups need RoleManagement too)",
    "read and write group memberships the signed-in user can change",
  ),
  "policy.readwrite.conditionalaccess": C(
    "identity takeover",
    "read and write your organization's conditional access policies",
    "read and write conditional access policies as the signed-in user",
  ),
  "mail.read": C("data read", "read mail in all mailboxes", "read the signed-in user's mail"),
  "mail.readbasic.all": C(
    "data read",
    "read basic mail in all mailboxes",
    "read the signed-in user's basic mail",
  ),
  "files.read.all": C(
    "data read",
    "read files in all site collections",
    "read files the signed-in user can access",
  ),
  "sites.read.all": C(
    "data read",
    "read items in all site collections",
    "read items in sites the signed-in user can access",
  ),
  "calendars.read": C("data read", "read calendars in all mailboxes", "read the signed-in user's calendars"),
  "contacts.read": C("data read", "read contacts in all mailboxes", "read the signed-in user's contacts"),
  "chat.read.all": C("data read", "read all chat messages", "read the signed-in user's chats"),
  "channelmessage.read.all": C(
    "data read",
    "read all channel messages",
    "read channel messages the signed-in user can access",
  ),
  "mail.readwrite": C(
    "data write/send",
    "read and write mail in all mailboxes",
    "read and write the signed-in user's mail",
  ),
  "mail.send": C("data write/send", "send mail as any user", "send mail as the signed-in user"),
  "files.readwrite.all": C(
    "data write/send",
    "read and write files in all site collections",
    "read and write files the signed-in user can access",
  ),
  "sites.readwrite.all": C(
    "data write/send",
    "read and write items in all site collections",
    "read and write items in sites the signed-in user can access",
  ),
  "sites.fullcontrol.all": C(
    "data write/send",
    "have full control of all site collections",
    "have full control of sites the signed-in user controls",
  ),
  "calendars.readwrite": C(
    "data write/send",
    "read and write calendars in all mailboxes",
    "read and write the signed-in user's calendars",
  ),
  "chat.readwrite.all": C(
    "data write/send",
    "read and write all chat messages",
    "read and write the signed-in user's chats",
  ),
};

/** The qualifier a data-class row carries: the nominal grant, not the tenant's effective reach. */
export const DATA_REACH_NOTE = "nominal reach — application access policies are not in this record";

/** The scopes an ordinary one-user consent carries; Microsoft rates such consent Low. */
export const LOW_PRIVILEGE_SCOPES = new Set([
  "openid",
  "profile",
  "email",
  "offline_access",
  "user.read",
  "user.readbasic.all",
]);

/** The capability of `value` on the API `appId`, or null when the API is not identified here. */
export function capabilityOf(appId: string, value: string): Capability | null {
  if (appId.toLowerCase() !== GRAPH_APP_ID) return null;
  return GRAPH[value.trim().toLowerCase()] ?? { class: "other", allows: "", delegated: "" };
}

export type RoleTier = "tier-0" | "admin" | "other";

// Directory roles by template id (immutable, the same in every tenant), each with the capability
// Microsoft's built-in-roles reference documents for it — tier-0 roles can take over the tenant.
// The role's concrete scope is not in the record; these words are the role's documented scope.
const R = (name: string, tier: RoleTier, can: string) => ({ name, tier, can });
const ROLES: Record<string, { name: string; tier: RoleTier; can: string }> = {
  "62e90394-69f5-4237-9190-012177145e10": R(
    "Global Administrator",
    "tier-0",
    "can manage everything in the tenant",
  ),
  "e8611ab8-c189-46e8-94e1-60213ab1f814": R(
    "Privileged Role Administrator",
    "tier-0",
    "can assign any directory role, Global Administrator included",
  ),
  "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": R(
    "Privileged Authentication Administrator",
    "tier-0",
    "can reset any user's authentication methods, administrators included",
  ),
  "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": R(
    "Application Administrator",
    "tier-0",
    "can add credentials to any application and consent on its behalf — then sign in as it",
  ),
  "158c047a-c907-4556-b7ef-446551a6b5f7": R(
    "Cloud Application Administrator",
    "tier-0",
    "can add credentials to any cloud application and consent on its behalf — then sign in as it",
  ),
  "e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8": R(
    "Partner Tier2 Support",
    "tier-0",
    "can reset any user's password, administrators included",
  ),
  "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2": R(
    "Hybrid Identity Administrator",
    "tier-0",
    "can manage federation and directory sync — a path to any synced user",
  ),
  "29232cdf-9323-42fd-ade2-1d097af3e4de": R(
    "Exchange Administrator",
    "admin",
    "can manage Exchange Online — every mailbox and mail flow",
  ),
  "f28a1f50-f6e7-4571-818b-6a12f2af6b6c": R(
    "SharePoint Administrator",
    "admin",
    "can manage SharePoint Online — every site",
  ),
  "194ae4cb-b126-40b2-bd5b-6091b380977d": R(
    "Security Administrator",
    "admin",
    "can change security settings and read security data across the tenant",
  ),
  "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9": R(
    "Conditional Access Administrator",
    "admin",
    "can change Conditional Access policies",
  ),
  "fe930be7-5e62-47db-91af-98c3a49a38b1": R(
    "User Administrator",
    "admin",
    "can manage users and groups and reset non-administrator passwords",
  ),
  "c4e39bd9-1100-46d3-8c65-fb160da0071f": R(
    "Authentication Administrator",
    "admin",
    "can reset non-administrator users' authentication methods",
  ),
  "729827e3-9c14-49f7-bb1b-9608f156bbb8": R(
    "Helpdesk Administrator",
    "admin",
    "can reset non-administrator users' passwords",
  ),
  "3a2c62db-5318-420d-8d74-23affee5d9d5": R(
    "Intune Administrator",
    "admin",
    "can manage Intune — every managed device",
  ),
  "966707d0-3269-4727-9be2-8c3a10f19b9d": R(
    "Password Administrator",
    "admin",
    "can reset non-administrator users' passwords",
  ),
  "17315797-102d-40b4-93e0-432062caca18": R(
    "Compliance Administrator",
    "admin",
    "can manage compliance features — eDiscovery and retention included",
  ),
};

/** The documented name, tier and capability of a directory role by template id; null for a custom or unlisted role. */
export function roleTier(templateId: string): { name: string; tier: RoleTier; can: string } | null {
  return ROLES[templateId.trim().toLowerCase()] ?? null;
}

/** The grade an APPLICATION permission's class carries on an identified API. */
export function classSeverity(c: CapabilityClass): Severity {
  return c === "other" ? "Medium" : "High";
}
