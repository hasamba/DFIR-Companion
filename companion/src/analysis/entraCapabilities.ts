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
  /** What the APPLICATION permission allows, in the words of Microsoft's permission reference. */
  allows: string;
}

/** Immutable application ids of the Microsoft first-party APIs this module identifies. */
export const KNOWN_APIS: Record<string, string> = {
  "00000003-0000-0000-c000-000000000000": "Microsoft Graph",
  "00000002-0000-0000-c000-000000000000": "Azure AD Graph",
  "00000002-0000-0ff1-ce00-000000000000": "Exchange Online",
  "00000003-0000-0ff1-ce00-000000000000": "SharePoint Online",
};
export const GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000";

// Microsoft Graph APPLICATION permissions. Delegated scopes with the same spelling are bounded by
// the consenting user's own access and are graded separately (see entraAppChange.ts).
const GRAPH: Record<string, Capability> = {
  "approleassignment.readwrite.all": {
    class: "app-role grant management",
    allows:
      "can assign any app role, Graph application permissions included, to any principal without admin consent",
  },
  "delegatedpermissiongrant.readwrite.all": {
    class: "delegated-grant management",
    allows: "can create delegated permission grants for any app on behalf of any user",
  },
  "application.readwrite.all": {
    class: "credential management",
    allows: "can add credentials to any application or service principal, then sign in as it",
  },
  "application.readwrite.ownedby": {
    class: "credential management",
    allows: "can add credentials to the applications this app owns, then sign in as them",
  },
  "rolemanagement.readwrite.directory": {
    class: "directory RBAC",
    allows: "can assign any directory role, Global Administrator included, to any principal",
  },
  "privilegedaccess.readwrite.azuread": {
    class: "directory RBAC",
    allows: "can manage privileged-access (PIM) role assignments",
  },
  "user.readwrite.all": { class: "identity takeover", allows: "can change any non-admin user's properties" },
  "userauthenticationmethod.readwrite.all": {
    class: "identity takeover",
    allows: "can reset any non-admin user's authentication methods",
  },
  "directory.readwrite.all": {
    class: "identity takeover",
    allows: "can write most directory objects (users, groups, apps); not role assignments",
  },
  "group.readwrite.all": { class: "identity takeover", allows: "can change any group and its membership" },
  "groupmember.readwrite.all": { class: "identity takeover", allows: "can change any group's membership" },
  "policy.readwrite.conditionalaccess": {
    class: "identity takeover",
    allows: "can change Conditional Access policies",
  },
  "mail.read": { class: "data read", allows: "can read every mailbox" },
  "mail.readbasic.all": { class: "data read", allows: "can read every mailbox's message headers" },
  "files.read.all": { class: "data read", allows: "can read every file in every site and drive" },
  "sites.read.all": { class: "data read", allows: "can read every site collection" },
  "calendars.read": { class: "data read", allows: "can read every calendar" },
  "contacts.read": { class: "data read", allows: "can read every contact list" },
  "chat.read.all": { class: "data read", allows: "can read every Teams chat" },
  "channelmessage.read.all": { class: "data read", allows: "can read every Teams channel message" },
  "mail.readwrite": { class: "data write/send", allows: "can read and change every mailbox" },
  "mail.send": { class: "data write/send", allows: "can send mail as any user" },
  "files.readwrite.all": { class: "data write/send", allows: "can read and change every file" },
  "sites.readwrite.all": { class: "data write/send", allows: "can read and change every site" },
  "sites.fullcontrol.all": { class: "data write/send", allows: "has full control of every site" },
  "calendars.readwrite": { class: "data write/send", allows: "can read and change every calendar" },
  "chat.readwrite.all": { class: "data write/send", allows: "can read and change every Teams chat" },
};

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
  return GRAPH[value.trim().toLowerCase()] ?? { class: "other", allows: "" };
}

export type RoleTier = "tier-0" | "admin" | "other";

// Directory roles by template id (immutable, the same in every tenant). Tier-0 roles can take
// over the tenant; admin roles administer one service. The role's concrete scope is not in the
// record — these words are the role's documented scope.
const ROLES: Record<string, { name: string; tier: RoleTier }> = {
  "62e90394-69f5-4237-9190-012177145e10": { name: "Global Administrator", tier: "tier-0" },
  "e8611ab8-c189-46e8-94e1-60213ab1f814": { name: "Privileged Role Administrator", tier: "tier-0" },
  "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": { name: "Privileged Authentication Administrator", tier: "tier-0" },
  "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": { name: "Application Administrator", tier: "tier-0" },
  "158c047a-c907-4556-b7ef-446551a6b5f7": { name: "Cloud Application Administrator", tier: "tier-0" },
  "e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8": { name: "Partner Tier2 Support", tier: "tier-0" },
  "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2": { name: "Hybrid Identity Administrator", tier: "tier-0" },
  "29232cdf-9323-42fd-ade2-1d097af3e4de": { name: "Exchange Administrator", tier: "admin" },
  "f28a1f50-f6e7-4571-818b-6a12f2af6b6c": { name: "SharePoint Administrator", tier: "admin" },
  "194ae4cb-b126-40b2-bd5b-6091b380977d": { name: "Security Administrator", tier: "admin" },
  "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9": { name: "Conditional Access Administrator", tier: "admin" },
  "fe930be7-5e62-47db-91af-98c3a49a38b1": { name: "User Administrator", tier: "admin" },
  "c4e39bd9-1100-46d3-8c65-fb160da0071f": { name: "Authentication Administrator", tier: "admin" },
  "729827e3-9c14-49f7-bb1b-9608f156bbb8": { name: "Helpdesk Administrator", tier: "admin" },
  "3a2c62db-5318-420d-8d74-23affee5d9d5": { name: "Intune Administrator", tier: "admin" },
  "966707d0-3269-4727-9be2-8c3a10f19b9d": { name: "Password Administrator", tier: "admin" },
  "17315797-102d-40b4-93e0-432062caca18": { name: "Compliance Administrator", tier: "admin" },
};

/** The documented tier of a directory role by template id; `other` for a custom or unlisted role. */
export function roleTier(templateId: string): { name: string; tier: RoleTier } | null {
  return ROLES[templateId.trim().toLowerCase()] ?? null;
}

/** The grade an APPLICATION permission's class carries on an identified API. */
export function classSeverity(c: CapabilityClass): Severity {
  return c === "other" ? "Medium" : "High";
}
