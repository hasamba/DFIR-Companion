// OAuth-grant and MFA-method snapshots (#2305) → observed state.
//
// OAuth: MES writes one row per (app, permission type, resource, scope, principal). Identity is
// exactly that tuple; the rest (consent type, enabled, display names, publisher) is state. A grant of
// a high-risk scope grades High as an application permission (the app acts without a user, on every
// mailbox or file) and Medium as a delegated one (bounded by the consenting user).
//
// MFA: one row per user. "No MFA method registered" grades Low, never higher: the export cannot say
// whether Conditional Access or security defaults enforce MFA at sign-in, and a tenant with hundreds
// of such users must not flood the forensic timeline with them.

import {
  clean,
  col,
  historyDetail,
  identityKey,
  quoted,
  stateOf,
  type MappedSnapshot,
  type SnapRow,
} from "./cloudSnapshotModel.js";

const NAME_MAX = 60;

/**
 * Scopes whose grant alone is enough to read, change or send a tenant's mail or files, or to take
 * over the tenant, and that consent-phishing and tenant-compromise reports name. Short on purpose:
 *   Mail.ReadWrite, Mail.Send, MailboxSettings.ReadWrite — read/delete/send mail, set forwarding (BEC);
 *   full_access_as_app — EWS full access to every mailbox (application);
 *   Files.ReadWrite.All — every file the grant reaches (exfiltration, ransom);
 *   Directory.ReadWrite.All, RoleManagement.ReadWrite.Directory, AppRoleAssignment.ReadWrite.All —
 *     change the directory, assign roles, grant itself more permissions (tenant takeover).
 * Matched exactly (case-insensitive): `Mail.ReadWrite.Shared` is not `Mail.ReadWrite`.
 */
export const HIGH_RISK_SCOPES: readonly string[] = [
  "Mail.ReadWrite",
  "Mail.Send",
  "MailboxSettings.ReadWrite",
  "full_access_as_app",
  "Files.ReadWrite.All",
  "Directory.ReadWrite.All",
  "RoleManagement.ReadWrite.Directory",
  "AppRoleAssignment.ReadWrite.All",
];
const HIGH_RISK = new Set(HIGH_RISK_SCOPES.map((s) => s.toLowerCase()));

const OAUTH_IDENTITY = ["appid", "permissiontype", "resourceobjectid", "permission", "principalobjectid"];

function oauthGrade(scope: string, application: boolean): Pick<MappedSnapshot, "severity" | "mitre"> {
  if (!HIGH_RISK.has(scope.toLowerCase())) return { severity: "Info", mitre: [] };
  return { severity: application ? "High" : "Medium", mitre: ["T1528"] };
}

/** One OAuth-permission row. */
export function mapOauthGrant(row: SnapRow): MappedSnapshot | null {
  const appId = col(row, "appid");
  const scope = col(row, "permission");
  if (!appId || !scope) return null;
  const type = col(row, "permissiontype");
  const application = /^application$/i.test(type);
  const resourceId = col(row, "resourceobjectid", "resourcedisplayname", "resourceobjectdisplayname");
  const consent = col(row, "consenttype");
  const principalId = col(row, "principalobjectid") || (/allprincipals/i.test(consent) ? "all" : "");
  const appName = col(row, "appdisplayname", "clientdisplayname");
  const resource = col(row, "resourcedisplayname", "resourceobjectdisplayname");
  const principal =
    principalId === "all" || application
      ? "all principals"
      : col(row, "principaluserprincipalname", "principaldisplayname") ||
        principalId ||
        "an unnamed principal";
  const disabled = /^false$/i.test(col(row, "isenabled"));
  const summary = [
    `${application ? "application" : "delegated"} permission ${quoted(scope, NAME_MAX)}` +
      (resource ? ` on ${quoted(resource, NAME_MAX)}` : ""),
    `app ${appName ? `${quoted(appName, NAME_MAX)} ` : ""}(${clean(appId, 40)})`,
    `granted for ${clean(principal, NAME_MAX)}`,
    ...(disabled ? ["disabled"] : []),
  ].join("; ");
  return {
    identityKey: identityKey(
      "entra",
      "",
      "oauth-grant",
      [appId, type, resourceId, scope, principalId].join("|"),
    ),
    state: stateOf(row, OAUTH_IDENTITY),
    subject: "OAuth grant",
    summary,
    details: historyDetail(row),
    ...oauthGrade(scope, application),
  };
}

// ───────────────────────────── MFA methods ─────────────────────────────

// Second factors only: a password is not one, and an email method is self-service password reset.
const MFA_METHODS: ReadonlyArray<[string, string]> = [
  ["fido2", "FIDO2 key"],
  ["app", "authenticator app"],
  ["phone", "phone"],
  ["softwareoath", "software OATH token"],
  ["hellobusiness", "Windows Hello for Business"],
  ["temporaryaccesspass", "temporary access pass"],
  ["tempaccess", "temporary access pass"],
  ["certificatebasedauthconfiguration", "certificate"],
  ["qrcodepin", "QR code PIN"],
];

const isTrue = (v: string | undefined): boolean => /^(true|1|yes)$/i.test((v ?? "").trim());

export const NO_MFA = "no MFA method registered";
const CA_UNKNOWN = "whether Conditional Access or security defaults enforce MFA at sign-in is unknown";

/** One MFA-status row. */
export function mapMfaState(row: SnapRow): MappedSnapshot | null {
  const user = col(row, "user", "userprincipalname").toLowerCase();
  if (!user) return null;
  const methods = [...new Set(MFA_METHODS.filter(([k]) => isTrue(row[k])).map(([, w]) => w))];
  const status = col(row, "mfastatus");
  const none = status ? /^disabled$/i.test(status) : methods.length === 0;
  const others = [isTrue(row.password) ? "password" : "", isTrue(row.email) ? "email" : ""].filter(Boolean);
  const summary = none
    ? `${NO_MFA}${others.length ? ` (registered: ${others.join(", ")})` : ""}; ${CA_UNKNOWN}`
    : `MFA methods registered: ${methods.join(", ") || "none listed, status Enabled"}`;
  return {
    identityKey: identityKey("entra", "", "mfa-methods", user),
    state: stateOf(row, ["user", "userprincipalname"]),
    subject: `MFA methods for ${clean(user, NAME_MAX)}`,
    summary,
    details: historyDetail(row),
    severity: none ? "Low" : "Info",
    mitre: [],
  };
}
