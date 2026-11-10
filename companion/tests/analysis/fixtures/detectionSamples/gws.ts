// Google Workspace Reports API samples (#2522) for the detection-overlap check and the Workspace Sigma
// reachability test. Synthetic: example.com accounts, documentation IPs, fake ids. The shape is the
// Admin SDK Reports API `activities.list` item: id / actor / ipAddress, then `events[]`, each with a
// typed `parameters[]` (value, boolValue, intValue, multiValue).
import { sample, type DetectionSample } from "./types.js";

type Row = Record<string, unknown>;

/** One Reports API parameter in its wire shape: a boolean as boolValue, a list as multiValue. */
export const gwsParam = (name: string, v: unknown): Row =>
  typeof v === "boolean"
    ? { name, boolValue: v }
    : Array.isArray(v)
      ? { name, multiValue: v.map(String) }
      : { name, value: String(v) };

/** A Reports API activity of one application carrying the given events. */
export const gwsActivity = (app: string, events: Row[], over: Row = {}): Row => ({
  kind: "admin#reports#activity",
  id: {
    time: "2026-03-01T10:00:00.000Z",
    uniqueQualifier: "-1234567890123456789",
    applicationName: app,
    customerId: "C00example",
  },
  etag: '"example"',
  actor: { callerType: "USER", email: "admin@example.com", profileId: "100000000000000000001" },
  ipAddress: "198.51.100.7",
  ...over,
  events,
});

/** One event: its name and parameters (`{ NEW_VALUE: "true", is_suspicious: true }`). */
export const gwsEvent = (name: string, params: Row = {}, type = "event"): Row => ({
  type,
  name,
  parameters: Object.entries(params).map(([k, v]) => gwsParam(k, v)),
});

/** A neutral event of one application for the built Sigma samples: no importer entry, no rule. */
export const gwsBase = (app: string): Row => gwsActivity(app, [gwsEvent("detection_overlap_neutral", {})]);

/** One real-shaped record and the exact Sigma rule ids it must match at the given statuses. */
export interface GwsRealSample {
  id: string;
  record: Row;
  expect: readonly string[];
}

const login = (name: string, params: Row = {}) => gwsActivity("login", [gwsEvent(name, params, "login")]);
const admin = (name: string, params: Row = {}, type = "USER_SETTINGS") =>
  gwsActivity("admin", [gwsEvent(name, { USER_EMAIL: "victim@example.com", ...params }, type)]);
const drive = (name: string, params: Row = {}) =>
  gwsActivity("drive", [
    gwsEvent(
      name,
      { doc_id: "1AbCdEfGhIjK", doc_title: "Q3 plan", owner: "admin@example.com", ...params },
      "acl_change",
    ),
  ]);

// Suzaku rule ids (suzaku/gws) and SigmaHQ (rules/cloud/gcp/gworkspace), named for reading.
export const GWS_RULE = {
  backupCodes: "8aa41139-f0b0-4402-becb-76143b174b22",
  twoSvRevokedByAdmin: "4661b697-cfd9-4e7d-99c1-e70826681c58",
  forcedReset: "62c7a447-8a51-411a-8a54-6c638f6a56ec",
  gmailSetting: "3ec412e2-f31c-468f-aec4-47262ffaff5b",
  recoveryRemoved: "f77645a9-4764-4f06-807e-f924175f1cf6",
  roleGranted: "d1da9eee-39f0-4ed6-965f-c4b329ab0b44",
  cookiesReset: "2bd9099c-bc6c-4461-80bb-f5a520d7af70",
  offboarding: "d05ca7d4-e8cc-4bcd-b64d-dd8d332895ba",
  driveShared: "e211a71d-9031-427e-aece-efc566246681",
  driveOwner: "3b77f2b3-6a50-44f4-97df-0481a681995f",
  twoSvDisabled: "ab6f70b1-eff9-4607-a194-5af77358dc83",
  bounceBlocked: "497da258-561c-44d8-aacc-b239645d05bd",
  delegate: "a134bbe6-25df-4c32-8402-c4b586a7f27a",
  forwarding: "ee4779eb-ca2c-4305-b838-9a10020ab109",
  flagged: "f50bb130-9638-4e5e-9e8d-9d0dc77f92f1",
  recoveryEdit: "306b60d0-3bda-4cd6-baac-b9f68c0a2945",
  riskyAction: "808f0a65-c078-47f9-8c73-5646e4767435",
  suspiciousSuccess: "662ee5fa-ea01-4be9-a470-50b96408c28c",
  hqContextAwareChanged: "22f2fb54-5312-435d-852f-7c74f81684ca",
  hqAppRemoved: "ee2803f0-71c8-4831-b48b-a1fc57601ee4",
  hqDomainClientGrant: "04e2a23a-9b29-4a5c-be3a-3542e3f982ba",
  hqMfaDisabled: "780601d1-6376-4f2a-884e-b8d45599f78c",
  hqRoleModified: "6aef64e3-60c6-4782-8db3-8448759c714e",
  hqPrivilegeDeleted: "bf638ef7-4d2d-44bb-a1dc-a238252e6267",
  hqAdminGranted: "2d1b83e4-17c6-4896-a37b-29140b40a788",
  hqGovAttack: "eafe6f2b-cfec-4612-aec2-49563c33a087",
  hqForwarding: "2a0bb2dd-eb5f-4517-8cb9-404f8ba764a5",
  hqSuspiciousLogin: "38360161-76c4-4283-842e-efcf997dafc8",
} as const;
const R = GWS_RULE;

/**
 * One record per loadable Workspace rule, written in the Reports API's own shape (not built from
 * the rule), with every rule it must match — SigmaHQ's experimental login rules included, so the
 * test runs with statuses experimental + test + stable.
 */
export const GWS_REAL_SAMPLES: readonly GwsRealSample[] = [
  { id: "admin.backup-codes", record: admin("GENERATE_2SV_SCRATCH_CODES"), expect: [R.backupCodes] },
  { id: "admin.passkey-revoked", record: admin("REVOKE_SECURITY_KEY"), expect: [R.twoSvRevokedByAdmin] },
  {
    id: "admin.force-password",
    record: admin("CHANGE_PASSWORD_ON_NEXT_LOGIN", { NEW_VALUE: "true", OLD_VALUE: "false" }),
    expect: [R.forcedReset],
  },
  {
    id: "admin.gmail-setting",
    record: admin("CHANGE_GMAIL_SETTING", { SETTING_NAME: "MESSAGE_SECURITY_RULE" }, "EMAIL_SETTINGS"),
    expect: [R.gmailSetting],
  },
  { id: "admin.recovery-removed", record: admin("REMOVE_RECOVERY_PHONE"), expect: [R.recoveryRemoved] },
  {
    id: "admin.assign-role",
    record: admin("ASSIGN_ROLE", { ROLE_NAME: "_SEED_ADMIN_ROLE" }),
    expect: [R.roleGranted],
  },
  {
    id: "admin.grant-admin",
    record: admin("GRANT_ADMIN_PRIVILEGE"),
    expect: [R.roleGranted, R.hqAdminGranted],
  },
  {
    id: "admin.update-role",
    record: admin("UPDATE_ROLE", { ROLE_NAME: "Helpdesk" }, "DELEGATED_ADMIN_SETTINGS"),
    expect: [R.roleGranted, R.hqRoleModified],
  },
  { id: "admin.cookies-reset", record: admin("RESET_SIGNIN_COOKIES"), expect: [R.cookiesReset] },
  { id: "admin.suspend-user", record: admin("SUSPEND_USER"), expect: [R.offboarding] },
  {
    id: "admin.access-level",
    record: admin(
      "CHANGE_APPLICATION_SETTING",
      { SETTING_NAME: "ContextAwareAccess AccessLevel", APPLICATION_NAME: "Security" },
      "APPLICATION_SETTINGS",
    ),
    expect: [R.hqContextAwareChanged],
  },
  {
    id: "admin.app-removed",
    record: admin("REMOVE_APPLICATION", { APPLICATION_NAME: "Example Notes" }, "DOMAIN_SETTINGS"),
    expect: [R.hqAppRemoved],
  },
  {
    id: "admin.api-access",
    record: admin("AUTHORIZE_API_CLIENT_ACCESS", { API_CLIENT_NAME: "1234567890" }, "DOMAIN_SETTINGS"),
    expect: [R.hqDomainClientGrant],
  },
  {
    id: "admin.mfa-enforcement-off",
    record: admin(
      "ENFORCE_STRONG_AUTHENTICATION",
      { NEW_VALUE: "false", OLD_VALUE: "true" },
      "SECURITY_SETTINGS",
    ),
    expect: [R.hqMfaDisabled],
  },
  { id: "admin.remove-privilege", record: admin("REMOVE_PRIVILEGE"), expect: [R.hqPrivilegeDeleted] },
  {
    id: "drive.shared-externally",
    record: drive("change_document_visibility", {
      visibility: "shared_externally",
      old_visibility: "private",
    }),
    expect: [R.driveShared],
  },
  {
    id: "drive.owner",
    record: drive("change_owner", { new_owner: "bob@example.com" }),
    expect: [R.driveOwner],
  },
  { id: "login.2sv-disable", record: login("2sv_disable"), expect: [R.twoSvDisabled] },
  {
    id: "login.bounce-blocked",
    record: login("blocked_sender", { affected_email_address: "mailer-daemon@example.com" }),
    expect: [R.bounceBlocked],
  },
  {
    id: "login.delegate",
    record: login("delegate_grant", { delegate: "bob@example.com" }),
    expect: [R.delegate],
  },
  {
    id: "login.forwarding",
    record: login("email_forwarding_out_of_domain", {
      email_forwarding_destination_address: "x@example.net",
    }),
    expect: [R.forwarding, R.hqForwarding],
  },
  { id: "login.suspicious", record: login("suspicious_login"), expect: [R.flagged, R.hqSuspiciousLogin] },
  { id: "login.gov-attack", record: login("gov_attack_warning"), expect: [R.flagged, R.hqGovAttack] },
  { id: "login.recovery-edit", record: login("recovery_phone_edit"), expect: [R.recoveryEdit] },
  {
    id: "login.risky-action",
    record: login("risky_sensitive_action_allowed", { sensitive_action_name: "Change password" }),
    expect: [R.riskyAction],
  },
  {
    id: "login.suspicious-success",
    record: login("login_success", { login_type: "google_password", is_suspicious: true }),
    expect: [R.suspiciousSuccess],
  },
  // The rules' exclusions and the parameter types, read for what they mean.
  {
    id: "login.suspicious-reauth-excluded",
    record: login("login_success", { login_type: "reauth", is_suspicious: true }),
    expect: [],
  },
  {
    id: "login.success-not-suspicious",
    record: login("login_success", { login_type: "google_password", is_suspicious: false }),
    expect: [],
  },
  {
    id: "login.risky-ads-excluded",
    record: login("risky_sensitive_action_allowed", {
      sensitive_action_name: "Periodic check in Google Ads",
    }),
    expect: [],
  },
  {
    id: "admin.force-password-cleared",
    record: admin("CHANGE_PASSWORD_ON_NEXT_LOGIN", { NEW_VALUE: "false" }),
    expect: [],
  },
  {
    id: "drive.shared-internally",
    record: drive("change_document_visibility", { visibility: "private" }),
    expect: [],
  },
  // A login rule never runs on another application's event of the same name.
  { id: "admin.not-a-login-event", record: admin("2sv_disable"), expect: [] },
];

/** Hand samples for the overlap check: Workspace events the importer itself grades above Info. */
export const GWS_SAMPLES: readonly DetectionSample[] = GWS_REAL_SAMPLES.filter((s) =>
  [
    "admin.grant-admin",
    "admin.assign-role",
    "admin.suspend-user",
    "drive.shared-externally",
    "login.2sv-disable",
    "login.forwarding",
    "login.suspicious",
    "login.gov-attack",
    "login.recovery-edit",
  ].includes(s.id),
).map((s) => sample("gws", `gws.${s.id}`, "gws.ts GWS_REAL_SAMPLES", s.record));
