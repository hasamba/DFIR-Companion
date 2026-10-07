import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { compileText } from "../../src/analysis/taggerStore.js";
import { runTagger, applyToForensicEvent } from "../../src/analysis/tagger.js";
import { parseM365Audit } from "../../src/analysis/m365Import.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// The ts_m365_* / ts_entra_* rules are a faithful tag-only port of a community Timesketch tagger
// ruleset (M365 UAL + Entra audit_log). They key on the operation literal the importer renders into
// `description`, so these tests run the REAL m365/entra importers and the SHIPPED ruleset, not
// hand-built events: a port that names an operation the importer never emits would read as live
// while being dead.
const RULES = compileText(
  readFileSync(fileURLToPath(new URL("../../data/tags.yaml", import.meta.url)), "utf8"),
);

function tagged(text: string): { desc: string; ruleIds: string[] }[] {
  const parsed = parseM365Audit(text);
  return parsed.events.map((m, i) => {
    const event = {
      ...m,
      id: `e${i}`,
      relatedFindingIds: [],
      sourceScreenshots: [],
      mitreTechniques: m.mitreTechniques ?? [],
    } as unknown as ForensicEvent;
    const proposal = runTagger([event], RULES).perEvent[0];
    const after = proposal ? applyToForensicEvent(event, proposal) : event;
    return { desc: after.description, ruleIds: proposal?.ruleIds ?? [] };
  });
}

const ids = (text: string) => tagged(text).flatMap((e) => e.ruleIds);

// A UAL record in the Search-UnifiedAuditLog shape (Operation + AuditData JSON string).
const ual = (ad: Record<string, unknown>) =>
  JSON.stringify([
    {
      RecordType: 1,
      CreationDate: "2023-05-01T10:00:00",
      UserIds: "a@v.com",
      Operations: ad.Operation,
      AuditData: JSON.stringify({ CreationTime: "2023-05-01T10:00:00", UserId: "a@v.com", ...ad }),
    },
  ]);

const entraSignin = (over: Record<string, unknown>) =>
  JSON.stringify([
    {
      createdDateTime: "2023-05-02T08:10:00Z",
      userPrincipalName: "v@v.com",
      appDisplayName: "Azure CLI",
      ipAddress: "198.51.100.9",
      ...over,
    },
  ]);

const entraAudit = (over: Record<string, unknown>) =>
  JSON.stringify([
    {
      activityDisplayName: "Add member to role",
      operationType: "Update",
      result: "success",
      initiatedBy: { user: { userPrincipalName: "adm@v.com" } },
      targetResources: [{ type: "User", userPrincipalName: "victim@v.com", id: "u1" }],
      ...over,
    },
  ]);

describe("bundled data/tags.yaml — Timesketch M365/Entra parity", () => {
  it("tags an Azure AD role-membership change (privilege_change / role_assignment)", () => {
    const r = ids(ual({ Operation: "Add member to role.", Workload: "AzureActiveDirectory" }));
    expect(r).toContain("ts_m365_role_assignment");
    expect(r).toContain("ts_m365_aad_role_change");
    expect(r).toContain("ts_m365_privileged_role_assignment");
  });

  it("tags a directory-role removal", () => {
    const r = ids(ual({ Operation: "Remove member from role.", Workload: "AzureActiveDirectory" }));
    expect(r).toContain("ts_m365_role_assignment");
  });

  it("tags an app role assignment grant to a user", () => {
    const r = ids(
      ual({ Operation: "Add app role assignment grant to user.", Workload: "AzureActiveDirectory" }),
    );
    expect(r).toContain("ts_m365_app_role_assignment");
  });

  it("tags OAuth consent + app registration + service principal (OAuth persistence)", () => {
    expect(ids(ual({ Operation: "Consent to application.", Workload: "AzureActiveDirectory" }))).toContain(
      "ts_m365_oauth_consent",
    );
    expect(ids(ual({ Operation: "Add application.", Workload: "AzureActiveDirectory" }))).toContain(
      "ts_m365_app_registration",
    );
    expect(ids(ual({ Operation: "Add service principal.", Workload: "AzureActiveDirectory" }))).toContain(
      "ts_entra_service_principal_created",
    );
  });

  it("tags a new client secret on an application", () => {
    expect(
      ids(ual({ Operation: "Add service principal credentials.", Workload: "AzureActiveDirectory" })),
    ).toContain("ts_entra_app_secret_added");
  });

  it("tags an inbox rule AND a forwarding rule only when the rule forwards", () => {
    const plain = ual({
      Operation: "New-InboxRule",
      Workload: "Exchange",
      Parameters: [{ Name: "SubjectContainsWords", Value: "invoice" }],
    });
    expect(ids(plain)).toContain("ts_m365_inbox_rule");
    expect(ids(plain)).not.toContain("ts_m365_mailbox_forwarding");

    const fwd = ual({
      Operation: "New-InboxRule",
      Workload: "Exchange",
      Parameters: [{ Name: "ForwardTo", Value: "x@evil.com" }],
    });
    expect(ids(fwd)).toContain("ts_m365_inbox_rule");
    expect(ids(fwd)).toContain("ts_m365_mailbox_forwarding");
  });

  it("tags transport rules and mailbox permissions", () => {
    expect(ids(ual({ Operation: "New-TransportRule", Workload: "Exchange" }))).toContain(
      "ts_m365_transport_rule",
    );
    expect(ids(ual({ Operation: "Add-MailboxPermission", Workload: "Exchange" }))).toContain(
      "ts_m365_mailbox_permission",
    );
  });

  it("tags user create / delete / update / password reset", () => {
    expect(ids(ual({ Operation: "Add user.", Workload: "AzureActiveDirectory" }))).toContain(
      "ts_m365_user_added",
    );
    expect(ids(ual({ Operation: "Delete user.", Workload: "AzureActiveDirectory" }))).toContain(
      "ts_m365_user_deleted",
    );
    expect(ids(ual({ Operation: "Update user.", Workload: "AzureActiveDirectory" }))).toContain(
      "ts_m365_user_updated",
    );
    expect(ids(ual({ Operation: "Reset user password.", Workload: "AzureActiveDirectory" }))).toContain(
      "ts_m365_password_reset",
    );
  });

  it("tags sign-in success / failure on the UAL path", () => {
    expect(ids(ual({ Operation: "UserLoggedIn", Workload: "AzureActiveDirectory" }))).toContain(
      "ts_m365_signin_success",
    );
    expect(ids(ual({ Operation: "UserLoginFailed", Workload: "AzureActiveDirectory" }))).toContain(
      "ts_m365_signin_failed",
    );
  });

  it("tags an Entra sign-in carrying a risk signal, and a ROPC (legacy-auth) sign-in", () => {
    expect(ids(entraSignin({ riskLevelDuringSignIn: "high" }))).toContain("ts_entra_signin_risk");
    expect(ids(entraSignin({ userAgent: "BAV2ROPC", riskLevelDuringSignIn: "none" }))).toContain(
      "ts_entra_legacy_auth",
    );
  });

  it("tags an Entra directory-role assignment", () => {
    expect(ids(entraAudit({ activityDisplayName: "Add member to role" }))).toContain(
      "ts_m365_role_assignment",
    );
  });

  it("tags Entra conditional-access policy changes and audit-log settings changes", () => {
    expect(ids(entraAudit({ activityDisplayName: "Create conditional access policy" }))).toContain(
      "ts_entra_policy_change",
    );
    expect(ids(entraAudit({ activityDisplayName: "Update authentication methods policy" }))).toContain(
      "ts_entra_policy_change",
    );
    expect(ids(entraAudit({ activityDisplayName: "Update auditLogSettings" }))).toContain(
      "ts_entra_audit_policy_changed",
    );
  });

  it("tags Entra PIM activation and risky-user dismissal", () => {
    expect(ids(entraAudit({ activityDisplayName: "Activate eligible role assignment" }))).toContain(
      "ts_entra_pim",
    );
    expect(ids(entraAudit({ activityDisplayName: "Dismiss risky user" }))).toContain(
      "ts_entra_risky_user_action",
    );
  });

  // ── the benign half: an unrelated operation must not pick up a cloud tag ──
  it("leaves a routine operation untagged", () => {
    const r = ids(ual({ Operation: "MailItemsAccessed", Workload: "Exchange" }));
    expect(r).not.toContain("ts_m365_inbox_rule");
    expect(r).not.toContain("ts_m365_role_assignment");
    expect(r).not.toContain("ts_m365_user_added");
  });
});
