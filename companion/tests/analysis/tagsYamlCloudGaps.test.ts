// #2306 — the gap rules and the Microsoft-Analyzer-Suite rules in the SHIPPED tags.yaml, each run over
// the REAL importer's rendered row: one positive and one negative fixture per rule.
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { compileText } from "../../src/analysis/taggerStore.js";
import { runTagger } from "../../src/analysis/tagger.js";
import { parseCloudTrail } from "../../src/analysis/awsImport.js";
import { parseCloudActivity } from "../../src/analysis/cloudActivityImport.js";
import { parseM365Audit } from "../../src/analysis/m365Import.js";
import { parseCloudSnapshot } from "../../src/analysis/cloudSnapshotParse.js";
import type { SiemEvent } from "../../src/analysis/siemImport.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

const YAML = readFileSync(fileURLToPath(new URL("../../data/tags.yaml", import.meta.url)), "utf8");
const RULES = compileText(YAML);

interface Row {
  description: string;
  severity: string;
  ruleIds: string[];
}
function tag(events: ReadonlyArray<Pick<SiemEvent, "description" | "severity">>): Row[] {
  return events.map((e, i) => {
    const event = {
      ...e,
      id: `e${i}`,
      relatedFindingIds: [],
      sourceScreenshots: [],
    } as unknown as ForensicEvent;
    return {
      description: e.description,
      severity: e.severity,
      ruleIds: runTagger([event], RULES).perEvent[0]?.ruleIds ?? [],
    };
  });
}
const only = (rows: Row[]): Row => {
  expect(rows).toHaveLength(1);
  return rows[0];
};

// ───────────────────────────── AWS ─────────────────────────────
const awsBase = {
  eventTime: "2026-01-01T00:00:00Z",
  userIdentity: { type: "IAMUser", userName: "alice", accountId: "111122223333" },
  sourceIPAddress: "198.51.100.7",
  awsRegion: "us-east-1",
  recipientAccountId: "111122223333",
};
const aws = (eventName: string, eventSource: string, requestParameters: unknown, extra = {}): Row =>
  only(
    tag(
      parseCloudTrail(
        JSON.stringify({ Records: [{ ...awsBase, eventName, eventSource, requestParameters, ...extra }] }),
      ).events,
    ),
  );
const snapshot = (perm: unknown) =>
  aws("ModifySnapshotAttribute", "ec2.amazonaws.com", {
    snapshotId: "snap-0123456789abcdef0",
    attributeType: "CREATE_VOLUME_PERMISSION",
    createVolumePermission: perm,
  });
const policy = (statement: unknown) =>
  aws("PutBucketPolicy", "s3.amazonaws.com", {
    bucketName: "b1",
    bucketPolicy: { Version: "2012-10-17", Statement: [statement] },
  });

describe("gap rules — AWS (#2306)", () => {
  it("cloud_aws_event_selectors_changed: PutEventSelectors yes, StopLogging no", () => {
    const yes = aws("PutEventSelectors", "cloudtrail.amazonaws.com", {
      trailName: "main",
      eventSelectors: [{ readWriteType: "WriteOnly", includeManagementEvents: false }],
    });
    expect(yes.ruleIds).toContain("cloud_aws_event_selectors_changed");
    const no = aws("StopLogging", "cloudtrail.amazonaws.com", { name: "main" });
    expect(no.ruleIds).not.toContain("cloud_aws_event_selectors_changed");
  });

  it("cloud_aws_snapshot_shared: a share with an account or the world yes, a removal no", () => {
    const account = snapshot({ add: { items: [{ userId: "444455556666" }] } });
    expect(account.description).toContain("shares snapshot snap-0123456789abcdef0 with account 444455556666");
    expect(account.ruleIds).toContain("cloud_aws_snapshot_shared");
    const world = snapshot({ add: { items: [{ group: "all" }] } });
    expect(world.description).toContain("publicly");
    expect(world.ruleIds).toContain("cloud_aws_snapshot_shared");
    const removed = snapshot({ remove: { items: [{ userId: "444455556666" }] } });
    expect(removed.description).toContain("removes sharing of snapshot");
    expect(removed.ruleIds).not.toContain("cloud_aws_snapshot_shared");
  });

  it("cloud_aws_bucket_public: a world-readable policy or ACL yes; an account principal, a conditional '*', a private ACL no", () => {
    const pub = policy({
      Effect: "Allow",
      Principal: "*",
      Action: "s3:GetObject",
      Resource: "arn:aws:s3:::b1/*",
    });
    expect(pub.ruleIds).toContain("cloud_aws_bucket_public");
    const acl = aws("PutBucketAcl", "s3.amazonaws.com", {
      bucketName: "b3",
      AccessControlPolicy: {
        AccessControlList: {
          Grant: [
            { Grantee: { URI: "http://acs.amazonaws.com/groups/global/AllUsers" }, Permission: "READ" },
          ],
        },
      },
    });
    expect(acl.description).toContain("makes bucket b3 public (ACL grants READ to AllUsers)");
    expect(acl.ruleIds).toContain("cloud_aws_bucket_public");
    const canned = aws("PutBucketAcl", "s3.amazonaws.com", {
      bucketName: "b4",
      "x-amz-acl": ["public-read"],
    });
    expect(canned.ruleIds).toContain("cloud_aws_bucket_public");

    const scoped = policy({
      Effect: "Allow",
      Principal: { AWS: "arn:aws:iam::111122223333:root" },
      Action: "s3:GetObject",
      Resource: "arn:aws:s3:::b1/*",
    });
    expect(scoped.ruleIds).not.toContain("cloud_aws_bucket_public");
    const conditional = policy({
      Effect: "Allow",
      Principal: "*",
      Action: "s3:GetObject",
      Resource: "arn:aws:s3:::b1/*",
      Condition: { IpAddress: { "aws:SourceIp": "192.0.2.0/24" } },
    });
    expect(conditional.description).toContain("under a condition");
    expect(conditional.ruleIds).not.toContain("cloud_aws_bucket_public");
    const privateAcl = aws("PutBucketAcl", "s3.amazonaws.com", {
      bucketName: "b5",
      "x-amz-acl": ["private"],
    });
    expect(privateAcl.ruleIds).not.toContain("cloud_aws_bucket_public");
  });
});

// ───────────────────────────── GCP ─────────────────────────────
const gcp = (role: string, member: string, action = "ADD", caller = "bob@example.com"): Row =>
  only(
    tag(
      parseCloudActivity(
        JSON.stringify({
          timestamp: "2026-01-01T00:00:00Z",
          logName: "projects/p1/logs/cloudaudit.googleapis.com%2Factivity",
          resource: { type: "project", labels: { project_id: "p1" } },
          protoPayload: {
            "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
            methodName: "SetIamPolicy",
            serviceName: "cloudresourcemanager.googleapis.com",
            resourceName: "projects/p1",
            authenticationInfo: { principalEmail: caller },
            requestMetadata: { callerIp: "203.0.113.9" },
            serviceData: { policyDelta: { bindingDeltas: [{ action, role, member }] } },
          },
        }),
      ).events,
    ).filter((r) => r.description.startsWith("GCP SetIamPolicy")), // a service-account caller adds a join row
  );

describe("gap rules — GCP (#2306)", () => {
  it("cloud_gcp_owner_granted: roles/owner added yes; removed, or another role, no", () => {
    expect(gcp("roles/owner", "user:carol@example.com").ruleIds).toContain("cloud_gcp_owner_granted");
    expect(gcp("roles/owner", "user:carol@example.com", "REMOVE").ruleIds).not.toContain(
      "cloud_gcp_owner_granted",
    );
    expect(gcp("roles/editor", "user:carol@example.com").ruleIds).not.toContain("cloud_gcp_owner_granted");
  });

  it("cloud_gcp_external_member_added: an outside-domain or public member yes; a same-domain one, or a service-account caller, no", () => {
    const outside = gcp("roles/viewer", "user:mallory@example.net");
    expect(outside.description).toContain("user:mallory@example.net (outside the caller's domain)");
    expect(outside.ruleIds).toContain("cloud_gcp_external_member_added");
    expect(gcp("roles/viewer", "allUsers").ruleIds).toContain("cloud_gcp_external_member_added");
    expect(gcp("roles/viewer", "user:carol@example.com").ruleIds).not.toContain(
      "cloud_gcp_external_member_added",
    );
    const saCaller = gcp(
      "roles/viewer",
      "user:mallory@example.net",
      "ADD",
      "deployer@p1.iam.gserviceaccount.com",
    );
    expect(saCaller.description).not.toContain("outside the caller");
    expect(saCaller.ruleIds).not.toContain("cloud_gcp_external_member_added");
  });
});

// ───────────────────────────── M365 (Analyzer-Suite) ─────────────────────────────
let n = 0;
const ual = (Workload: string, Operation: string, extra: Record<string, unknown> = {}) => ({
  CreationTime: "2026-01-01T00:00:00",
  Id: `aaaaaaaa-0000-4000-8000-${String(++n).padStart(12, "0")}`,
  Operation,
  Workload,
  RecordType: 1,
  UserId: "admin@example.com",
  ClientIP: "198.51.100.4",
  OrganizationId: "11111111-1111-4111-8111-111111111111",
  ResultStatus: "Succeeded",
  ...extra,
});
const m365 = (...recs: unknown[]): Row[] =>
  tag(parseM365Audit(JSON.stringify(recs), { aggregate: false }).events);
const m1 = (rec: unknown): Row => only(m365(rec));
const ex = (op: string, params: Array<[string, string]> = []) =>
  m1(ual("Exchange", op, { Parameters: params.map(([Name, Value]) => ({ Name, Value })) }));

describe("Analyzer-Suite operations (#2306)", () => {
  it("mas_operation_audit_config_changed: Set-AdminAuditLogConfig tagged (graded by the importer, #2549); Get no", () => {
    const yes = ex("Set-AdminAuditLogConfig", [["UnifiedAuditLogIngestionEnabled", "False"]]);
    expect(yes.ruleIds).toContain("mas_operation_audit_config_changed");
    expect(ex("Get-AdminAuditLogConfig").ruleIds).not.toContain("mas_operation_audit_config_changed");
  });

  it("mas_operation_mail_flow_change: New-InboundConnector yes; Get-InboundConnector no", () => {
    expect(ex("New-InboundConnector", [["Name", "c1"]]).ruleIds).toContain("mas_operation_mail_flow_change");
    expect(ex("Get-InboundConnector").ruleIds).not.toContain("mas_operation_mail_flow_change");
  });

  it("mas_operation_inbox_rule_toggled: Enable-InboxRule yes; Get-InboxRule no", () => {
    expect(ex("Enable-InboxRule", [["Identity", "r"]]).ruleIds).toContain("mas_operation_inbox_rule_toggled");
    expect(ex("Get-InboxRule").ruleIds).not.toContain("mas_operation_inbox_rule_toggled");
  });

  it("mas_operation_mailbox_delegation: Add-RecipientPermission yes; Get-RecipientPermission no", () => {
    const yes = ex("Add-RecipientPermission", [
      ["Identity", "ceo"],
      ["Trustee", "x@example.com"],
      ["AccessRights", "SendAs"],
    ]);
    expect(yes.ruleIds).toContain("mas_operation_mailbox_delegation");
    expect(ex("Get-RecipientPermission").ruleIds).not.toContain("mas_operation_mailbox_delegation");
  });

  it("mas_operation_app_owner_added: Add owner to application yes; Remove owner no", () => {
    const yes = m1(ual("AzureActiveDirectory", "Add owner to application.", { RecordType: 8 }));
    expect(yes.ruleIds).toContain("mas_operation_app_owner_added");
    const no = m1(ual("AzureActiveDirectory", "Remove owner from application.", { RecordType: 8 }));
    expect(no.ruleIds).not.toContain("mas_operation_app_owner_added");
  });

  it("mas_operation_app_changed: Update service principal yes; Add user no", () => {
    expect(m1(ual("AzureActiveDirectory", "Update service principal.", { RecordType: 8 })).ruleIds).toContain(
      "mas_operation_app_changed",
    );
    expect(m1(ual("AzureActiveDirectory", "Add user.", { RecordType: 8 })).ruleIds).not.toContain(
      "mas_operation_app_changed",
    );
  });

  it("mas_operation_search_query: SearchQueryInitiatedExchange yes; MailItemsAccessed no", () => {
    expect(ex("SearchQueryInitiatedExchange").ruleIds).toContain("mas_operation_search_query");
    expect(ex("MailItemsAccessed").ruleIds).not.toContain("mas_operation_search_query");
  });

  it("mas_operation_sync_download: FileSyncDownloadedFull yes; FileAccessed no", () => {
    const sp = (op: string) =>
      m1(ual("SharePoint", op, { ObjectId: "https://example.sharepoint.com/a.docx" }));
    expect(sp("FileSyncDownloadedFull").ruleIds).toContain("mas_operation_sync_download");
    expect(sp("FileAccessed").ruleIds).not.toContain("mas_operation_sync_download");
  });

  it("mas_operation_security_detection: AtpDetection yes; another ThreatIntelligence operation no", () => {
    const ti = (op: string) => m1(ual("ThreatIntelligence", op, { RecordType: 47 }));
    expect(ti("AtpDetection").ruleIds).toContain("mas_operation_security_detection");
    expect(ti("TIMailData").ruleIds).not.toContain("mas_operation_security_detection");
  });
});

describe("Analyzer-Suite move-to folders (#2306)", () => {
  it("mas_inbox_rule_hiding_folder: a rule moving mail to a localized hiding folder yes; to an ordinary folder no", () => {
    const yes = ex("New-InboxRule", [
      ["Name", "r"],
      ["MoveToFolder", "Archiv"],
    ]);
    expect(yes.description).toContain('moves to "Archiv"');
    expect(yes.ruleIds).toContain("mas_inbox_rule_hiding_folder");
    const no = ex("New-InboxRule", [
      ["Name", "r"],
      ["MoveToFolder", "Receipts"],
    ]);
    expect(no.ruleIds).not.toContain("mas_inbox_rule_hiding_folder");
  });

  it("snapshot rows: a localized name matches, an English name stays with snap_inbox_rule_hides_mail", () => {
    const snap = (folder: string) =>
      tag(
        parseCloudSnapshot(
          [
            '"UserName","RuleName","RuleIdentity","Enabled","MoveToFolder"',
            `"user1@example.com","r","1","True","${folder}"`,
          ].join("\n"),
          { label: "snap.csv", importedAt: "2026-11-05T00:00:00Z" },
        ).events,
      )[0];
    expect(snap("Posta indesiderata").ruleIds).toContain("mas_inbox_rule_hiding_folder");
    const english = snap("RSS Feeds");
    expect(english.ruleIds).toContain("snap_inbox_rule_hides_mail");
    expect(english.ruleIds).not.toContain("mas_inbox_rule_hiding_folder");
  });
});

describe("Analyzer-Suite OAuth permissions (#2306)", () => {
  const SP = "cccccccc-0000-4000-8000-000000000001";
  const grant = (activity: string, prop: string, value: string) =>
    m365({
      id: `bbbbbbbb-0000-4000-8000-${String(++n).padStart(12, "0")}`,
      activityDateTime: "2026-01-01T00:00:00Z",
      activityDisplayName: activity,
      category: "ApplicationManagement",
      loggedByService: "Core Directory",
      result: "success",
      initiatedBy: { user: { userPrincipalName: "admin@example.com", ipAddress: "198.51.100.4" } },
      targetResources: [
        {
          type: "ServicePrincipal",
          id: SP,
          displayName: "Sync",
          modifiedProperties: [{ displayName: prop, oldValue: '""', newValue: `"${value}"` }],
        },
      ],
    });

  it("mas_oauth_risky_delegated_permission: Mail.Read yes; openid (a Low entry) no", () => {
    const rows = grant(
      "Add delegated permission grant",
      "DelegatedPermissionGrant.Scope",
      "Mail.Read openid",
    );
    const mail = rows.find((r) => r.description.includes("delegated permission Mail.Read "));
    const openid = rows.find((r) => r.description.includes("delegated permission openid "));
    expect(mail?.ruleIds).toContain("mas_oauth_risky_delegated_permission");
    expect(openid?.ruleIds).not.toContain("mas_oauth_risky_delegated_permission");
  });

  it("mas_oauth_risky_application_permission: an observed Calendars.Read application grant yes; User.Read.All no", () => {
    const snap = (scope: string) =>
      tag(
        parseCloudSnapshot(
          [
            '"PermissionType","AppId","ClientObjectId","ClientDisplayName","ResourceDisplayName","Permission","ConsentType","PrincipalDisplayName"',
            `"Application","dddddddd-0000-4000-8000-000000000001","${SP}","Sync","Microsoft Graph","${scope}","AllPrincipals",""`,
          ].join("\n"),
          { label: "oauth.csv", importedAt: "2026-11-05T00:00:00Z" },
        ).events,
      );
    const yes = snap("Calendars.Read");
    expect(yes.some((r) => r.ruleIds.includes("mas_oauth_risky_application_permission"))).toBe(true);
    const no = snap("User.Read.All");
    expect(no.some((r) => r.ruleIds.includes("mas_oauth_risky_application_permission"))).toBe(false);
  });
});

describe("Analyzer-Suite user agents (#2306)", () => {
  const signIn = (userAgent: string, extra: Record<string, unknown> = {}) =>
    m1({
      id: `dddddddd-0000-4000-8000-${String(++n).padStart(12, "0")}`,
      createdDateTime: "2026-01-01T00:00:00Z",
      userPrincipalName: "u@example.com",
      appDisplayName: "Office 365",
      ipAddress: "203.0.113.5",
      userAgent,
      status: { errorCode: 0 },
      resourceTenantId: "11111111-1111-4111-8111-111111111111",
      ...extra,
    });
  const browser =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36";

  it("mas_user_agent_aitm_or_spray: axios yes, a browser no", () => {
    const yes = signIn("axios/1.6.8");
    expect(yes.description).toContain("[ua: axios/1.6.8]");
    expect(yes.ruleIds).toContain("mas_user_agent_aitm_or_spray");
    expect(signIn(browser).ruleIds).not.toContain("mas_user_agent_aitm_or_spray");
  });

  // #2483 — a non-interactive sign-in (a token refresh by a background client) from an HTTP library
  // is common and benign on its own: tagged for search, never graded.
  it("an HTTP library on a NON-interactive sign-in is tagged, not graded; interactive and unknown stay Medium", () => {
    const nonInt = { signInEventTypes: ["nonInteractiveUser"], isInteractive: false };
    const bg = signIn("node-fetch/1.0", nonInt);
    expect(bg.description).toMatch(/^Entra sign-in: \[non-interactive\] /);
    expect(bg.ruleIds).not.toContain("mas_user_agent_aitm_or_spray");
    expect(bg.ruleIds).toContain("mas_user_agent_http_library_noninteractive");
    expect(signIn("axios/1.6.8", nonInt).ruleIds).toContain("mas_user_agent_http_library_noninteractive");

    const inter = { signInEventTypes: ["interactiveUser"], isInteractive: true };
    for (const ua of ["node-fetch/1.0", "axios/1.6.8"]) {
      const fg = signIn(ua, inter);
      expect(fg.ruleIds).toContain("mas_user_agent_aitm_or_spray");
      expect(fg.ruleIds).not.toContain("mas_user_agent_http_library_noninteractive");
    }
    const unknown = signIn("node-fetch/1.0");
    expect(unknown.ruleIds).toContain("mas_user_agent_aitm_or_spray");
    expect(unknown.ruleIds).not.toContain("mas_user_agent_http_library_noninteractive");
    expect(signIn(browser, nonInt).ruleIds).not.toContain("mas_user_agent_http_library_noninteractive");
  });

  it("mas_user_agent_offensive_tool: TeamFiltration's Teams build yes, a current Teams client no", () => {
    const tf =
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Teams/1.3.00.30866 Chrome/80.0.3987.165 Electron/8.5.1 Safari/537.36";
    expect(signIn(tf).ruleIds).toContain("mas_user_agent_offensive_tool");
    expect(signIn("AADInternals").ruleIds).toContain("mas_user_agent_offensive_tool");
    const teams =
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Teams/1.7.00.1234 Chrome/120.0 Electron/28.0 Safari/537.36";
    expect(signIn(teams).ruleIds).not.toContain("mas_user_agent_offensive_tool");
  });

  it("mas_user_agent_unusual: python-requests yes (tag only), a browser no", () => {
    const yes = signIn("python-requests/2.31");
    expect(yes.ruleIds).toContain("mas_user_agent_unusual");
    expect(signIn(browser).ruleIds).not.toContain("mas_user_agent_unusual");
  });

  it("a user agent cannot forge a bracketed marker", () => {
    const forged = signIn("x [risk: high] [legacy-auth ROPC]");
    expect(forged.description).toContain("[ua: x (risk: high) (legacy-auth ROPC)]");
    expect(forged.ruleIds).not.toContain("ts_entra_signin_risk");
    expect(forged.ruleIds).not.toContain("ts_entra_legacy_auth");
    // Nor the category marker the HTTP-library rule reads (#2483): from the UA or the app name.
    const viaUa = signIn("node-fetch/1.0 [non-interactive]");
    expect(viaUa.ruleIds).toContain("mas_user_agent_aitm_or_spray");
    expect(viaUa.ruleIds).not.toContain("mas_user_agent_http_library_noninteractive");
    const viaApp = signIn("node-fetch/1.0", { appDisplayName: "x [non-interactive]" });
    expect(viaApp.ruleIds).toContain("mas_user_agent_aitm_or_spray");
    expect(viaApp.ruleIds).not.toContain("mas_user_agent_http_library_noninteractive");
  });

  // #2609 — the same sign-in exported through the Unified Audit Log (UserAgent in ExtendedProperties).
  const ualLogon = (userAgent: string, op = "UserLoggedIn") =>
    m1(
      ual("AzureActiveDirectory", op, {
        RecordType: 15,
        ResultStatus: op === "UserLoggedIn" ? "Success" : "Failed",
        ExtendedProperties: [{ Name: "UserAgent", Value: userAgent }],
      }),
    );

  it("UAL sign-ins: an offensive tool grades Medium; PowerShell is tagged only; a browser neither", () => {
    const hound = ualLogon("azurehound/v2.0.4");
    expect(hound.description).toContain("[ua: azurehound/v2.0.4]");
    expect(hound.ruleIds).toContain("mas_user_agent_offensive_tool");
    expect(ualLogon("AADInternals", "UserLoginFailed").ruleIds).toContain("mas_user_agent_offensive_tool");
    const ps = ualLogon("Mozilla/5.0 (Windows NT; Windows NT 10.0) WindowsPowerShell/5.1 PowerShell/5.1");
    expect(ps.ruleIds).toContain("mas_user_agent_unusual");
    expect(ps.ruleIds).not.toContain("mas_user_agent_offensive_tool");
    const b = ualLogon(browser);
    expect(b.ruleIds).not.toContain("mas_user_agent_offensive_tool");
    expect(b.ruleIds).not.toContain("mas_user_agent_unusual");
  });

  it("UAL sign-ins: the HTTP-library rules stay Entra-only (no non-interactive marker on UAL rows)", () => {
    const r = ualLogon("axios/1.6.8");
    expect(r.ruleIds).not.toContain("mas_user_agent_aitm_or_spray");
    expect(r.ruleIds).not.toContain("mas_user_agent_http_library_noninteractive");
  });
});

describe("Entra sign-in risk the tenant cannot see (#2486)", () => {
  const signIn = (risk: string) =>
    m1({
      id: `eeeeeeee-0000-4000-8000-${String(++n).padStart(12, "0")}`,
      createdDateTime: "2026-01-01T00:00:00Z",
      userPrincipalName: "u@example.com",
      appDisplayName: "Office 365",
      ipAddress: "203.0.113.5",
      status: { errorCode: 0 },
      riskLevelDuringSignIn: risk,
      resourceTenantId: "11111111-1111-4111-8111-111111111111",
    });

  it("a hidden risk level (no Entra ID P2) is not a risk signal; a real level still is", () => {
    const hidden = signIn("hidden");
    expect(hidden.description).toContain("[risk level not visible (no Entra ID P2)]");
    expect(hidden.ruleIds).not.toContain("ts_entra_signin_risk");
    expect(signIn("low").ruleIds).toContain("ts_entra_signin_risk");
  });

  it("a row stored before the fix with '[risk: hidden]' is not tagged as risky", () => {
    const old = only(
      tag([
        { description: "Entra sign-in: u@example.com from 203.0.113.5 [risk: hidden]", severity: "Info" },
      ]),
    );
    expect(old.ruleIds).not.toContain("ts_entra_signin_risk");
    const real = only(
      tag([{ description: "Entra sign-in: u@example.com from 203.0.113.5 [risk: low]", severity: "Info" }]),
    );
    expect(real.ruleIds).toContain("ts_entra_signin_risk");
  });
});
