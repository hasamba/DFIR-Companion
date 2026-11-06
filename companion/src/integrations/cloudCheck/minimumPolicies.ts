// The minimum read-only grant for each provider (#2309): shown in Settings when an account is added
// and published in mkdocs-docs/reference/cloud-collection.md (a test keeps the two in step).
//
// Placeholders in angle brackets are the analyst's to fill. The read check tests some of these reads;
// it never tests what else the identity may do, so granting exactly this is how an analyst keeps a
// collection credential read-only.

import type { CloudProvider } from "../cloudAccounts/types.js";

export interface MinimumPolicy {
  provider: CloudProvider;
  title: string;
  /** What to grant, ready to paste: an IAM policy document, or one permission or role per line. */
  grant: string;
  notes: string[];
}

/** IAM policy for CloudTrail collection. Drop the KMS statement for a trail without SSE-KMS. */
export const AWS_MINIMUM_POLICY_DOCUMENT = {
  Version: "2012-10-17",
  Statement: [
    {
      Sid: "CloudTrailRead",
      Effect: "Allow",
      Action: ["cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus", "cloudtrail:LookupEvents"],
      Resource: "*",
    },
    {
      Sid: "EnabledRegionsList",
      Effect: "Allow",
      Action: ["ec2:DescribeRegions"],
      Resource: "*",
    },
    {
      Sid: "TrailBucketList",
      Effect: "Allow",
      Action: ["s3:ListBucket"],
      Resource: "arn:aws:s3:::<trail-bucket>",
    },
    {
      Sid: "TrailObjectsRead",
      Effect: "Allow",
      Action: ["s3:GetObject"],
      Resource: "arn:aws:s3:::<trail-bucket>/*",
    },
    {
      Sid: "TrailKmsDecryptOnlyWhenKmsEncrypted",
      Effect: "Allow",
      Action: ["kms:Decrypt"],
      Resource: "arn:aws:kms:<region>:<account-id>:key/<trail-key-id>",
    },
    {
      Sid: "GuardDutyReadOptional",
      Effect: "Allow",
      Action: ["guardduty:ListDetectors", "guardduty:ListFindings", "guardduty:GetFindings"],
      Resource: "*",
    },
  ],
} as const;

/**
 * Microsoft Graph application permissions (admin consent), as #2315 collects them — checked against
 * Microsoft Learn on 2026-11-06: AuditLogsQuery.Read.All for audit log queries (the per-workload
 * AuditLogsQuery-*.Read.All names return only their workload's records); AuditLog.Read.All, the
 * least-privileged permission for both sign-ins and directory audits. Directory.Read.All is only a
 * higher-privileged alternative for directory audits, so it is not asked for.
 */
export const MICROSOFT_GRAPH_PERMISSIONS = ["AuditLogsQuery.Read.All", "AuditLog.Read.All"] as const;
export const MICROSOFT_AZURE_ROLE = "Reader";

export const GCP_ROLES = [
  "roles/logging.viewer",
  "roles/logging.privateLogViewer",
  "roles/storage.objectViewer",
] as const;

const AWS: MinimumPolicy = {
  provider: "aws",
  title: "AWS: IAM policy for the collection role or user",
  grant: JSON.stringify(AWS_MINIMUM_POLICY_DOCUMENT, null, 2),
  notes: [
    "Replace <trail-bucket> with the bucket the trail writes to. For an organization trail, use the organization's log bucket.",
    "Keep the kms:Decrypt statement only when the trail is encrypted with a KMS key, and name that key. Without it, listing works but every trail file read fails.",
    "ec2:DescribeRegions lists the regions enabled on the account, opt-in regions included. Without it, collection uses the default region list and says so.",
    "The GuardDuty statement is needed only to collect GuardDuty findings and to test them with Check access. Remove it if you do not collect GuardDuty findings.",
    "For an assumed role, the role's trust policy must also allow the calling identity (and the external ID, if you set one).",
  ],
};

const MICROSOFT: MinimumPolicy = {
  provider: "microsoft",
  title: "Microsoft: Graph application permissions and Azure role",
  grant: [
    ...MICROSOFT_GRAPH_PERMISSIONS.map((p) => `Microsoft Graph (application): ${p}`),
    `Azure role: ${MICROSOFT_AZURE_ROLE}, on each subscription to collect Activity logs from`,
  ].join("\n"),
  notes: [
    "Add the Graph permissions as application permissions (not delegated) and grant admin consent.",
    "AuditLogsQuery.Read.All reads the whole unified audit log. The per-workload permissions (AuditLogsQuery-Entra.Read.All, -Exchange, -SharePoint, -OneDrive, -CRM, -Endpoint) are narrower, but a query then returns only that workload's records.",
    "AuditLog.Read.All reads sign-in and directory audit logs. Without Policy.Read.All the sign-ins leave out which Conditional Access policies applied; add it only if you need that.",
    "Reading sign-in logs needs a Microsoft Entra ID P1 or P2 licence in the tenant.",
    "Upload the certificate's public part to the app registration. The companion keeps the private key in its vault.",
  ],
};

const GCP: MinimumPolicy = {
  provider: "gcp",
  title: "GCP: IAM roles on the project",
  grant: [
    "roles/logging.viewer: Admin Activity, System Event and Policy audit logs",
    "roles/logging.privateLogViewer: Data Access audit logs",
    "roles/storage.objectViewer: only when collecting from a log sink bucket, on that bucket",
  ].join("\n"),
  notes: [
    "Grant the roles to the service account the companion signs in as (the impersonated one, when you use impersonation).",
    "For impersonation, the base identity also needs roles/iam.serviceAccountTokenCreator on the impersonated service account.",
  ],
};

export const MINIMUM_POLICIES: Readonly<Record<CloudProvider, MinimumPolicy>> = {
  aws: AWS,
  microsoft: MICROSOFT,
  gcp: GCP,
};
