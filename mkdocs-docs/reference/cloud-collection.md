# Cloud Collection

Cloud collection reads audit logs straight from an AWS account, a Microsoft tenant or a GCP
project, and saves them as case evidence. It uses a **cloud account**: the credential for one
account, tenant or project, kept in an encrypted vault.

Add cloud accounts in **Settings → Integrations → Cloud accounts**, with a case open. An account
belongs to the cases it is attached to, and you need write access to a case to see, add, check or
use its accounts. Cloud accounts are disabled on the public demo.

---

## Check access

Each account in the list has a **Check access** button. Pick the log sources to test and press
**Run check**. For each source, the companion makes **one read** with the account's credential —
a page of one entry, or one file listing and one file read — and reports which reads worked and
which failed, with the reason the cloud gave.

| Provider | Source | The one read the check makes |
|---|---|---|
| AWS | CloudTrail event history | One page of CloudTrail event history (`LookupEvents`) |
| AWS | CloudTrail S3 bucket | List one file under the trail's key prefix, then read the first byte of that file |
| Microsoft | Entra sign-in logs | One page of sign-ins |
| Microsoft | Entra directory audit logs | One page of directory audits |
| GCP | Admin Activity, System Event and Policy audit logs | One page of those logs (`entries.list`) |
| GCP | Data Access audit logs | One page of Data Access logs (`entries.list`) |

Before any source, AWS asks who the credential belongs to (`GetCallerIdentity`) and shows the
answer. Microsoft and GCP first get a sign-in token. **A sign-in that works proves nothing about
what the account can read**, so a sign-in alone never counts as a success.

The result always takes this form:

> Tested reads succeeded for: CloudTrail event history. Failed: CloudTrail S3 bucket (…). The
> companion did not test whether this identity can also write. Use the minimum policy.

**The check never says an account is read-only.** It makes no write of any kind and does not ask
the AWS policy simulator: the simulator needs extra permission of its own and still cannot prove
an identity is read-only. To keep a collection credential read-only, grant it exactly the minimum
policy below and nothing more.

Some sources can be reported as **Not tested**, with the reason:

- **CloudTrail S3 bucket** — you did not name the trail bucket, or the key prefix holds no file
  to read. Enter the bucket and, if the trail uses one, its key prefix (default `AWSLogs/`).
- **GCP Data Access audit logs** — the last 30 days hold no Data Access entry, so reading them
  could not be proven either way.

When the trail is encrypted with a KMS key, listing the bucket works but reading a trail file
fails until the identity also has `kms:Decrypt` on that key. The check says so when a file read
fails.

The check does not test the Microsoft unified audit log (searching it starts by creating a
query, which is a write), Azure Activity logs, GuardDuty or a GCP log sink bucket.

Every check is recorded in the team audit log as `cloud-account-check`. No credential ever
appears in a result, a log line or the audit log.

---

## Minimum policies

The add form in Settings shows the minimum policy for the provider you pick. Grant this and
nothing more.

### AWS

An IAM policy for the role or user the companion signs in as. Replace `<trail-bucket>` with the
bucket the trail writes to — for an organization trail, the organization's log bucket.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CloudTrailRead",
      "Effect": "Allow",
      "Action": [
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "cloudtrail:LookupEvents"
      ],
      "Resource": "*"
    },
    {
      "Sid": "TrailBucketList",
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket"
      ],
      "Resource": "arn:aws:s3:::<trail-bucket>"
    },
    {
      "Sid": "TrailObjectsRead",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject"
      ],
      "Resource": "arn:aws:s3:::<trail-bucket>/*"
    },
    {
      "Sid": "TrailKmsDecryptOnlyWhenKmsEncrypted",
      "Effect": "Allow",
      "Action": [
        "kms:Decrypt"
      ],
      "Resource": "arn:aws:kms:<region>:<account-id>:key/<trail-key-id>"
    },
    {
      "Sid": "GuardDutyReadOptional",
      "Effect": "Allow",
      "Action": [
        "guardduty:ListDetectors",
        "guardduty:ListFindings",
        "guardduty:GetFindings"
      ],
      "Resource": "*"
    }
  ]
}
```

- Keep the `kms:Decrypt` statement only when the trail is encrypted with a KMS key, and name that
  key. Without it, listing works but every trail file read fails.
- The GuardDuty statement is optional. Remove it if you do not collect GuardDuty findings.
- For an assumed role, the role's trust policy must also allow the calling identity (and the
  external ID, if you set one).

### Microsoft

Microsoft Graph **application** permissions, with admin consent:

- `AuditLogsQuery.Read.All` — unified audit log queries, every workload
  ([Create auditLogQuery](https://learn.microsoft.com/graph/api/security-auditcoreroot-post-auditlogqueries?view=graph-rest-1.0))
- `AuditLog.Read.All` — sign-in logs and directory audit logs; the least-privileged permission for
  both ([List signIns](https://learn.microsoft.com/graph/api/signin-list?view=graph-rest-beta),
  [List directoryAudits](https://learn.microsoft.com/graph/api/directoryaudit-list?view=graph-rest-1.0))

And the Azure role **Reader** on each subscription to collect Activity logs from.

- The per-workload permissions (`AuditLogsQuery-Entra.Read.All`, `-Exchange`, `-SharePoint`,
  `-OneDrive`, `-CRM`, `-Endpoint`) are narrower than `AuditLogsQuery.Read.All`, but a query then
  returns only that workload's records.
- `Directory.Read.All` is not needed: Microsoft lists it only as a higher-privileged alternative
  for directory audits.
- Without `Policy.Read.All`, sign-ins leave out which Conditional Access policies applied. Add it
  only if you need that.
- Reading sign-in logs needs a Microsoft Entra ID P1 or P2 licence in the tenant.
- Upload the certificate's public part to the app registration. The companion keeps the private
  key in its vault. A PFX certificate works as well as PEM: the companion opens it in memory each
  time it signs in and never writes the key to disk.

These names were checked against Microsoft Learn on 2026-11-06.

### GCP

IAM roles on the project, granted to the service account the companion signs in as (the
impersonated one, when you use impersonation):

- `roles/logging.viewer` — Admin Activity, System Event and Policy audit logs
- `roles/logging.privateLogViewer` — Data Access audit logs
- `roles/storage.objectViewer` — only when collecting from a log sink bucket, on that bucket

For impersonation, the base identity also needs `roles/iam.serviceAccountTokenCreator` on the
impersonated service account.

---

## Collecting from Microsoft

Open **Cloud logs** in the toolbar, pick a Microsoft account of the case, a time window and the
log sources, and press **Check and start**. The pre-check shows the windows outside each log's
retention and how much of the tenant's daily audit query quota this companion has used. **Confirm
and start** runs the collection as a background job.

| Source | Where it comes from | API version |
|---|---|---|
| Microsoft 365 unified audit log | Graph audit log query (`/security/auditLog/queries`) | v1.0 |
| Entra directory audit logs | Graph `/auditLogs/directoryAudits` | v1.0 |
| Entra sign-ins — interactive user, non-interactive user, service principal, managed identity | Graph `/auditLogs/signIns`, one filter per category | beta |
| Azure Activity log | Azure Monitor, every subscription the app can read | 2015-04-01 |

- **Unified audit log.** Each time window is one audit query. Microsoft runs the query before any
  record can be read, which often takes **10 minutes or more**; the collection's row shows the
  query's status while it waits ("audit query running — 4 min"). A query that hits Microsoft's
  record limit is split into two halves, down to one minute, and then one query per record type.
  Each query counts against the tenant's daily quota (at least 200 a rolling day, shared with every
  other tool), and the collection stops as **partial — budget used** before it goes past this
  companion's share (`DFIR_CLOUD_M365_QUERY_BUDGET`, default 50). Resume it later.
  `Search-UnifiedAuditLog` is never used.
- **Sign-ins.** Graph returns only interactive sign-ins unless a request names the category, so
  each category is its own source with its own filter. The result lists each one, so you can see
  which categories were collected. Category filters exist only on the Graph beta version, so the
  sign-in sources use beta. Graph allows 5 sign-in and directory-audit requests per 10 seconds per
  app and tenant; the collection keeps to that.
- **Azure Activity.** Every subscription the app holds a role on is collected, one after another.
  An app that can read no subscription fails this source with what to grant.
- **Not collected:** mailbox audit, transport rules and message trace. Collect them with Microsoft
  Extractor Suite (MES) and import the files; the cloud tool compatibility matrix (#2300) says which
  file covers what.

Every page Microsoft returns is saved exactly as it came, with its SHA-256 in the collection's
manifest, and imported: unified audit log and Entra pages through the Microsoft 365 importer, Azure
Activity pages through the cloud activity importer. A Graph audit record grades exactly like the
same record in a classic unified audit log export.

---

## Network settings

Every cloud request — sign-in token requests included — goes through the cloud TLS and proxy
settings in **Settings → Integrations → Cloud accounts**: `DFIR_CLOUD_CA`, `DFIR_CLOUD_INSECURE`
and `DFIR_CLOUD_PROXY_URL`. The standard `HTTPS_PROXY` variable is not used for cloud collection.

### The machine's own credentials

An AWS account set to assume a role with the **ambient profile or instance role**, and a GCP account
that impersonates with **ambient credentials**, sign in with the credentials of the machine the
companion runs on. Those sign-ins go through the same proxy and TLS settings: AWS profiles that
assume a role, SSO profiles, web-identity tokens, and Google user logins and service-account key
files.

**Metadata endpoints are always reached directly, never through the proxy.** On a cloud VM or
container the credentials come from a metadata service on the machine's own network link: AWS
instance metadata (`169.254.169.254`), the ECS and EKS container credential endpoints
(`169.254.170.2`, `169.254.170.23`) and the Google metadata server (`metadata.google.internal`). A
proxy cannot reach those addresses, and they only answer the machine itself.

Cloud collection refuses to run when:

- `AWS_EC2_METADATA_SERVICE_ENDPOINT` or `AWS_CONTAINER_CREDENTIALS_FULL_URI` points at a host that
  is not on the machine's own link, or `GCE_METADATA_HOST` / `GCE_METADATA_IP` does. Those requests
  would leave the machine without the proxy and TLS settings.
- The machine's Google credentials are an **external account** (workload identity federation). That
  sign-in fetches tokens with its own network clients. Store a service-account key on the account
  instead.

An AWS profile with `credential_process` runs the program you configured. Whatever network that
program uses is its own, outside the companion's settings.
