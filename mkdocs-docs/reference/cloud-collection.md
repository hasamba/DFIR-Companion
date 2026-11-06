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
- **Microsoft accounts with a PFX certificate** — the check cannot sign in with a PFX file yet.
  Microsoft collection adds PFX support. To check now, save the certificate as PEM instead.

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

- `AuditLogsQuery.Read.All` — unified audit log searches
- `AuditLog.Read.All` — sign-in and directory audit logs
- `Directory.Read.All` — directory data the sign-in logs refer to

And the Azure role **Reader** on each subscription to collect Activity logs from.

- Reading sign-in logs needs a Microsoft Entra ID P1 or P2 licence in the tenant.
- Upload the certificate's public part to the app registration. The companion keeps the private
  key in its vault.
- Microsoft collection confirms the final permission names against Microsoft Learn when it is
  built.

### GCP

IAM roles on the project, granted to the service account the companion signs in as (the
impersonated one, when you use impersonation):

- `roles/logging.viewer` — Admin Activity, System Event and Policy audit logs
- `roles/logging.privateLogViewer` — Data Access audit logs
- `roles/storage.objectViewer` — only when collecting from a log sink bucket, on that bucket

For impersonation, the base identity also needs `roles/iam.serviceAccountTokenCreator` on the
impersonated service account.

---

## Network settings

Every cloud request — sign-in token requests included — goes through the cloud TLS and proxy
settings in **Settings → Integrations → Cloud accounts**: `DFIR_CLOUD_CA`, `DFIR_CLOUD_INSECURE`
and `DFIR_CLOUD_PROXY_URL`. The standard `HTTPS_PROXY` variable is not used for cloud collection.
