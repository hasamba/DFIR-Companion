# Cloud Collection

Cloud collection reads audit logs straight from an AWS account, a Microsoft tenant or a GCP
project, and saves them as case evidence. It uses a **cloud account**: the credential for one
account, tenant or project, kept in an encrypted vault.

Add cloud accounts in **Settings → Integrations → Cloud accounts**, with a case open. An account
belongs to the cases it is attached to, and you need write access to a case to see, add, check or
use its accounts. Cloud accounts are disabled on the public demo.

---

## When the case ends

A cloud credential is usually issued for one investigation, so it ends with the case:

- **Close the case.** If the case has cloud accounts, the close dialog lists them and asks
  **Delete credentials** (the default) or **Keep credentials**. Kept credentials stay usable, and
  Settings → Cloud accounts shows the case as **closed — credentials kept**.
- **Archive or delete the case.** Its credentials are always deleted, first. If the companion
  cannot delete them, the case is left in place, unchanged: delete refuses with an error, and
  archive still gives you the archive file but keeps the case in the active list. Try again, or
  delete the credentials from Settings → Cloud accounts first.
- **Shared accounts.** An account another case also uses is only detached. It is deleted with its
  last case.
- **A running collection** blocks closing, archiving or deleting the case until it is stopped or
  finishes.
- **Revoke it in the cloud.** Deleting the companion's copy does not stop the key working. Revoke
  the AWS access key, the Microsoft app certificate or secret, or the GCP service-account key, as
  well.
- **The record stays.** Each case the credential was attached to gets a `credential-deleted` entry
  in its chain of custody: provider, account, tenant or project ID, who added it and when, which
  collections used it, who deleted it, when and why. A case a shared account is only detached from
  gets the same details as a `credential-detached` entry. Reports can still say where the collected
  evidence came from. No secret is recorded.

Settings → Cloud accounts lists every credential you can see, with its cases, who added it and when
it was last used, and deletes one or several at once. See
[Settings → Cloud accounts](settings.md#cloud-accounts).

## Check access

Each account in the list has a **Check access** button. Pick the log sources to test and press
**Run check**. For each source, the companion makes **one read** with the account's credential —
a page of one entry, or one file listing and one file read — and reports which reads worked and
which failed, with the reason the cloud gave.

| Provider | Source | The one read the check makes |
|---|---|---|
| AWS | CloudTrail event history | One page of CloudTrail event history (`LookupEvents`) |
| AWS | CloudTrail S3 bucket | List one file under the trail's key prefix, then read the first byte of that file |
| AWS | Enabled regions (ec2:DescribeRegions) | List the regions enabled on the account (`DescribeRegions`) |
| AWS | GuardDuty findings | List the GuardDuty detectors of the account's region (`ListDetectors`) |
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

- **GuardDuty findings** is reported as a success with a note when the account's region has no
  GuardDuty detector: the read worked, but GuardDuty is off in that region. Collection still asks
  every other region.
- **CloudTrail S3 bucket** — you did not name the trail bucket, or the key prefix holds no file
  to read. Enter the bucket and, if the trail uses one, its key prefix (default `AWSLogs/`).
- **GCP Data Access audit logs** — the last 30 days hold no Data Access entry, so reading them
  could not be proven either way.

When the trail is encrypted with a KMS key, listing the bucket works but reading a trail file
fails until the identity also has `kms:Decrypt` on that key. The check says so when a file read
fails.

The check does not test the Microsoft unified audit log (searching it starts by creating a
query, which is a write), Azure Activity logs or a GCP log sink bucket.

Every check is recorded in the team audit log as `cloud-account-check`. No credential ever
appears in a result, a log line or the audit log.

---

## Collect from AWS

Open the **Collect cloud logs** panel in a case, pick an AWS account, tick the log sources and set
the time window. The companion saves what AWS returns as case evidence and imports it through the
same CloudTrail importer as an uploaded CloudTrail file, so the events are graded by the same rules.
GuardDuty findings go through the GuardDuty importer, the same one that reads a findings export you
import by hand.

| Source | What it reads | Covers |
|---|---|---|
| **CloudTrail S3 trail files** | The trail's own files in its S3 bucket | Everything the trail logs, for as long as the bucket keeps it — data events included |
| **CloudTrail event history** | `LookupEvents`, region by region | The last 90 days of management events only |
| **GuardDuty findings** | `ListDetectors`, `ListFindings` and `GetFindings`, region by region | The findings GuardDuty updated inside the window, in every region where it has a detector — 90 days |

### Regions

When you pick an AWS account, the panel lists the regions enabled on it, **all ticked**. The
companion asks AWS for this list (`ec2:DescribeRegions`), so opt-in regions you turned on (for
example `af-south-1`) are in it. The account's own region is marked **(account region)**. Use
**Tick all** and **Untick all**, or untick single regions.

- The choice applies to **event history** (only the ticked regions are asked) and to the
  **S3 trail files** (only the ticked regions are asked for trails, and a region folder you
  unticked is not read). A trail folder of a region that is not enabled any more (an opt-in region
  turned off after it logged) is still read unless you unticked it.
- The pre-check lists how many regions are ticked and names each one you unticked.
- The result names every region you unticked as **skipped by choice**. A region you ticked but
  that is no longer enabled when the collection starts is not asked, and the result names it.
- The regions are fixed when the collection starts and recorded in its manifest. **Resume** asks
  the same regions again, even if the account's regions changed since.
- **Without `ec2:DescribeRegions`** the panel shows the default list (the account's own region
  and the regions AWS enables by default) with a warning that says why. The pre-check and the
  result say the same, so an opt-in region missing from the list is never a silent gap. Add the
  permission (see the minimum policy) and start a new collection to collect those regions.
- Listing the regions signs in with the account's credential, so each listing is recorded in the
  team audit log as `cloud-account-regions`.
- If the list cannot be loaded at all, the panel says so, the companion lists the regions itself
  when the collection starts, and the result says which list it used. A collection whose sign-in
  fails is not created; the start error says why.

Pick **CloudTrail S3 trail files** whenever the account has a trail that writes to S3. Pick
**CloudTrail event history** when it has none, or as a quick look at recent management activity.
The pre-check and the result always say that event history holds 90 days of management events
only.

### S3 trail files

- The companion asks CloudTrail in every ticked region which trails the account has (`DescribeTrails`) and reads each
  trail's bucket and key prefix. It finds the account's folder itself, for an account trail
  (`AWSLogs/<account-id>/CloudTrail/<region>/YYYY/MM/DD/`) and for an **organization trail**
  (`AWSLogs/<org-id>/<account-id>/CloudTrail/<region>/YYYY/MM/DD/`). From an organization bucket it
  reads only the folder of the account you collect with, never the other member accounts.
- It reads every region folder the bucket holds that you did not untick, and only the days the window touches plus the
  day after. A file is taken when its delivery time is inside the window or up to **24 hours**
  after its end: CloudTrail usually delivers a file 5 to 15 minutes after the events in it, but a
  late file can come hours later. A file can hold events outside the window; they are imported
  too, and duplicates are removed. Files delivered more than 24 hours after the window end are not
  collected, and the result says so. Collect the window again later to pick them up.
- **Speed.** Each trail folder is listed once (up to 1,000 files per listing), and the next few
  files (up to 6, each at most 8 MB) are downloaded while the current one is saved. Files are still
  saved and recorded one at a time, in order, so the manifest, Resume and Cancel behave exactly as
  before. A cancel stops the downloads in flight too.
- **Each file is saved exactly as stored** — the `.json.gz` CloudTrail wrote, not unpacked or
  changed. The collection's manifest records its bucket, key, SHA-256 and, when the bucket has
  versioning on, its **S3 version id**.
- When the trail is encrypted with a KMS key and the identity may not use that key, that file
  cannot be read. The collection goes on with the other files, the result is **partial**, and it
  lists each file it skipped, with the reason. Add `kms:Decrypt` on the trail key (see the minimum
  policy) and press **Resume**: the collection reads the window again, the skipped files included.
  Files already collected are not imported twice.
- When no trail writes to a bucket the identity can list, the S3 source is reported as missing,
  and the result tells you to collect event history instead.
- When the trail folders hold no file for the window, the source **completes with 0 files**. The
  manifest records which folders were listed. If the trail should have been logging, check the
  trail status (a `StopLogging` call shows in the trail just before the gap) and the bucket's
  lifecycle rules. For a window that ends in the last few minutes, collect again later: CloudTrail
  delivers files 5 to 15 minutes late.
- **Progress.** The companion reads the trail one folder at a time: one folder per region per day.
  The job line shows how many files are saved and which folder it is in ("folder 12 of 119"). It
  estimates the total and the ETA from that position. Folders are not all the same size, so the
  ETA is approximate. While the first folder is still being read, there is no estimate yet, and
  the line shows no bar and no ETA. A trail writes about one file per region every 5 minutes, so a
  week of every region can be tens of thousands of files.

### Event history

- The companion asks every ticked region in turn, the account's own region first (see
  [Regions](#regions)). Opt-in regions enabled on the account are asked too. A region that answers
  that it is not enabled is skipped and named in the result.
- A network failure (a name that does not resolve, a dropped connection) is never taken for a
  region that is not enabled. That part of the collection is reported missing with the error, and
  **Resume** carries on from the page it stopped at.
- Requests are paced at 2 a second per region, the CloudTrail limit, and slowed further when AWS
  asks.
- Event history returns each event inside an envelope. The companion saves the CloudTrail record
  text from each event exactly as AWS returned it, inside a standard `{"Records": [...]}` file, so
  the importer reads it like a trail file. The manifest notes this on every event history page.

### GuardDuty findings

- The companion asks the regions the collection walks, one by one — the same regions as event
  history: the regions enabled on the account, opt-in regions included, minus any you unticked in
  the region picker (see [Regions](#regions)). In each region it asks for the GuardDuty detector.
  A region without a detector has GuardDuty turned off; a region the account has not enabled cannot
  have one. Neither is an error: each page names those regions (`noDetectorRegions`,
  `regionsNotEnabled` in the manifest). A network failure is never taken for either; that part of
  the collection is reported missing with the error, and **Resume** carries on from the page it
  stopped at.
- Findings are chosen by the time GuardDuty **last updated** them: every finding updated inside
  the window, archived findings included. GuardDuty updates a finding each time it sees the
  activity again, so a finding first seen long before the window is collected when it was
  updated inside it. A finding updated again after the window end is saved as it is now; the
  manifest counts those (`updatedAfterWindow`).
- Each page holds up to 50 findings, saved as `{"Findings": [...]}` — the findings as the AWS SDK
  returns them, the same shape `aws guardduty get-findings` prints. The manifest notes this on
  every GuardDuty page, with the number of findings listed and fetched.
- Collecting the same findings again is safe. A finding that has not changed is a duplicate and
  is not imported twice. A finding GuardDuty updated since is imported as a new event, so the
  timeline shows each update.
- When the identity may not read GuardDuty, the source is reported missing with the reason. Add
  the GuardDuty statement of the minimum policy and press **Resume**.
- Each finding becomes one event, graded by GuardDuty's own severity: **Critical** from 9.0,
  **High** from 7.0, **Medium** from 4.0, **Low** below 4.0. An **archived** finding is graded
  **Info**, so it is in the super-timeline only, with "archived" in its description. See
  [Importing — AWS GuardDuty findings](importing.md#aws-guardduty-findings).

### CloudTrail sources

- Every request — sign-in included — goes through the cloud network settings below.
- The newest 15 minutes of the window may still be arriving when you collect. The result states
  the time the collection is settled up to. Collect again from that time to pick up later events;
  overlapping windows are safe, duplicates are removed.

---

## Minimum policies

The add form in Settings shows the minimum policy for the provider you pick. Grant this and
nothing more.

New to cloud consoles? [Setting Up Cloud Accounts](cloud-account-setup.md) walks through creating
each identity, click by click, and adding it to a case.

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
      "Sid": "EnabledRegionsList",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeRegions"
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
- `ec2:DescribeRegions` lists the regions enabled on the account, opt-in regions included, for
  the region picker. It reads nothing else. Without it, collection uses the default region list
  and says so (see [Regions](#regions)).
- The GuardDuty statement is needed only to collect GuardDuty findings and to test them with
  Check access. Remove it if you do not collect GuardDuty findings.
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
  That last step uses the list of record types known when this release was built, so a record type
  Microsoft adds later is not covered by it until the list is updated.
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
  An app that can read no subscription fails this source with what to grant. A subscription that
  refuses its Activity log (no role on it, or it was disabled or deleted) is skipped and the next
  one is collected; the result is partial and names the skipped subscription, and **Resume** tries
  it again.
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

---

## Collect GCP audit logs

Pick a GCP cloud account, a source and a time window. The companion collects the project's four
Cloud Audit Logs — **Admin Activity**, **Data Access**, **System Event** and **Policy** — saves
every page as evidence, and imports it through the GCP importer. It needs no `gcloud` and no
Windows tools.

| Source | Where the logs come from |
|---|---|
| **GCP audit logs** | The Cloud Logging API |
| **GCP audit logs from a log sink bucket** | A Cloud Storage bucket that a log sink writes to, when the sink passes the checks below. Otherwise the Cloud Logging API |

### The Cloud Logging API

The companion asks for 1,000 entries per page, oldest first, with this filter:

```
logName=("projects/<p>/logs/cloudaudit.googleapis.com%2Factivity" OR "projects/<p>/logs/cloudaudit.googleapis.com%2Fdata_access" OR "projects/<p>/logs/cloudaudit.googleapis.com%2Fsystem_event" OR "projects/<p>/logs/cloudaudit.googleapis.com%2Fpolicy") AND timestamp>="<start>" AND timestamp<"<end>"
```

- It makes at most **60 requests per minute**, the Cloud Logging read limit. When Google answers
  that the quota is used, the companion waits and tries again.
- Each saved page is Google's answer exactly as it came back. The manifest records the filter.
- A page token expires after **24 hours**. If a stopped collection resumes later than that, the
  companion starts that part of the window again from its start. Pages already saved stay as
  evidence; the import removes the duplicates.
- A part of the window with very many pages is split into smaller time windows, down to one
  second, and then into one request per audit log.
- Cloud Logging keeps Admin Activity, System Event and Policy logs **400 days**, and Data Access
  logs **30 days** in the `_Default` bucket unless someone changed it. **Data Access logs are off
  by default** for most services: unless someone turned them on, there are none to collect.

### A log sink bucket

A log sink can copy audit logs to a Cloud Storage bucket, which often keeps them longer than Cloud
Logging does. The companion uses a sink **only after it checks**:

1. **The filter.** The sink must provably send all four audit logs. The companion accepts only an
   empty filter, or a filter made of `logName` terms joined by `OR` — for example
   `logName:"cloudaudit.googleapis.com"`, or the four exact audit log names. Any other filter is
   rejected because the companion cannot prove it keeps every audit entry. That includes a second
   condition on its own line (Cloud Logging joins it with an implicit `AND`), `AND`, `NOT` or `-`,
   another field, and a sink with exclusion filters.
2. **The history.** Logs are in the bucket from the latest of three times: when the sink was
   created, when it was last changed (its filter may have been widened then), and its oldest audit
   log file. A sink whose last-change time is unknown is not used. A window that starts earlier is
   collected from the Cloud Logging API.
3. **The permission.** The account must be able to list the bucket (`roles/storage.objectViewer`).

When a check fails, the companion collects from the Cloud Logging API. The result's notes say why
the sink was not used — for example `Log sink not used: sink "audit-sink": its filter does not
include the data_access audit logs` — and so does the manifest.

From a sink, each saved page is one log file from the bucket, exactly as stored: the hourly files
and the addendum files (`…_A0:<time>.json`) that Cloud Logging writes later for entries that
arrived late. A window with no log file in the bucket saves the bucket listing as its page, as
evidence that the window was empty; that page is not imported. **Sinks write hourly batches, and parts of an hour can arrive late.** The companion
treats the logs as settled only up to the last whole hour that is at least **three hours** old, and
the result says so: *Settled up to … only*. That delay is an estimate. Cloud Logging does not
guarantee that a sink delivered every entry, so **a collection from a sink is never reported as
complete**: it ends as partial, with the note *Log sink delivery is not guaranteed complete*. For a
completeness guarantee, collect the same window with the **GCP audit logs** source as well;
duplicates are removed.

### Roles

- `roles/logging.viewer` — Admin Activity, System Event and Policy logs, and the list of log sinks
- `roles/logging.privateLogViewer` — Data Access logs
- `roles/storage.objectViewer` — on the sink's bucket, only for the log sink source
