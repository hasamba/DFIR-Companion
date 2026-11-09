# Setting Up Cloud Accounts

A click-by-click guide to creating the identity the companion collects with, in AWS, Google Cloud
and Microsoft 365 / Entra / Azure, and adding it to a case. No cloud experience is assumed.

For what each permission is for, and what the companion collects with it, see
[Cloud Collection](cloud-collection.md). For the Settings fields, see
[Settings → Cloud accounts](settings.md#cloud-accounts).

!!! warning "Read-only, short-lived, one case"
    - **Grant exactly the permissions below and nothing more.** The companion never checks whether
      an identity could also *write*; the permissions you grant are what keep it read-only.
    - **One identity per investigation.** Attach it to the case. When the case closes, the
      companion deletes its stored copy (unless you choose to keep it). Delete or disable the
      identity in the cloud too.
    - **On a client's environment, the client creates the identity.** Send them the section for
      their cloud. Never ask for an administrator login.
    - Practise on a lab account (an AWS sandbox account, a GCP test project, a Microsoft 365
      developer tenant) before a real case.

The console menus below were current in November 2026. Cloud providers rename menus from time to
time; the names of the permissions and roles do not change.

---

## Before you start, in the companion

1. Open (or create) the case the collection is for.
2. Open **Settings** and switch the **Essential / All** toggle at the top to **All** — the cloud
   accounts list is hidden in *Essential* mode.
3. Go to the **Integrations** tab and scroll past the DFIR-IRIS and Timesketch server sets to
   **Cloud accounts (AWS, Microsoft, GCP)**.
4. Keep this page open. You come back to it at the end of each cloud's section.

While a case is open, an account you add here is attached to that case. An account added with no
case open goes to the **Cloud credentials held** list; open the case and press
**Attach to this case** to use it.

When you pick a provider in **+ Add cloud account**, the form shows the minimum permissions for
that provider. They are the same as in this guide.

---

## AWS

You create three things: a **trail** (if the account has none), a **read-only policy**, and a
**user** with an **access key** that the companion signs in with.

### Step 1 — Check that the account has a trail

A trail is what writes the account's activity log (CloudTrail) to an S3 bucket. Without one the
companion can still read the last 90 days of management events, but not the full history.

1. Sign in to the [AWS console](https://console.aws.amazon.com/) with an administrator of the
   account.
2. In the search bar at the top, type **CloudTrail** and open it.
3. In the left menu, click **Trails**.
4. **If a trail is listed:** click it and write down the **S3 bucket** name shown under
   *General details*. Also note whether **Log file SSE-KMS encryption** says *Enabled* — if it
   does, write down the **AWS KMS key** ARN. Go to step 2.
5. **If no trail is listed:** click **Create trail**.
    - **Trail name:** for example `account-trail`.
    - **Storage location:** *Create new S3 bucket*. Write down the bucket name it proposes.
    - **Log file SSE-KMS encryption:** for a lab, **untick** it — that keeps the policy simpler.
      (On a real account keep whatever the client uses; step 2 covers both.)
    - Leave the rest as it is, click **Next**.
    - **Events:** leave **Management events** ticked, with **Read** and **Write**. Click **Next**,
      then **Create trail**.

A new trail writes its first files about 5–15 minutes later. It does not contain anything from
before it was created.

### Step 2 — Create the read-only policy

1. In the search bar, type **IAM** and open it.
2. In the left menu, click **Policies**, then **Create policy**.
3. Click the **JSON** tab. Delete what is in the editor and paste this:

    ```json
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "CloudTrailRead",
          "Effect": "Allow",
          "Action": ["cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus", "cloudtrail:LookupEvents"],
          "Resource": "*"
        },
        {
          "Sid": "EnabledRegionsList",
          "Effect": "Allow",
          "Action": ["ec2:DescribeRegions"],
          "Resource": "*"
        },
        {
          "Sid": "TrailBucketList",
          "Effect": "Allow",
          "Action": ["s3:ListBucket"],
          "Resource": "arn:aws:s3:::<trail-bucket>"
        },
        {
          "Sid": "TrailObjectsRead",
          "Effect": "Allow",
          "Action": ["s3:GetObject"],
          "Resource": "arn:aws:s3:::<trail-bucket>/*"
        },
        {
          "Sid": "TrailKmsDecryptOnlyWhenKmsEncrypted",
          "Effect": "Allow",
          "Action": ["kms:Decrypt"],
          "Resource": "arn:aws:kms:<region>:<account-id>:key/<trail-key-id>"
        },
        {
          "Sid": "GuardDutyReadOptional",
          "Effect": "Allow",
          "Action": ["guardduty:ListDetectors", "guardduty:ListFindings", "guardduty:GetFindings"],
          "Resource": "*"
        }
      ]
    }
    ```

4. Edit it:
    - Replace **both** `<trail-bucket>` with the bucket name from step 1 (only the name, for
      example `aws-cloudtrail-logs-123456789012-a1b2c3d4`).
    - **Trail not KMS-encrypted** (the lab default above): delete the whole
      `TrailKmsDecryptOnlyWhenKmsEncrypted` block — from its `{` to its `},` — so the JSON stays
      valid.
    - **Trail KMS-encrypted:** replace the whole `arn:aws:kms:…` value with the KMS key ARN from
      step 1.
    - **No GuardDuty:** you may delete the `GuardDutyReadOptional` block. Keeping it does no harm.
5. Click **Next**. **Policy name:** `dfir-companion-read`. Click **Create policy**.

If the editor shows a red error, a comma or a bracket is out of place — usually after deleting a
block. The last block must not end with a comma.

### Step 3 — Create the user and attach the policy

1. In IAM's left menu, click **Users**, then **Create user**.
2. **User name:** for example `dfir-companion`. Leave **Provide user access to the AWS Management
   Console** **unticked** — this user never signs in to the console. Click **Next**.
3. Choose **Attach policies directly**. In the search box type `dfir-companion-read` and tick it.
   Click **Next**, then **Create user**.

### Step 4 — Create the access key

1. Click the new user's name to open it, then the **Security credentials** tab.
2. Under **Access keys**, click **Create access key**.
3. **Use case:** choose **Third-party service** (or **Application running outside AWS**). If AWS
   suggests an alternative, tick the confirmation box and click **Next**.
4. Optionally add a description (for example the case name), then **Create access key**.
5. Copy the **Access key** and the **Secret access key** now, or click **Download .csv file**.
   **The secret is shown only once.** Keep it out of email and chat.

### Step 5 — Add it to the companion

In **Settings → Cloud Accounts**, with the case open:

1. Click **+ Add cloud account**.
2. **Name:** for example `client AWS prod`. **Provider:** *AWS account*.
3. **Sign-in:** *Access key*.
4. **Region:** the account's main region, for example `eu-west-1`. Optional; it is the region
   asked first.
5. **Access key ID** and **Secret access key:** paste them. Leave **Session token** empty.
6. Click **Save**. The account now appears in the list.
7. On the account's row, click **Check access**. Tick the sources, enter the **Trail bucket** from
   step 1 (leave **Key prefix** as `AWSLogs/` unless the trail uses another), and run it.

Every source should report success. *GuardDuty findings* reports success with a note when
GuardDuty is off in that region — that is fine. A failure names the missing permission: fix the
policy in step 2 and run the check again.

You can now collect from the case's **Collect cloud logs** button (see
[Collect from AWS](cloud-collection.md#collect-from-aws)).

### Optional — a role instead of a long-lived key (recommended for real cases)

An access key works until someone deletes it. A **role** gives the companion sessions of at most
one hour, and the user's own key can do nothing except start those sessions.

1. **IAM → Roles → Create role.** **Trusted entity type:** *AWS account*, **This account** (or
   **Another AWS account** with the account ID the user lives in). Optionally tick **Require
   external ID** and type a random value. Click **Next**.
2. Tick `dfir-companion-read`, click **Next**. **Role name:** `dfir-companion-collector`. Click
   **Create role**, open it and copy its **ARN**.
3. On the user from step 3, remove `dfir-companion-read` and add an inline policy instead
   (**Add permissions → Create inline policy → JSON**):

    ```json
    {
      "Version": "2012-10-17",
      "Statement": [
        { "Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "<role-arn>" }
      ]
    }
    ```

4. In the companion: **Sign-in:** *Assume role*, **Role ARN:** the role's ARN, **External ID:** the
   value from step 1 (if any), **Base credential:** *Stored access key*, and the user's access key
   and secret.

### Clean up (AWS)

When the investigation ends: delete the access key (**IAM → Users → the user → Security
credentials → Actions → Delete**), then the user, the role and the policy. A trail you created only
for a lab can be deleted in **CloudTrail → Trails** (its bucket stays until you empty and delete
it in **S3**).

---

## Google Cloud (GCP)

You create a **service account** with two read roles, turn on **Data Access** logs if you need
them, and give the companion a **key** for the service account.

### Step 1 — Open the right project

1. Sign in to the [Google Cloud console](https://console.cloud.google.com/) with an owner or IAM
   administrator of the project.
2. In the project picker at the top, select the project to investigate. Write down its
   **Project ID** (shown in the picker and on the dashboard — it is not always the same as the
   project's name).

### Step 2 — Create the service account

1. Open the menu (☰) → **IAM & Admin → Service Accounts**.
2. Click **+ Create service account**.
3. **Service account name:** for example `dfir-companion`. The ID fills in by itself. Click
   **Create and continue**.
4. **Grant this service account access to project** — click **Select a role** and add:
    - **Logging → Logs Viewer** (`roles/logging.viewer`): Admin Activity, System Event and Policy
      audit logs.
    - Click **+ Add another role** → **Logging → Private Logs Viewer**
      (`roles/logging.privateLogViewer`): Data Access audit logs.
5. Click **Continue**, then **Done**.

### Step 3 — Turn on Data Access logs (optional, but often what you need)

Admin Activity logs are always on. **Data Access** logs (who read which data) are **off by
default** for most services, so they only exist from the moment you turn them on.

1. Menu (☰) → **IAM & Admin → Audit Logs**.
2. Tick the services that matter (for example **Google Cloud Storage**, **BigQuery**,
   **Secret Manager**).
3. In the panel that opens, tick **Data Read** and **Data Write**, then **Save**.

Data Access logs can be large and are billed above the free allowance. On a client project, ask
the client before turning them on.

### Step 4 — Create a key for the service account

1. In **IAM & Admin → Service Accounts**, click the `dfir-companion` account.
2. Open the **Keys** tab → **Add key → Create new key** → **JSON** → **Create**.
3. A `.json` file downloads. It is a credential: keep it out of email and chat, and delete it once
   it is in the companion.

**"Service account key creation is disabled"?** The organization enforces the policy that blocks
keys (newer organizations do by default). Either:

- ask an organization administrator to allow keys for this one project (**IAM & Admin →
  Organization Policies → Disable service account key creation → Manage policy → Override**), or
- skip the key and use **impersonation**: on the companion machine run
  `gcloud auth application-default login` as a user who has **Service Account Token Creator**
  (`roles/iam.serviceAccountTokenCreator`) on the service account, enable the
  **IAM Service Account Credentials API** in the project, and in the companion choose
  *Impersonate a service account* with **Base credential:** *Ambient credentials*.

### Step 5 — Add it to the companion

In **Settings → Cloud Accounts**, with the case open:

1. Click **+ Add cloud account**. **Name:** for example `client GCP`. **Provider:** *GCP project*.
2. **Project ID:** from step 1.
3. **Sign-in:** *Service-account key*. Open the `.json` file in a text editor, copy all of it and
   paste it into **Service-account key JSON**.
4. Click **Save**, then **Check access** on the account's row.

*Data Access audit logs* may report **Not tested** when the project has no Data Access entry in the
last 30 days — that only means there was nothing to read yet.

You can now collect from the case's **Collect cloud logs** button (see
[Collect GCP audit logs](cloud-collection.md#collect-gcp-audit-logs)).

### Optional — a log sink bucket

If the project exports its audit logs to a Cloud Storage bucket (a *log sink*), the companion can
read older logs from there. Give the service account **Storage Object Viewer**
(`roles/storage.objectViewer`) **on that bucket only**: **Cloud Storage → Buckets → the bucket →
Permissions → Grant access**.

### Clean up (GCP)

Delete the key (**Service Accounts → the account → Keys → delete**), then the service account. Turn
Data Access logs back off if you turned them on only for a lab.

---

## Microsoft 365, Entra ID and Azure

You create an **app registration** that signs in with a **certificate**, give it two Microsoft
Graph permissions, and (for Azure Activity logs) the **Reader** role on each subscription.

### Step 1 — Check the tenant's prerequisites

- **Auditing is on.** Open the [Microsoft Purview portal](https://purview.microsoft.com/) →
  **Audit**. If a banner offers **Start recording user and admin activity**, click it; recording
  can take up to an hour to start. Most tenants have it on already.
- **Sign-in logs need Entra ID P1 or P2.** Microsoft 365 E3/E5, Business Premium and the developer
  and trial tenants include it. Without it, the sign-in logs are not available; the other sources
  still are.
- You need a **Global Administrator** or **Privileged Role Administrator** for the admin consent in
  step 5, and **Owner** or **User Access Administrator** on the Azure subscription for step 6.

### Step 2 — Make a certificate

The companion signs in with a certificate, not a password. Make one on your own computer, in an
empty folder you delete afterwards.

**Linux or macOS** (needs `openssl`, installed on almost every system):

```bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout dfir.key -out dfir.crt -days 30 -subj "/CN=dfir-companion"
```

This makes `dfir.crt` (the public part — uploaded to Microsoft) and `dfir.key` (the private key —
goes only into the companion). `-days 30` makes it expire after 30 days; set it to the length of
the investigation.

**Windows** (PowerShell, no extra tools):

```powershell
$c = New-SelfSignedCertificate -Subject "CN=dfir-companion" -CertStoreLocation "Cert:\CurrentUser\My" `
  -KeyExportPolicy Exportable -KeySpec Signature -KeyAlgorithm RSA -KeyLength 2048 -NotAfter (Get-Date).AddDays(30)
Export-Certificate -Cert $c -FilePath dfir.cer
$pw = Read-Host -AsSecureString "Choose a PFX password"
Export-PfxCertificate -Cert $c -FilePath dfir.pfx -Password $pw
```

This makes `dfir.cer` (the public part — uploaded to Microsoft) and `dfir.pfx` (certificate and
private key, protected by the password — goes only into the companion).

### Step 3 — Register the app

1. Sign in to the [Microsoft Entra admin center](https://entra.microsoft.com/).
2. Go to **Entra ID → App registrations** (in some tenants: **Identity → Applications → App
   registrations**) and click **+ New registration**.
3. **Name:** for example `DFIR Companion collector`. **Supported account types:** *Accounts in this
   organizational directory only (single tenant)*. Leave **Redirect URI** empty. Click
   **Register**.
4. On the app's **Overview** page, copy the **Application (client) ID** and the
   **Directory (tenant) ID**.

### Step 4 — Upload the certificate

1. In the app, open **Certificates & secrets → Certificates** tab → **Upload certificate**.
2. Choose `dfir.crt` (Linux/macOS) or `dfir.cer` (Windows) — the **public** part only. Add a
   description (for example the case name) and click **Add**.

Do not create a *client secret*; the companion does not use one.

### Step 5 — Grant the Graph permissions

1. In the app, open **API permissions → + Add a permission → Microsoft Graph →
   Application permissions** (not *Delegated*).
2. Search for and tick:
    - `AuditLogsQuery.Read.All` — the unified audit log, every workload
    - `AuditLog.Read.All` — sign-in logs and directory audit logs
3. Click **Add permissions**.
4. Click **Grant admin consent for <your tenant>** and confirm. Both permissions must show a green
   tick under *Status*. Without consent the companion's sign-in works, but every read is refused.

The default **User.Read** (delegated) permission can stay or be removed; the companion does not
use it. Add **Policy.Read.All** only if you need to see which Conditional Access policies applied
to each sign-in.

### Step 6 — Give it Reader on Azure subscriptions (only for Azure Activity logs)

Skip this if you only need Microsoft 365 and Entra logs.

1. Sign in to the [Azure portal](https://portal.azure.com/) → **Subscriptions** → click the
   subscription.
2. **Access control (IAM) → + Add → Add role assignment.**
3. **Role** tab: search **Reader**, select it, click **Next**.
4. **Members** tab: **Assign access to:** *User, group, or service principal* → **+ Select
   members** → type the app's name (`DFIR Companion collector`) → select it → **Select**.
5. **Review + assign** (twice).

Repeat for every subscription to collect from. The companion collects every subscription the app
can read.

### Step 7 — Add it to the companion

In **Settings → Cloud Accounts**, with the case open:

1. Click **+ Add cloud account**. **Name:** for example `client M365`. **Provider:**
   *Microsoft tenant*.
2. **Tenant ID** and **Application (client) ID:** from step 3.
3. **Certificate:**
    - **Linux/macOS — PEM:** choose *PEM (certificate and private key)*. Open `dfir.crt` and
      `dfir.key` in a text editor and paste **both**, one after the other, into
      **Certificate PEM** (or run `cat dfir.crt dfir.key` and paste the output).
    - **Windows — PFX:** choose *PFX file and password*, pick `dfir.pfx` and type its password.
      The companion checks the password when you save.
4. Click **Save**, then **Check access** on the account's row.
5. Delete the certificate files from your computer (on Windows also remove the certificate from
   **Certificates – Current User → Personal**). The companion keeps the private key encrypted in
   its vault.

You can now collect from the case's **Collect cloud logs** button (see
[Collecting from Microsoft](cloud-collection.md#collecting-from-microsoft)). An audit-log query can
take around 10 minutes on Microsoft's side; the panel shows its status.

### Clean up (Microsoft)

Delete the app registration (**App registrations → the app → Delete**). That removes its
permissions and its certificate at once. Remove its **Reader** assignment from each subscription
(**Access control (IAM) → Role assignments**) if the portal still lists it.

---

## When Check access fails

| What it says | What to do |
|---|---|
| AWS **AccessDenied** on a CloudTrail, EC2 or GuardDuty call | The policy is missing that action, or is not attached to the user. Re-check AWS step 2 and step 3. |
| AWS bucket listing works, file read **AccessDenied** | The trail is KMS-encrypted: add the `kms:Decrypt` block with the trail's key ARN. If the key belongs to another account, its key policy must also allow your user. |
| AWS **InvalidClientTokenId** or **SignatureDoesNotMatch** | The access key ID or secret was pasted wrongly, or the key was deleted. Edit the account and paste them again. |
| GCP **403 PERMISSION_DENIED** on Data Access logs | The service account lacks **Private Logs Viewer**. |
| GCP **403** on everything | Wrong Project ID, or the roles were granted in another project. |
| Microsoft **AADSTS700027** or **AADSTS700016** | The certificate uploaded to the app does not match the one in the companion, or the client ID or tenant ID is wrong. |
| Microsoft **403 / Authorization_RequestDenied** | Admin consent was not granted (Microsoft step 5), or the permission was added as *Delegated* instead of *Application*. |
| Microsoft sign-in logs refused, the rest works | The tenant has no Entra ID P1/P2 licence. |
| Azure Activity: **no subscription** | The app has no **Reader** role on any subscription (Microsoft step 6). Role assignments can take a few minutes to apply. |
