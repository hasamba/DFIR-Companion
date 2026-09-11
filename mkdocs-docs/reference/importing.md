# Importing Evidence

## The Import Button

Toolbar → **Import** button. Drag or select any file. The server **auto-detects the format** and routes it to the correct importer. You do not need to tell it what kind of file it is.

After import completes, a banner shows `📥 last import N ago / +N new events / +N new IOCs`. New items are highlighted `NEW` in the timeline and IOC panel for easy review.

## Optional Severity Floor

Before importing, you can set a **minimum severity** filter. Events below the floor are dropped during import, reducing noise. Leave it blank to import everything.

!!! note
    Events with no built-in severity (plain host-triage artifacts like KAPE or Plaso) are always imported in full, regardless of the floor.

!!! tip "Remember this choice"
    Check **Remember this choice — don't ask again** on the prompt to skip it on future imports and reuse the saved floor. Manage or clear the saved choice in **Settings → General → Import severity**. Per-browser, no server round-trip.

## Supported Formats

| Category | Formats |
|----------|---------|
| **Windows detection** | Chainsaw hunt JSON/JSONL, EVTX dump (evtx_dump), Hayabusa JSON/CSV timeline |
| **Windows Event Log XML** | Event Viewer "Save As XML", `wevtutil qe /f:xml`, PowerShell `Get-WinEvent … ToXml()` (Security, Sysmon, System, any channel) — same per-EID Windows/Sysmon mapping as the SIEM/EVTX-JSON paths |
| **Windows crash reports** | Windows Error Reporting `Report.wer` — the faulting application, its loaded modules and the crash signature |
| **Windows host triage** | KAPE/EZ Tools CSVs (Prefetch, Amcache, ShimCache, LNK, JumpLists, USN Journal, MFT, SRUM, Recycle Bin, Shellbags), Cyber Triage JSONL/JSON/CSV |
| **EDR / SIEM** | Velociraptor native JSON/JSONL/artifact-map, Velociraptor **upload-only artifacts** (e.g. THOR) — paste the GUI's "Uploaded Files" tab URL to import just the uploaded report, skipping rows entirely; also reads `.csv`/`.txt`/`.log`/`.jsonl` uploads, not just `.json`, SIEM/EDR JSON (Elastic, Splunk, Kibana, winlogbeat), Wazuh JSON, THOR Nextron JSONL, ECAR (EDR Common Activity Record) NDJSON |
| **Network** | Suricata eve.json, Zeek JSON (combined or per-stream conn/dns/http/ssl/x509/files), Security Onion events |
| **Firewall / IDS / web logs** | Cisco ASA syslog (Built/Teardown/Deny), Snort/Suricata `alert_fast` IDS alerts, Apache/Nginx/Squid combined access logs, plain syslog (RFC 5424 / RFC 3164, Linux/Unix hosts) |
| **Memory forensics** | Volatility 3 JSON + default text output, Rekall JSON, MemProcFS timeline CSV, MemProcFS findevil, Intact (trimmed VolWeb) `memory_payload.json` + `yarascan_results.jsonl` |
| **Cloud IR** | AWS CloudTrail JSON, M365 Unified Audit Log, Entra ID sign-in/audit logs, GCP Cloud Audit Logs, Azure Activity Log |
| **Identity provider** | Okta System Log, Google Workspace admin/login audit — severity comes from the event type, not the vendor's own operational grade, so IdP account-takeover tradecraft (MFA/2SV disabled, admin role granted, API token minted, OAuth grant consented, session impersonated, Workspace mail monitor added) grades above Info |
| **Browser artifacts** | Hindsight JSON or CSV — Chrome/Edge/Brave history, downloads and interpretations. Every row is Info: browser artifacts are evidence, not verdicts, so they land in the super-timeline |
| **macOS** | Unified log (`log show --style json`), LSQuarantine download provenance — quarantine rows carry both the data URL and the referring origin URL; **persistence artifacts** — LaunchAgent/LaunchDaemon plists, cron and shell profiles (see [Collecting macOS persistence artifacts](#collecting-macos-persistence-artifacts)) |
| **Mobile** | iLEAPP / ALEAPP TSV exports (iOS and Android extractions), one artifact per import. Generic by design: LEAPP artifacts share no schema, so the parser finds each row's time column and renders the rest. A table with no time column (installed apps, permissions, accounts) is imported **undated** — see below |
| **Exfiltration tooling** | rclone configuration (`rclone.conf`), rclone transfer log, MEGAsync/megacmd log — recovers remote destinations, file names, outcomes and the byte total. **Credentials are redacted in the parser**, so no token or secret key is ever stored, displayed, exported or sent to an AI |
| **Malware analysis** | CAPEv2 report.json, CrowdStrike Falcon Sandbox summary JSON, sandbox report arrays, YARA CLI scan output (`yara -s -m`) |
| **Super-timeline** | Plaso/log2timeline psort CSV (dynamic and l2tcsv) — files over 200 MB are streamed line-by-line automatically; filter your `psort` output first to reduce size |
| **Linux** | shell history (`.bash_history` / `.zsh_history`, with or without timestamps), auditd logs (raw/ausearch/aureport), journald JSON (`journalctl -o json`), **persistence artifacts** — SSH authorized keys, cron, systemd units, shell profiles, SUID listings and PATH (see [Collecting Linux persistence artifacts](#collecting-linux-persistence-artifacts)) |
| **Container/syscall** | Falco alert JSON, sysdig JSON, Kubernetes API-server audit log (`audit.k8s.io` JSON-lines / EventList) |
| **Host telemetry** | osquery scheduled-query result log (differential + snapshot) |
| **Case management** | TheHive 5 case/alert/observable export |
| **Email** | .eml (full fidelity), .msg (Outlook OLE, best-effort) |
| **SO-CRATES** | SO-CRATES event exports (Suricata, YARA, Sigma overlays) |
| **Generic** | CSV (AI-assisted field detection), log files (AI-assisted triage), DFIR-IRIS import |
| **Custom** | Analyst-defined declarative importer specs (JSON) |

All of the above except CSV/log/DFIR-IRIS are **fully deterministic — no AI call** — they map the tool's own verdict/fields, not re-detect threats.

Deterministic imports also retain a [versioned canonical event envelope](canonical-events.md) with
structured identities and field-level provenance. This lets graphs and cross-source correlation use
the source facts rather than parsing the displayed description back into data.

### Collecting Linux persistence artifacts

The Companion reads the files that decide what a Linux host runs on its own: SSH authorized keys,
cron, systemd units, shell profiles, a SUID listing and PATH.

**Upload one file.** Either a single artifact, named for what it is — `authorized_keys`,
`something.service`, `crontab`, `.bashrc` — or several files concatenated under a header line each.
Any of these header spellings works, and the path must be absolute:

```
==> /root/.ssh/authorized_keys <==
=== /etc/crontab ===
##### /home/alice/.bashrc #####
# FILE: /etc/systemd/system/telemetry.service
```

`head -n -0` writes the first form, so the simplest collection is one command:

```bash
head -n -0 /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys /etc/crontab /etc/cron.d/*   /var/spool/cron/crontabs/* /etc/systemd/system/*.service /home/*/.bashrc /etc/profile   /etc/environment > linux-persistence.txt
```

Add a SUID listing to the same file — `find / -perm -4000 -type f -ls` — under its own header.

**Add modification times if you can.** Most collections carry none, and without them the Companion
cannot tell a file changed during the incident from one that has been there for years. It says so on
every finding rather than assuming. To supply them, put a `# mtime:` line directly under a header:

```
==> /etc/systemd/system/telemetry.service <==
# mtime: 2026-01-02T09:00:00Z
# owner: root
```

**What it reports.** Not the artifacts themselves — a host is meant to have cron jobs and authorized
keys. It reports payloads that run from world-writable directories, commands that download and
execute in one line, reverse shells, root running files a user can rewrite, setuid interpreters,
SUID binaries no distribution installs, PATH resolving out of the working directory, and one SSH key
that opens two accounts. Where your environment legitimately does one of those, the finding names the
file and the line so you can rule it out.

### Collecting macOS persistence artifacts

Same shape as the Linux collection above — one upload, headers per file — and macOS cron and shell
profiles are read by the same rules. What this adds is **launchd**.

```bash
head -n -0 /Library/LaunchDaemons/*.plist /Library/LaunchAgents/*.plist \
  /Users/*/Library/LaunchAgents/*.plist /usr/lib/cron/tabs/* /Users/*/.zshrc > mac-persistence.txt
```

**Convert binary plists first.** Most plists on disk are `bplist00`, which is not text. The
Companion recognises one and tells you to convert it rather than reading nothing out of it:

```bash
plutil -convert xml1 -o - /Library/LaunchDaemons/com.example.plist
```

**Two extra facts are worth collecting**, because neither can be recovered from the plist. Put them
under the plist's header:

```
==> /Library/LaunchDaemons/com.example.plist <==
# mtime: 2026-01-02T09:00:00Z
# codesign: unsigned
# quarantine: https://example.test/update.zip
```

`codesign -dv --verbose=2 <program>` gives the first; `xattr -p com.apple.quarantine <program>` gives
the second.

**Neither one is a finding on its own, by design.** Homebrew formulas, internal builds and much
commercial software are unsigned, and almost every Mac application installs a LaunchAgent. Signing
status and a quarantine record raise and explain a job that is already suspicious for a reason of its
own: a program in a directory anything can write, a label that claims to be Apple's on something
Apple did not ship, or a command that downloads and executes in one line.

### rclone and MEGAsync evidence

Three artifacts, all plain text, all detected by content — the filename is never needed:

| Artifact | Where it usually is | What it answers |
|---|---|---|
| `rclone.conf` | `%APPDATA%\rclone\rclone.conf`, `~/.config/rclone/rclone.conf` | Where data COULD go, and under whose account |
| rclone log | wherever `--log-file` pointed | What actually moved, and how many bytes |
| `MEGAsync.log` | `%LOCALAPPDATA%\Mega Limited\MEGAsync\logs\` | Which files finished uploading to MEGA |

**A configuration is not proof of exfiltration.** Every finding from `rclone.conf` says so in as
many words. It establishes capability and intent — someone set this host up to move data to that
destination. The transfer log is what shows data moving; the config file cannot.

**Credentials never reach the tool.** An `rclone.conf` holds live OAuth refresh tokens, S3 secret
keys and service-account JSON — often the victim's own, because operators frequently configure the
remote using the victim's cloud account. Redaction happens inside the parser, so the value never
exists in the imported data at all. What you get instead is which credential keys were present and
how long each value was, plus a reminder to rotate them. Treat every credential in a collected
config as live.

**The byte total is real.** An rclone run summary carries the number of bytes transferred. No cloud
provider's audit log records that, so where you have both, the rclone log is the stronger evidence
of volume.

**Version**: neither artifact is required to declare one. Where a version appears the import note
records it; where it does not, the note says the format could not be confirmed against the tool that
wrote it.

### Intact (trimmed VolWeb output)

Intact runs VolWeb over a RAM image, then combines and trims the result into two files. Drop either
or both on the **Import** button — both are recognised as memory imports:

- `memory_payload.json` — the Volatility 3 plugin tables (process tree, cmdline, malfind, svcscan,
  dlllist, mutantscan, userassist, …) plus a stripped copy of the YARA hits.
- `yarascan_results.jsonl` — one YARA hit per line, with the matched string and value.

Three things are specific to Intact:

- **The two YARA sets overlap.** The copy inside `memory_payload.json` is a subset of the JSON-Lines
  file. Importing both is the obvious thing to do, so a hit is keyed on the address and the rule name
  and lands on ONE timeline row either way — it is never counted twice.
- **Memory YARA hits grade Low**, one tier below a file-based YARA match. A match in RAM names no
  file, and a rule set loaded into memory matches its own strings. When many DIFFERENT rules fire
  inside a few kilobytes of one another, that is a rule file rather than a set of detections, and
  those rows drop to Info with the reason shown in the row.
- **Intact caps its tables.** A table that came back holding the cap is named in the import note:
  rows beyond it were never exported, so absence in that table is not evidence of absence.

### Sandbox reports (CAPEv2, Falcon Sandbox)

A sandbox report says what a **file** does when detonated in a lab. It says nothing about what
happened on any host, so its rows are handled differently from every other import:

- **Every sandbox row goes to the super-timeline, never the forensic timeline.** The verdict and each
  behavioural signature are there to search and to promote; the AI never reads them as chronology.
  A detonation on 10 September is not something that happened on the victim on 10 September.
- **The sample's verdict reaches the AI through the events that carry its hash.** When any host
  artifact in the case (a process create, a file listing, an Amcache row) carries the same SHA-256,
  that event gains a compact `<sandbox:…>` tag naming the source, verdict, family, score and top
  signatures — at the event's own time and place. Import order does not matter: a report imported
  last week annotates a sighting that arrives today.
- **Two detonations of one sample are two records.** The newest shows first; a benign rerun never
  hides a malicious one.
- **A sandbox row is never merged with a host row**, even when they share a hash. Before this rule,
  a KAPE "file created invoice.exe" could come out of correlation described as the sandbox's
  "injects into explorer.exe" — a real host event narrated with lab behaviour.
- **The AI is not yet told what the tag means.** The synthesis prompt's tag glossary is a governed
  built-in (#378): changing it requires a real-model no-regression run against an accepted baseline.
  Until that lands, the model reads the tag by its own words — `sandbox`, the source, the verdict.

- **Only a real SHA-256 joins.** A report whose sample hash is missing or malformed still produces
  super-timeline rows and IOCs, but no verdict can attach to a sighting.

### Web access logs: decoded requests and attack shapes

A request target arrives in the log the way the client sent it — encoded. `%2e%2e%2f` is `../`,
`%3B` is `;`, and `%2525` decodes twice. The combined-log importer now decodes each request target
and Referer (up to three layers, never evaluating anything) and looks for **attack shapes** in the
decoded text and in the User-Agent:

- **traversal** — `../` segments followed by a sensitive target (`etc/passwd`, `win.ini`, `.env`,
  `.ssh/`, `id_rsa`, `.git/`); a lone `../` or a relative image path does not count.
- **cmd** — a shell separator followed by an interpreter or transfer tool with an argument
  (`;cat /etc/passwd`, `&& curl http://…`), or by a recon command (`;id`, `|whoami`, `x|uname -a`).
  A REST field list such as `fields=name|id` does not count.
- **expression** — `${jndi:…}`, a nested lookup, or a template expression with an operator or a
  call (`{{7*7}}`); a plain placeholder such as `${price}` does not count.
- **sqli** — `union select`, `' or 1=1`, a timing call with an argument, a stacked statement; a
  function name in a docs path or a search box does not count.

A row that carries one is graded **Medium** with T1190 and its description starts with the
evidence: `[web-attack: cmd] [status: 200] [match: ";cat /etc/passwd"] GET /index.php?cmd=…`. The
family names the field when it was not the target (`expression@ua`, `sqli@referer`). The HTTP
status sits in its own slot and is stated, not interpreted: **a 200 does not prove the command
ran and a 500 does not prove it was stopped** — the prefix says "web-attack", never "compromise".
Rows with no attack shape are unchanged.

Two different payloads on one path are two rows; the same payload with different padding is one.
A scanner run is bounded: after 64 distinct payloads on one path, the rest fold into one
`[overflow: …]` row per path that names every family seen. A field longer than 64 KiB is not
inspected at all — the row says `oversized@target (N chars, not inspected)` instead of silently
scanning a prefix — and a decoded control character is shown as `\x00`, never written as the byte.
### Mobile evidence with no clock (iLEAPP / ALEAPP)

Most of what a phone examination is for has no timestamp: the installed-apps list, permissions,
accounts, settings. Those tables used to be refused ("no usable timestamp column") and a row whose
time cell was empty was dropped. Now:

- **Every row is imported.** A row with no usable time is kept **undated**: it shows as `(undated)`,
  sorts after every dated row in the super-timeline, stays inside any time window you set (it
  cannot be proven out of range), and is searchable and promotable like any other row. The import
  response and the activity line say how many rows carry no clock.
- **Each row keeps the meaning of its clock.** A LEAPP table often has several time columns
  (Timestamp, Created, Last Modified) and a row's populated one is not the same for every row. Each
  row takes its first populated time column and names it in the description —
  `iLEAPP Files [Last Modified: 2026-05-03 09:00:00]: …` — with the raw text kept as written, so a
  guessed normalisation is visible. The unused clocks stay in the description as `Header: value`.
- **Rows that differ only in time are different events.** Two "app opened" rows at two times are two
  rows, not one row with a count; only byte-identical rows fold.
- **Every LEAPP row is Info** — evidence, not a verdict — so it lives in the analyst-only
  super-timeline and reaches the AI only through the deterministic tagger's rules, exactly like the
  generic import path. The dedicated LEAPP button now runs the same import spine as the generic
  button: the import lock, the super-timeline copy, the tagger, the import record and undo.

### Defender detections: what the action means

Microsoft Defender's Operational log records a detection (event 1116) and, separately, the action
it took on it (1117) or failed to take (1118, 1119). Those events used to import as plain
informational rows — the threat, the file and the result unread, and invisible to the AI. Each
now imports as a Medium row whose description starts with what Defender did:

| First token | Meaning |
|---|---|
| `[control: unknown]` | Detected; the action is a later event |
| `[control: remediated]` | Quarantine / Remove / Clean reported success |
| `[control: blocked]` | Block reported success |
| `[control: allowed]` | Defender was told to **allow** it — an explicit decision, not a cleanup |
| `[control: none-observed]` | The action was "no action" |
| `[control: remediation-failed]` | The action failed (the error code and text follow) |

Then the threat name and its severity, the flagged file, its container when it sat inside an
archive, and any further flagged members (listed; the first member is the row's path). Two actions
on one file are two rows, whatever order they were logged in.

What these rows do **not** say: a detection is the scanner's claim, not a verdict; `allowed` is not
a compromise and `remediated` is not proof the payload never ran; no second alert is not evidence
that it did; the scanner runs as SYSTEM, so its identity is never the person who launched the file;
a drive letter alone is not removable media. Linking a detection to a later start of the same file
is tracked separately (#964). Hayabusa's own Defender rows keep their Sigma grading and do not yet
carry this token.

### Cloud remote execution (AWS Systems Manager, Azure Run Command)

A cloud identity can run commands on a machine without ever logging on to it. Those calls now
import with the evidence they carry and with the phases kept apart:

- **Discovery** — `ListDocuments`, `DescribeInstanceInformation`, `GetCommandInvocation` and the
  like are Info: listing what could be run is not running it.
- **Request** — `SendCommand` is **High** and reads `[AWS-RunShellScript@1] cmd-… Pending: requested
  → i-0abc…`, with the commands themselves (`cmd: "…"`) when the document is a shell or PowerShell
  script. The whole payload is graded by the same tables a shell history is (tradecraft, spilled
  secrets, recon), so a `curl … | sh` sent through SSM grades like one typed at a prompt. The
  status at the call is *Pending*: **the result is not in CloudTrail** — the row says "requested",
  never "ran". A fleet-management document (`AWS-RunPatchBaseline`, `AWS-UpdateSSMAgent`,
  `AWS-GatherSoftwareInventory`, `AWS-InstallWindowsUpdates`) is Low **only** with routine
  parameters; an agent downgrade, a patch override list, or a parameter the document does not
  normally take is High with the reason. Any other document, custom ones included, is High.
- **Connection** — `StartSession` is High and names the target, the document and the session id.
  A port-forwarding session names the remote host and port it reaches through the node and is
  tagged as a tunnel. The session's commands are not in CloudTrail (Session Manager logging to
  S3/CloudWatch holds them, when enabled). `ResumeSession` is a connection too — often the only
  evidence when the start lies outside the collected logs.
- **Lifecycle** — `TerminateSession` is Info.

Every request and session is its own row (the command or session id is part of the identity);
a denied call is Medium and says the request did not execute. Nothing says which user the command
ran as — the SSM agent's configured user does, and guest evidence decides.

Azure `runCommand/action` and the managed `runCommands/write` (on a VM or a scale-set instance)
grade the same way: High, the target machine named, and the note that the script body is not in
the Activity Log. Two machines by one caller are two rows.

### IAM changes: what the record says

An IAM change used to import as `AWS PutRolePolicy (iam) by bob` — High for every policy write,
Low and wordless for every detach or delete, the policy document unread. A single CloudTrail record
holds no before-and-after, so the row now says exactly what the record establishes and nothing
more:

- **What the call did** — a verb, never a direction: `attaches managed policy`, `replaces inline
  policy`, `removes permissions boundary`, `sets access key status Active`, `adds user to group`.
  A detach or a delete stays Low but says so, so an eradication step reads as one. Attaching a Deny
  policy tightens and detaching one loosens — which is why no row claims "widened" or "narrowed";
  and a status update says the status requested, not "re-enabled", because the record does not
  hold the status before it.
- **What changed** — every identity the record names: the user, role or group, the policy (by
  name), the version, the access-key id, the MFA serial. Identities the response creates — a new
  access key's id, a new policy version's number — are read too. Two policies attached to one role
  in one minute are two rows.
- **The document's own words** — `grants — all actions on all resources`, `all actions except
  iam:* on all resources`, the escalation permissions it names (`iam:PassRole`, `sts:AssumeRole`,
  `iam:CreatePolicyVersion`, …), `denies 1 statement`. A broad grant is High; a Deny-only document
  keeps the call's grade. A managed policy's document is **not in the record** — the row says so and
  claims nothing about it, `AdministratorAccess` included.
- **Who a role trusts** — `allows sts:AssumeRole to external account 999988887777` (High), `to any
  principal — unrestricted public assumption` (High), `to same-account`, `to service
  lambda.amazonaws.com`. A statement with a Condition is marked `(conditional)` and the row carries
  `conditional — not evaluated here`; the word "unrestricted" is dropped, but the grade is not — a
  condition the row did not evaluate may restrict the principal or may be vacuous, and an
  unevaluated condition never lowers a grade.
- **Role passing** — `iam:PassRole` is a permission, not an event. The row for the call that uses
  it names the binding: `passing instance profile … → i-0abc` on `RunInstances` (a profile, not a
  role — the two can differ), `passing role … → my-function` on Lambda, both roles on an ECS task
  definition, the role on a CloudFormation stack, the role on a Glue dev endpoint. Medium on
  success. A `PassRole` denial reads
  `role passing denied: <role>` — an attempt, Medium, never "passed".
- **A failed call is an attempt** — `attempted to replace inline policy — denied (AccessDenied)`,
  the requested document shown, no High floor: the change did not happen. Only an authorisation
  code reads "denied"; any other error (`EntityAlreadyExists`, `LimitExceeded`) reads "failed".

Every row with a document ends with `effective access depends on controls not in this record`:
permission boundaries, organisation policies and resource policies decide what the grant does, and
the record holds none of them. A replace (`Put*`, `UpdateAssumeRolePolicy`) also says `previous
document not in this record`. Those qualifiers, the outcome and the object have reserved room in the
description; a long principal name or a long document is clipped before they are.

### Entra applications: credentials, grants, roles, sign-ins

An application that gains a credential, then a powerful permission, then acts, is the classic
tenant takeover. Each of those is an Entra directory-audit record, and each used to import as
`Entra audit: Consent to application by admin@…` — High whatever the consent said, and the
permission itself never shown. Both export shapes (the Graph `directoryAudits` object and the
Unified Audit Log's AzureActiveDirectory record) now read the same way, one row per change:

- **Credentials** — `adds Password credential 9c1d2e3f… "deploy" (2 now) for Sync`: the
  credential ADDED is the record's new list minus its old list, by key id. Two credentials in one
  record are two rows. No secret value exists in the record and none is stored; a removal reads
  `removes …` and is Low.
- **Application permissions** — `grants application permission RoleManagement.ReadWrite.Directory
  on Microsoft Graph for Sync — read and write all directory RBAC settings (any directory role,
  Global Administrator included, to any principal)`. The words are Microsoft's own description of
  the permission — the nominal grant; a data permission also says `nominal reach — application
  access policies are not in this record`, because an Exchange access policy can narrow it and the
  record does not say. The class (grant management, credential management, directory RBAC,
  identity takeover, data read, data write/send) sets the grade — High for every named class,
  Medium for anything else on Graph.
- **The API is identified only by its immutable application id.** A display name can be set to
  "Microsoft Graph" by anyone who owns a custom API, and a custom API can expose a scope spelled
  `Mail.ReadWrite` that reads no mailbox. When a record names its API only by a tenant-specific
  object id (every consent record does), the row says `API not identified in this record` and
  stays Medium whatever the spelling — unless another record of the same export states that
  object id's application id (an app-role assignment does, a service-principal sign-in does), in
  which case the class applies.
- **Consent** — `grants delegated permission Mail.Read on Microsoft Graph for Sync (admin consent,
  for all users) — read the signed-in user's mail`, one row per scope. A delegated scope is
  described as what the app can do AS THE SIGNED-IN USER, and the row says `delegated — as the
  signed-in user, within that user's access`: a delegated `Mail.Read` reads the mail of whoever is
  signed in, never every mailbox. A one-user consent to `openid profile User.Read` is Low; other
  scopes Medium; a data-write or identity scope High; admin consent for all users of a data or
  identity scope High. `IsAppOnly` consent grants application permissions and reads as such. A
  consent listing more than 32 scopes shows 32 and one more row saying how many were cut.
- **Directory roles** — `assigns directory role Global Administrator to service principal Sync —
  can manage everything in the tenant`: each built-in role carries its documented capability
  (`Application Administrator — can add credentials to any application and consent on its behalf —
  then sign in as it`); High for a tier-0 role (Global Administrator, Privileged Role
  Administrator, Privileged Authentication Administrator, Application Administrator, Cloud
  Application Administrator, Partner Tier2 Support, Hybrid Identity Administrator), Medium for the
  other built-in administrator roles, and only the name for a custom role — nothing is claimed
  about a role the table does not know. `eligible` and `(PIM activation)` are kept in the words —
  an eligible assignment is not an active one.
- **Self-grant** — when the initiating application IS the subject (by id, never by name), the row
  starts `self-grant:` and is High.
- **Attempts** — `attempted to grant application permission … — failed … [requested, not granted]`,
  Medium, no High: the change did not happen.
- **Application sign-ins** are rows now (they used to be dropped): `Entra sign-in: application
  Sync (app-id) token issued → Microsoft Graph from 198.51.100.7 credential: clientSecret k-1`.
  The credential type comes from `clientCredentialType`, never from a key id; a secret is Low, a
  certificate Info. `credential rejected (invalid client secret, AADSTS7000215)` is Medium; any
  other failure is Low with its code. Two sign-ins from two addresses, or with two credentials,
  are two rows. A Unified Audit Log sign-in record (`UserLoggedIn`, `UserLoginFailed`) is never
  read as a directory change — its `ResultStatus` says the request completed, not that the login
  succeeded.

Every grant and role row ends `assigned, not yet observed in use`: the row says what was given,
never that it was used. A sign-in after a credential was added is a separate row, not a link — the
chain finding (credential → grant → use, joined on ids with matched credential keys) is #973.
A familiar application name or a verified publisher is neither proof of safety nor of compromise;
read the initiator, the capability and the consent reach.

### Mailbox access and forwarding: what one record says

A mailbox compromise leaves Unified Audit Log records of the Exchange workload: an inbox rule
created, a mailbox forwarding address set, a permission granted, a delegate binding to messages,
mail sent as the owner, items deleted. Each used to import as `M365 Exchange: New-InboxRule by
bob@… → bob@…` — High for every rule whatever it did, the rule's actions never read, and a
delegate binding to ten mailboxes folded into one row. Each record now reads for what it holds:

- **Inbox rules** — `creates inbox rule ".." forwards to drop@… (outside the mailbox's domain),
  deletes the message on every message`. The actions and conditions are the cmdlet's own
  parameters. A rule that forwards or redirects outside the mailbox's domain is High; one that
  forwards inside, or only hides (deletes, moves, marks read), is Medium; other actions Low.
  `Set-InboxRule` carries only what changed: the row reports those deltas (`now forwards to …`,
  `renamed to …`, `now enabled`) and says `effective conditions and actions not in this record` —
  an absent parameter is unchanged, never absent, so a rename never reads as a harmless rule.
  `Disable-` and `Remove-InboxRule` are posture only and Low: removing a rule is not creating
  persistence. Outlook-created rules (`UpdateInboxRules`) read the same way from the rule's JSON
  actions.
- **"Outside the mailbox's domain"** compares the address with the domain of the mailbox owner —
  the only tenant fact the record holds. The row never says "external to the tenant": the
  tenant's verified domains are not in the record. A recipient that is not an SMTP address gets
  no class.
- **Mailbox forwarding** (`Set-Mailbox`) — `sets SMTP forwarding to x@… (outside the mailbox's
  domain)` (High); `sets forwarding to in-organization recipient …` (`ForwardingAddress` — an
  alias, name or DN, no domain class; Medium); `a copy stays` / `no copy stays` only when
  `DeliverToMailboxAndForward` is in the same record; `clears SMTP forwarding` (Low). When both
  addresses are set the row says `ForwardingAddress takes precedence`. Every partial change says
  `effective forwarding state not in this record`.
- **Permissions** — `grants FullAccess on alice@… to helper@… (outside the mailbox's domain)`,
  Medium; `Add-RecipientPermission` names its `Trustee`; removals Low.
- **Access** (`MailItemsAccessed`) — `binds 5 items in 2 folders (7 operations) on alice@… as
  delegate via REST session sess-…`. The item count is the items the record LISTS;
  `OperationCount` counts operations and is shown separately, never as messages. `Sync` is folder
  scope (`syncs folder "\Inbox"`, with `possible offline copy after sync`). Every access row says
  `item access; whether a person read the content is not established`. Grade is
  privilege-based priority, not suspicion: Admin logon (eDiscovery, MAPI Editor, impersonation —
  Microsoft records a FullAccess administrator as Delegate) Medium, Delegate Low, the owner's own
  access Info. `AppId`/`ClientAppId` is shown as `client app …` — the client, not the actor,
  unless the record's `UserType` says the actor is an application. A throttled record says the
  item list is incomplete.
- **Send and delete** — `sends as ceo@…` (the identity the record's own `SendAsUserSmtp` names;
  a non-owner: Low, the subject bounded), `hard-deletes 3 items from "\Inbox"` (the items the
  record lists; one `Item` on a single-item record).
- **A failed or unknown result is an attempt** — `attempted to create inbox rule "r" — failed`,
  Medium, no technique. A `PartiallySucceeded` result reads `partly creates …` with `which
  actions completed is not in this record`.
- **A condition the reader does not decode is still a condition** — `conditions supplied, not
  decoded: senderdomainis, except from`; `on every message` is said only for a successful
  `New-InboxRule` that supplied no condition or exception parameter at all.

Every Exchange row keys on the tenant, record type, operation, outcome, mailbox, actor, address,
client application, client string, logon and access type, session, and a digest of the complete
scope (every folder and item id, the operation count and throttling state, the cmdlet's complete
parameter values), so ten mailboxes bound by one delegate are ten rows and two addresses are two
rows; when a record's scope identity is incomplete, the record id joins so it never folds.

**Coverage — read before treating an absent row as absence of access.** Whether a
`MailItemsAccessed` record could exist for a period depends on licence, audit configuration and
retention at the time. From Microsoft's pages: mailbox auditing has been on by default since
January 2019; `MailItemsAccessed` shipped with Advanced Audit (E5) on 20 February 2020; broader
logging was announced on 19 July 2023 with the rollout from September 2023, and `MailItemsAccessed`
for Audit Standard entered public preview on 20 May 2024 — Microsoft's current page says E3 and
E5 are enabled by default and publishes no general-availability date. Retention: Audit Standard
keeps records generated before 17 October 2023 for 90 days and records from that date for 180
days; Audit Premium keeps Exchange records for one year. The 1,000-record / 24-hour throttling
behaviour (once a mailbox exceeded 1,000 `MailItemsAccessed` records in 24 hours, further access
went unlogged for the rest of the day) has no Microsoft-published retirement date; a throttled
row therefore says the gap depends on the service behaviour at the time of the event. An absent
`MailItemsAccessed` row never proves absence of access without verified coverage for the period.

The chain across records — a suspicious sign-in, then access, then a rule, then sending or
deletion — is a join by session and time, not a per-record fact; it is #975.

## Evidence Drop Folder (Auto-Import Inbox)

Every case gets a `cases/<id>/drop/` folder on creation. Copy any file into it — at any depth, subfolders included — and a background poller picks it up once the file size/mtime is stable (safe for Dropbox/OneDrive sync), then imports it through the same detection + import chain as the **Import** button. Screenshots are ingested as capture evidence; everything else is imported as an artifact.

Processed files move to `drop/_processed/`; failures move to `drop/_failed/` and are reported in the dashboard **📥 Drop** banner and any configured notification channel.

Every auto-processed file's outcome (imported / failed / pending, with reason) is appended to a
running `drop-log.txt` in the same `drop/` folder — including the terminal outcome once a
previously-pending file is later run manually. Use it as an audit trail of everything the watcher has
seen for this case.

Enabled by default. Configure via `DFIR_DROP_ENABLED`, `DFIR_DROP_POLL_S` (poll interval), `DFIR_DROP_MAX_BYTES` (size cap).

## SO-CRATES (direct API)

Set `DFIR_TOOL_SOCRATES_URL` (for example `http://localhost:8000`) in **Settings → Tools**. Importing
a PCAP, binary, EVTX, or archive then offers SO-CRATES alongside any local tool that claims the same
file — tick one or both, since a local Suricata and SO-CRATES run different rulesets. Verdicts flow
into the forensic timeline tagged `SO-CRATES` plus the underlying engine.

Analysis is asynchronous: the run returns immediately and the banner shows
`SO-CRATES: analyzing (network)…` until results land. Because SO-CRATES keys every analysis by MD5,
re-importing an unchanged file costs one request instead of a re-analysis.

Only detections are imported — Suricata alerts, YARA file matches, and Zircolite Sigma alerts. Raw
telemetry (dns/http/tls/flow) stays in SO-CRATES, one click away in its own UI.

### Password-protected archives

The Companion extracts the archive itself before uploading. This is deliberate: the SO-CRATES API
can only ever try `infected` (its password list is built server-side from the filename, with no
request field to override it) and it extracts through Python's `zipfile`, which cannot open
WinZip AES archives at all — so a 7-Zip archive fails there under any password.

- Leave the password box empty for `infected`; type one for anything else.
- ZipCrypto and WinZip AES-128/192/256 are both supported.
- A `YYYY-MM-DD` date in the filename also tries `infected_YYYYMMDD` (the malware-traffic-analysis.net
  convention).
- **Every** file in the archive is analyzed, up to 25 entries. SO-CRATES itself keeps only one file
  per archive and discards the rest.
- Nested archives are reported rather than unpacked recursively.

### Exposure

SO-CRATES has no authentication of any kind and binds `127.0.0.1` by default. Pointing
`DFIR_TOOL_SOCRATES_URL` at a non-local address means unauthenticated evidence reachable by anyone
who can route to it. Every submission is written to the case custody log, since the uploaded file
stays on the SO-CRATES host until deleted there.

## Per-Format Import Buttons

The toolbar also exposes per-format buttons for cases where you want to import by type explicitly:

- Import THOR
- Import SIEM/EDR
- Import Chainsaw/EVTX
- Import Hayabusa
- Import Velociraptor
- Import Log
- Import Suricata/Zeek
- Import KAPE/EZ
- Import M365/Entra
- Import AWS CloudTrail
- Import GCP/Azure
- Import Plaso
- Import Sandbox
- Import Memory

Some of these offer additional options (like a severity floor prompt for THOR).

## Custom Declarative Importers

You can teach the Companion a new file format **without writing code** by dropping a JSON importer spec into the importers folder. The spec describes how to detect the file and how to map its columns to forensic events.

Manage custom importers in **Settings → Importers**. A built-in AI prompt (`GET /importers/prompt`) can write the spec for you — describe your file format and it generates the JSON.

!!! tip "Security"
    Declarative importers are pure data — no code is executed. User-supplied regex patterns are length-bounded to prevent ReDoS attacks.
