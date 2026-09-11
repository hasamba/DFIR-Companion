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
| **Mobile** | iLEAPP / ALEAPP TSV exports (iOS and Android extractions), one artifact per import. Generic by design: LEAPP artifacts share no schema beyond a timestamp column, so the parser finds that column and renders the rest |
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
