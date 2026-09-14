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
# quarantine: 0083;5f3a1b2c;Safari;550E8400-E29B-41D4-A716-446655440000
```

`codesign -dv --verbose=2 <program>` gives the first; `xattr -p com.apple.quarantine <program>` gives
the second — paste its value verbatim. The Companion decodes it by its documented form: the flags
(`download`, `sandbox`, `hard`, `user-approved` — any other bit shown as hex), the time it was
marked (a Unix epoch in hex — not the database's Cocoa epoch), the agent, and the event identifier
that joins the file to its row in the quarantine database. An older collection that put a bare URL
here is still read as before.

**Neither one is a finding on its own, by design.** Homebrew formulas, internal builds and much
commercial software are unsigned, and almost every Mac application installs a LaunchAgent. Signing
status and a quarantine record raise and explain a job that is already suspicious for a reason of its
own: a program in a directory anything can write, a label that claims to be Apple's on something
Apple did not ship, or a command that downloads and executes in one line.

**A plist is a configuration, not a run.** Every launchd finding says what the file *asks for* —
"configured to run as root at boot", "asks launchd to start it when loaded" — and never that the
job loaded or ran, because nothing in a plist shows that. Two more header lines let the collector
say what the plist cannot:

```
==> /Library/LaunchDaemons/com.example.plist <==
# target: path=/usr/local/bin/helper owner=alice mode=0755 group=staff mtime=2026-01-02T09:00:00Z
# launchctl: system 412 0 com.example
```

- `# target:` is what `stat` found at **one path**, and it is applied only when that path is the
  program the plist names (an absolute path, or a relative one joined to `WorkingDirectory` — a
  bare name or a `~` names no file, and the row says so). `path=` is required; `missing` instead
  of the other pairs records that nothing was there. On a job configured for root, a program owned
  by another account or writable by every account raises the finding: that is a write path to
  what root runs. Group-write is shown and not raised — who is in the group was not recorded — and
  the row says ACLs, flags and parent directories were not read.
  `stat -f 'path=%N owner=%Su group=%Sg mode=%Lp mtime=%Sm' -t '%Y-%m-%dT%H:%M:%SZ' <program>`
  produces the line (set `TZ=UTC` first).
- `# launchctl:` is the `launchctl list` line for the label, **prefixed with the domain you
  queried** — `system` (run as root) for a daemon; `gui/<uid>` for an agent — or `<domain> not
  loaded`. Labels are unique only within a domain, so a line without one is not applied, and a
  domain that does not load the plist's directory (a `gui/` view of a LaunchDaemon) is not
  applied either. A PID means the job was loaded and running at collection time; a non-zero last
  status means it has run at least once; status `0` with no PID is also the value of a job that
  has never run, so it says nothing. `sudo launchctl list | grep <label>` for a daemon;
  `launchctl list | grep <label>` as the user for an agent.

Where the plist sits decides who it is configured for. `UserName` is honoured only on a
LaunchDaemon; on an agent launchd ignores it and the row says so. A `LimitLoadToSessionType` of
`LoginWindow` configures an agent for root, before anyone logs in. A plist outside the launchd
directories is loaded by nothing on its own, and the row says the file alone does not establish
that it was ever loaded.

**Login items are not read.** Background Task Management (`BackgroundItems-v4.btm`, macOS 13+)
and the older LSSharedFileList login items keep their targets as bookmark/alias blobs inside a
binary keyed archive; decoding those is a separate importer. `sfltool dumpbtm` (13+) lists them
for you to read by hand.

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

### What a memory export establishes

A Volatility export establishes three things, and the Companion reads each on its own:

- **The rows** — the process list, the connections, the injected regions, as before.
- **The export's shape.** An export that holds **zero rows** — a text export with only a header, a
  `[]`, an empty array under a plugin key — used to be refused ("no parseable memory output"). It
  now imports as one Low row: *Memory export holds zero rows [label: windows.malfind (claimed by the
  export name)] — completion of the search and the pages it covered are not established by this
  export.* That is all the export establishes. Volatility writes the header before the plugin
  runs, `[]` is an empty tree, and the filename is a name you chose — none of them shows that the
  plugin completed, or that it found nothing. "Malfind was clean" needs the run's exit status and
  its stderr, which the export does not carry; treat the row as "this search was attempted" and
  keep the result outside the case notes until you have both.
- **The image**, when the upload holds `windows.info` or `windows.crashinfo`. Those used to be
  twenty generic rows. They are now one Low row that says only what the table says: the **kernel
  SystemTime recovered from the image** (the clock value the plugin reads out of the kernel —
  never "captured at", because a snapshot may be smeared), the OS version, bitness, the symbol
  table used, the **layer stack** with the dump kind for the layer classes Volatility names
  (crash dump, LiME, AVML, VMware, ELF core, QEMU suspend; a bare file layer establishes no
  format), and for a crash dump its **type as Volatility renders it** — a `Bitmap Dump (0x5)`
  holds only the pages its bitmap lists, and which pages were excluded is not in the record. Every
  row from the same upload carries those facts, and rows of Medium or above say the kernel
  SystemTime in their text. **Do not clear user-space behaviour from a bitmap dump**: an empty
  user-space plugin over it says nothing about pages the dump never held.

- **A socket object.** `netscan` / `netstat` rows say what the record holds and how the plugin
  reported it: the stored **state** verbatim with Volatility's own reading (a listening endpoint,
  stored state ESTABLISHED, a connection setup state, a TCP teardown state, a closed-state object,
  a UDP endpoint with no state), whether the object was **reported by pool scan** (an allocated or
  a freed object) or **by traversal of the network tracking structures**, and the owner's own two
  fields (PID and name, either of which can be absent — an absent owner is "not in the record",
  never an indicator of concealment). Nothing says the connection was live or that traffic passed.
  When the same upload holds process rows, the row adds an **internal consistency note** against
  them — "consistent with one submitted process row: X, created T", "not consistent: the
  submitted process row at PID N is named Y", "…was created after this socket's Created value",
  "…reports exit before this socket's Created value", "ambiguous: 2 distinct submitted process
  rows have PID N", or "no process rows submitted to compare". It is a comparison of submitted
  rows, not validation, and it never rewrites the socket's own owner fields; cross-tool
  correlation on the process name happens only when exactly one submitted row is consistent. A
  tuple outside its protocol's shape (a non-listening TCP object with no peer, a port above 65535,
  an address that is not one) is kept as a row marked *tuple incomplete* and mints no indicator.
  Two rows at one object offset are one object reported twice; a row without an offset never
  folds. An externally addressed object in stored state ESTABLISHED is Low as a triage priority,
  not as a claim of traffic.

Text that looks like a Volatility diagnostic (`Unsatisfied requirement …`, a traceback, `unable to
read a requested page`) is shown in the import note as **unverified text**, never used to grade or
to claim a failure — an artifact value can spell it. A **Volatility 2** export is recognised only
to say that its profile-based layout is not read; re-run under Volatility 3 or export JSON.
Volatility's `-` and `N/A` cells are absent values and never become a name, a path or an IOC.

**The run envelope: what makes an empty result a completed search.** Nothing in an export says
whether the plugin completed. A **run envelope** written by the script that invoked Volatility —
the command, the plugin, the exit status, **stderr as its own field** (never a `2>&1` capture),
the SHA-256 of the image, and the stdout it describes — does. Upload one JSON object per run, or a
bundle `{ "type": "dfir.volatility-run", "envelopeVersion": 1, "runs": [ … ] }`; each run carries
`"type": "dfir.volatility-run"` and embeds its stdout (`stdoutBase64` for the raw bytes, or
`stdout` as text) beside `command`, `plugin`, `exitStatus`, `stderr`, `imageSha256` and,
optionally, `stdoutSha256`, `volatilityVersion`, `symbols`, `renderer`, `startedAt`, `endedAt`.
The embedded export imports exactly as it would on its own, and one row per run states what the
envelope establishes:

- *Memory run envelope (uploader-supplied, unsigned) states: windows.malfind — **windows.malfind
  completed with no rows over the pages this image holds and the structures the plugin reads; not
  evidence about pages the dump does not hold** [exit 0; 0 rows in the embedded export; …]* — exit
  0, a header or rows read, zero rows, no page-error line on stderr. Low.
- *did not complete: symbol/translation validation failed: Unsatisfied requirement …; the absence
  of rows is not evidence* — a validation line on stderr, or any non-zero exit (`did not complete:
  exit status 137`). Medium.
- *did not complete after N rows; later candidates may never have been searched* — `Volatility was
  unable to read a requested page` on stderr (Volatility treats that error as terminal). Medium.
- *a Volatility 2 run (profile-based); the export is not read; the envelope names the run* — a
  `vol.py` / `--profile` command line. The legacy workflow is named, never imitated.
- An exit 0 **wins over a traceback on stderr** (an optional import can fail loudly while the
  plugin succeeds); the row says *stderr carries a traceback (unverified; the run exited 0)*.
- A `windows.crashinfo` run **of the same image** (same `imageSha256`) in the same bundle whose
  dump is a `Bitmap Dump (0x5)` adds *over a dump that may not hold user-space pages; an empty
  result does not clear user-space behaviour* to an empty malfind / cmdline / dlllist /
  ldrmodules / handles / envars / vadinfo / yarascan run; without one the row says *dump type not
  established for this run*.

What the envelope does **not** establish: its own provenance. It is uploader-supplied and
unsigned, so every verdict is worded as the envelope's statement; an attestation scheme is out of
scope. The whole `stderr` is scanned before anything is shortened (past 1 MB the verdict is
*indeterminate*, never "completed"). The digest of the embedded stdout is computed over the bytes
(`stdoutBase64`) or the UTF-8 text (`stdout`), and a stated `stdoutSha256` that disagrees — line
endings, a BOM, an encoding — leaves the run *applied to nothing* while its export still imports.
An envelope with no stdout embedded is applied to nothing: two images' empty exports are
byte-identical, so a digest alone names no run — the envelope must travel with its stdout. An
export whose own label names another plugin than the envelope (`{"windows.pslist.PsList": []}`
under a malfind envelope) leaves the run applied to nothing too. Embedded bytes are read by their
BOM (UTF-8, UTF-16) or as strict UTF-8 — invalid bytes are not guessed at. The row's identity is
the whole material envelope, so two runs with the same words stay two rows and a re-import folds.
256 runs per bundle are read; the rest are counted; the bundle's rows share one `maxEvents`
budget.

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
### Web access logs: what one line establishes

A combined-format line (Apache, nginx, Squid) carries more than the request and the status, and the
importer used to drop it: everything a deployment appends after the User-Agent — Squid's result and
hierarchy codes, a request time, a vhost, an `X-Forwarded-For` header — was parsed past. A cache
**hit** therefore read exactly like a **miss**, a `CONNECT` tunnel read like a request for a URL,
and a 302 read like a 200 with a small body. Each line now says what its own fields establish:

- **The request target's form**, as HTTP defines it, never the deployment's role: an
  `[absolute-form request target]` (a full URL — usually a proxy, but an origin server must accept
  one too), `[tunnel attempt to vault.example.invalid:443 — the requests inside are not in this
  record]` for a `CONNECT`, `[asterisk-form request (server-wide)]`, `[invalid request target]`. An
  ordinary path adds nothing, so those rows read as before.
- **The proxy's two legs**, when the FILE is a Squid log: the result code says what the proxy did
  for its client, the hierarchy code says what the next hop was — `[proxy: served from its cache;
  upstream: not contacted]`, `[proxy: cache miss; fetched upstream; upstream: fetched from the
  origin (direct)]`, `[proxy: revalidated upstream and served its cached copy]`, `[proxy:
  revalidation failed; served the stale cached copy]`, `[proxy: denied the request]`. "The origin"
  is said only where the hierarchy code names a direct fetch — a fetch through a parent or a
  sibling proxy says so instead. **A cache hit is not a new transfer from the server.**
- **Whose format it is, declared — never read off the lines.** A token that looks like a Squid
  code proves nothing on its own: an Apache `LogFormat` can append a request header, and the
  client writes that header. No count of lines or of clients turns the client's text into the
  server's format — twenty unanimous Squid-shaped lines from two addresses are still twenty
  requests. The Squid slot is read only under a **declared** trailer layout (the import option
  `trailerProfile`; the import screen does not expose it yet), and the row then says
  `(squid_combined, declared format)`. Even then a line's value must be a result code **and** a
  hierarchy code the tables name (`squid_combined` always writes both, so a bare `TCP_MISS` is not
  the field). Without a declaration every appended token is shown as `[trailer: …]` — verbatim,
  unlabelled, never an indicator, and never the client's identity — and a hit and a miss still
  stay two rows, because the trailer's text is part of the row's identity.
  A line whose slot holds something the tables do not name (`TCP_FOO:BAR`, or a known result with
  an unrecognised hierarchy such as `TCP_MISS:NONCE_7`) keeps that value as one of those tokens
  rather than reading as a disposition: uninterpretable text must not become a claim, and it must
  not become an unbounded key either;
  its brackets and control characters are neutralised, so a token cannot forge a tag the reader
  trusts — and so are the request target, the Referer, the User-Agent and the auth user, which the
  client writes too. **An address named only in a Referer is no indicator**: the client claimed it,
  nothing observed it; a named Referer host stays a domain indicator as before.
- **A row that does not show its whole record says so.** When anything shown was clipped or
  neutralised — a long trailer, an attack excerpt, a bracket turned into a parenthesis, a line
  rebuilt past 600 characters — the description ends in an identity mark (`#` and 22 characters of a digest
  of the row's full key). Two records that read alike then stay two rows through import; the
  Companion's re-import check treats one time, one text and one host as one observation. A line
  shown in full carries no mark. What a `[trailer: …]` tag shows is never read as an
  artifact by the merge either: a hash or a file path a client appended to its request cannot
  join that request to an unrelated event that really carries the hash or the file. **A forwarded-for header is not the client**: `srcIp` stays the address the server or
  proxy actually saw.
- **What the status and the byte count do not say.** `[redirect — the Location is not in this
  format]` for 301/302/303/307/308; `[not modified — no body]` for 304 (never a redirect);
  `[no body by definition (HEAD)]`; `[no body for this status]` for 204 and 1xx; and on a `CONNECT`,
  `[the logged size is the tunnel's, not a response body]` — or, when the proxy did not answer 2xx,
  `[no tunnel was established; the logged size is the HTTP response's]`. A byte count is the size
  the server
  logged — Apache's excludes headers, Squid's includes them, neither is network bytes, and no
  status proves the client received them. An invalid target mints no destination indicator either:
  a malformed host never becomes a domain IOC or the key's host field, only the row's own path
  identity: a bracketed literal must be an address, and a registered name must be real labels with
  well-formed escapes.

On a row that also carries an attack shape (the decoding above), the attacker-shaped parts give way
to the record's own facts: the matched excerpts and the shown target shrink so the status's tag and
the proxy's legs always fit, and every tag closes its own bracket.

Keys: the target's form and the proxy's disposition join the aggregation key, so a hit and a miss
of one URL are two rows. The appended tokens are
not part of a row's base identity — an attacker can write them, and a request time would be one
group per request — but a digest of them is a bounded **variant** of it: a row that shows a
trailer never folds into a row that does not, and beyond 64 distinct values on one path the rest
fold into one row that says so. A row that also carries an attack shape is identified by its
payload instead, so trailer churn cannot crowd out a genuinely different payload; its trailer text
still shows on the row that survives. A very long request target can never push the status or these
facts out of the row: past the 600-character clip the row is laid out status-first, and the tags
are kept whole in evidence order — the proxy's legs, what the status establishes, what the size
does not, the target's form, and the uninterpreted trailer last.

**What the format cannot hold.** There is no request or session identifier, no HTTP/2 stream id, no
`Location` header, no content type, and no response body — so which request led to which redirect,
which response carried which payload, and which file on an endpoint matches a transfer cannot be
read from one line. That chain (and the proxy-to-workstation link) is a join across records and
formats, with its own issue.

### macOS quarantine records: what one record establishes

An `LSQuarantineEventsV2` row (CSV or JSON dump) is a **download event**, and the row says only
what the record establishes:

`macOS quarantine [kind: web download] [agent: Safari (com.apple.Safari)] [data url: https://…]
[origin: https://… ("page title")] [sender: name <address>] [time: Cocoa seconds (column LSQuarantineTimeStamp)] [event: <uuid>]
[local file: not in this record — joined by the event identifier]`

- **The kind** is Apple's `LSQuarantineTypeNumber` (web download, other download, email
  attachment, message attachment, calendar attachment, other attachment); a number the table does
  not name is shown as such.
- **Two URLs, two facts.** The data URL is the *resource* the agent fetched; the origin is the
  *referring page* (the lure, on a phishing question). The URL's last path segment is never called
  the file: the database keeps no local path. The file is joined through the event identifier —
  the same UUID sits in the file's `com.apple.quarantine` attribute — and that join is a separate
  design. A row therefore never says the file ran or was malicious; every row is Info.
- **Time by its declared form, never by its size.** The native `LSQuarantineTimeStamp` column is
  Cocoa seconds (since 2001) and is decoded as such; an ISO string is ISO. A converted dump names
  its epoch in the column: `unix_time` (or `epoch`) is Unix seconds, `unix_ms` (or `epoch_ms`) is
  Unix milliseconds. A number under a generic header (`timestamp`, `time`) could be either an
  aliased native column or a converted one, so it establishes no time; the row then says
  `[time: not readable — the column names no epoch …]` and keeps the raw value. The encoding used
  is always named on the row.
- **Indicators.** The data URL and its host (an address is an `ip`, a name a `domain`) when the
  scheme is http(s) or ftp; the origin URL and its host only when http(s) — a `mailto:` origin or
  a `file:` data URL mints nothing. A sender name or address is never an indicator.
- **Identity.** Each event identifier is its own row; a re-dump of the same record folds; two
  records that share an identifier but disagree on a fact stay two rows and both say `[event
  identifier shared by records with different facts]`. An identifier that is not a UUID is shown
  as text and is never used to join.
- **The xattr.** When a persistence collection pastes the raw `com.apple.quarantine` value under a
  plist header, the finding says `[quarantine mark: download, sandbox (+0x0080); agent Safari;
  marked 2020-08-17T05:52:44.000Z (Unix hex); event …]` — the flags per Apple's SPI, the time in
  the attribute's own Unix-hex form, the agent, the event id. The attribute carries no URL. The
  finding is raised only when the flags say `download` (or a legacy collection pasted the URL);
  a sandbox-only mark, or one that cannot be decoded, is shown and raises nothing.
- **The origin alias.** `LSQuarantineOriginAlias` is bookmark data: it is part of the row's
  identity (two dumps that differ only in it are two rows) and is never shown.

### macOS quarantine: what one upload joins

A **file-attribute record** — a path and its raw `com.apple.quarantine` value, as `xattr -p
com.apple.quarantine` over a directory, `ls -l@` or a collector glob with `xattr()` emit them,
one file per CSV row or JSON object — is read by the macOS importer beside the database dump, and
the two are joined only through the event identifier both carry, inside one upload.

- **The attribute row** reads `macOS quarantine attribute [file: /Users/x/Downloads/installer.dmg]
  [quarantine mark: download, sandbox (+0x0080); agent Safari; marked 2020-08-17T05:52:44.000Z
  (Unix hex); event 8f1c…] [download event: data url https://…; origin https://…; agent Safari
  (com.apple.Safari) — the database record with this event identifier] [agent agrees] [marked and
  recorded in the same second (attribute: Unix hex; database: Cocoa seconds)] [download flag set]
  [host: mac-01]`. The record is recognised by the one header no other export carries,
  `com.apple.quarantine`; `quarantine`, `xattr` and a path column are not a signature. The path
  columns read are `path`, `file`, `fullpath`, `name`, `filename`, `OSPath`; every occurrence is
  read, and a record with two different paths or two different attribute values says so
  (`[path: 2 values in this record]`) and joins nothing — as does a record with two different host
  values (`[host: 2 values in this record]`) or a clipped path. An optional `sha256`/`md5` column
  is carried when it is valid hex and rides on the row, so the file correlates with any other
  record carrying the same hash; a `size` column when it is a number. Two readings of one file that
  differ in hash or size are two rows, never silently one. Nothing is minted as an indicator — a
  path is not one, and the database row already carries the URLs.
- **An empty cell is not absence.** `[attribute value empty or not reported — absence of the
  attribute not established]`: a blank cell can be a collection failure, a null the exporter
  wrote, or a field the collector did not read. The row never says "no quarantine attribute"
  and never "local origin" — Gatekeeper-exempt agents write no attribute and a stripped one
  leaves no trace. A value that is not the four-field form (a bare URL, garbage) is
  `[quarantine mark (not decodable): …]` and carries no identifier; a path past 4,096 characters
  or a value past 1,024 is clipped, marked and never joined.
- **The join.** For an identifier both a database record and an attribute record carry, the
  database row's `[local file: not in this record — …]` becomes `[local file:
  /Users/x/Downloads/installer.dmg — the file's quarantine attribute carries this event
  identifier]`, and the attribute row gains the `[download event: …]` span above. Agreement is
  said per fact and never assumed: `[agent agrees]` (the attribute keeps the agent's name, the
  database its name and bundle id — compared against both) or `[agent differs: attribute curl;
  database Safari (com.apple.Safari)]`; `[marked and recorded in the same second …]` or `[marked
  ≤10 s after the record …]` / `[marked ≤24 h before the record …]` (a band, never the exact
  seconds, with both encodings named — the attribute is written when the file is created, the
  record when the agent logs the event, so they can differ) or `[time not compared: the database
  time is not readable]`; `[download flag set]` or `[download flag not set]` — `— sandbox mark
  only` is added only when the flag word is exactly the sandbox bit. Several files with one identifier read `[local files: 2 — a.zip, a/app.bin — the same
  identifier on several files: a copy, or an archive's extracted members; the records do not say
  which]` (a `.zip` propagates the mark to what is extracted; the row never decides). Identical
  attribute records are one file; a file with two different attribute values is an ambiguity —
  `[local file: an attribute record carries this identifier, but the file carries two attribute
  values — not joined]` — never two files.
- **What is never joined.** A basename, a URL's last segment, a time; an identifier whose
  database records disagree (#1009's `[event identifier shared by records with different facts]`
  — both sides say `database records with this identifier disagree — not joined`); a record on
  another host (a `hostname`/`host`/`computer`/`fqdn`/`clientid`/`machinename` column partitions
  the join, hostnames compared case-insensitively; records naming no host are one partition per
  upload and every joined row says `[host not named in the records]`; a named host never joins an
  unnamed record; a record with two host values joins nothing); an attribute with no
  database record (`[download event: not among this upload's database records]`) or a database
  record with no attribute (`[local file: not in this record — no attribute record carries this
  identifier in this upload]`, said only when the upload carried attribute records at all — a
  plain database dump reads as before). The joined database row carries no structured path: the
  correlate layer case-folds paths and an APFS volume may not, so the exact path lives in the
  row's words and data only.
- **Identity, bounds, grading.** The host, the path, the raw value, the join state and every
  joined fact are the attribute row's identity; the join state and its facts join the database
  row's, so a joined row is another row than the unjoined one and a re-dump folds. 65,536
  attribute records are retained per upload (the rest fold into one overflow row that shows
  nothing); 256 files are tracked per identifier while the lists are built (`256+` past it), three
  shown, eight named in the database row's provenance. Every row is Info
  with no technique: quarantine presence is provenance, not execution and not maliciousness —
  the join says which link it established and which it did not. Each joined field's provenance
  names the record it came from: each listed path rests on its own attribute record, the URLs and
  agent on the database record (addressed by position, `record:N`), the agreement facts on both,
  and a refused join on every database record it consulted.
- **What this does not do.** It does not join the file to the evidence it ran (no macOS
  process-execution record is parsed — link 2 of #1037), the origin URL to a browser-history
  visit (link 3), a persistence target's own attribute to a database record (a different upload
  format), or anything across uploads; a bare URL in the attribute column (a legacy collector
  form) is not decoded here.

### TLS records: what one record establishes

Zeek `ssl.log` and `x509.log` and Suricata `tls` records are folded into rows the way `conn`
folds into flows — one row per observed relationship, one per certificate — and each row says only
what its records say:

- **A session row** reads `TLS <client> → <server>:<port> [sni: …] [TLSv13, cipher …] [cert:
  subject …; issuer …; fp …] [chain check: ok] [ja3 …] [ja3s …] — N TLS records`. Every fact shown
  is part of the row's identity: a TLS 1.3 session that established and a TLS 1.2 attempt that did
  not, a different certificate, a different chain-check result, a different sensor — each is its
  own row. A record with no SNI says `[no SNI]`; one the sensor saw fail says `[not established]`;
  a resumed session says `[session resumed]` and, when the sensor saw no certificate, `[no
  server certificate observed in this record]`; a client certificate, when Zeek saw one, is shown
  apart as `[client cert: …]`; a session whose TLS client was the connection's responder (Zeek's
  `^` in `ssl_history`) is attributed the right way round and says so.
- **What the words mean.** The SNI is the name the *client* asked for — a claim, like a DNS query,
  and the row's only indicator. The certificate is what the *server* presented. `chain check` is
  the sensor's own verdict on the chain (`ok`, `self signed certificate`, …) — it is not
  "benign". JA3 and JA3S are TLS library signatures, not identities. Nothing on a row says
  malicious, C2, "the same operator", or "an inspection proxy": an issuer is shown as written, and
  what it means is the analyst's call.
- **A certificate row** — one per certificate identity — reads `[certificate: <fingerprint or cert
  identity>; subject …; issuer …; valid …–…; covers N names: a, b, c (+n more)] — N certificate
  records`. A certificate's identity is the leaf's DER bytes hashed here when the record carries
  them, else a source-given fingerprint (Suricata `tls.fingerprint`, Zeek builds that write one) —
  the same order on the session and on the certificate row, so one certificate keys one way — or
  else its issuer and serial — the pair that names one certificate under one CA — spelled
  `certid-v1:…` and never called a fingerprint.
  A certificate with no serial and no fingerprint (a standard Zeek `ssl` row) has **no** identity:
  its subject and issuer are attributes of the session, and a renewed certificate with the same
  names is the same session shape. The attributes a certificate row shows are its first
  observation's; the row is marked (`#…`) to say so.
- **Names on a certificate are not contacts.** A certificate covering `www.example.net` does not
  establish that anyone asked for it, so SAN names and the subject CN are never domain indicators
  (they used to be — a CDN certificate minted a hundred). They stay on the certificate's row for
  the analyst and for the graph. A fingerprint is never an indicator either — no indicator type
  means "certificate", and `hash` means a file — and it is shown as its ends (`fp abcdef01…ef01`)
  so the merge never reads it as one.
- **Every row is Info** and carries no technique: a handshake proves nothing on its own. Rows are
  kept most-seen-first under the import's event budget, so a scanner's one-off names cannot crowd
  out the persistent relationships.
- **A session joined to its certificate record.** A Zeek `ssl.log` row that carries only
  `cert_chain_fuids` (Zeek 4–5, or a Zeek 6 export without `cert_chain_fps`) takes its identity
  from the `x509.log` row in the same upload whose `id` is that FUID, on the same sensor, and says
  `[cert: subject …; issuer …; cert identity certid-v1:… — identity from the x509 record]`. The
  join fills only the identity, never the record's own facts; a row with its own fingerprint keeps
  it, and when the x509 record's fingerprint of the same kind disagrees the row says `x509 record
  for this chain disagrees, not joined`. Two x509 records for one id that disagree join nothing
  (`x509 records for this chain disagree`); a session whose own subject or issuer differ from the
  x509 record's keeps the identity and says `subject/issuer differ from the x509 record`; past the
  certificate bound (below) a chain whose x509 record was not retained says `x509 record not among
  those read`, never a silent "unavailable". Records that name no sensor are one partition per
  upload and never join records that name one. Every join fact is part of the row's identity. A
  Suricata `tls` record carries its certificate inline and needs no join.
- **What this does not do.** It does not link relationships across uploads or across sensors, or
  decode chain members (a chain entry is a sha256 and nothing else). The relationships one upload
  establishes are the rows below.

### TLS relationships: what one upload establishes

Beside the session and certificate rows, the network importer builds **relationship rows** over
the un-aggregated TLS sessions of one upload, per sensor — one row per *node*: a server
certificate identity, a name (SNI), a client certificate identity (mTLS), or a JA3 hash. Each row
lists the distinct values the sessions showed beside the node, the observation range, and the
leads a cluster suggests, and every claim is bounded to what the retained records show. Rows start
`TLS-graph ` so they are found in the super-timeline apart from the session rows.

- **A certificate row** reads `TLS-graph certificate sha256 3f2a1b0c…9c0d [presented under: 3
  names — a.example.net, b.example.net, c.example.net] [at server addresses: 2 — 203.0.113.9:443,
  203.0.113.10:443] [client addresses: 14] [chain check: ok] [subject: …] [issuer: …] [valid:
  2023-11-03 – 2024-01-23] [lists 200 DNS names] [observed 2023-11-14 22:13 → 2023-11-15 09:00]
  @ sensor01 — 212 session records, 1 certificate record`. The names are the SNIs the clients
  asked for — claims, like a DNS query — and never indicators here either; the certificate's own
  facts come from the upload's certificate records (Zeek `x509`, Suricata DER) for that identity.
  Sessions with no SNI are counted (`[no SNI in 2 sessions]`), as are the sessions Zeek marked
  `SNI does not match the certificate`. **Every count is a count of addresses** — `client
  addresses: 14` — never of clients, devices or a fleet: NAT puts many clients behind one address
  and DHCP gives one client several. `[issuer string shared by 3 certificate identities in this
  upload]` is a string equality; nothing verifies a signature, so the row never says "signs".
- **A name row** — emitted when a name was served with two or more certificate identities or at
  two or more server addresses (a name with one certificate at one address is already said by the
  certificate row and the session rows) — reads `TLS-graph name [name: cdn.example.net] [served
  with: 2 certificates in sequence — a renewal or a replacement; the records do not say which; the
  later certificate lists the same DNS names — cert identity certid-v1:… (2023-11-14 22:13 →
  2023-12-01 08:00), cert identity certid-v1:… (2023-12-01 08:00 → 2024-01-05 08:00)] [at server
  addresses: 1 — 203.0.113.9:443] [client addresses: 14] …`. "In sequence" is said only when
  every identity has a readable range and every pair was compared (64 identities at most);
  otherwise the row says `their order is not established by the readable times`. Sessions whose
  certificate identity was unavailable are counted on the name. "The same DNS names" is said only
  when both certificate records were retained, agree with themselves and list their names
  completely. A Suricata record's inline certificate fields (subject, issuer, validity, SANs)
  feed the node under the same identity, with no certificate record counted.
- **A client certificate row** (mTLS) reads `TLS-graph client certificate sha256 … [presented by:
  1 client address — 10.0.0.5] [presented to: 2 servers — 10.0.0.9:8443, 10.0.0.10:8443] [under:
  2 names — a.corp, b.corp] …`.
- **A JA3 row** — emitted when a hash has two or more sessions — reads `TLS-graph ja3 e7d705a3…6865
  [client addresses: 3] [to server addresses: 2 — …] [under: 2 names — …] [a TLS library signature
  — every client with the same stack shares it; never an identity] …`. A hash seen from 150
  addresses says `[client addresses: 150]` and nothing more.
- **Leads, with the alternative in the same span.** A lead ranks first under the budget and is
  kept before a plain node at the bound; it is a stronger *basis*, not a grade — every row stays
  Info with no technique, and every lead ends `a cluster proves nothing on its own — strengthen it
  with a process that made the connection or a payload`. The four: `lead: one certificate
  presented under 57 names — shared hosting, a CDN or an inspection proxy present one certificate
  for many names; the records do not say which` (8 names or more); `lead: presented under 1 name
  not among the 200 DNS names listed by the retained certificate record: evil.example` (compared
  only against the record's typed DNS names — exact, or a `*.` entry covering exactly one more
  label — with both sides in wire form; never made when the record lists no DNS names, when its
  list was truncated at 64, when the certificate records for the identity disagree, when the
  certificate records exceed the retained bound, or for an SNI that is not a valid hostname; the
  row then says `[covered-name comparison not made: …]`); `lead: served with 2 certificates in
  alternation — observation ranges overlap; the records do not say both were served at one instant`
  (an observation of each identity falls inside the other's range; ranges that merely follow each
  other are the sequence fact above); `lead: 40 sessions from 3 client addresses to only 2 server
  addresses — concentrated` (20 sessions or more to at most 3 server addresses).
- **What is never said.** "Same operator", "malicious", "benign" (`chain check: ok` is the
  sensor's verdict on the chain and nothing more), "CDN", "proxy" or "interception" as a decision
  (only as the named alternatives), "connected" (a session record is a handshake the sensor saw —
  the rows count *session records*), a covered name as a contact, a JA3 as an identity, a
  fingerprint as a file hash. Nothing fetches, resolves or connects to any observed infrastructure.
  A row carries no source or destination address of its own — it names many — so it never joins an
  endpoint event by address on its own; the session rows do that.
- **Certificate records that disagree.** Two certificate records for one identity that differ in
  subject, issuer, validity or DNS names make the row say `[certificate records for this identity
  disagree: subject, names]`, and every derived claim that needs the disputed field (the
  covered-name comparison, the issuer-string count, "the same DNS names") is withheld. An absent
  fact is not a disagreement: a chain member carries no facts beside the leaf.
- **Range, sensor, coverage.** The range is the first and last readable session time; sessions
  with none are counted (`[1 session with no readable time excluded from the range]`). Rows are
  partitioned by sensor (`observer.name`, or Suricata's `host`): one sensor's clock, one node.
  Records that name no sensor — a plain Zeek log directory — are one partition per upload, and
  every such row says `[sensor not named in the records]`, so a mixed upload's ranges are visibly
  resting on that. 65,536 session observations and 65,536 certificate observations are retained
  per upload for the join and the graph; a session past the bound still folds into its session
  row but is absent from the graph, and every relationship row then says `[graph over 65,536 of
  90,000 session records]` and `[certificate records: 65,536 of 90,000 read]`. Distinct values are
  tracked to 256 per edge (the 256 lexicographically smallest, so the listing is the same in any
  upload order) and said as `256+` past it; three are shown, eight kept in the row's data. 8,192
  nodes are kept per kind, chosen by lead first, then most sessions, then earliest, then identity
  — the same set in any upload order; the rest fold into one overflow row per kind, sensor and
  source set. Session shapes and certificate shapes have separate 8,192-shape bounds, so an
  upload of many distinct certificates can never fold the session rows into overflow.
- **Identity.** Every fact the words and the row's data show is the row's identity: a re-import
  of the same upload folds, another upload's different edges are another row. Session and
  certificate record counts, each certificate's session count on a name row and the coverage
  statement are aggregates, like every row's count;
  `uid`, x509 `id` and record indexes are never keyed. The graph, TLS session, flow, web and DNS
  families share the event budget the upload's detections leave, round-robin.
- **What this does not do.** It does not relate records across uploads or sensors, decode chain
  members, build JA3S (server-signature) nodes, draw a graph in the dashboard, or strengthen a
  lead with endpoint evidence on its own — the correlate layer unions the *session* rows by
  address as it does today.

### Web requests and transfers: what one record establishes, and what one upload joins

Zeek `http.log` and `files.log` and Suricata `http` and `fileinfo` records are folded into rows
the way TLS records are — one row per request/response pair, one per transfer the sensor
reassembled — and the rows are joined **only through an identifier both records carry**: a Zeek
`fuid` named by the request's `resp_fuids` / `orig_fuids`, or Suricata's `flow_id` + `tx_id`.
Nothing is joined by timing, by shape or by adjacency.

- **A request row** reads `HTTP GET [target: www.example.com/dl/setup.exe] → 200 [body: sha256
  3a7b0000…c9e1; 1.2 MB whole; mime: application/x-dosexec] [203.0.113.9 → 198.51.100.7:80]
  [HTTP/1.1] — N records`. The pair is one record: Zeek logs the request and its status on one
  line, Suricata's `http` event carries `status`. A row with no status says `→ no response
  recorded`. The target is read by the same rule as a combined-log line (a `CONNECT` is a tunnel
  attempt with no URL; a 304 is `not modified — no body`); the Host header is validated as a host
  and is the row's domain (or ip) indicator. The Referer's named host is a domain indicator, an
  address in it is not. A request body the client sent (`orig_fuids`) reads `[body sent by the
  client: …]`. A `username` (proxy auth), the User-Agent and Zeek's `proxied` headers are shown
  neutralised in their own spans and are never indicators or identities.
- **A transfer row** reads `Transfer over HTTP: sha256 3a7b0000…c9e1; 1.2 MB whole [mime: …]
  [filename: setup.exe] [from 198.51.100.7 to 203.0.113.9] [request: GET [target: …] → 200] — N
  records`. Direction is said only when the record says it (`is_orig`, or the old schema's
  `tx_hosts`/`rx_hosts`); a Suricata `fileinfo` names the flow's two endpoints and says `sender not
  recorded`. A transfer over SMTP, FTP or SMB names no request.
- **Coverage is the sensor's own counters, and it decides what the digest is.** Zeek's
  `seen_bytes` / `total_bytes` / `missing_bytes` / `timedout` and Suricata's `state` / `gaps` /
  `start` read as: `whole` (seen equals total, nothing missing), `seen; object size not recorded`
  (no size from the peer, delivered to EOF), `N of M seen` (truncated), `seen, K missing`
  (gapped — Zeek computes no digest across a gap), `a range, not the whole object` (a 206
  response or a non-zero offset), `timed out`, or `size not recorded`. **Only `whole` and
  `unsized` make the digest a file identity:** then it is the row's `sha256`, a hash indicator,
  and the identity an endpoint file is joined by. Otherwise the row says `partial digest sha256 …
  over the bytes seen` — kept on the row, never a hash indicator, never a file identity.
- **The redirect hop says what the record says.** Zeek's `http.log` carries no Location, so a 3xx
  reads `[redirect target: not in this record]`; Suricata's `http.redirect` reads `[redirect
  target (stated by the server): …]` — the server's claim, never an observed follow. The next
  transaction on the same connection (`uid`, `trans_depth` + 1) is named as `[next: GET … (transaction
  2) — order on the connection, not the redirect target]`; its absence is `next transaction (2) not
  in this upload`, a gap is `later on this connection: transaction 4 — not adjacent`, and an
  HTTP/2 row (a `stream_id`) is `not read: HTTP/2 stream` — interleaved streams are never
  ordered by depth.
- **A shared identifier is necessary, not sufficient.** A `files` record over SMTP against an
  http carrier, a connection id present on both sides that differs, or two different sensors
  read `[body: identifier conflict — not joined]`; two `files` records with one `fuid` and
  different facts read `[body: conflicting files records]` and neither is chosen. A 206 on any
  request that carries a body makes that body a range.
- **Every missing hop is named.** A `fuid` with no `files` record: `[body: no files record in
  this upload]` (the identifier stays on the row's data, never in its words). A transfer whose
  request record is absent: `[request: not in this upload]`. When an upload had more records
  than the importer reads (65,536 per kind), every absence says `not among the records read`
  instead. A Suricata `fileinfo` carries its request inline and says `[request (inline): …]`.
- **Transfer → endpoint file.** The two rows never merge: a transfer is a *wire* observation, and
  the file event on the endpoint is a *host* observation; they are joined by the hash and by
  nothing else. Two transfers of one file at two times stay two rows too — a wire row folds only
  with the same record re-imported. The hash indicator's provenance chain lists both — the transfer row as the
  indicator's own extraction and every event that carries the same hash as a field. The row
  never says the file ran, reached disk or came from this transfer.
- **Identity and bounds.** A row's identity is every fact it shows — every body's digest and
  coverage, every joined request, the redirect hop, the client's fields — so two different chains
  are two rows and a repeated chain folds with a count; `uid`, `fuid`, `trans_depth`, `flow_id`
  and `tx_id` are locators and never part of it. Identifier lists are read to 32 per record
  (proxy headers to 8), 8 bodies and 4 requests are named per row (the rest counted), a repeated
  identifier is followed to 16 records, shapes past 8,192 per kind fold into one overflow row
  that shows nothing — a late row that names a file or is graded displaces a plain shape rather
  than folding — and under the import's event budget rows that name a file identity come first,
  then graded rows, then the most seen. A method that is not an HTTP token and a version that is
  not a version reach no words.
- **Grading.** An attack pattern or a secret in a Zeek-seen target grades exactly as it would in
  an Apache line (Medium, T1190). Every other row is Info with no technique.
- **What this does not do.** It does not join a proxy log's client to a workstation (that needs
  the trailer-profile declaration and a host identity across logs), does not order HTTP/2
  streams, and does not join an `http` upload to a `files` upload imported separately.

### DNS records: what one record establishes

Sysmon Event 22 and the Windows DNS Client operational log (`Microsoft-Windows-DNS-Client/
Operational` — 3006 query called, 3008 query completed, 3020 query result) are read for what one
record establishes, and no more:

- **A query is not a resolution, and a resolution is not a connection.** The row says which
  process asked for which name, what type of record it asked for when the record says so (`[A
  query]`; Sysmon does not log the type, so `[type not in this record]`), and what the resolver
  client reported: `[returned: …]` on success, `[NXDOMAIN — the name does not exist at this
  resolver]`, `[no records of the queried type]`, `[timed out — no answer]`, `[refused]`, `[server
  failure]`, or `[status 1234 (not in the table)]` for a code the table does not name — never read
  as success or failure. A record that carries no status (3006) says `[outcome not in this
  record]`; a 3006 also says whether the call went to a server at all (`[not a network query]`),
  because a call is not a transmission — and it does not say the call was answered. A resolved query and a NXDOMAIN of the same name are two rows; a re-query answered
  with the same set of values is one row with a count and a first/last time — **the count is how
  many times that answer was seen, not how many values it had, and the row does not keep each
  observation's time**.
- **Returned, not answered.** The values are what the resolver *returned* for the query. The record
  keeps no owner name and no section for them, so an address returned beside the answers (an
  ADDITIONAL-section record, an unrelated AAAA on an A query) reads exactly like an answer. The row
  therefore never says "resolves to", and a returned address is **never an indicator** — nothing in
  the record observed a connection to it. A queried name is a domain indicator even when it never
  resolved (a name that fails is still the lead), but only when it is a real name with at least one dot (`wpad` is a valid query and not an
  indicator): a query name
  that is not one (`good.example] [returned: …`, a path) is shown neutralised, marked `[query name
  is not a valid name]`, and mints nothing.
- **Whose view it is.** These records are the endpoint's own stub resolver's view: the answer is
  whatever the host's configured resolver returned — from its cache or not, the record does not
  say — and the record does not name the resolver or say whether it forwarded. A network sensor's
  `dns.log` is a different view (its client may be a forwarding resolver, not the endpoint), and a
  resolver's own log is a third; neither is read as events today. TTLs are not in these records.
- **What the merge does not read.** The queried name and the returned values are shown inside
  `[query: …]` and `[returned: …]` tags that the merge never scans for a file hash or a path, so a
  TXT answer of 32 hex characters or a path-shaped name cannot join the query to an unrelated file
  event. A row whose shown text is not its whole record — more than eight returned values, a long
  value, a neutralised character — ends in an identity mark (`#…`) so two records that read alike
  stay two rows through import.
- **Churn is bounded.** An authority can answer one query with a new value every time. The first
  64 distinct returned-value sets for one query (on one host, from one process, with one status)
  stay separate rows; every later distinct set folds into one row that says `[overflow: distinct
  returned-value sets beyond 64 for this query folded; none shown]` — so a churning answer can
  never crowd unrelated evidence out of the import's event budget.
- **What this does not do.** It does not join a Windows record's returned values to a later
  Sysmon 3 / firewall connection from the same host; that join is spec'd on #996. A network
  sensor's own records are joined inside one upload — the next section.

### DNS answers and connections: what one upload joins

Zeek `dns.log` records and Suricata `dns` answer/response events are folded into rows the way
TLS and web records are — one row per exchange shape — and each returned **address** is joined
to the connection records of the **same upload** (Zeek `conn.log`, Suricata `flow` / `netflow`)
from the **same client** on the **same sensor**, and to nothing else. A Suricata `dns` query
event establishes a query and stays indicator-only.

- **The row** reads `DNS 10.0.0.5 → 10.0.0.1: [query: www.example.com] A → answered
  [93.184.216.34: connection record ≤10 s after the answer arrived, inside the window — answered
  by the peer] [returned: 93.184.216.34, 2606:2800::1] [2606:2800::1: no connection from
  10.0.0.5 in this upload] [window: TTL 300 s +1 s] @ sensor01 — 12 records`. The arrow names
  the server the client asked — a recursive resolver, or an authority when the client is itself
  a resolver (`[authoritative answer]`); the record does not say which, so the row never says
  "resolver". A Suricata event whose ports do not say which end asked reads `a ↔ b (direction
  not in this record)` and asserts no client. The outcome is the response code as the record
  says it: `answered`, `NXDOMAIN — the name does not exist at this server`, `NOERROR — no records
  of the queried type`, `SERVFAIL`, `REFUSED`, `rejected by the server`, `no response recorded`
  (a Zeek line that saw none; a Suricata answer event with no code says `response code not in
  this record`), or an unknown code inside its own `[rcode: …]` span. The sensor (`observer.name`,
  or Suricata's own `host`) is shown after the tags.
- **Returned, or answers.** Zeek keeps the answer section's data with no owner name, so its values
  are `[returned: …]` — never "resolves to", exactly like the Windows records. Suricata keeps
  `rrname` per answer, so those read `[answers: www.example.com CNAME cdn.example.net;
  cdn.example.net A 93.184.216.34]` — the record's own claim, still not a resolution the sensor
  verified. A Suricata v1 event is one answer RR per event and its `rrname` is that RR's owner,
  so the row says `[query: (not in this record)]` and mints nothing. Eight values are shown, 32
  are read, and the identity covers every value. An untyped value that looks like an address
  (Zeek keeps no RR type per answer) is an address only when the query could return one — a TXT
  answer that spells an address is data, never a lead.
- **The window is the answer's own TTL, and it says so.** It opens when the answer *arrived*
  (Zeek's `ts` is the query; its `rtt` moves the arrival later) and closes TTL + 1 s later — the
  second is for the client's resolve-to-connect latency, so a TTL-0 answer followed by a
  connection in the same second is inside it. A record with no TTL gets `[window: fixed 300 s —
  no TTL in this record]`. A folded row shows the TTL range across its records (`TTL 240–300 s`),
  because a cached answer counts down on every re-query. The window bounds candidates and
  confirms nothing: TTL is cache guidance, a client may hold an answer past it, and the same
  address is returned for many names.
- **What one address's lead says** — one of, and each is part of the row's identity:
  `connection record ≤10 s after the answer arrived, inside the window` (the gap is a band —
  ≤1 s, ≤10 s, ≤60 s, ≤10 min, ≤1 h, ≤24 h, >24 h — never the exact seconds); `first connection
  record ≤1 h after the answer arrived — after the window`; `a connection record began before
  this answer arrived` (the client did not wait for it); `a connection open at the time of this
  answer — started before it`; `earlier connection records only — none after this answer`; `no
  connection from 10.0.0.5; other clients connected inside the window — the record does not say
  they used this answer` (said only when the client is itself observed as a queried server, i.e.
  it forwards); `no connection from 10.0.0.5 in this upload`. An in-window or after-window lead
  is always said even when an earlier record also began before the answer arrived or was open at
  that time — that fact is added beside it (`; a connection was also open at the time of this
  answer`), never instead of it. A lead whose address another record returned to the same client
  for a different name inside the window adds `also returned for other names to this client
  inside the window`.
- **A connection record is not a connection.** Zeek's `conn_state` and Suricata's packet counts
  say whether the peer ever answered: `answered by the peer` (SF, S1, S2, S3, RSTO, RSTR, RSTRH,
  SHR, OTH; a flow with packets to the client), `no reply from the peer` (S0, REJ, RSTOS0, SH; a
  new flow with none), or nothing when the record carries no state (a `netflow` record). The
  lead never says the client "connected"; a lone SYN to a returned address is a record with no
  reply.
- **What is never joined.** The DNS exchange's own connection (the shared `uid` / `flow_id`);
  a record from another sensor (`observer.name`, or Suricata's `host`); a name (nothing connects
  to a name); a query that returned no address (`[no address returned — no connection can be
  matched]`); a client that is loopback, link-local, multicast or absent (`[connection join: the
  asking address is not one a sensor's connection records can be matched to …]` — a host's own
  stub resolver, LLMNR and mDNS name nothing the sensor can match); an upload with no connection
  records at all (`[connection join: no connection records in this upload]`, once per row, not
  per address) or whose connection records carry no start time (`… carry no start time — not
  joined`); and any upload whose connection records exceed the index (1,048,576) — then no lead
  is computed for any row, because a partial index would compute a wrong "first connection", and
  every row says `connection records exceed the index — not joined`.
- **Identity and bounds.** A row's identity is the exchange's ends, the query (its wire form —
  one row per name, not per capitalisation), the type, the response code, the flags, every
  returned value, the window basis and every lead's state, band and reply; `uid`, `flow_id` and
  the TTL values are not. 65,536 DNS records are retained per upload (the rest fold into an
  overflow row that shows nothing and still mint their indicators), 8,192 shapes are kept with
  rank eviction (an in-window lead displaces a plain shape rather than folding), and under the
  import's event budget rows with an in-window contact come first, then rows answered with an
  address, then the most seen. The flow, TLS, web and DNS families share the budget that the
  upload's detections (alerts, notices) leave, round-robin, each in its own order, so a day of
  `dns.log` cannot evict the biggest flow. The join is linear in the records: every lookup is a
  binary search over a list sorted once, so a beacon that resolves and connects every second for
  a day joins in seconds.
- **Grading and indicators.** Every row is Info with no technique — a web visit is exactly this
  shape; the lead is a stronger basis, not a higher grade. The queried name is a domain indicator
  by the same rule as the Windows records (a real name with a dot, in wire form), minted against
  the row so its provenance names the row; a returned address is never an indicator, even when
  connected — the contact is a fact on the row, not a reputation claim about the address.
- **What this does not do.** It does not join a `dns.log` upload to a `conn.log` upload imported
  separately (one upload has one clock; two do not), does not read a resolver's own log, does not
  pair a Suricata query event with its answer event, and does not join the Windows records
  (Sysmon 22 / DNS-Client) to Sysmon 3 — all still open on #996.

### Mobile evidence with no clock (iLEAPP / ALEAPP)

Most of what a phone examination is for has no timestamp: the installed-apps list, permissions,
accounts, settings. Those tables used to be refused ("no usable timestamp column") and a row whose
time cell was empty was dropped. Now:

- **Every row is imported.** A row with no usable time is kept **undated**: it shows as `(undated)`,
  sorts after every dated row in the super-timeline, stays inside any time window you set (it
  cannot be proven out of range), and is searchable and promotable like any other row. The import
  response and the activity line say how many rows carry no clock.
- **An undated row never borrows a time.** Correlation merges rows that share a file hash or a path
  — but never an undated row into a dated one, so an installed-app entry cannot come out saying it
  happened when some file event on the same host did. Undated rows still fold with each other.
- **A Timesketch export says what it left out.** Timesketch requires a time per event, so undated
  rows are omitted from the JSONL and the push; the status line gives the count.
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
a drive letter alone is not removable media. Hayabusa's own Defender rows keep their Sigma grading
and do not yet carry this token.

### Defender episodes: an action, then a later start of the same file

When a process-start record (Sysmon 1, Security 4688, an EDR start row) names the same host and
the same path as a file Defender acted on, and is dated after that action, the start row gains a
note and rises to at least Medium:

```
[after Defender: remediation-failed of Trojan:Win32/Wacatac.B!ml; a process later started from the
same path C:\Users\a.mehta\Downloads\invoice.exe (1h 5m later)]
```

The Defender row gains its own note saying how many starts followed and when the first was. The
pass runs on every merge, so the two records can arrive in separate imports and in either order.

**Which action the note names.** Defender's records about one detection on one host form an
*episode* (the Detection ID, else the threat name and path; two records further apart than
`DFIR_DEFENDER_EPISODE_GAP_HOURS`, default 24, are two episodes). A start binds to the **one**
record whose interval it falls in — from that record until the next record of the episode — and
the note carries that record's disposition. After *remediation failed*, then a start, then a
successful quarantine, the start says `remediation-failed`; the reverse order says `remediated`.
A start inside two seconds of the record has no established order and is not paired. A detection
with no action yet reads `detected (no action recorded)`.

**Path versus file.** Defender Operational records carry no file hash, so from an EVTX export the
note says exactly what the evidence supports: *a process later started from the same path*. It
never says "the same file", "retry" or "re-dropped", and adds no technique — a process start is not
a user-mediated launch and supports execution, not completion. Only when the Defender record
itself carries the file's digest (an export that includes it) and a start row carries the same
sha256 does the note say *the same file (sha256) later started* and the row rise to High. A digest
is never borrowed from an earlier row at the same path, nor from another tool's row that
correlation merged with the Defender record: the file may have been replaced before Defender
looked. Every flagged resource counts, including a second archive member; a resource past
the bounded list is said, not matched.

**The finding.** For a record that *allowed* the threat, *failed to remediate* it, or says it
*remediated* it, followed by a same-sha256 start, one deterministic finding is created at
synthesis: severity High, `control` = that record's disposition and `execution: observed`, both
machine-set (an analyst's outcome decision still wins). It links both rows, so the generic
high-severity backfill does not raise a second finding. A path-only pairing gets no finding.

**Hosts and bounds.** Two rows pair on the same full host name, or on a short name that names
exactly one host in the case; `ws01.corp-a` and `ws01.corp-b` never pair. Two explicit, differing
drive letters are two locations. A start that falls inside the intervals of two Defender records
binds to the later record; two records at the same instant establish no order and claim nothing.
Per host the newest 512 Defender records are indexed (an unread one says so on its own row); per
record at most 64 starts inside its interval are read and the rest counted on its note.

**What it does not say.** No second AV alert is not evidence that the file ran or that remediation
held; the scanner's identity is never the launcher — read the start row's own account; a drive
letter is not removable media; `allowed` is not a compromise verdict and `remediated` is not proof
the file never ran. Hayabusa's Defender rows carry no typed block and form no episode on their
own; when a Hayabusa row and the Windows importer's row describe the same record they merge and
the episode still forms.

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

### AWS identities: which credential, which role, which account

Every CloudTrail row now says who called in the record's own words, after the head: `AssumedRole
key ASIA… (temporary) session i-0abc123 since 2024-05-01T09:00:00Z CloudTrail mfaAuthenticated=false
issuer Role arn:aws:iam::…:role/admin-role`. Each clause is a field of the record, rendered
literally:

- **The kind** — `IAMUser`, `Root`, `AssumedRole`, `Role`, `FederatedUser`, `SAMLUser`,
  `WebIdentityUser`, `AWSService`, `AWSAccount`, `IdentityCenterUser`; an unlisted value is shown
  as `Unknown type <value>`, never mapped to a guess. `AWSService` is a request made by an AWS
  service; `AWSAccount` is a principal of another account whose identity this record does not
  carry; `SAMLUser` and `WebIdentityUser` name the external caller of an issuance, not a credential
  in use.
- **The credential** — the access key id the call was signed with (or an Identity Center
  credential id) and its class: `temporary` for an assumed role, a federated user, or a user or
  root whose record carries a session (GetSessionToken credentials keep the user's type);
  `long-term` for a user or root without one. The `ASIA`/`AKIA` prefix is shown as data and never
  used to classify or grade — a temporary key alone is normal telemetry.
- **The session** — its name, when it started, `CloudTrail mfaAuthenticated=<value>` (the
  record's own claim about MFA at AWS, not a verdict on a provider's MFA), a source identity,
  `credential originated from a console session`, `instance-role credentials delivered via
  IMDSv1|IMDSv2` (the row never says the credential was stolen — that needs the instance's own
  addresses from another source), `federated via <provider>`, and the **issuer** with its own
  type (`issuer Role arn:…` for an assumed role, `issuer IAMUser arn:…` for a federated user).
- **The accounts** — `cross-account: caller <A>, recipient <B>` when the record was delivered to
  an account other than the caller's. An account boundary is not an organisation boundary; the
  row says nothing about organisations. The two records CloudTrail writes for one cross-account
  action (one in each account, sharing a `sharedEventID`) are **one row** with both records as
  provenance and `[also in account <B>]` — when they arrive in one file; two files are two
  rows. On that row the caller's account is `cloud.accountId` and the resource owner's is
  `cloud.recipientAccountId`, so a Hunt on either account finds the action. The notice sits in
  front of the row's caveats, which are never the part that clips.
- **Issuance rows** — `AssumeRole`, `AssumeRoleWithSAML`, `AssumeRoleWithWebIdentity`,
  `GetFederationToken`, `GetSessionToken` and `AssumeRoot` read their own fields: `issues
  temporary credentials role arn:… session deploy → key ASIA… expires … MFA device … source
  identity … external id supplied`. The issued key id is the row's identity, so a later call can be
  matched to the issuance that minted its credential by the key it carries — never by a role's
  display name. A denied call is `attempted to assume role … — denied (…)`; a record with no error
  and no response (CloudTrail truncates large events) is `requested to assume role … — outcome
  unknown`, never an issuance, and never invents a key. `AssumeRoot` (a root session for a member
  account) is High only when the response proves a session was issued; denied or unknown is
  Medium. `invoked by delegate provider account <id>` names an external product acting with
  delegated permissions.

Two calls by one session name under two access keys are two rows. The credential, the issuer, the
kind and the recipient account are typed on every row (`authentication.credentialId`,
`authentication.issuer`, `authentication.mechanism`, `cloud.recipientAccountId`) and searchable in
Hunt. A merged cross-account action keys on its `sharedEventID`, so two distinct actions that share
every other dimension stay two rows.

**What one upload joins: the credential lineage.** Beside the rows, the importer emits one summary
row per credential whose upload records form a lineage — `AWS credential lineage: ASIA…7Q (account
111122223333) [issued 2024-05-01T09:00:00Z by AssumeRole of arn:aws:iam::…:role/Deploy as session
ci-42 by IAMUser arn:aws:iam::…:user/alice (MFA not recorded on the issuance) — record:0; uses: 14
records 09:00:12Z (record:1) → 11:40:03Z (record:40); first use from each source: 203.0.113.5
aws-cli/2.15 at 09:00:12Z (record:1, 12 records); 198.51.100.7 python-requests/2.31 at 10:02:40Z
(record:33, 2 records); second source 62 min after the issuance; the workload's own addresses are
not in this evidence; privileged change: iam CreateAccessKey at 10:03:10Z (record:34) — after the
second source; record retention and the trails' selectors are not in this evidence; issuance and
14 uses in this upload]`. It is built over every record of ONE upload, before aggregation and the
event cap, because the data-plane rows a credential is used for are Info and leave the forensic
timeline at import; a lineage across uploads is not built.

- **Joined through the access key id only** (or the Identity Center credential id). A session name
  or a role's display name never joins: two sessions named `ci-42` under two keys are two rows.
  The owning account is the target role's for `AssumeRole*`, the target principal's for
  `AssumeRoot` (as an account id or a root ARN), the caller's for a session or federation token —
  so a cross-account assumption's issuance and its uses meet on the role's account. A cross-account
  replica counts once, and the informative replica is the one read whichever the file lists first.
- **"Issued at" only on the exact key.** A use whose key no issuance record exposes says `no
  issuance record in this upload exposes this credential id (N records, first → last)`; an
  `AssumeRole` request for the same role and session whose response is not in the record is listed
  beside it and never joined. A workload key (`ec2RoleDelivery`, or `inScopeOf` naming a Lambda
  function or an ECS task) says `delivered by the service; no STS record is expected` — never
  "missing".
- **Every source, never "new".** Each address and client is named with its first use and its
  record count; `the workload's own addresses are not in this evidence` is said whenever there is
  a second source or a workload key — nothing in this case supplies an instance's addresses.
- **Shapes are exact, successful calls.** Enumeration is ≥ 3 services inside 10 minutes from a
  fixed list (`sts GetCallerIdentity`, `iam ListUsers`, `s3 ListBuckets`, `ec2 DescribeInstances`,
  …); a privileged change and remote execution are fixed lists too (`iam CreateAccessKey`, `kms
  PutKeyPolicy`, `cloudtrail StopLogging`, `ssm SendCommand`, `lambda Invoke`, …). A denied call is
  an attempt and raises nothing; an `s3 GetObject` across three services is not enumeration.
- **Grade only raises.** A privileged change or remote execution after the first use from a
  second source → High; a shape or a second source → Medium; an issuance with single-source uses
  → Low (a lineage to pivot on, not a finding). An issuance alone, or single-source uses with no
  issuance and no shape, is no row. Techniques are the shapes' own.
- **Every record is scanned; only the narration is bounded.** 256 rows per upload (the rest
  counted), the 64 earliest sources tracked per key (8 named, further distinct sources counted,
  further records "from untracked sources"), 256 records cited with the issuance, the first and
  last use and the decisive shape always among them (the rest counted as `N further records not
  individually cited`). The decisive shape — the record the grade rests on — is never clipped from
  the words. The row's identity is (account, key), so a re-import folds; the summaries never evict
  a source row (`maxEvents` bounds source rows; the result's `summaries` counts these).
- **Bulk reads match by key.** A cloud bulk-read group is now one credential in one account of
  one provider; the assumption that produced the reader's session is the issuance that minted THAT
  key in that account, before the reads began (`matched by the key id`); rows without a key fall
  back to the role-name-and-time match and say so.

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
chain is the finding below. A familiar application name or a verified publisher is neither proof
of safety nor of compromise; read the initiator, the capability and the consent reach.

**What one export joins: the privilege path per application.** Beside the rows, the importer
emits one summary row per application whose records form a path — `Entra privilege path: Sync
(app id …) [2024-05-01T10:00:00Z credential added by admin@…: Password k-new "deploy";
2024-05-01T10:02:00Z privileged capability granted by admin@…: application permission
RoleManagement.ReadWrite.Directory on Microsoft Graph (directory RBAC); 2024-05-01T10:05:00Z
signed in → Microsoft Graph (clientSecret k-new) — with the new credential; 2024-05-01T10:06:00Z
acted: Add member to role — consistent with the granted RoleManagement.ReadWrite.Directory; the
authorization the token carried is not in the record; all four stages in order]`. It is built
over every record of ONE export, before aggregation and the event cap, because sign-in rows are
Info or Low and leave the forensic timeline at import; a chain across exports is not built.

- **Joined through the application's app id only.** A change names its subject by an object id;
  that id links to an app id only through a record of the same export that states both (a sign-in
  carries `servicePrincipalId` and `appId`; a consent record carries `ServicePrincipal.ObjectID`
  and `ServicePrincipal.AppId`). A display name is never a join — two applications named `Sync`
  are two findings. A change whose id no record links is counted (`N changes named an
  application by an id no record of this export links to an app id — not joined`).
- **Four stages, in order, inside a 30-day window opened by the credential.** A credential added;
  a capability granted (an application permission or a directory role — a delegated scope needs a
  signed-in user and is not a step; an eligible role is not an activated one; a failed attempt is
  not a step); a *successful* sign-in whose credential key id matches the key this episode added
  (`signed in … — with the new credential` only on the exact key-id match — otherwise `with an
  unmatched credential`; a certificate thumbprint is never a key id; a rejected attempt with the
  matched key is listed and never counted; a matched sign-in before the grant says so); an
  action by the application whose operation is *consistent* with a granted permission by the
  literal table (`Add member to role` ↔ `RoleManagement.ReadWrite.Directory`, `Add app role
  assignment to service principal` ↔ `AppRoleAssignment.ReadWrite.All`, application writes ↔
  `Application.ReadWrite.All` or `.OwnedBy`, owner writes need `Directory.Read.All` as well, user
  writes ↔ `User.ReadWrite.All`, …; a tier-0 directory role covers any) — worded `consistent with
  …; the authorization the token carried is not in the record`, never "exercised". An operation the
  table does not name says `the action's required permission was not mapped`; one mapped but not
  granted says `needs …, not among the permissions live at that time`. A credential removed, or a
  grant or role revoked, ends its interval: a later step is judged against what was live at its
  time; a re-grant after a revocation is its own interval. The order is a real one — each stage
  strictly after the one before; equal timestamps establish none.
- **Grade by stages.** All four with a tenant-control grant (app-role grant management,
  delegated-grant management, credential management, directory RBAC, identity takeover, or a
  tier-0 / admin directory role) → High; three → Medium; two → Low; a lone step is no row. A
  data-class grant (`Mail.Read`) is a stage but never carries the path to High. Techniques are
  the steps' own: T1098.001 for the credential, T1098.003 for a directory role.
- **Absence rests on the export and is scoped to the window.** `no successful sign-in with the
  new credential inside the window among the 88 sign-in records of this export (2024-05-01 →
  2024-05-31)`, or `sign-in log not in this export`; the same for directory changes; a match
  outside the window is listed under `outside the 30-day window`, never contradicted. Graph
  directory audits name no tenant: they join the export's sign-ins only when those name one
  tenant, else the row says so. Every credential opens an episode; the finding is the episode of
  the highest grade, then the most recent, and names the others. 1,024 steps per application are
  read; the rest are counted.
- **Never said:** "enabled", "exercised", "automation" or "rotation" (the initiator is named on
  every step — `by Deployer (an application, not a user)` when it is one), that a failed sign-in
  was a use, that a name links records. 256 findings per import, by grade, then completeness,
  then recency; one row counts the rest. The row's identity is a digest of (tenant, app id), so a
  re-import folds.

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
  Medium; `Add-RecipientPermission` names its `Trustee`; removals Low. A `-Deny` entry reads in its
  own direction: `adds a Deny entry …` restricts (Low), `removes a Deny entry … (effective access
  may widen)` is Medium. A `-WhatIf` or `-ValidateOnly` cmdlet reads `simulates …` — no change
  was made.
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
- **Send, move and delete** — `sends as ceo@… to cfo@… (inside the mailbox's domain), x@…
  (outside the mailbox's domain)` (the identity the record's own `SendAsUserSmtp` names, the
  recipients it lists; a non-owner: Low, the subject bounded), `copies 2 items from "\Inbox" to
  mailbox drop@… to "\Archive"` (a cross-mailbox destination is named), `hard-deletes 3 items
  from "\Inbox"` (the items the record lists; one `Item` on a single-item record).
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

**What one export joins: the mailbox chain per mailbox and session.** Beside the rows, the
importer emits one summary row per mailbox and session whose records form a chain — `Mailbox
chain: alice@… (join: session 3f2a1b0c…) [2024-05-01T10:00:00Z signed in from 203.0.113.9
(Chrome…) OAuth2:Authorize; 2024-05-01T10:03:00Z accessed: binds 5 items in 2 folders (7
operations) as delegate via REST; 2024-05-01T10:05:00Z configured: creates inbox rule "."
forwards to drop@… (outside the mailbox's domain), deletes the message — delivery through the
forwarding is not in this evidence; 2024-05-01T10:08:00Z sends as alice@… to cfo@…; items listed:
6 across the joined records; continuous coverage of the window is not established by this
export; licence, audit configuration and retention are not in this evidence; four stages in
order]`. It is built over every record of ONE export, before aggregation and the event cap,
because the sign-in and the owner's access rows are Info and leave the forensic timeline at
import; a chain across exports is not built.

- **The join is said, never assumed.** Records that carry the same `SessionId` (mailbox-audit
  access, `UpdateInboxRules`, sends, deletes; a UAL logon whose device properties name one) join
  by session. A record with no session — an admin cmdlet such as `New-InboxRule` or `Set-Mailbox`,
  a logon without one — joins the ONE session of that mailbox sharing its actor and client address
  within 24 hours, and the step says `(joined by actor + address, not by session)`; with two or
  more matching sessions it joins none and is counted; with none, such records form an
  `actor + address, 24-hour window` chain of their own. A session is one id, one actor and one
  address inside one window — a placeholder id shared by another actor, or reused months apart,
  joins nothing. A record with no actor or address to join by joins nothing and is counted. A
  logon joins only inside its own tenant. Two sessions on one mailbox are two findings; one
  session on two mailboxes is two findings.
- **Identity.** The mailbox is its GUID; a UPN resolves to the GUID a record of the same export
  states beside it; a cmdlet naming the mailbox by an alias, a display name or a DN joins nothing
  and is counted. A name is never a join.
- **Stages count only in order and only for what landed.** sign-in < access < rule / forwarding /
  permission < send / delete (sends and deletions only; a bind is an access; a move, copy or
  update is `not a stage:`), each strictly after the previous — the subsequence with the most
  stages, then the highest-graded one; a step before the stage it would follow is listed as out
  of order. A failed or partial command, a `-WhatIf` run, a removal, a disable or a cleared
  forwarding is listed as `attempt:` / `simulation:` / `reversal:` and never counted; a rule
  record with no decoded action (an enable, a rename) is `not a stage:`. A UAL `UserLoggedIn` is a sign-in only when `ErrorNumber` is absent or 0, no
  `LogonError` is set and `ResultStatus` says success — `ResultStatus` alone reports the
  operation, not the authentication.
- **Risk.** An interactive sign-in of the export for the same user, address and tenant within
  ±10 minutes lends its verdict as `a contemporaneous sign-in in the sign-in log (1 min apart)
  carries risk: atRisk, medium — not established as the same sign-in`. Nothing says "suspicious".
- **Never said.** "forwarded" (only configured, with `delivery through the forwarding is not in
  this evidence`), "read" (accessed / bound; a folder sync adds `possible offline copy after a
  folder sync — inferred, not observed`), a count the records do not list (`items listed: N across
  the M cited records; K operations in aggregated records, items not listed` — every cited record
  is in the row's evidence), absence as proof: an
  absent stage is `no access record for this mailbox among the 1,204 supplied Exchange
  mailbox-audit records (earliest …, latest …)` or `… log not in this export`, always with the
  coverage clause above.
- **Grade only raises.** The row is never below its highest step; an owner signing in, reading
  and sending their own mail is all Info and is no row. Three or more stages with a persistence
  step → High when the destination is outside the mailbox's domain, else Medium; three stages
  without one → Medium; two → Low. Techniques are the steps' own. 256 chains per import, 1,024
  steps per mailbox and stage (the earliest kept, the rest counted — the same finding whatever the
  file order); the summaries never evict a source row; the row's identity is (tenant, mailbox,
  join), so a re-import folds.

### Process access and remote threads: what the record establishes

Sysmon writes three records when one process reaches into another: **Event 10** (ProcessAccess —
a handle was opened, with these rights), **Event 8** (CreateRemoteThread — a thread was started in
another process) and **Event 25** (ProcessTampering — the sensor saw an image replaced or locked).
Event 10 used to be graded by its id: Medium + T1003 on every handle, so `explorer.exe` opening
`chrome.exe` read as credential dumping, with one special case for `lsass.exe`. Event 8 was High +
T1055 on every row unless the source was a known benign process. The fields that say what the
record establishes were never read.

A row now says the rights, the trace and the start, and grades by the record's own evidence
first — source trust lowers only one documented routine shape:

- **Rights, decoded by bit** (`GrantedAccess`): `opens lsass.exe with VM_READ|QUERY_LIMITED_INFORMATION
  (0x1010) from mimikatz.exe — handle rights, not a read observed`. `ALL_ACCESS` is a display alias;
  every rule runs on the bits. A bit outside the table is shown as hex and never lowers a grade.
- **The call trace** (`CallTrace`): a frame no module backs (`UNKNOWN(…)`) means code outside any
  module opened the handle — High whatever the rights or the source, `call trace has 1 unbacked
  frame`. A module outside System32 is named (`via tool.dll`).
- **Grades for a handle (Event 10)**, in order: an unbacked frame → High; a write-, duplication-,
  thread-creation- or VM_OPERATION-capable handle on `lsass.exe` → High + T1003.001, no trust
  exception; a read-capable handle on `lsass.exe` → High + T1003.001, unless the source is a benign
  accessor at its own system or vendor path AND the mask is exactly the routine read shape
  (VM_READ plus query/synchronize bits, nothing else, no unknown bit) AND the trace is absent or
  fully backed → Low with no technique; rights absent from the record (a feed that drops the
  field) → the source context decides, and the row says `rights not in this record`; rights present
  but unreadable → Medium, no technique; query-only on `lsass.exe` → Low. On any other target a
  write-capable handle, a duplication right (`can yield full access`) or a thread-creation right is
  Medium with no technique and `handle rights, not a write observed` — a system-path source is said
  in the words, never used to lower; a system process name or an EDR agent's name from a non-system
  path raises to High (`a system process name from a non-system path`); a read of another process
  is Low from a non-system path and Info from a system one; query-only is Info.
- **A remote thread (Event 8)** reads where the thread starts: outside any module (`StartModule` is
  `-`, empty or `UNKNOWN`) → High + T1055, `thread start outside any module`; a `LoadLibrary*`
  start → High + T1055.001, `the DLL-injection shape`; a masqueraded system or EDR name, or a
  source at a suspicious path (Temp, AppData, Public) → High + T1055; a module-backed start from an
  untrusted source → Medium + T1055; from a benign thread source at its system path → Low, no
  technique. A start ABSENT from the record is not an unbacked claim: `start module not in this
  record`, Medium + T1055 (Low from a benign source).
- **Tampering (Event 25)** keeps the sensor's verdict (High + T1055.012) and names the `Type`.

**Identity is kept for the join.** Both process GUIDs and pids are in the row's key (two instances
of one image are two rows; PID reuse stays two rows; how a feed spelled the image path is not in
the key) and in the canonical envelope — the source as the `subject`, the target as the `object`,
each `{ process, GUID, name, pid }`, the target as the event's process with its provenance on the
Target fields. A record with no usable GUIDs (absent, all zeros, malformed) keys on its own record
id (or its position in the import) so it never folds with another, and says `process GUIDs not in
this record`. Events 8, 10 and 25 are canonical process events (`access`, `remote_thread`,
`tamper`). Trust is root-anchored: `C:\Staging\Windows\System32\svchost.exe` is not a system
path, a core Windows name (`svchost.exe`, `csrss.exe`, …) is trusted only from the Windows
directory — `C:\Program Files\Acme\svchost.exe` is not it — and a call trace is read to its
end: an unbacked frame past the thirty-second still grades. The key also carries the evidence the
record holds (rights or their absence, the unbacked count, the first module outside the system
directories), so two records with the same processes and different evidence stay two rows.

**What a handle does not prove.** A read-capable handle on `lsass.exe` is the credential-dump
shape; it is not a read. A write-capable handle is the injection precondition; it is not a write.
A remote thread is an execution transfer; whether its code was hostile is not in the record. The
sequence is the join below.

**What the case joins: sequences by process GUID.** At every merge, the Sysmon 10 / 8 / 25 / 1
rows are joined only through a matching process GUID — the record's own identity, normalised one
way for every row (braces off, the zero GUID rejected; a Sysmon 1 row now carries its GUID as
`process.id`) — never through an image name and never through closeness in time alone. The facts
the join reads are structured (`event.action`: the decoded rights, the thread start, the tamper
type, whether the source is a path-anchored system image), never the prose; a row imported before
this version says `structured rights unavailable — this row may predate the sequence mapping` and
raises nothing.

- **Injection-shaped: access, then execution transfer.** A write-capable handle (VM_WRITE with
  VM_OPERATION, or ALL_ACCESS) — or, as its own shape, a thread-capable one (CREATE_THREAD) —
  opened by source S on target T, then a remote thread from the *same* source GUID into the *same*
  target GUID at or after the handle and within 10 minutes. Both rows read `[injection sequence:
  injection-shaped: write-capable handle VM_WRITE|VM_OPERATION from evil.exe (guid 1111…) into
  notepad.exe (guid aaaa…), then remote thread 3 s later starting at 0x7ff… — outside any module —
  access, then execution transfer; no memory write was recorded]`, raised to High + T1055. The
  words say what the records establish: a shape, never a completed injection — Sysmon never
  records the write. A thread before the handle, or outside the window, is said (`not the
  sequence: the thread precedes the handle by 7 s`) and raises nothing; a handle alone or a thread
  alone gets nothing (Sysmon 10 is commonly filtered; silence is not evidence); a read-only handle
  is not the shape.
- **Hollowing: created, image replaced, reached into.** For a target whose Sysmon 25 says `Image
  is replaced`: the Sysmon 1 that created it (`created 10:00:00 by evil.exe`, or `creation not in
  the case (or imported before this version)`), the tamper (`image replaced 0.4 s after
  creation`), and any handle or thread into it afterwards (`a remote thread into it 1 s later` /
  `no handle or thread into it seen`) — on the tamper row, High + T1055.012; the creation row and
  the rows into it are noted too. `suspended / resumed not in the records`: Sysmon has neither. A
  tamper of another type is left to its own grade.
- **GUID-less feeds** (eCAR, Velociraptor remote-thread rows, `pid:N` ids) join only on one host
  with both endpoints' pids matching, inside an hour, every such note ending `by pid — PID reuse
  not excluded`; a GUID and a pid are never compared.
- **A path-anchored system source keeps its grade.** When the per-record rule applied its
  path-anchored exception to both members (a Low grade from a source with a real system path — a
  basename alone is never trusted), the sequence is noted with `source is a path-anchored system
  image — shape kept, grade not raised`; the timeline never re-decides trust. A memory observation
  for the target is not read here: a memory row has no process lifetime to attribute it by.
- **Bounds, recompute, provenance.** The join slides with the record: the 64 handles nearest before
  a thread inside its window (and the one just before the window and the one just after the
  thread, so a stale or out-of-order pair is said), the 64 rows nearest after a tamper — the rest
  counted on the row (`N rows beyond the index were not evaluated`), so old noise never hides a
  new pair; four sequences named per row, the rest counted; every name and address neutralised, every note capped; the notes are recomputed from
  the current evidence on every merge and nothing is lowered. Correlation now keeps every
  registered note from every merged member, not one note from one member.

### NTFS alternate data streams: a download mark is not a hidden payload

NTFS lets a file carry named streams beside its contents. Windows and browsers write one —
`Zone.Identifier`, the mark of the web — next to every download, and an attacker can write
another: a 1 MB executable hidden behind `notes.txt:payload.dll`. Three artifacts show streams,
and each used to read them the same way: an MFTECmd `$MFT` row (`IsAds`, the stream after the
colon in the file name, `HasAds` and the copied `ZoneIdContents` on the host file's own row), a
Velociraptor `Windows.NTFS.MFT` row (the stream in the path) and Sysmon Event 15 (the stream's
first bytes in `Contents`) — a bare path with a colon in it on the MFT surfaces, Medium +
T1564.004 for every stream on Sysmon, a browser's mark included.

A stream row now says what the record establishes, in this order — evidence before the name,
because the name is attacker-chosen:

1. **Executable content** — the record's own bytes, magic or type say code (`MZ`, `PE32`, `ELF`,
   `#!`, a code MIME type): `alternate data stream "SmartScreen" on notes.txt (40960 bytes) —
   executable content (starts with MZ)`, Medium + T1564.004, whatever the stream is called.
2. **A download mark** — `Zone.Identifier` whose contents have the mark's structure (or, with no
   contents in the record, a mark-sized stream): `downloaded from the Internet zone
   (https://…, referrer …)`; the grade is the same rule EvidenceOfDownload uses — Medium for a
   runnable or a disk image from the Internet or Restricted zone, Info for a document — with
   `download provenance, not execution`. A `Zone.Identifier` that fails the structure, or is
   larger than any mark, is a named stream wearing the name.
3. **A code-like name or a size** — a stream named like code (`payload.dll`, `run.ps1`) is
   Medium + T1564.004 with `stream content not in this record`; a stream of 64 KB or more,
   whatever it is called (a `SmartScreen` of 1 MB included), is Low (`large named stream`). A
   name never excuses the size the record carries.
4. **An application stream** — a literal list (September 2026): `SmartScreen`, `OECustomProperty`,
   `encryptable`, `favicon`, `Afp_AfpInfo`, `Afp_Resource`, `com.dropbox.attrs`,
   `com.dropbox.attributes`, `com.apple.quarantine`, `com.apple.FinderInfo`,
   `com.apple.ResourceFork`, `WofCompressedData`, `$TXF_DATA`,
   `{4c8cc155-6c1e-11d1-8e41-00c04fb9386d}`, `Win32App_1`, `evernote.metadata`, `Evernote.Base`,
   `ms-properties`. Info by name, at an ordinary size.
5. **A named stream** with no signal — an empty one and everything else — is Info. The name is
   the lead, never the proof.

A host file's own MFT row reads its flag and its mark: `MFT: C:\…\tool.exe (40960 bytes) — has
alternate data streams; downloaded from the Internet zone (https://…) — download provenance, not
execution`. The URL and the referrer become url indicators. On Sysmon Event 15 the `Hash` field is
the hash of the file the stream was added to, never the stream's: the row's path and hash are
that host file's (not the process that wrote the stream), the hash joins the row's identity so
the same stream re-created on a replaced file is a second row, and no hash is claimed for the
stream. A stream row is its own row: `payload1.dll` and `payload2.dll` on one file are two, the
same stream on `WS-01` and `WS-02` is two (an MFT key no longer folds the digits of a host name),
and ransomware detection reads the host file's name, never a stream's (`report.docx:cache.akira`
is not an encrypted file).

**Download marks carry no technique.** The `Zone.Identifier` stream establishes where a file came
from — the zone and, when the browser wrote it, the URL. It does not establish that the file ran
(T1204.002) or that a compromised website delivered it (T1189); both used to be attached to every
runnable download from the Internet zone, on the EvidenceOfDownload rows too, and are withdrawn.
The grade stays Medium: a runnable pulled from the internet is worth an eye. What corroborates a
mark is the join across records below; no technique returns with it — an execution record says
that code ran, not that a user opened it (T1204.002) or that a website delivered it (T1189).

Reading rules the rows enforce: a normal `Zone.Identifier` stream is not a hidden payload;
download provenance is not execution, user intent or proof of a drive-by; a missing or stripped
mark is inconclusive — propagation depends on the software that wrote the file (a `.iso` mounted
strips the mark from what is inside; many tools never write one); a stream's name is not its
content.

**What the case joins: a mark and the records that say the same file ran.** At every merge, each
download-mark row is read against the execution records of the same file — Prefetch (whose row now
carries the executable's own path, read from the `FilesLoaded` list when exactly one entry's leaf
is the executable's name, and the PECmd `ComputerName` as its host), Sysmon 1, Security 4688 and
EDR process starts — and against the presence records (Amcache, ShimCache). The file is the same
file only when the path below the volume root matches (drive letters, `\VOLUME{…}` GUIDs and
MFTECmd's leading `.\` stripped, case folded — never a basename), the volumes agree where both name
one (a GUID against a drive letter is `volume not compared`), the hosts agree where both name one
(an unnamed record attaches only when the case's records for that path name at most one host;
otherwise `N records not attributed — the case names several hosts with this path`), and the
hashes agree where both carry the same digest (a mismatch is `path reused … — not the same file`,
and nothing is raised). A process start that carries the marked file's hash under another path is
joined `by hash`. Junctions, 8.3 names and `\\?\` device paths are not resolved: a mismatch is a
miss, never a guess.

The mark row then reads `[download-marked file executed: against the host file's recorded
creation time; …; Prefetch last run 2026-05-02T10:00:03Z, 3 s after; Sysmon 1 process start …,
3 s after]` — raised to **High**, with no technique — when an execution record is dated more than
2 s after the row's own anchor. The anchor is named because it is not the same thing on every
row: a Sysmon 15 row's time is the stream's creation; an MFT host row's time is `Created0x10`, the
host file's recorded creation, which does not prove download-before-execution. A run before the
anchor (`1 d before`), within 2 s of it (`order not established (within 2 s)`) or with no readable
time is said and raises nothing; presence records are listed as `present (not an execution
record)` and raise nothing. Eight executions are named, the rest counted; 64 records are indexed
per path or hash and the rest are `beyond the index, not read`. A note whose evidence has since
left the case comes off on the next merge; the severity a pass raised stays — no pass lowers. The execution record
that corroborated a mark is itself raised to Medium — `[ran a download-marked file: …]` — so it
survives the Info cut. The notes are recomputed from the current evidence on every merge; nothing
is ever lowered.

**Order matters, because nothing automatic reads the raw record.** The pass reads the forensic
timeline only (the boundary in the architecture notes), so an ordinary Prefetch row imported
*before* its mark was demoted to the super-timeline and is out of the pass's reach. Import the MFT
/ Sysmon collection before the execution artifacts, or re-collect; a Prefetch row already graded
above Info (a named tool) is reachable in either order.

**A hidden stream and the command line that referenced it.** A stream row graded Medium as a
payload or a code-named stream is read against every process start's command line for a
`file:stream` token (`rundll32 C:\Users\x\notes.txt:payload.dll,Entry`; a drive letter is never
one). An absolute reference that resolves to a stream row on the same host raises that row to
High: `[stream referenced by a command line: rundll32 … (Sysmon 1, 2026-…, ws-01)]` — the same
volume and the same host rule as the mark join (a hostless stream row attaches only when the
commands referencing it name at most one host). A bare or relative reference (`wscript
notes.txt:run.js`) resolves to nothing — the working directory is not in the record — and is not
a lead either: the same token shape is an ordinary `host:port` argument. An absolute reference
with no stream row at that location is a Medium lead on the process row: `[command line
references a stream: C:\…\other.txt:p.dll — no stream row at this location carries it]`.
Sysmon 15 stream rows carry the host path only and are outside this half; command lines are
scanned to 4,096 characters, four references each, every excerpt and every host, time and
artifact label is neutralised, and every note is capped.
### Google Workspace OAuth: which app, which scopes, what it called

A Workspace account takeover through OAuth leaves records of the `token` application in the
Reports API export. Each used to import as `Google Workspace token: authorize by alice@… →
Mail Backup Pro` — High whatever the app was granted, the display name and nothing else. Two
apps can share a display name; the application's identity is its `client_id`, and the row now
names both. Each of the application's five events reads for what its record establishes:

- **`authorize`** — `authorises Mail Backup Pro (client 1234…apps.googleusercontent.com, WEB)
  for 2 scopes: gmail.readonly, openid — authorization recorded; this record does not evidence
  API use`. The grade follows the scopes granted, by a literal table of full scope URIs taken
  from Google's OAuth scope catalogue (as of September 2026 — no family shorthand, no prefix
  match); the highest wins. **High**: full mail (`https://mail.google.com/`), `gmail.readonly`
  and every Gmail modify/send/settings scope, `drive`, `drive.readonly`, `drive.meet.readonly`
  and `drive.scripts`, Docs/Sheets/Slides/Forms (read-only included), `calendar`,
  `calendar.events`, `calendar.calendars`, `calendar.acls` and the legacy
  `https://www.google.com/calendar/feeds`, `contacts`, `contacts.other.readonly` and the legacy
  `https://www.google.com/m8/feeds`, the Admin SDK directory (users, groups, members, org units,
  devices, domains, roles, user security and schemas), data transfer, reports and group
  settings/migration, Cloud Identity groups, policies and inbound SSO, Vault eDiscovery,
  `cloud-platform`, Cloud Search, Classroom rosters, coursework and submissions, Photos, Meet
  conference records (transcripts), Apps Script, Chat messages/import and the organisation-wide Chat read (`chat.app.all.messages.readonly`). **Medium**: metadata-only and activity scopes
  (`gmail.metadata`, `gmail.labels`, the Gmail add-on current-message scopes, `drive.metadata*`,
  `drive.activity*`), read-only Calendar, Contacts, Keep, Tasks, Chat spaces and memberships,
  `directory.readonly`, the read-only Admin SDK and Cloud Identity device, alias, schema and
  settings scopes, licensing and alerts, Classroom courses and announcements, Cloud Search
  settings and indexing, the People `user.*.read` scopes — and **every scope the table does not
  name** (conservative: a scope Google adds after this table is written reads Medium until the
  table is updated). **Low**: per-file and app-data Drive (`drive.file`, `drive.appdata`,
  `drive.install`, `drive.apps.readonly`), free/busy and public calendar reads, Classroom topics
  and add-ons, Meet space creation and settings, and the identity-only scopes (`openid`, `email`, `profile`,
  `userinfo.*`). Four classes
  are shown and the rest counted. A record with no `scope` reads `scopes not in this record` and
  stays High — the table cannot say less when the record does not.
- **`activity`** — `API call drive.drive.files.get by Mail Backup Pro (client …) 4096 bytes
  returned product DRIVE — bytes returned are not proof that file contents were downloaded`. The
  application is the actor here (it called the API on the user's behalf). Info. A response size
  is shown only when the record carries `num_response_bytes`, and it is kept as the record's
  exact digits (the field is a 64-bit integer; an export that wrote it as a bare number beyond
  2^53 was rounded by the JSON parser and is not claimed); two calls to one method that returned
  different sizes are two rows, so a large transfer never folds under a small one.
- **`request`** — `requests access: … for 1 scope: gmail.readonly requester bob@… — access
  requested, not granted by this record`, Low. A delegated request reads `delegated request —
  Google does not display the requested scopes` and claims no scope count.
- **`deny`** — `denied access: … rejection ADMIN_BLOCKED`, Low; the rejection type is the record's own
  word (an admin block and a restricted-service policy are different controls).
- **`revoke`** — `revokes Mail Backup Pro (client …) scopes: drive, gmail.readonly`, Low. The
  row never says what happened after it. Two reading rules: a password reset does not revoke
  every token, so a revocation is the only record of the grant ending; and activity after a
  revocation may be delayed delivery of earlier calls or a legitimate re-authorization — read
  the `authorize` rows around it before calling it a bypass.

Every token row keys on the tenant, the client id (when a record carries none, the record's
own id joins the key so two applications never fold behind one display name), the sorted set of
scopes (a reordered duplicate folds; a real difference is a second row), the API method with its
response size and product, and the request, requester and rejection fields; every Workspace row
of any application now keys on the tenant (`id.customerId`), so two customers' identical rows
stay two. The record's actor is read for what it is: a user (`email`/`profileId`), a service
account or two-legged-OAuth caller (`callerType: KEY` and its `key`), or an application
(`applicationInfo.oauthClientId`) — when an application record also names the user it acts
for, the row reads `by <app> as <user>`, both identities are in the key (two applications
impersonating one user are two rows) and the user is the envelope's subject; an application
or key record with no stable id never folds with another (a name is a label); a record that
names no actor claims none. Token rows carry the canonical envelope: the actor and the application typed as
actor and object (or actor and subject on an `activity`; a requester named on a `request` is
the subject), the cloud principal following the actor (the client on an `activity`, the user's
profile id, the key or the application's client id otherwise, typed as `user`, `key` or
`application`), the tenant, the API method as the resource, and a locator to the record and
event they came from.

**What one export joins: the OAuth lifecycle per client.** Beside the rows, the importer emits
one summary row per client whose export records form a lifecycle — `Google Workspace OAuth
lifecycle: Mail Backup Pro (client 1234….apps.googleusercontent.com) [alice@…: authorized
2026-05-02T10:00:00Z (High: gmail.readonly) — record:0/event:0; activity: 42 calls, 184,220,113
bytes returned, 3 methods (gmail.users.messages.get ×38, …) 10:01:00Z → 12:03:00Z; 42 after an
authorization and before a revocation; revoked 2026-05-02T18:00:00Z (record:91/event:0); bob@…:
authorized … no activity record in this export; no revocation record in this export; the current
grant state is not established; 2 users authorized this client in the 1,204 token records of this
export (2026-05-01 → 2026-05-31); the Reports API retains token events for 6 months; the export's
completeness for the period is not established by this evidence; highest authorization covered:
High]`. It is built over every record of ONE export, before aggregation and the event cap, because
`activity` rows are Info and leave the forensic timeline at import; a lifecycle across exports is
not built.

- **Identity is the tenant, the client id and the user's profile id.** The app name is a label —
  two clients named "Mail Backup Pro" are two rows. A user is a real `profileId` (Google's
  placeholder id and an empty id join nothing); an email resolves only through a record of the
  same tenant that states both, and two ids for one email teach nothing. A token record missing
  a tenant, a client id or a user is counted (`N token records without … — not joined`).
- **Activity is placed in time, never tied to a grant.** A call is "after an authorization and
  before a revocation" for the same user, "before any authorization in this export — the grant
  predates the export or was not exported", or "after a revocation": with a later authorization
  before it, said so; with none, `delayed delivery of earlier calls or a live token; not
  established`. No record carries a grant or token id, so nothing says "under the grant" or which
  scopes a call used. A call at the same timestamp as an authorization or a revocation is
  `order not established`. An authorization with no scope in the record claims no tier.
- **A request never opens a lifecycle**; request- or deny-only clients get a Low summary so the
  evidence stays visible. A missing revocation is `no revocation record in this export; the
  current grant state is not established` — never "live".
- **Beside, never joined into the grade:** admin app-control rows (`ADD_TO_TRUSTED_OAUTH2_APPS`,
  `REMOVE_FROM_TRUSTED_OAUTH2_APPS`, `ADD_TO_BLOCKED_OAUTH2_APPS`, `REMOVE_FROM_BLOCKED_
  OAUTH2_APPS`) joined by `OAUTH2_APP_ID` only for an `OAUTH2_CLIENT` (an Android, iOS or
  Chrome-extension id is not a client id); `login_success` / `login_failure` rows of the user, in
  the same tenant, within ±10 minutes of an authorization (`contemporaneous, not established as
  the same session`); Drive rows of the user between an authorization and a revocation are
  counted, `not attributed to the app`.
- **Totals cover every record, the narration is bounded.** Calls and bytes are summed over every
  activity record (bytes as an exact big integer); 64 methods tracked per user (8 named, calls
  beyond them counted); 16 users named per row (the rest counted); 256 rows per export ordered by
  grade, then the highest scope tier, then users — the omitted row carries the count and the
  highest omitted grade. The grade is the highest authorization the row covers (the scope tier);
  activity with no authorization in the export is Medium (the scopes are unknown). The row's
  identity is (tenant, client id), so a re-import folds; the summaries never evict a source row
  (`maxEvents` bounds source rows; the result's `summaries` counts these).

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
