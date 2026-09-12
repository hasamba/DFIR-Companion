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
  certificate observed in this record]`.
- **What the words mean.** The SNI is the name the *client* asked for — a claim, like a DNS query,
  and the row's only indicator. The certificate is what the *server* presented. `chain check` is
  the sensor's own verdict on the chain (`ok`, `self signed certificate`, …) — it is not
  "benign". JA3 and JA3S are TLS library signatures, not identities. Nothing on a row says
  malicious, C2, "the same operator", or "an inspection proxy": an issuer is shown as written, and
  what it means is the analyst's call.
- **A certificate row** — one per certificate identity — reads `[certificate: <fingerprint or cert
  identity>; subject …; issuer …; valid …–…; covers N names: a, b, c (+n more)] — N certificate
  records`. A certificate's identity is a source-given fingerprint (Suricata `tls.fingerprint`, Zeek
  builds that write one, a leaf's DER bytes hashed here), or else its issuer and serial — the pair
  that names one certificate under one CA — spelled `certid-v1:…` and never called a fingerprint.
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
- **What this does not do.** It does not join a session to its certificate record by Zeek's
  `cert_chain_fuids`, find clusters, or link fingerprints across sensors and time; that graph is a
  separate design over un-aggregated records, and every fact it needs is kept in the row's data.

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
- **What this does not do.** It does not join a query to a later connection, bound by a TTL or a
  window; that is a separate, cross-record design over un-aggregated records.

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
every other dimension stay two rows. The lineage across records — which later calls used the credential an issuance minted, a
workload role used from a new source — is a join by access key id, filed as #931 item 5's chain.

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

The chain across records — a suspicious sign-in, then access, then a rule, then sending or
deletion — is a join by session and time, not a per-record fact; it is #975.

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
sequence — access → write → execution transfer; suspended child → image replaced → resumed — is a
join across records by process GUID and time, and a spec issue of its own.

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
The grade stays Medium: a runnable pulled from the internet is worth an eye. The techniques return
through corroboration — a Prefetch, Amcache, ShimCache or process record for the same file — which
is a join across records and a spec issue of its own.

Reading rules the rows enforce: a normal `Zone.Identifier` stream is not a hidden payload;
download provenance is not execution, user intent or proof of a drive-by; a missing or stripped
mark is inconclusive — propagation depends on the software that wrote the file (a `.iso` mounted
strips the mark from what is inside; many tools never write one); a stream's name is not its
content.
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

The lifecycle across records — an authorization, the activity under it, the revocation, "every
user who authorized this client" — is a join by `client_id` across users and time, not a
per-record fact; it is a spec issue of its own.

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
