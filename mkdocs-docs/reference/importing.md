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
| **Windows host triage** | KAPE/EZ Tools CSVs (Prefetch, Amcache, ShimCache, LNK, JumpLists, USN Journal, MFT, SRUM, Recycle Bin, Shellbags), Cyber Triage JSONL/JSON/CSV |
| **EDR / SIEM** | Velociraptor native JSON/JSONL/artifact-map, Velociraptor **upload-only artifacts** (e.g. THOR) — paste the GUI's "Uploaded Files" tab URL to import just the uploaded report, skipping rows entirely; also reads `.csv`/`.txt`/`.log`/`.jsonl` uploads, not just `.json`, SIEM/EDR JSON (Elastic, Splunk, Kibana, winlogbeat), Wazuh JSON, THOR Nextron JSONL, ECAR (EDR Common Activity Record) NDJSON |
| **Network** | Suricata eve.json, Zeek JSON (combined or per-stream conn/dns/http/ssl/x509/files), Security Onion events |
| **Firewall / IDS / web logs** | Cisco ASA syslog (Built/Teardown/Deny), Snort/Suricata `alert_fast` IDS alerts, Apache/Nginx/Squid combined access logs, plain syslog (RFC 5424 / RFC 3164, Linux/Unix hosts) |
| **Memory forensics** | Volatility 3 JSON + default text output, Rekall JSON, MemProcFS timeline CSV, MemProcFS findevil |
| **Cloud IR** | AWS CloudTrail JSON, M365 Unified Audit Log, Entra ID sign-in/audit logs, GCP Cloud Audit Logs, Azure Activity Log |
| **Malware analysis** | CAPEv2 report.json, CrowdStrike Falcon Sandbox summary JSON, sandbox report arrays, YARA CLI scan output (`yara -s -m`) |
| **Super-timeline** | Plaso/log2timeline psort CSV (dynamic and l2tcsv) — files over 200 MB are streamed line-by-line automatically; filter your `psort` output first to reduce size |
| **Linux** | shell history (`.bash_history` / `.zsh_history`, with or without timestamps), auditd logs (raw/ausearch/aureport), journald JSON (`journalctl -o json`) |
| **Container/syscall** | Falco alert JSON, sysdig JSON, Kubernetes API-server audit log (`audit.k8s.io` JSON-lines / EventList) |
| **Host telemetry** | osquery scheduled-query result log (differential + snapshot) |
| **Case management** | TheHive 5 case/alert/observable export |
| **Email** | .eml (full fidelity), .msg (Outlook OLE, best-effort) |
| **SO-CRATES** | SO-CRATES event exports (Suricata, YARA, Sigma overlays) |
| **Generic** | CSV (AI-assisted field detection), log files (AI-assisted triage), DFIR-IRIS import |
| **Custom** | Analyst-defined declarative importer specs (JSON) |

All of the above except CSV/log/DFIR-IRIS are **fully deterministic — no AI call** — they map the tool's own verdict/fields, not re-detect threats.

## Evidence Drop Folder (Auto-Import Inbox)

Every case gets a `cases/<id>/drop/` folder on creation. Copy any file into it — at any depth, subfolders included — and a background poller picks it up once the file size/mtime is stable (safe for Dropbox/OneDrive sync), then imports it through the same detection + import chain as the **Import** button. Screenshots are ingested as capture evidence; everything else is imported as an artifact.

Processed files move to `drop/_processed/`; failures move to `drop/_failed/` and are reported in the dashboard **📥 Drop** banner and any configured notification channel.

Every auto-processed file's outcome (imported / failed / pending, with reason) is appended to a
running `drop-log.txt` in the same `drop/` folder — including the terminal outcome once a
previously-pending file is later run manually. Use it as an audit trail of everything the watcher has
seen for this case.

Enabled by default. Configure via `DFIR_DROP_ENABLED`, `DFIR_DROP_POLL_S` (poll interval), `DFIR_DROP_MAX_BYTES` (size cap).

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
