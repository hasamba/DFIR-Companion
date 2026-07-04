# Settings Reference

Open Settings with the **⚙ Settings** button in the toolbar.

---

## General

- Case root location
- Server port
- Log level (debug / info / warn / error) — live toggle, no restart
- **Open setup wizard** link
- Push ingest token management
- Update check (opt-in dashboard banner for new GitHub releases)
- Theme (dark / light)
- **Import severity** — manage or clear the remembered minimum-severity import floor (see [Importing Evidence](importing.md#optional-severity-floor))
- **Timeline row display** — choose which sub-elements show on each forensic-timeline row (see [Dashboard → Forensic Timeline](dashboard.md#forensic-timeline))
- **Screenshot OCR search** — enable/disable local Tesseract OCR indexing of captures
- **Evidence drop folder** — enable/disable the per-case auto-import watcher, poll interval, and per-file size cap (see [Importing Evidence](importing.md#evidence-drop-folder-auto-import-inbox))

---

## AI

- Provider, model, API key, base URL (extraction)
- Synthesis model (optional separate model for findings/attacker path)
- VQL-generation model (optional dedicated model — many general models struggle with VQL syntax)
- Timeout, max tokens, context window size
- Chain-of-Thought (synthesis thinking tokens)
- Anonymisation on/off and category settings
- Preflight diagnostics disable
- **Re-run the setup wizard**
- **Live AI test** — confirms the current key works right now

---

## Enrichment

Lists all 13 enrichment providers. Each shows:

- Current status (configured / key missing)
- Which environment variable to set
- Enable/disable for this case

!!! info
    Nothing is sent externally until you enable a provider for the specific case you're working on.

---

## Exposure

Customer exposure check configuration:

- Add customer domains and email addresses
- Select which providers to use (LeakCheck, HIBP, DeHashed, Shodan)
- Run the exposure check and view results

---

## Integrations

- DFIR-IRIS (URL, key, reconnect)
- Timesketch (URL, credentials, reconnect)
- Notion (API token)
- ClickUp (API token)

---

## Velociraptor

- API config file path
- Reconnect button
- Browse server artifacts
- Triage bundle management (Fast/Full/custom)
- Hunt parameters (timeout, filters)
- **IR Templates** toggle for the Response Playbook
- Live Monitoring tab (add/stop/start monitors)

---

## Tools

Run your **own locally-installed** external tools against raw evidence the Companion can't parse
(EVTX/PCAP/files), then ingest the tool's *output* through the existing importers. The Companion never
downloads or bundles a binary — install and update it yourself (repo links are shown per tool).

- **Hayabusa / Velociraptor CLI** — EVTX → csv/json-timeline / artifact JSON
- **Suricata / Snort** — PCAP → alerts (Snort uses your own rules file)
- **YARA** — scan files/dirs → rule matches (file/hash IOCs)

**Custom tools** — beyond the five built-ins, add your own: a name, the binary path, a run command
(`<target>` = input file, `<output>` = output file, omit for stdout), an optional update command, and
the file extensions it handles. The output is auto-detected and routed to the right importer. Add as
many as you like; each appears in the Import/drop banners for its extensions.

Per tool: binary path (blank = off), run-args template (`<target>`/`<output>`/`<rules>` placeholders),
rules path (Snort/YARA), a separate **Update rules** command + button, an **auto-run on drop** toggle,
and timeout/output caps. Click **Reconnect / apply** to apply saved paths without a restart. A raw
`.evtx`/`.evt`/`.pcap`/`.pcapng` copied into a case's `drop/` folder runs automatically when a matching
tool has auto-run on; the Import dialog shows a banner for these formats. Config is stored in `.env`
(`DFIR_TOOL_*`, not a secret). Commands run with **no shell** (args tokenized) and the target path is
contained to the case directory. Master kill-switch: `DFIR_TOOL_AUTO_RUN=off`.

---

## IOC Whitelist

Global known-good pattern list:

- Add CIDR, exact, or regex rules
- Optional type scoping (e.g. "only match IPs")
- Import/export as CSV or JSON
- **Apply to current case** — retroactively marks matching IOCs false-positive

---

## NSRL

Known-good file hash database:

- Paste hashes, import a flat hash file, or load an NSRL RDS hash list by file path
- Connect to a large NSRL RDS SQLite database (Node 22.5+)
- Apply to current case

---

## Importers

Custom declarative importers:

- List all custom importers (filename, format, match criteria)
- Add a new importer (paste JSON spec)
- Reload importers from disk
- **Get AI prompt** — copy the prompt to use with your AI assistant to generate a spec for a new file format
- Precedence setting: built-in-first (default) or external-first

---

## KEV

CISA Known Exploited Vulnerabilities integration:

- Enable/disable KEV cross-reference
- CVEs in findings/events are checked against CISA KEV
- KEV-listed CVEs are highlighted and mentioned in synthesis context and report

---

## Report Templates

Manage report templates:

- Edit the default template or create new ones
- Set: cover title, subtitle, accent colour, running header/footer, logo visibility
- Enable/disable and reorder report sections
- Assign a template per case

Built-in templates: **Standard** (full technical report), **Executive** (condensed), and any you create.

---

## Dashboard Views

Preset panel layouts:

| View | Best for |
|------|----------|
| **Analyst** | All technical panels |
| **Lead** | Findings, timeline, playbook, hunting |
| **Executive** | Findings, attack path, countermeasures, exposure |
| **Triage** | Timeline, IOCs, MITRE, assets |
| **Report** | Report-oriented panel order |
| **Deep-Dive** | Evidence chain, hypotheses, threads, notebook |
| **Hunt-Prep** | Hunting profile, adversary hints, next techniques, query translator |

Each preset is fully customisable — reorder panels, set a severity floor, cap the timeline row count, link a report template. Saved per case.

---

## Notifications

Alert channels for new findings, playbook updates, and investigation milestones:

- **Slack** webhook
- **Microsoft Teams** webhook
- **Mattermost** webhook
- **Discord** webhook
- **Telegram** bot
- **SMTP email**

Each channel has:

- A minimum severity threshold (only notify for High+, for example)
- Per-event-type toggles (findings / playbook / milestones)
- A **Test** button that sends a test message

!!! info
    Notification configs are stored in a global config file (not `.env`) and webhook URLs are redacted in all API responses.

---

## Updates

Opt-in GitHub release check. Shows a dashboard banner when a newer version is available. Never auto-installs.

---

## Diagnostics

Operator health view:

- Disk usage and warning level on the cases folder
- Case count (open / closed)
- Processing queue (screenshots pending analysis, synthesis in flight)
- Redacted AI config (provider, model, timeout — **never the API key**)
- Recent AI error counts by type
- Importer health (attempt counts over 24h/7d)
- **Compute case sizes** button
- **Live AI test** — connectivity test with latency
- **Pre-flight check** — re-run startup diagnostics on demand
- **Per-case backup list** — state backups with one-click restore
- **State backup configuration** (retention counts, interval)

!!! tip
    The Diagnostics page is your first stop when something breaks. It shows the AI error count by type — auth errors = wrong key, billing errors = quota exceeded, rate limit = slow down — without ever showing your API key.
