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

## IOC Whitelist

Global known-good pattern list:

- Add CIDR, exact, or regex rules
- Optional type scoping (e.g. "only match IPs")
- Import/export as CSV or JSON
- **Apply to current case** — retroactively marks matching IOCs legitimate

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
