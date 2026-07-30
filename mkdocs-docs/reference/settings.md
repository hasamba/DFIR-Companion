# Settings Reference

Open Settings with the **⚙ Settings** button in the toolbar.

---

## Essential vs All

Settings opens on **Essential**, which shows only the controls a feature is dead without — the AI
models, enrichment and exposure API keys, and integration URLs and credentials — across six tabs.
**All** shows everything: 16 tabs and every tuning knob. The choice is remembered per browser.

The rule, for anyone adding a field:

> A control is **Essential** if the feature behind it does nothing until you type something in.
> Anything with a working default lives under **All**.

So credentials and endpoint URLs are Essential; timeouts, retry counts, throttle delays, output
caps, TLS trust overrides (`_CA`, `_INSECURE`), and prompt-file overrides are not. Tabs that manage
content rather than configuration — IOC Whitelist, NSRL, Importers, KEV, Report Templates,
Dashboard Views — sit under All too: they are empty and working out of the box.

**Tools** is All-only in full. Every external binary it wires up (Hayabusa, the Velociraptor CLI,
Suricata, Snort, YARA) is blank-means-off, so nothing is broken by leaving them unconfigured —
setting one up is a deliberate trip to All rather than something a new install must face.

In the markup an Essential control carries a `data-essential` attribute, so a newly added field
stays out of Essential until someone opts it in.
`companion/tests/settings/settingsEssentialAll.test.ts` pins the full Essential set; adding to it
means editing that list.

Hiding a field never changes what is saved. Save posts only the keys whose values you actually
changed, so a field you cannot see cannot blank a `.env` key, and switching modes mid-edit keeps
whatever you have typed.

---

## Search

The box beside the Settings title filters every field as you type. Tokens are ANDed and matched as
substrings, against a field's label, its hint, and its env key: `max events`, `DFIR_MAX_EVENTS` and
`dfir-max-events` all find the same control, so a key copied out of `.env` or the docs works as-is.
Select options are searchable too — `ollama` finds the AI provider dropdown.

**Search always spans All, whichever mode you are in.** You search precisely because you cannot find
something, so a search confined to Essential would report "no results" for a field that exists. Tabs
Essential hides — Velociraptor, Tools, Dashboard Views and the rest — appear in the tab bar while a
search is active, each badged with the number of fields it will show. Typing a tab's own name (`kev`,
`whitelist`, `nsrl`) matches the tab and shows its pane unfiltered, which is how the tabs that manage
content rather than configuration stay reachable.

The Essential / All toggle steps aside while a search is active, because search has suspended the
Essential filter and the toggle would have no visible effect. Clear the box — empty it, use the ⨯, or
press Escape in it — and the toggle returns with your choice unchanged. Searching never rewrites the
remembered Essential/All preference, and closing Settings clears the box.

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
- **Vim-style timeline navigation** — toggle `j`/`k`/`f`/`i`/`p`/`n`/`?` keyboard shortcuts on the Forensic Timeline, default on (see [Dashboard → Forensic Timeline](dashboard.md#vim-style-keyboard-navigation))
- **`DFIR_MAX_EVENTS`** (env var) — the per-import event ingestion cap, default 2000. Raise it for cases that need a full MFT/USN import; guarded against 0/negative/NaN silently reinstating the default.
- **`DFIR_ALLOWED_ORIGINS`** (env var) — comma-separated CORS allowlist of extra trusted browser origins beyond loopback, the extension, and any origin the companion itself served; every other origin gets a `403`. Only needed when the dashboard is reached through a hostname (reverse proxy, hosted deployment) — localhost/LAN/Docker setups need no configuration.
- **`DFIR_ALLOWED_HOSTS`** / **`DFIR_ALLOWED_HOST_SUFFIXES`** (env vars) — comma-separated hostnames (or domain suffixes such as `.lab.example.com`) that this companion answers to. Loopback and bare IP addresses are always accepted, so localhost, Docker, and LAN access via `http://192.168.1.50:4773` need no configuration. An unrecognised **name** gets a `403` before any route runs: that is the DNS-rebinding defence, which stops a website you merely visit from pointing its own domain at your machine and reading your case data. Suffixes match on a label boundary, so `.acme.com` never matches `evilacme.com`.

---

## AI

- Provider, model, API key, base URL (extraction)
- Synthesis model (optional separate model for findings/attacker path) — also configurable directly in the first-run **setup wizard**'s AI step, not just here
- VQL-generation model (optional dedicated model — many general models struggle with VQL syntax)
- Timeout, max tokens, context window size
- Chain-of-Thought (synthesis thinking tokens)
- **Anonymisation** on/off and per-category toggles — IPs (internal *and* public), hostnames, usernames, domains, emails, paths, encoded commands, SIDs, credit cards, phone numbers, national ID numbers; see [AI Analysis → What the AI Sees](ai-analysis.md#what-the-ai-sees-anonymization) for exactly what each one catches, the redacted-export exception for public IPs, and known limitations (the narrow IPv4/IPv6 masking gaps, screenshot IP loss, national-ID false positives)
- **Presidio** (optional external PII detector) — analyzer URL, confidence floor, and a **Test connection** button; see [Presidio & PII Masking](presidio.md)
- Preflight diagnostics disable
- **Re-run the setup wizard**
- **Live AI test** — confirms the current key works right now

**Screenshot/vision provider** — `DFIR_VISION_PROVIDER`/`_MODEL`/`_KEY`/`_BASE_URL`/`_IMAGE_DETAIL` configure the screenshot-OCR-only model, renamed from `DFIR_AI_*` (legacy names still work as a fallback). Text-only AI features run off the synthesis provider and never need a vision provider configured.

**Deep pass** — `DFIR_DEEP_PASS_MAX_BATCHES` (default 30) caps how many batches a [deep pass](dashboard.md#deep-pass) run may take, refusing oversized runs up front; `DFIR_AI_OBSERVE_PROMPT_FILE` is an ejectable override of its batch-observation prompt.

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

### MCP servers

MCP servers are configured in Claude Code, then allowed under
**Settings → All → Tools → MCP servers**. Companion stores policy and evidence-delivery settings,
not the MCP endpoint or token. Leaving **Restrict to tools** blank allows all tools offered by an
enabled server; use the field only when you want a narrower allowlist.

See [MCP Analysis](mcp-analysis.md) for recommended REMnux and SIFT servers, Claude Code
registration, shared-path and SCP configuration, validation, security notes, and plain-English
prompt examples.

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

## Content Tagger

Controls the [content-based event tagger](advanced.md) (`companion/data/tags.yaml`), env-configured (no dashboard fields):

- `TAGGER_AUTO` — run the tagger automatically after every import (default `true`; `false` = manual-only, via Super-Timeline → Content tagger → Run tagger)
- `TAGGER_SCOPE` — `forensic` | `super` | `both` (default `both`); `super` only tags the super-timeline (never mutates severity/MITRE)

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
| **Analyst** *(default)* | All technical panels, in the app's intended reading order |
| **Lead** | Findings, timeline, playbook, hunting |
| **Executive** | Findings, attack path, countermeasures, exposure |
| **Triage** | Timeline, IOCs, MITRE, assets |
| **Report** | Report-oriented panel order |
| **Deep-Dive** | Evidence chain, hypotheses, threads, notebook |
| **Hunt-Prep** | Hunting profile, adversary hints, next techniques, query translator |

A new case (or any case with no saved per-case dashboard-view choice) opens with **Analyst** instead
of the raw "Custom" section order. Explicitly picking **Custom** from the dashboard-view menu still
sticks across reloads. A permanent note below all panels points back here for further customization.

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

## War-Room Bot

Inbound slash commands from Slack / Teams / Telegram — see [War-Room Slash-Command Bot](war-room-bot.md) for setup. Configured entirely in `.env`; each platform switches on when its secret is set.

| Variable | Meaning |
|---|---|
| `DFIR_SLACK_SOCKET_MODE` | `=on` to receive Slack commands over an outbound WebSocket. **No tunnel, no Request URL.** Needs `DFIR_SLACK_APP_TOKEN` |
| `DFIR_SLACK_APP_TOKEN` | App-level token, `xapp-…`, scope `connections:write`. Not a bot token |
| `DFIR_TELEGRAM_POLL` | `=on` to receive Telegram commands by long polling. **No tunnel, no inbound URL.** Needs only `DFIR_TELEGRAM_BOT_TOKEN` |
| `DFIR_TELEGRAM_BOT_TOKEN` | @BotFather token. Required for polling; in webhook mode it delivers `ask`/`hunt`/`synthesize` results |
| `DFIR_ALLOWED_HOSTS` | Hostnames the Companion answers to. **Required in webhook mode** — the tunnel/proxy hostname must be listed, or requests are refused with 403. Not used by Socket Mode or polling |
| `DFIR_SLACK_SIGNING_SECRET` | Slack app signing secret; enables `/integrations/slack/command`. Webhook mode only |
| `DFIR_TEAMS_TOKEN` | Shared bearer token; enables `/integrations/teams/command` |
| `DFIR_TELEGRAM_SECRET_TOKEN` | `setWebhook` secret; enables `/integrations/telegram/command`. Webhook mode only |
| `DFIR_SLACK_ACTION_USERS`<br>`DFIR_TEAMS_ACTION_USERS`<br>`DFIR_TELEGRAM_ACTION_USERS` | Comma-separated user ids allowed to run `ask`/`hunt`/`synthesize`/`bind`. Unset = open to the whole channel; once set, everyone else is confined to the channel's bound case |
| `DFIR_SLACK_RESPONSE_HOSTS`<br>`DFIR_TEAMS_RESPONSE_HOSTS` | Extra hosts an async result may be delivered to, for a self-hosted Slack-compatible server. Defaults cover the platforms' own hosts |
| `DFIR_TELEGRAM_API_BASE` | Bot API base URL override (default `https://api.telegram.org`) |

Channel-to-case bindings are stored alongside the notification config, not in `.env`.

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
- **AI cost — this case** — calls, dollar cost, and token counts broken down by Vision / Synthesis /
  Other and by model, read from the provider's real per-call cost and token counts (never a guessed
  price). Providers that don't report cost/tokens show "n/a", never a fabricated `$0.00`.
- Importer health (attempt counts over 24h/7d)
- **Compute case sizes** button
- **Live AI test** — connectivity test with latency
- **Pre-flight check** — re-run startup diagnostics on demand
- **Per-case backup list** — state backups with one-click restore
- **State backup configuration** (retention counts, interval)
- **Evidence integrity** — the result of the last chain-of-custody verification: which triggers are
  active, how long ago a case was last checked, how many artifacts verified clean, and any case whose
  evidence or custody log failed. See [Chain of Custody](chain-of-custody.md)

### Evidence integrity environment variables

| Variable | Default | Effect |
|---|---|---|
| `DFIR_CUSTODY_VERIFY_ON_OPEN_MS` | `14400000` (4h) | How long a case's verification stays fresh. Opening a case re-verifies it in the background unless it was checked within this window. `0` turns on-open verification off |
| `DFIR_CUSTODY_VERIFY_INTERVAL_MS` | `0` (off) | Interval for a sweep of **every** case, archived included. Off by default so an idle install does no background hashing — set it if you want unattended assurance across the whole store |
- **Case Statistics** — per-case totals, per-source event breakdown, and import velocity
- **Large-import reliability** — atomic state-save retry count for big imports is tunable via `DFIR_ATOMIC_WRITE_RETRIES` (default 20, ~8.4s of retries) for setups where antivirus/search indexing can outlast the default retry budget on a large USN/MFT import

!!! tip
    The Diagnostics page is your first stop when something breaks. It shows the AI error count by type — auth errors = wrong key, billing errors = quota exceeded, rate limit = slow down — without ever showing your API key.
