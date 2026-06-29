# DFIR Companion — User Manual

> Plain-English guide for security analysts, incident responders, and anyone who wants to
> understand what the tool does, how to reach every feature, and how to get the most out of it.

---

## Table of Contents

1. [What Is DFIR Companion?](#1-what-is-dfir-companion)
2. [What It Is NOT](#2-what-it-is-not)
3. [Getting Started](#3-getting-started)
4. [Analyst Walkthrough](#4-analyst-walkthrough)
5. [Cases](#5-cases)
6. [Evidence Capture (Browser Extension)](#6-evidence-capture-browser-extension)
7. [Importing Evidence](#7-importing-evidence)
8. [AI Analysis](#8-ai-analysis)
9. [Dashboard Panels — Reference](#9-dashboard-panels--reference)
10. [IOC Enrichment](#10-ioc-enrichment)
11. [Threat Hunting](#11-threat-hunting)
12. [Reports & Exports](#12-reports--exports)
13. [Presentation Mode](#13-presentation-mode)
14. [Integrations](#14-integrations)
15. [Live Monitoring & Push Ingest](#15-live-monitoring--push-ingest)
16. [Settings Reference](#16-settings-reference)
17. [Mobile Companion](#17-mobile-companion)
18. [Advanced Features](#18-advanced-features)
19. [Tips for Analysts](#19-tips-for-analysts)

---

## 1. What Is DFIR Companion?

DFIR Companion is a **localhost** web application that sits on your analysis workstation and helps you go from a pile of raw forensic evidence to a finished incident-response report.

In plain terms, it does three things:

1. **Collects evidence.** You capture screenshots of your investigation tools — SIEM dashboards, EDR consoles, Velociraptor hunt results, log viewers — by pressing a hotkey in the browser extension. You can also drag-and-drop or upload artifact files directly (CSV exports, JSON reports, log files, memory images, network captures, cloud audit logs, email files, and many more).

2. **Analyzes the evidence with AI.** The server reads the evidence and builds a structured **forensic timeline** of real events with real timestamps. It then runs a second AI pass to produce **findings** (what the attacker did), **MITRE ATT&CK technique mappings**, and an **attacker-path narrative** (the story of the intrusion from first foothold to last known activity).

3. **Helps you understand and communicate.** It surfaces the timeline in a dashboard with filters, graphs, and derived panels (kill chain, asset graph, adversary hints, defensive countermeasures, hunting leads). It generates a Word/HTML/Markdown/CSV report, a presentation slide deck, and can push the findings to your SIEM, Notion, ClickUp, or DFIR-IRIS.

Everything runs on your machine. Evidence never leaves your network unless you explicitly opt in to a third-party enrichment service.

---

## 2. What It Is NOT

Understanding this avoids confusion:

- **It is NOT a detection engine.** It does not run Sigma rules, YARA rules, or write detections. That is your SIEM/EDR/Chainsaw/Hayabusa's job. DFIR Companion consumes *their* results and makes sense of them.
- **It is NOT a SIEM.** It does not ingest raw events in real time (except via the optional push-ingest webhook). It is a case-analysis layer that runs *after* your detection tools have already fired.
- **It is NOT a replacement for analyst judgment.** The AI assists. Every finding, timeline entry, and IOC is shown to you so you can confirm, reject, or mark it legitimate.

---

## 3. Getting Started

### 3.1 Installation

Choose the method that fits your setup:

#### From source (recommended for development)

1. Install [Node.js](https://nodejs.org/) **20 or later** (Node 22.5+ if you want the NSRL SQLite backend).
2. Clone or download the repository.
3. Run:
   ```
   cd companion
   npm install
   cp .env.example .env
   npm run dev
   ```
4. The server starts on **http://127.0.0.1:4773**. Open the dashboard at **http://127.0.0.1:4773/dashboard**.

#### Windows — Chocolatey

```powershell
choco install dfir-companion
```

Installs the portable Windows build and bundles the capture extension on disk for offline "Load unpacked". Data is stored in `%LOCALAPPDATA%\DFIR-Companion`.

#### Windows — Portable executable

Download `dfir-companion-win.zip` from the [latest GitHub release](https://github.com/hasamba/DFIR-Companion/releases/latest), extract, and run `dfir-companion.exe`. No Node.js required.

#### Linux — AppImage

Download `dfir-companion-linux.AppImage` from the [latest GitHub release](https://github.com/hasamba/DFIR-Companion/releases/latest), make it executable (`chmod +x`), and run it. Set `DFIR_ENV_FILE` to point to your `.env` if you need the file outside the AppImage mount.

#### Docker

```bash
docker run -p 4773:4773 \
  -v /your/cases:/cases \
  -e DFIR_CASES_ROOT=/cases \
  ghcr.io/hasamba/dfir-companion:latest
```

Dashboard is then at **http://127.0.0.1:4773/dashboard**. Mount a local volume for persistent case storage.

---

> **Already running?** If the dashboard says "companion offline", the server is not running. If you see `EADDRINUSE`, another instance is already running — just use that one, or free the port:
> ```powershell
> Get-NetTCPConnection -LocalPort 4773 -State Listen | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force }
> ```

### 3.2 First-Run Setup Wizard

When you open the dashboard for the first time with no AI provider configured, a **Setup Wizard** appears automatically. It walks you through everything in a guided, multi-step flow:

| Step | What you configure |
|------|--------------------|
| **AI analysis** | Provider (OpenAI, Anthropic/Claude, OpenRouter, Gemini, Ollama, LiteLLM), model name, API key. A "Save & test" button confirms the key works before you proceed. |
| **Velociraptor** | API config path for hunt-and-collect integration. |
| **DFIR-IRIS** | URL + key for bidirectional case sync. |
| **Timesketch** | URL + credentials to push the timeline to Timesketch. |
| **Notion** | API token for exporting cases to Notion pages. |
| **ClickUp** | API token for pushing the response playbook to ClickUp. |
| **Threat-intel enrichment** | API keys for VirusTotal, AbuseIPDB, Hunting.ch, CrowdStrike, Shodan, MISP, YETI, OpenCTI, RockyRaccoon, GeoIP. |
| **Customer exposure** | Keys for LeakCheck, HIBP, DeHashed. |
| **Push ingest** | Token for the webhook endpoint. |
| **NSRL** | Path to a known-good hash database. |
| **Notifications** | Slack/Teams/Mattermost/Discord webhook for alert notifications. |

Everything is optional. You can dismiss the wizard and add things later from **Settings**. You can reopen the wizard any time from **Settings → General → Open setup wizard**.

### 3.3 Installing the Browser Extension

The capture extension lets you screenshot any browser tab with a keyboard shortcut.

#### Chrome Web Store (easiest)

Install directly from the Chrome Web Store — no developer mode needed:

**[DFIR Companion — Evidence Capture & Push](https://chromewebstore.google.com/detail/dfir-companion-%E2%80%94-evidence/jhlffkfnamlmfkijgpaopdnbmbajldmf)**

Click **Add to Chrome**, confirm the permissions, and the extension icon appears in your toolbar.

#### Load unpacked (from source or Chocolatey)

1. In Chrome (or any Chromium browser), go to `chrome://extensions/`.
2. Enable **Developer mode** (top-right toggle).
3. Click **Load unpacked** and select the `extension/dist/` folder (run `npm run build` inside `extension/` first if building from source; Chocolatey installs it pre-built on disk).
4. The extension icon appears in the toolbar.

**Keyboard shortcut:** `Ctrl+Shift+S` (Windows/Linux) toggles capture mode on/off. When capture is active, a floating push button appears on the page.

---

## 4. Analyst Walkthrough

This section walks through a complete investigation from start to finish. Think of it as the recommended workflow.

### Step 1 — Create a case

Open the dashboard. Click **+ New case** in the top toolbar. Fill in:
- **Case ID** — a short slug (e.g. `ir-2026-001`). Must be unique.
- **Case name** — human-readable title.
- **Investigator** — your name.

Click **Create**. The case is selected and the dashboard is ready.

### Step 2 — Capture screenshots as you investigate

As you work through your SIEM, EDR console, Velociraptor, or any browser-based tool:
1. Select your case in the extension popup (click the extension icon).
2. Press `Ctrl+Shift+S` to enable capture mode.
3. A floating **Push chip** button appears on the page. Click it to send the current screenshot to the Companion.
4. A green confirmation toast confirms receipt.

> **Tip — use the push chip in Velociraptor, Splunk, or any browser-based console:** when you're looking at hunt results in Velociraptor's web GUI, a Splunk search result, or any other tool, activate capture mode with `Ctrl+Shift+S` and click the floating Push chip. You don't need to switch windows or save a screenshot manually — one click sends exactly what's on screen to the Companion and attaches it to your case.

For specifically recognized consoles (Security Onion Alerts/Hunt, Kibana, SO-CRATES), the extension also injects **per-row push buttons** automatically, so you can push individual events or alerts without enabling capture mode and without a full-page screenshot.

**What gets captured:** the full visible tab content (a screenshot) plus the URL and tab title. Evidence is stored to disk immediately — before any AI analysis.

### Step 3 — Import artifact files

While screenshots are great for consoles, you should also import raw artifact exports whenever possible. Raw exports give the AI more structured data.

Click the **Import** button (toolbar, top of dashboard). A file picker opens. Drag or select any of the supported file types (see Section 7 for the full list). The server auto-detects the format and imports it.

Recommended imports for a Windows IR case:
- Chainsaw/Hayabusa hunt results (JSON or CSV)
- Velociraptor collection export (JSON or artifact map)
- KAPE/Eric Zimmerman tool outputs (CSV)
- THOR scanner report (JSONL)
- Suricata/Zeek network logs
- Memory image analysis (Volatility 3 JSON or text)
- Phishing email samples (.eml)

### Step 4 — Let the AI analyze

After each import (and after enough screenshots accumulate), click **AI Analyze** in the toolbar to run extraction over any unprocessed evidence. The server reads each batch of screenshots and structured files, then emits raw forensic events into the timeline.

When you want findings and an attacker narrative, click **AI Re-synthesize**. This runs one text-only AI call over the entire forensic timeline and produces:
- **Findings** — named conclusions (e.g. "Credential dumping via LSASS access")
- **MITRE ATT&CK techniques** — mapped to each finding
- **Attacker path** — a narrative paragraph connecting the dots
- **Kill chain** — which phases are covered

Synthesis is smart: it skips re-running if nothing changed since last time. Force it with the **Force re-synthesize** option.

### Step 5 — Review the dashboard

Walk through the dashboard panels (see Section 9 for each one in detail):

1. **Findings** — do these make sense? Any false positives?
2. **Forensic Timeline** — scan for gaps, anomalies, and events that look out of place.
3. **MITRE ATT&CK** — which techniques? What's missing?
4. **Compromised Assets & IoC Graph** — which machines and accounts were touched?
5. **IOCs** — run enrichment on suspicious indicators (Section 10).
6. **Adversary Hints** — any known threat groups match this technique set?

### Step 6 — Mark false positives and known-good items

Every finding, IOC, and forensic event has a **⚑ Mark legitimate** button. Click it to exclude an item from analysis. It moves to the **Confirmed Legitimate** panel. You can reverse the decision any time.

For bulk exclusions (e.g. an entire internal IP range), use **Settings → IOC Whitelist** to add a CIDR rule. Any IOC matching the rule is automatically marked legitimate on import.

### Step 7 — Hunt for more evidence

The **Recommended Next Steps** and **Key Investigative Questions** panels suggest what to look for next. If you have Velociraptor connected, the dashboard surfaces **AI-generated VQL hunt queries** — click the deploy button to launch a fleet hunt. Results auto-import into the case.

Use the **Query Translator** panel to write plain English ("show me all PowerShell executions in the last 24 hours") and get it translated to VQL, KQL, ES|QL, SPL, Sigma, YARA, or Suricata.

### Step 8 — Work the Response Playbook

The **Playbook** panel lists response tasks auto-generated from your findings. Each task has:
- Status (pending / in progress / done / deferred)
- Assignee and due date
- Notes

Mark tasks as you complete them. Enable **IR Templates** in Settings → Velociraptor to expand each Critical/High finding into phase-based response steps (Contain → Investigate → Eradicate → Recover).

### Step 9 — Generate the report

Click **Export → Report (Word)** (or Markdown, HTML) to download the full IR report. The report contains every finding, the timeline, IOCs, MITRE mapping, attacker path narrative, and recommended countermeasures.

Customize the report's cover page, accent color, and section order in **Settings → Report Templates**.

### Step 10 — Hand off

- **Present mode** (`▶ Present` toolbar button) — a slide deck for executive briefings. Navigate with arrow keys or use fullscreen.
- **Export snapshot** — a portable JSON package of the case you can share with another analyst (no raw evidence bytes, just the investigation state).
- **Push to DFIR-IRIS / Timesketch / Notion / ClickUp** — export to integrated platforms.

---

## 5. Cases

### Creating a case

Toolbar → **+ New case**. Fill in Case ID, name, and investigator.

Cases live in the `cases/` folder (location configured by `DFIR_CASES_ROOT`).

### Switching between cases

The case selector dropdown (top-left of dashboard) lists all cases, newest first. Select one to load it.

### Case lifecycle

Each case has a status: **Open** or **Closed**.

Toolbar **☰ Case lifecycle** menu lets you:
- **Close** a case (marks it inactive)
- **Archive** a case — packages it as a ZIP with a SHA-256 manifest
- **Delete** a case (destructive — prompts for confirmation)

The toolbar also shows a disk-space warning if the cases folder is running low.

### Investigation Snapshot (export/import)

**Export snapshot:** toolbar → **Export → Investigation snapshot**. Produces a single JSON file containing all investigation data (findings, timeline, IOCs, MITRE, playbook, analyst notes, tags, etc.) but no raw evidence bytes. Share with a colleague or restore on another machine.

**Import snapshot:** toolbar → **Import case → Investigation snapshot**. Restores as a new case. If the Case ID already exists you get a conflict warning.

---

## 6. Evidence Capture (Browser Extension)

### How it works

The extension captures a screenshot of the current browser tab and POSTs it to `POST /captures` on the Companion server. The server saves the image to `cases/<id>/screenshots/` before doing anything else — evidence is always persisted first.

### Capture modes

| Method | How |
|--------|-----|
| **Hotkey** | `Ctrl+Shift+S` in any browser tab |
| **Extension popup** | Click the extension icon → select case → click Capture |
| **Floating push button** | Button injected into recognized DFIR consoles; single-click sends the current event/row |

### Recognized consoles (one-click push)

The extension automatically injects a push button into:
- **Security Onion** (Alerts, Hunt, Dashboards)
- **SO-CRATES** (network/file events, Sigma detections)
- **Elasticsearch/Kibana** (standard and modern async-search)

### Screenshot OCR full-text search

Every screenshot is OCR'd locally in the background after capture (using Tesseract — no AI, nothing leaves the machine). You can search the text content of all screenshots using the **🔍 Screenshot text** box in the dashboard filter bar.

Results link back to the original screenshot. This is useful when you remember seeing a hostname, hash, or error message but can not find where.

To backfill OCR for older cases: `npm run ocr-index -- <caseId>`

---

## 7. Importing Evidence

### The Import button

Toolbar → **Import** button. Drag or select any file. The server **auto-detects the format** and routes it to the correct importer. You do not need to tell it what kind of file it is.

After import completes, a banner shows `📥 last import N ago / +N new events / +N new IOCs`. New items are highlighted `NEW` in the timeline and IOC panel for easy review.

### Optional severity floor

Before importing, you can set a **minimum severity** filter. Events below the floor are dropped during import, reducing noise. Leave it blank to import everything.

> Events with no built-in severity (plain host-triage artifacts like KAPE or Plaso) are always imported in full, regardless of the floor.

### Supported formats

| Category | Formats |
|----------|---------|
| **Windows detection** | Chainsaw hunt JSON/JSONL, EVTX dump (evtx_dump), Hayabusa JSON/CSV timeline |
| **Windows host triage** | KAPE/EZ Tools CSVs (Prefetch, Amcache, ShimCache, LNK, JumpLists, USN Journal, MFT, SRUM, Recycle Bin, Shellbags), Cyber Triage JSONL/JSON/CSV |
| **EDR / SIEM** | Velociraptor native JSON/JSONL/artifact-map, SIEM/EDR JSON (Elastic, Splunk, Kibana, winlogbeat), Wazuh JSON, THOR Nextron JSONL |
| **Network** | Suricata eve.json, Zeek JSON, Security Onion events |
| **Memory forensics** | Volatility 3 JSON + default text output, Rekall JSON, MemProcFS timeline CSV, MemProcFS findevil |
| **Cloud IR** | AWS CloudTrail JSON, M365 Unified Audit Log, Entra ID sign-in/audit logs, GCP Cloud Audit Logs, Azure Activity Log |
| **Malware analysis** | CAPEv2 report.json, CrowdStrike Falcon Sandbox summary JSON, sandbox report arrays |
| **Super-timeline** | Plaso/log2timeline psort CSV (dynamic and l2tcsv) — files over 200 MB are streamed line-by-line automatically; filter your `psort` output first to reduce size |
| **Linux** | auditd logs (raw/ausearch/aureport), journald JSON (`journalctl -o json`) |
| **Container/syscall** | Falco alert JSON, sysdig JSON |
| **Case management** | TheHive 5 case/alert/observable export |
| **Email** | .eml (full fidelity), .msg (Outlook OLE, best-effort) |
| **SO-CRATES** | SO-CRATES event exports (Suricata, YARA, Sigma overlays) |
| **Generic** | CSV (AI-assisted field detection), log files (AI-assisted triage), DFIR-IRIS import |
| **Custom** | Analyst-defined declarative importer specs (JSON) |

### Per-format import buttons

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

### Custom Declarative Importers

You can teach the Companion a new file format **without writing code** by dropping a JSON importer spec into the importers folder. The spec describes how to detect the file and how to map its columns to forensic events.

Manage custom importers in **Settings → Importers**. A built-in AI prompt (`GET /importers/prompt`) can write the spec for you — describe your file format and it generates the JSON.

---

## 8. AI Analysis

### Two-phase design

The AI pipeline has two distinct passes:

**Phase 1 — Extraction (per-batch):** A vision-capable model reads each batch of screenshots and structured files. It extracts raw **forensic events** — dated rows with a timestamp, description, severity, and optional structured fields (asset, process, hash, IOC references). This pass runs automatically after import and after enough new screenshots accumulate.

**Phase 2 — Synthesis (holistic):** One text-only call reads the entire forensic timeline. It produces:
- Named **findings** (conclusions)
- **MITRE ATT&CK** technique assignments
- **Attacker path** narrative
- **Kill chain** phase coverage
- **Key investigative questions**
- **Recommended next steps**

Synthesis is skipped automatically if nothing in the timeline changed since last time (skip-if-unchanged). Click **AI Re-synthesize** → **Force** to override.

### AI providers

DFIR Companion supports multiple AI backends:

| Provider | Setting |
|----------|---------|
| **OpenAI** | `DFIR_AI_PROVIDER=openai` |
| **Anthropic (Claude)** | `DFIR_AI_PROVIDER=openai` with `DFIR_AI_BASE_URL=https://api.anthropic.com/v1` |
| **OpenRouter** | `DFIR_AI_PROVIDER=openrouter` |
| **Google Gemini** | `DFIR_AI_PROVIDER=gemini` |
| **Ollama** (local) | `DFIR_AI_PROVIDER=ollama`, `DFIR_AI_BASE_URL=http://localhost:11434/v1` |
| **LiteLLM** (local proxy) | `DFIR_AI_PROVIDER=litellm` |

Configure via the Setup Wizard or in `.env`. All AI calls are made server-side — API keys never go to the browser.

> **Using a local model?** Screenshot extraction needs a **multimodal** (vision) model. Text-only models still work for CSV/log import, synthesis, and all other text-only AI features. Use the two-tier setup (`DFIR_AI_MODEL` for extraction, `DFIR_AI_SYNTH_MODEL` for synthesis) to pair a cheap vision model with a stronger reasoning model.

### What the AI sees (anonymization)

By default, the Companion **tokenizes identifying information** before sending anything to an external AI provider:
- IP addresses → `ANON_IP_1`, `ANON_IP_2`, …
- Hostnames → `ANON_HOST_1`, …
- Usernames → `ANON_USER_1`, …
- Domain names → `ANON_DOMAIN_1`, …
- File paths → `ANON_PATH_1`, …
- Hashes → `ANON_HASH_1`, …
- PowerShell encoded commands → decoded, then the decoded blob is anonymized
- Windows SIDs → tokenized (well-known SIDs like SYSTEM are preserved)

This anonymization is applied transparently. The timeline and findings shown to you use the real values (the mapping is maintained per-case).

Toggle anonymization in **Settings → AI → Anonymization** or in the per-case AI control panel.

### AI controls (per case)

The AI control panel lets you:
- Enable/disable AI analysis for this case
- Enable/disable synthesis
- Enable/disable enrichment
- Toggle the **🧠 Deep** checkbox — enables Chain-of-Thought (extended thinking) for synthesis, giving the model more reasoning budget for complex cases

### Second AI opinion

Click **2nd Opinion** in the toolbar (when `DFIR_AI_SECOND_OPINION_MODEL` is configured). A different model re-synthesizes the case independently. The dashboard shows where the two models disagree — added findings, removed findings, severity differences, MITRE differences. For each delta you can **Accept** (adopt the second model's view) or **Keep A** (keep the original). Accepted deltas survive future re-syntheses.

---

## 9. Dashboard Panels — Reference

All panels are visible by default. Some are collapsed until they have data. Use **Settings → Dashboard Views** to show/hide panels per role or phase.

### Summary bar

The top of the dashboard shows:
- Case name and investigator
- Screenshot count and last capture time
- Last synthesis time and what changed
- Last import time and how many new events/IOCs it added
- A severity summary badge (Critical / High / Medium counts)

### Findings

Your primary conclusions. Each finding has:
- **Title** — what happened
- **Severity** — Critical / High / Medium / Low / Info
- **MITRE techniques** — linked to attack.mitre.org
- **Supporting events** — click to jump to each event in the timeline
- **Supporting IOCs** — the indicators that back this finding
- **⚑ Mark legitimate** — exclude from analysis

The finding list is sorted worst-first. Click a finding to expand it.

### Attack Path

A narrative paragraph written by the AI describing the full attacker journey — from initial access through the kill chain to last known activity. Plain English.

### Kill Chain

Shows which **Cyber Kill Chain phases** are covered by the evidence: Reconnaissance, Weaponization, Delivery, Exploitation, Installation, Command & Control, Actions on Objectives.

Phases with evidence are highlighted. Gaps may indicate coverage blind spots.

### Forensic Timeline

The core of the investigation. A table of all forensic events, sorted by timestamp (or severity — click the column header to sort).

Each row shows:
- Timestamp
- Severity badge (color-coded)
- Description
- Source tool(s) — e.g. Chainsaw, Velociraptor, SIEM
- Asset (affected host)
- Evidence link (click to open the screenshot or imported file)
- `NEW` badge if added in the last import
- **💡 Explain** button — AI explains this event, gives ATT&CK context, and suggests pivot queries
- **[Decoded]** expander — for events with base64/PowerShell encoded payloads, shows the decoded content
- **⚑ Mark legitimate** — excludes this event from analysis

**Filters:**
- **Severity** — Critical / High / Medium / Low / Info
- **Source** — show/hide by tool (e.g. hide all Chainsaw, show only Velociraptor)
- **Date range** — filter by time window (or use the **Scope** bar to set the investigation scope)
- **🔍 Screenshot text** — full-text search across OCR'd screenshots
- **Pagination** — 100 / 250 / 500 / All rows per page

**Drag to scope:** drag a time range on the **Timeline Swimlane** (below) to instantly scope the timeline to that window.

### Attack Phases

Groups the forensic timeline into temporal **bursts** — clusters of activity separated by periods of silence. Each burst is labeled with the dominant MITRE tactic (Initial Access, Execution, Persistence, etc.).

This shows the *when* axis: not just what happened, but which phase of the attack was most active at what time.

No AI — derived deterministically from the timeline data.

### Timeline Swimlane

A visual chart with:
- **Y-axis:** compromised assets (hosts)
- **X-axis:** time
- **Color:** event severity

Useful for spotting lateral movement (events jumping between assets) and attack timing. Drag a time range to scope the timeline to that window. Exports as SVG.

### Timeline Anomalies

Detects assets whose event rate spikes above the per-bucket median. A sudden burst of activity from one asset stands out here.

Useful for spotting data exfiltration, log flooding, or initial-access beachheads. No AI — purely statistical.

Configure thresholds via `DFIR_ANOMALY_BUCKET_MINUTES`, `DFIR_ANOMALY_SPIKE_FACTOR`, `DFIR_ANOMALY_MIN_EVENTS`.

### Beacon Candidates

Outbound network connections that are *too regular to be human* — suggesting automated beaconing (C2 keepalives, malware checking in). Ranked by periodicity. A hunting lead, not a verdict.

### MITRE ATT\&CK

Shows all ATT&CK techniques identified across findings and events, grouped by tactic. Click a technique to jump to the events that evidence it.

### Compromised Assets & IoC Graph

A graph showing:
- **Known compromised assets** (hosts, accounts)
- **IoCs that touched each asset**

Assets are derived from events' `asset` field plus account mentions (DOMAIN\user, UPN). Click an asset to see all events and IOCs linked to it.

You can manually add assets or links using the **+** button.

### Evidence Chain

A causal graph showing:
- **Process trees** (parent → child process spawns)
- **File lineage** (file written then executed)
- **Lateral movement** (shared hashes or accounts across hosts)
- **Network flows** (host → IP connections)

This is the "how did we get here" graph — tracing the attack path through actual artifact relationships, not just the AI narrative. No AI — derived from structured event fields.

Filters: severity floor, SVG export.

### IOCs (Indicators of Compromise)

Every indicator extracted from all evidence:
- IP addresses
- Domains
- URLs
- File hashes (MD5, SHA-1, SHA-256)
- File paths
- Process names

**Filters:** by type (ip/domain/url/hash/file/process/other), by flagged-only, text search.

Each IOC shows:
- **Verdict badge** — reputation from enrichment providers (malicious / suspicious / clean / unknown)
- **Source badge** — how many tools corroborated this indicator (e.g. ⊕ 3 sources)
- **⚑ Mark legitimate** — known-good, excludes from analysis
- Click to run enrichment on demand

### Recommended Mitigations & Defensive Countermeasures

Two-part panel, fully AI-free and offline:

**ATT&CK Mitigations (M-codes):** Concrete MITRE-recommended mitigations for the case's techniques, ranked by how many techniques each mitigation addresses. Start with the highest-leverage mitigation.

**D3FEND Defensive Countermeasures:** MITRE D3FEND countermeasures grouped into two bands:
- *Harden now* — Prevent, Detect, Contain actions
- *This incident & context* — Evict, Restore, Model, Deceive actions

Each entry shows the D3FEND action (plain English label like "Prevent" instead of MITRE jargon), a definition on hover, and which of the case's techniques it addresses.

**✨ Generate remediation plan** button — one AI call produces an incident-specific, prioritized plan (Contain / Eradicate / Harden / Recover / Verify) grounded in the actual findings, ATT&CK mitigations, and D3FEND countermeasures. References real hosts, CVEs, and IOCs from your case.

### Adversary Hints

Compares the case's ATT&CK techniques against the MITRE ATT&CK Groups database to find groups with the highest technique overlap. Shows:
- Group name, aliases, and description
- How many techniques overlap (and which ones)
- **Likely next techniques** — techniques that matched groups use that haven't appeared in this case yet, ranked by how distinctive they are to those groups

**This is a hypothesis, not attribution.** Use it to guide hunting — if a matched group tends to pivot via RDP, that's worth looking for.

Offline, no AI, no network calls at runtime. Update the underlying data with `npm run data:update-attack`.

### Key Investigative Questions

Open questions the AI thinks you should be pursuing based on the current evidence — gaps, unknowns, and unexplained events.

### Recommended Next Steps

Prioritized list of concrete investigation actions: what files to check, what hunts to run, what questions to answer. Synthesis-generated.

### Ask the Case

A free-text question box. Type any question in natural language:
- "When did the attacker first access the domain controller?"
- "What credentials were likely stolen?"
- "List all C2 IP addresses and their first-seen times."

The AI answers using the full forensic timeline plus the **evidence-chain graph** — so it can trace multi-hop paths ("this process wrote a file which was executed by another process on a different host").

### Query Translator

Type a plain-English description of what you want to hunt for. Select the output query language:
- **VQL** (Velociraptor) — can be deployed as a fleet hunt in one click
- **KQL** (Kibana/Elastic)
- **ES|QL** (Elasticsearch)
- **SPL** (Splunk)
- **Sigma** (cross-SIEM)
- **YARA** (file/memory)
- **Suricata** (network IDS)

### Investigation Threads

Open and closed investigation threads — chains of related events grouped by the AI. Useful for multi-stage attack sequences.

### Hypotheses

Status-tracked investigation hypotheses. Can be:
- Auto-generated by AI from the evidence
- Manually added by the analyst
- Promoted from Analyst Notebook notes

Each hypothesis has a status: **Open / Supported / Refuted / Unknown**. Open hypotheses are fed into synthesis to steer the AI's analysis. Hypotheses with evidence links survive re-synthesis.

### Response Playbook

A trackable checklist of response tasks:
- Auto-generated from findings (Critical/High findings generate response steps)
- Analyst-added custom tasks

Each task has: status, assignee, due date, notes.

**IR Templates mode** (Settings → Velociraptor → IR Templates): expands each Critical/High finding into phase-based steps (Critical → Contain / Investigate / Eradicate / Recover; High → Investigate / Contain). The Investigate step is tailored to the finding's dominant ATT&CK tactic.

Push the playbook to **ClickUp** with one click (toolbar → Export → Push playbook to ClickUp).

### Hunting Profile

Shows what has been hunted in this case and whether each hunt found anything:
- Hunt title and VQL fingerprint
- Status (hit / miss / deployed / pending)
- Result row count and new events added to the case
- **Re-collect** button to pull fresh results
- **Expand** to view hunt rows inline

Used to track your hunting coverage and avoid running the same hunt twice.

### Analyst Notebook

Free-text notes. Supports Markdown. Notes are per-case and survive re-synthesis. Notes can be promoted to Hypotheses.

### Investigation Log

A durable log of every synthesis run — what the AI concluded each time and what changed. Useful for tracking how the investigation evolved.

### Customer Exposure

Check whether the victim organization's own domains and email addresses appear in breach databases.

Configure customer domains in this panel. Click **Run exposure check** to query your configured providers (LeakCheck, HIBP, DeHashed, Shodan for attack surface).

Raw passwords from breach results are **never stored** — only a `passwordPresent` flag.

### Case Details (for report)

Human-authored report metadata:
- Distribution / classification
- Business impact assessment
- Executive summary
- Recommendations section
- Glossary
- Custom report sections

These fields appear verbatim in the generated report.

### Geographic IP Map

Plots all IP IOCs on an interactive world map:
- Markers colored by severity
- Flow lines showing victim → attacker direction
- Country statistics panel
- Timeline sync (filter map by time range)
- CSV export

Requires GeoIP enrichment to be configured and enabled. No new network calls when you open the map — uses the enrichment data already fetched.

### Confirmed Legitimate (excluded from analysis)

Everything you have marked as a false positive or known-good. Shows findings, events, and IOCs with their exclusion reason. Click any item to reinstate it.

---

## 10. IOC Enrichment

### How it works

The IOC panel's enrichment system checks indicators against external and internal threat-intel services. **Nothing is sent externally until you opt in for the case** (Settings → Enrichment → enable sources for this case).

### Available enrichment providers

**External (opt-in per case):**
| Provider | What it checks | Key required |
|----------|----------------|--------------|
| VirusTotal | Hashes, IPs, domains, URLs | Yes |
| AbuseIPDB | IP addresses | Yes |
| Hunting.ch (abuse.ch) | MalwareBazaar + ThreatFox + URLhaus + YARAify | Yes (or legacy MB key) |
| CrowdStrike Falcon Intel | Hashes, IPs, domains, URLs via Indicators + MalQuery | Yes |
| Shodan | IP host lookup (open ports, services, CVEs) | Yes |
| CIRCL hashlookup | File hashes (NSRL-derived, free) | No |

**Local (no OPSEC concern by default):**
| Provider | What it checks | Setup |
|----------|----------------|-------|
| MISP | All IOC types | Self-hosted instance + key |
| YETI | All IOC types | Self-hosted instance + key |
| OpenCTI | All IOC types | Self-hosted instance + key |
| RockyRaccoon | Parent→child chain validation | Self-hosted |

**IP infrastructure (no reputation, no verdict — informational):**
| Provider | Information | Key required |
|----------|-------------|--------------|
| Reverse DNS | PTR hostnames for IPs | No |
| WHOIS/RDAP | Netblock, ASN, country, abuse contact | No |
| GeoIP | Country, city, ASN, org (ipinfo.io) | No |
| Shodan | Hosted domains, ports, CVEs | Yes (reuses Shodan key) |

### IOC Whitelist

Add known-good patterns in **Settings → IOC Whitelist**:
- **CIDR** — for internal IP ranges (e.g. `10.0.0.0/8`)
- **Exact** — specific hashes or values
- **Regex** — patterns (length-bounded to prevent ReDoS)

Any IOC matching a whitelist rule is **automatically marked legitimate on import** and excluded from enrichment.

### NSRL Known-Good Hashes

Upload or point to an NSRL (NIST National Software Reference Library) hash list in **Settings → NSRL**. File hashes in the NSRL are automatically marked as known-good software on import.

For large NSRL RDS databases (hundreds of millions of hashes), point to the SQLite `.db` file instead of importing — it queries on demand without loading into memory. Requires Node 22.5+.

---

## 11. Threat Hunting

### AI-generated hunt suggestions

After synthesis, the dashboard surfaces:

- **Fleet hunt suggestions** — AI-generated VQL queries to hunt fleet-wide for the threats seen in this case, grounded in the causal evidence graph
- **Playbook hunt suggestions** — VQL queries tied to specific response playbook tasks
- **Technique-based hunt suggestions** — hunts for ATT&CK techniques not yet evidenced in the case (from Adversary Hints)
- **Shadow artifact suggestions** — when the timeline has suspicious gaps, suggests KAPE/Velociraptor artifacts (Prefetch, SRUM, USN Journal, etc.) that might fill them

Each suggestion card shows the VQL query with a **Deploy hunt** button (requires Velociraptor connection). A **↻ Regenerate** button refreshes the VQL if it won't compile.

### Manual VQL hunts

**Run hunt (all clients):** Enter a VQL query directly. The dashboard launches a fleet hunt via Velociraptor and waits for results. Results auto-import into the case.

### Hunting feedback loop

The **Hunting Profile** panel tracks every hunt's outcome:
- Was the VQL deployed?
- Did it find anything (rows returned vs. new events added)?
- Has it been re-collected?

This prevents running the same hunt twice and helps you see what's been covered.

### Query Translator

Write in plain English. Get VQL, KQL, SPL, ES|QL, Sigma, YARA, or Suricata. One-click deploy for VQL. (See Section 9.)

### Timeline-gap hypotheses

When the AI detects suspicious silences (log gaps that don't match expected coverage), it hypothesizes what might have happened and suggests shadow artifacts to collect. Each suggestion is deployable as a Velociraptor collection.

---

## 12. Reports & Exports

### Report formats

Click **Export** in the toolbar to see all options:

| Format | Description |
|--------|-------------|
| **Word (.docx)** | Full formatted report with cover page, table of contents, findings, timeline, IOCs, MITRE matrix, attacker path, countermeasures |
| **HTML** | Same content as Word, rendered in the browser — printable |
| **Markdown** | Plain text report |
| **CSV** | IOC export (all indicators with enrichment verdicts and sources) |
| **IOC block-list** | Plain TXT, CSV, or STIX indicators — ready to load into a firewall or SIEM |
| **Presentation deck** | Slide-by-slide offline HTML file (see Section 13) |
| **Investigation snapshot** | Portable JSON of the entire investigation state |
| **Redacted case package** | The full case with anonymized AI input — shareable for model debugging without exposing evidence |

### Report customization

**Settings → Report Templates** lets you:
- Change the cover title, subtitle, running header/footer
- Set an accent color
- Show/hide the company logo and name
- Reorder or disable report sections

Multiple templates can be saved (e.g. "Executive" with fewer sections vs. "Technical" with full detail). Assign a template per case.

### What's in the report

1. Cover page (title, date, classification, investigator)
2. Executive summary (AI-generated or analyst-written)
3. Investigation narrative (attacker path, written prose)
4. Forensic timeline (with severity color coding)
5. Findings (each with evidence and MITRE techniques)
6. MITRE ATT&CK coverage matrix
7. IOCs (all indicators, with enrichment verdicts)
8. Compromised assets
9. Attack phases
10. Adversary hints
11. Recommended mitigations (ATT&CK M-codes)
12. D3FEND countermeasures
13. Customer exposure results
14. Geographic IP data
15. Key investigative questions
16. Response playbook
17. Case details (analyst-authored sections: BIA, recommendations, glossary)

### AI-generated executive summary

Click **✨ Generate executive summary** (in Case Details → Executive Summary field). One AI call produces a non-technical summary suitable for management.

### AI-generated narrative

Click **✨ Generate narrative**. Produces a flowing prose description of the incident suitable for the "Investigation Narrative" report section.

---

## 13. Presentation Mode

A read-only, step-through slide deck for handoff briefings and executive walkthroughs.

**Open:** toolbar → **▶ Present** (opens in a new tab).

**Export offline:** Export → Presentation deck. Produces a self-contained HTML file that works with no server.

### What's in the deck

1. **Cover slide** — case title, date, classification
2. **Summary slide** — narrative and attack path
3. **Finding slides** — one per finding, worst first (severity, description, asset, ATT&CK, supporting IOCs)
4. **Timeline event slides** — one per event, chronological (timestamp, source, description, supporting IOCs, screenshot thumbnail)

### Navigation

| Action | Key |
|--------|-----|
| Next slide | → or Space |
| Previous slide | ← |
| First slide | Home |
| Last slide | End |
| Fullscreen | F (or browser fullscreen button) |
| Auto-advance | Toggle button in controls |

### Filters

Set a **minimum severity** filter before opening — only findings/events at or above that level are included. Useful for an executive deck (Critical/High only) vs. a technical deck (everything).

The deck inherits the **report template** branding (accent color, cover title, company name) of the current case.

---

## 14. Integrations

All integrations are configured in **Settings → Integrations** (or via the Setup Wizard). Each is optional — removing credentials from `.env` disables the integration.

### Velociraptor

Run fleet hunts, collect artifacts, and stream live monitoring events into cases.

**Configure:** Settings → Velociraptor → set the API config file path. Click **Reconnect** to apply without restarting.

**Capabilities:**
- Browse available server artifacts
- Run hunt bundles (preset collections of artifacts)
- Custom VQL hunts from the dashboard
- Per-hunt auto-collect (results import automatically after `DFIR_VELO_HUNT_WAIT_MIN`)
- Live CLIENT_EVENT monitoring (see Section 15)
- Triage bundles (Fast Triage / Full Triage / custom)

**Triage bundles:** Settings → Velociraptor → Bundles. Built-in bundles include Fast Triage (quick artifact set) and Full Triage (comprehensive). You can create and save custom bundles. Run a bundle from the Settings tab — it launches a fleet hunt and auto-imports results.

### DFIR-IRIS

**Push:** Export findings, timeline, and IOCs from a Companion case into an IRIS case.

**Pull/Import:** Import an existing IRIS case (assets, IOCs, timeline) into a Companion case. Toolbar → Import case → From DFIR-IRIS.

**Configure:** Settings → Integrations → DFIR-IRIS (URL + API key). Reconnect button applies without restart.

### Timesketch

Push the forensic timeline to a Timesketch instance for collaborative timeline analysis.

**Configure:** Settings → Integrations → Timesketch. Reconnect without restart after saving credentials.

Command-line: `npm run timesketch:push -- <caseId>`

### Notion

Export a case to a Notion page.

- **New page:** created in your Notion database or as a child of a parent page
- **Re-export:** updates the managed content block on the same page without touching anything you wrote outside it

Toolbar → Export → Export to Notion.

### ClickUp

Push the Response Playbook as tasks to a ClickUp list.

- Task status maps to the list's real custom statuses
- Priority maps to ClickUp priority levels
- **Re-push:** updates existing tasks (by saved task ID) instead of duplicating

Toolbar → Export → Push playbook to ClickUp.

---

## 15. Live Monitoring & Push Ingest

These features bring evidence into a case in real time, as events happen.

### Velociraptor live monitoring

Stream CLIENT_EVENT artifacts (like Windows Event Log real-time forwarding or EDR telemetry) into a case automatically.

**Set up:** Settings → Velociraptor → Live Monitoring.

- Add a monitor for a specific client+artifact, or use **⚡ Auto-monitor configured events** to pick up every artifact already enabled in Velociraptor's Client Monitoring table.
- The server polls for new rows every 30 seconds (configurable via `DFIR_VELO_MONITOR_POLL_S`).
- New rows are ingested automatically → same import pipeline → re-synthesis in background.
- A **🔴 LIVE** badge appears in the toolbar when at least one monitor is active.
- The poll cursor is persisted — a restart resumes without re-ingesting old data.

### Push ingest (webhook)

Any external tool can POST evidence to a case via a webhook:

```
POST /cases/<caseId>/push
X-DFIR-Key: <your token>
Content-Type: application/json

{ "source": "MyTool", "events": [...] }
```

Or POST any file the Import button would accept.

**Configure:** Settings → General → Push ingest token (or `DFIR_PUSH_TOKEN` in `.env`). The endpoint is disabled until a token is set (returns 403). Per-case tokens are also supported.

---

## 16. Settings Reference

Open Settings with the **⚙ Settings** button in the toolbar.

### General

- Case root location
- Server port
- Log level (debug / info / warn / error) — live toggle, no restart
- **Open setup wizard** link
- Push ingest token management
- Update check (opt-in dashboard banner for new GitHub releases)
- Theme (dark / light)

### AI

- Provider, model, API key, base URL (extraction)
- Synthesis model (optional separate model for findings/attacker path)
- VQL-generation model (optional dedicated model — many general models struggle with VQL syntax)
- Timeout, max tokens, context window size
- Chain-of-Thought (synthesis thinking tokens)
- Anonymization on/off and category settings
- Preflight diagnostics disable
- **Re-run the setup wizard**
- **Live AI test** — confirms the current key works right now

### Enrichment

Lists all 13 enrichment providers. Each shows:
- Current status (configured / key missing)
- Which environment variable to set
- Enable/disable for this case

Nothing is sent externally until you enable a provider for the specific case you're working on.

### Exposure

Customer exposure check configuration:
- Add customer domains and email addresses
- Select which providers to use (LeakCheck, HIBP, DeHashed, Shodan)
- Run the exposure check and view results

### Integrations

- DFIR-IRIS (URL, key, reconnect)
- Timesketch (URL, credentials, reconnect)
- Notion (API token)
- ClickUp (API token)

### Velociraptor

- API config file path
- Reconnect button
- Browse server artifacts
- Triage bundle management (Fast/Full/custom)
- Hunt parameters (timeout, filters)
- **IR Templates** toggle for the Response Playbook
- Live Monitoring tab (add/stop/start monitors)

### IOC Whitelist

Global known-good pattern list:
- Add CIDR, exact, or regex rules
- Optional type scoping (e.g. "only match IPs")
- Import/export as CSV or JSON
- **Apply to current case** — retroactively marks matching IOCs legitimate

### NSRL

Known-good file hash database:
- Paste hashes, import a flat hash file, or load an NSRL RDS hash list by file path
- Connect to a large NSRL RDS SQLite database (Node 22.5+)
- Apply to current case

### Importers

Custom declarative importers:
- List all custom importers (filename, format, match criteria)
- Add a new importer (paste JSON spec)
- Reload importers from disk
- **Get AI prompt** — copy the prompt to use with your AI assistant to generate a spec for a new file format
- Precedence setting: built-in-first (default) or external-first

### KEV

CISA Known Exploited Vulnerabilities integration:
- Enable/disable KEV cross-reference
- CVEs in findings/events are checked against CISA KEV
- KEV-listed CVEs are highlighted and mentioned in synthesis context and report

### Report Templates

Manage report templates:
- Edit the default template or create new ones
- Set: cover title, subtitle, accent color, running header/footer, logo visibility
- Enable/disable and reorder report sections
- Assign a template per case

Built-in templates: Standard (full technical report), Executive (condensed), and any you create.

### Dashboard Views

Preset panel layouts:
- **Analyst** — all technical panels
- **Lead** — findings, timeline, playbook, hunting
- **Executive** — findings, attack path, countermeasures, exposure
- **Triage** — timeline, IOCs, MITRE, assets
- **Report** — report-oriented panel order
- **Deep-Dive** — evidence chain, hypotheses, threads, notebook
- **Hunt-Prep** — hunting profile, adversary hints, next techniques, query translator

Each preset is fully customizable — reorder panels, set a severity floor, cap the timeline row count, link a report template. Saved per case.

### Notifications

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

Notification configs are stored in a global config file (not `.env`) and webhook URLs are redacted in all API responses.

### Updates

Opt-in GitHub release check. Shows a dashboard banner when a newer version is available. Never auto-installs.

### Diagnostics

Operator health view:
- Disk usage and warning level on the cases folder
- Case count (open / closed)
- Processing queue (screenshots pending analysis, synthesis in flight)
- Redacted AI config (provider, model, timeout — **never the API key**)
- Recent AI error counts by type
- Importer health (attempt counts over 24h/7d)
- **Compute case sizes** button (separately triggered — walks the full cases directory, shows per-case sizes and top-N largest evidence files)
- **Live AI test** — connectivity test with latency
- **Pre-flight check** — re-run startup diagnostics on demand
- **Per-case backup list** — state backups with one-click restore (automatic backups taken before each synthesis and on a 1-hour timer)
- **State backup configuration** (retention counts, interval)

---

## 17. Mobile Companion

A read-only installable PWA (Progressive Web App) at **http://127.0.0.1:4773/mobile**.

Add it to your phone's home screen for a quick-glance view of the active investigation:
- Findings (worst first)
- Recent forensic events (most severe / most recent)
- IOCs (flagged first, with worst threat-intel verdict)
- Severity and entity counts

Lists are capped for mobile performance but the totals are shown. No editing, no AI calls — read only.

---

## 18. Advanced Features

### Anonymization

Enabled by default for external AI providers. Tokenizes PII and IOC values before sending to the model. The mapping is maintained per-case, so your timeline and findings always show real values.

Categories tokenized: IPs, hostnames, usernames, domains, file paths, hashes, PowerShell encoded blobs, Windows SIDs (well-known ones like SYSTEM are preserved).

Toggle: Settings → AI → Anonymization, or the per-case AI control panel.

### Investigation Scope

Set a time window for the investigation. Only events within the scope window are fed into synthesis. Events outside scope are preserved in the timeline but grayed out and excluded from findings/attacker path.

**Set scope:** the scope bar at the top of the forensic timeline (date pickers), or drag on the swimlane, or `POST /cases/:id/scope`.

Useful when: a case has pre-incident background noise, or you're narrowing focus to a specific attack window.

### Correlation Profile

Controls how aggressively the system deduplicates events from multiple tools.

Settings → Per-case → Correlation Profile:
- **Strict** — only exact duplicates are merged (same timestamp + description)
- **Moderate** (default) — also merges events with the same hash or path within a short time window
- **Aggressive** — wider time windows for path/hash matches

Use Aggressive when you have many tools all logging the same events differently. Use Strict when tools legitimately report the same artifact at different times for different reasons.

### State Backups & Restore

The server automatically backs up all per-case state (findings, timeline, IOCs, playbook, etc.) before each synthesis run and every hour.

View and restore backups in **Settings → Diagnostics → Per-case backup list**. One click restores to any saved state.

Configure: `DFIR_STATE_BACKUP_RETAIN` (how many per-synthesis backups to keep), `DFIR_STATE_BACKUP_INTERVAL_MS` (timer interval).

### Preflight Diagnostics

On startup, the server runs a self-test and logs OK/WARN/CRITICAL for:
- AI provider (live probe)
- Velociraptor (live probe)
- Local enrichment instances — MISP, YETI, OpenCTI (live probe)
- Other configured providers (reported as "configured" but not probed — OPSEC: no automatic third-party calls)

A red banner appears in the dashboard if a critical check fails (typically: AI not configured or key invalid).

Re-run on demand: Settings → Diagnostics → Pre-flight check.

Disable permanently: Settings → Diagnostics → disable pre-flight (for setups without AI).

### Custom AI Prompts

All AI prompts can be overridden without code changes:

1. Run `npm run prompts:eject -- ./prompts` to dump the built-in prompts to files.
2. Edit the files.
3. Set `DFIR_AI_SYSTEM_PROMPT_FILE=./prompts/system.txt` (etc.) in `.env`.
4. Changes are picked up on the next AI call — no restart needed.

Available prompts: `SYSTEM` (extraction), `CSV`, `LOG`, `SYNTH` (synthesis), `ASK`, `EXEC` (executive summary), `NARRATIVE`, `HUNTS`, `PBHUNTS`, `GAPHYP` (gap hypotheses), `MEMNEXT` (memory next steps), `QUERYXLATE` (query translator), `RECONCILE` (second opinion), `REMEDIATION`.

### Hypothesis-Driven Mode

The **Hypotheses** panel lets you track explicit investigation hypotheses. Open hypotheses are fed into synthesis as context, steering the AI to look for supporting or refuting evidence.

Auto-generated hypotheses come from: synthesis conclusions, timeline-gap analysis, and adversary-hints next-technique suggestions.

Analyst-added hypotheses: click **+ Add hypothesis** in the panel.

Hypotheses survive synthesis (unlike findings, which are replaced each time) and are included in investigation snapshots.

### CISA KEV Cross-Reference

Enable in **Settings → KEV**. CVEs mentioned in findings and events are cross-referenced against the CISA Known Exploited Vulnerabilities catalog. KEV-listed vulnerabilities are highlighted and mentioned in synthesis context, nudging the AI to treat them with appropriate urgency.

### Demo Mode

Set `DFIR_DEMO_MODE=true` in `.env`. All mutating routes are blocked. A demo case is pre-seeded. The demo case auto-resets hourly (`DFIR_DEMO_RESET_HOURS`). Useful for training or public demonstrations.

---

## 19. Tips for Analysts

**Start with structured imports, not just screenshots.** Screenshots are useful for context and for tools that don't export raw data. But a Chainsaw JSON export or Hayabusa CSV gives the AI much more structured data to work with and produces better findings.

**Use the severity floor on noisy imports.** When importing a large Velociraptor collection or Plaso super-timeline, set the minimum severity to `medium` or `high`. You can always lower it and re-import if you miss something.

**Mark false positives immediately.** Every time you see an event or finding that's clearly benign, mark it legitimate. It improves synthesis quality and keeps the timeline clean.

**Set the scope.** If your case has background noise from before the attack window, set the investigation scope to the incident timeframe. Synthesis will focus on that window.

**Run enrichment before generating the report.** Enrichment verdicts appear in the report's IOC table. Flagged IOCs also influence finding severity. Enable the enrichment sources you trust and run them before the final synthesis.

**Use the Hunting Profile to avoid duplication.** Before deploying a hunt, check the Hunting Profile panel to see if a similar VQL has already been run (and whether it found anything).

**The second opinion is most useful for high-stakes cases.** If `DFIR_AI_SECOND_OPINION_MODEL` is set to a model from a different provider, the second opinion catches blind spots the primary model misses. Accept individual deltas selectively — don't bulk-accept everything.

**Export the investigation snapshot before closing.** The snapshot is a portable record of all your investigative work — findings, timeline, IOCs, playbook, notes, hypotheses. Store it with your case documentation.

**Use the Query Translator early.** When you're not sure what VQL to write for a hunt, describe what you're looking for in plain English. It's faster than looking up VQL syntax.

**For presentations, filter by severity first.** Set the severity filter to `high+` before opening Presentation mode. You get a clean executive deck that covers the most important findings and events without the noise of Info/Low items.

**The Diagnostic page is your first stop when something breaks.** Settings → Diagnostics shows the AI error count by type (auth errors = wrong key, billing errors = quota exceeded, rate limit = slow down), the processing queue state, and integration health — without ever showing your API key.

---

*For technical details, see the `companion/README.md` and `CLAUDE.md` files in the repository.*
