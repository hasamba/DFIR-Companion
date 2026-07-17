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

Every finding, IOC, and forensic event has a **🚫 Mark False Positive** button. Click it, pick a reason (known-good tool, authorized test, detection misfire, duplicate, or other), and confirm to exclude the item from analysis. It moves to the **False Positives** panel. You can reverse the decision any time. Marking a finding/event also suggests similar items in the case to mark in the same action; marking a single IOC can also promote it to the global IOC whitelist.

For bulk exclusions (e.g. an entire internal IP range), use **Settings → IOC Whitelist** to add a CIDR rule. Any IOC matching the rule is automatically marked false-positive on import.

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
- **Export encrypted case archive** — a password-protected .dfircase file containing the ENTIRE case (evidence and screenshots included) you can share with another analyst.
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

### Encrypted Case Archive (export/import)

**Export archive:** toolbar → **Export → Export encrypted case archive (.dfircase)**. Enter a password (min 8 characters, confirmed twice). Produces a single `.dfircase` file containing the ENTIRE case — screenshots, raw evidence, timeline, findings, IOCs, MITRE, playbook, analyst notes, tags, everything — encrypted with AES-256-GCM under that password. Only openable via another DFIR Companion's Import (not a generic zip tool). Share the password out of band from the file itself.

**Import archive:** toolbar → **Import case → Encrypted case archive (.dfircase)**. Pick the file, enter the password, restores as a new case. If the Case ID already exists you get a conflict warning and can pick a new id.

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
| **OpenAI** | `DFIR_VISION_PROVIDER=openai` |
| **Anthropic (Claude)** | `DFIR_VISION_PROVIDER=openai` with `DFIR_VISION_BASE_URL=https://api.anthropic.com/v1` |
| **OpenRouter** | `DFIR_VISION_PROVIDER=openrouter` |
| **Google Gemini** | `DFIR_VISION_PROVIDER=gemini` |
| **Ollama** (local) | `DFIR_VISION_PROVIDER=ollama`, `DFIR_VISION_BASE_URL=http://localhost:11434/v1` |
| **LiteLLM** (local proxy) | `DFIR_VISION_PROVIDER=litellm` |

Configure via the Setup Wizard or in `.env`. All AI calls are made server-side — API keys never go to the browser. (The screenshot/vision vars were renamed from `DFIR_AI_*` to `DFIR_VISION_*`; the legacy `DFIR_AI_*` names still work as a deprecated fallback.)

> **Using a local model?** Only screenshot reading needs a **multimodal** (vision) model — that's `DFIR_VISION_MODEL`. Everything else (CSV/log import, synthesis, and all other text-only AI features) runs on `DFIR_AI_SYNTH_MODEL`, so a text-only model is fine there. Use the two-tier setup (`DFIR_VISION_MODEL` = cheap vision for screenshots, `DFIR_AI_SYNTH_MODEL` = strong reasoning for everything else) — a weak text model fails log triage silently, returning no events at all rather than wrong ones.

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

This section is a complete, panel-by-panel tour of the dashboard. For each panel you get a plain-English "what it does / what it's good for," followed by the **smart controls** in that panel — the buttons that run AI, call an external service, or apply real rule-based logic. Trivial controls (full-screen, download PNG/SVG/CSV, copy, collapse, pagination, plain sort/filter) are intentionally not listed.

**How to read the "behind the button" tags:**

- 🤖 **AI** — makes a call to your configured AI model.
- ⚙ **Logic** — deterministic rules/statistics computed on your machine. No AI, no network.
- 🌐 **Network** — calls an external service (threat-intel, Velociraptor, breach databases). Only runs when you opt in.

> **Panels come and go with the data.** All panels are available, but many stay hidden until they have something to show. Use **Settings → Dashboard Views** to show/hide panels per role or investigation phase (Analyst, Lead, Executive, Triage, Report, Deep-Dive, Hunt-Prep).

### Summary bar

The strip at the very top of the dashboard. It shows the case name and investigator, the screenshot count and last capture time, the last synthesis time and what changed, the last import (how many new events/IOCs it added), and a severity summary badge (Critical / High / Medium counts). Read-only.

---

*The panels below are grouped the way an investigation flows: **conclusions & narrative**, then **the timeline**, then **graphs**, then **intel & hunting**, then **notes & case record**.*

---

### Ask the LLM

Free-text Q&A over the whole synthesized case. Type an investigative question in plain English ("Was data exfiltrated? Was a USB connected? When did the attacker first touch the domain controller?") and the tool answers from the case's timeline, findings, attack path, and evidence-chain graph — citing the specific events it relied on. Answers are ephemeral until you choose to keep one.

- 🤖 **Ask** — one AI call grounded in the case's synthesized state. Returns a status (answered / partial / unknown), a prose answer, a "where to look" pointer, and cited event IDs. Requires a configured synthesis provider.
- ⚙ **Add to open questions** (on each answer) — files the Q&A into **Key Investigative Questions** so future synthesis runs keep trying to answer it as evidence accumulates. A persistent state change, not just display.

### Query Translator

Turns a plain-English description of what you want to hunt for into runnable queries across many platforms at once. Good for when you know *what* you're looking for but not the syntax.

- 🤖 **Translate** — one AI call that emits a schema-grounded query per selected platform (Velociraptor VQL, Defender/Sentinel KQL, Elastic ES|QL, Splunk SPL, Sigma, YARA, Suricata), each with an interpretation line and per-query caveats. Requires a synthesis provider.
- ⚙ **Platform checkboxes** — the picker only lists platforms your server's allowlist (`DFIR_HUNT_PLATFORMS`) has enabled; only checked ones are sent to the AI.
- 🌐 **Deploy hunt (all clients)** (Velociraptor VQL card only) — launches the generated VQL as a real fleet hunt. Enabled only when Velociraptor is configured.

### Executive Summary

Shows the case's auto-derived summary and, on demand, generates a polished, management-facing version you can review and save into the report.

- 🤖 **✨ Generate** — one AI call producing management-facing prose over the synthesized case. Guarded two ways: skipped if the panel is hidden (to save tokens), and refused server-side if the report's Executive Summary section is disabled in the template. Requires a synthesis provider.
- ⚙ **Save to report's Executive Summary** (after generating) — copies the generated text into the report metadata so it overrides the auto-generated summary in the exported report.

### Playbook

An actionable remediation/investigation checklist auto-derived from the case's recommended next steps and Critical/High findings. The derivation is deterministic and idempotent: it re-syncs on every synthesis while always preserving your per-task status, assignee, due date, notes, ordering, and any custom tasks.

- ⚙ **↻ Sync from analysis** — re-derives tasks from the latest next-steps and high-severity findings, refreshing auto-task text but preserving your edits. No AI.
- 🤖 **✨ Suggest Velociraptor hunts** — one AI call that proposes a VQL hunt for each endpoint-related task (a fleet hunt, or a single-host collection when the task is tied to one endpoint), each with a rationale to review before deploying. Needs a synthesis provider (not the Velociraptor API, just to view/copy the VQL).
- ⚙ **IR templates** (checkbox) — deterministic expansion: turns each Critical/High finding into Contain → Investigate → Eradicate → Recover tasks (High → Investigate + Contain only), tailored to the finding's dominant ATT&CK tactic.

### Attack Path

A read-only, kill-chain-ordered narrative of how the adversary progressed (initial access → execution → persistence → … → impact), citing finding IDs and times. Produced as part of the main synthesis, not by a button here.

*No smart buttons (view-only).*

### Narrative Timeline

Takes the Attack Path and, on demand, rewrites it into client-readable prose for stakeholders, then lets you polish the wording before it goes into a report.

- 🤖 **✨ Generate** — one AI call that writes a prose incident narrative and saves it to case state. Guarded like Executive Summary (skipped if hidden; refused if the report's Timeline section is disabled). Requires a synthesis provider.
- ⚙ **✏ Edit / Save** — hand-edit the narrative; Save persists the edited text (no AI). Survives until the next synthesis.

### Findings

The core analyst worklist: the synthesized, deduplicated conclusions (severity, confidence, ATT&CK techniques, supporting events and IOCs), sorted worst-first. This is where you triage, pin a shortlist, filter, and reconcile a second-opinion cross-check. The findings themselves come from synthesis; the controls here are triage actions.

- ⚙ **Corroboration lens (⊕ 2+ / 3+ src)** — a view filter that shows only findings whose supporting events span at least N distinct tools/sources. Non-destructive.
- ⚙ **🚫 Mark False Positive** (single or bulk) — excludes the finding(s) from analysis and cascades a re-synthesis that neutralizes any next-steps/answers those findings backed (they get a "stale — re-synthesis queued" badge). Marking also offers to mark similar items in the same action.
- 🤖 **Second-opinion diff (Apply / Apply all)** — after the toolbar's **2nd Opinion** runs a *different* model as an independent cross-check, this shows where it disagrees with the primary synthesis (findings added/dropped, severity, technique) and lets you accept or reject each delta. Non-destructive until you accept.

### Recommended Next Steps

A prioritized list of the most valuable next investigative actions, each with a rationale and a "where to look" pointer. It's a field of the main synthesis (hidden by default — the Playbook supersedes it for tracking, but it still feeds the Playbook, report, and exports).

- 🌐 **⬇ Collect on \<host\>** (per step, when the step carries a collection directive) — launches that collection on the named endpoint via Velociraptor. Rule-gated: the button only appears when Velociraptor is configured **and** the host matches a real case asset, so a hallucinated hostname never gets a deploy button (it degrades to a copyable manual-collection line).

---

### Forensic Timeline

The case's main event feed and primary triage surface: every analyzed/promoted event with severity, source, host, MITRE mapping, and IOCs. You filter it, star/tag/comment rows, mark false positives, and drill into individual events. Rendering and most controls are driven by imported data plus the deterministic content tagger; only the per-row Explain button uses AI.

- 🤖 **💡 Explain** (per row) — one AI call per click. Returns a plain-English "what happened," why it matters, normal-vs-suspicious context, an ATT&CK mapping, evidence for/against maliciousness, and suggested pivot/hunt queries. Changes no case state.
- ⚙ **[Decoded] expander** — shows content decoded at import time by a local decoder that detects and unpacks common obfuscation (PowerShell `-enc`/`-EncodedCommand` UTF-16LE base64, `[Convert]::FromBase64String(...)`, generic base64 near an execution marker) and extracts IOCs from it. No AI, no network.
- ⚙ **🚫 Mark False Positive** (per row / bulk) — flags the event as analyst-confirmed benign and excludes it from analysis (kept, not deleted). The exclusion propagates so every derived panel recomputes over the filtered set.
- ⚙ **Scope bar** (1h / 24h / 7d / 30d presets, from/to, Apply, Clear) — restricts the case to a UTC time window; **Apply** re-runs synthesis using only in-window events, **Clear** restores all.
- ⚙ **Corroboration lens (⊕ any / 2+ / 3+ src)** — shows only events seen by ≥N distinct tools. A view lens.
- ⚙ **🔍 Screenshot text search** — plain text match against the locally-built OCR index of every ingested screenshot (built with Tesseract, on your machine). Returns one hit per matching screenshot, each linking back to the source. No AI.

### Kill Chain

Groups the (scoped, false-positive-filtered) timeline into ATT&CK tactic buckets — Initial Access, Execution, Persistence, and so on — via each event's technique. A quick "where in the attack lifecycle is my evidence concentrated" view; clicking a tactic card expands its events. Entirely deterministic (a hard-coded technique→tactic table). The panel itself notes this is a categorization, not a confirmed stage.

*No smart buttons (view-only; tactic cards just expand).*

### Attack Phases

Segments the timeline into temporal **bursts** of activity — events grouped by the silent gaps between them, each phase labelled by its dominant tactic and time span. Good for seeing the attack as distinct waves rather than a flat list. Fully derived, no AI.

*No smart buttons (view-only).*

### Host & Account Ranking

Ranks the hosts and accounts that carry the attack by a **signal score** rather than by event volume — so a quiet-but-central host outranks a noisy benign one. The score deterministically weights severity-graded events (Critical/High/Medium), the number of distinct techniques on the entity, and "connective" IOCs that tie it to others. Expanding a row shows the contributing events and IOCs. No AI.

- ⚙ **⌖ Apply scope window** — when signal is concentrated on a few hosts, the panel computes a suggested time window around that activity and sets the investigation scope to it. Deterministic.

### Timeline Gaps

Detects suspicious silent periods in the timeline — windows where events go quiet. A complete gap, where *every* source goes dark at once, is flagged as the classic log-tampering signature. Detection is deterministic; the panel labels it a lead, not proof.

- 🤖 **✨ Hypothesize gaps** — one AI call over the already-detected gaps. For each silent window it hypothesizes what the attacker likely did (from the surrounding events) and pairs it with shadow-artifact collections that could reconstruct the missing window.
- 🌐 **▶ Deploy collection** (per hypothesized artifact) — launches the suggested shadow-artifact VQL collection to recover the missing evidence. Enabled only when Velociraptor is configured.

### Evidence Gaps

Answers "what is this case still missing?" It surfaces uncovered kill-chain phases (each with where/what to collect), silent windows, blind spots (sources collected but empty, or telemetry with no corroborating detector), and likely-next attacker techniques modeled from lookalike actors. Deterministic (`knownUnknowns`), surfaced once the case has a Critical/High finding. A lead, not proof.

- 🌐 **⬇ Collect on \<host\>** (per uncovered phase) — shown only for a host actually seen in this case and only when Velociraptor is configured; launches the recommended collection on that host. Otherwise degrades to a manual-collection hint.

### Timeline Swimlane

A visual chart of the timeline: Y-axis is your chosen grouping (asset, severity, or tactic), X-axis is time, dot color is severity. Good for spotting bursts, lateral spread across hosts, and clusters at a glance. Purely a visualization of the timeline (no AI). Clicking a dot flashes the matching timeline row; dragging the time axis filters the Forensic Timeline.

- ⚙ **🚫 Mark False Positive** (on box/shift-selected dots) — same exclusion action as the timeline: marks selected events benign and drops them across the derived panels.
- ⚙ **⌖ Scope to view** — sets the investigation scope to the time range currently visible in the chart.

### Super-Timeline

The complete superset of **every** event ever imported from any source, *before* scope and legitimacy filtering — nothing is removed. You filter by time/origin/host/tag, triage rows (star/comment/tag), then promote the events that matter up into the analyzed Forensic Timeline where the AI synthesizes them. Filtering and the content tagger are deterministic; the panel has two AI review buttons and one AI rule-drafting helper.

- ⚙ **⬆ Promote selected → forensic timeline** — copies the selected events up into the analyzed timeline so they enter synthesis. A copy operation, not an AI judgment.
- 🤖 **✨ Starred report** — one AI call producing a report over only the starred events (the Timesketch starred-events review workflow). Needs a synthesis provider.
- 🤖 **✨ Summarize view** — one AI call summarizing whatever the current filters show. Ephemeral. Needs a synthesis provider.
- ⚙ **Content tagger → Run tagger** — applies content-based YAML rules (any/all/none conditions over fields like description, message, asset, path, processName, sha256, port, severity) to tag matching events; rules can also re-grade severity/view. This is the deterministic tagger that runs after import — **it is why events can carry a severity even with AI turned off.**
- 🤖 **Content tagger → ✨ Suggest rule** — describe a rule in plain English and the AI drafts the tagger YAML for review; **Check matches** then counts how many events it would hit (deterministic, no changes) before you **Add rule**. The AI writes the rule; matching/applying is deterministic.

---

### Compromised Assets & IoC Graph

A network graph of the case's assets (hosts and accounts) and the IOCs that touched each one, with edges showing which indicator was seen in an event on which asset. Assets/IOCs are derived automatically from findings and the timeline; you can also add nodes and links by hand. Good for seeing at a glance which machines/accounts are involved and which indicators connect them. The graph derivation is fully deterministic (the findings/IOCs it draws may have been produced by AI earlier).

- ⚙ **+ Add asset** (name + type) — creates an analyst-authored node not auto-derived from the timeline. A persisted per-case overlay.
- ⚙ **Link / Unlink asset↔IoC** — add or suppress an edge by hand, to correct or augment the auto-derived edges. (Under the hood, auto-edges are computed by matching each IOC value against event fields with digit/dot-boundary regex so `1.1.1.1` doesn't falsely match inside `11.1.1.10`.)

### Login Graph

A Timesketch-style directed graph of "who logged on where" — accounts point to the hosts they authenticated to, built from Windows logon events (4624 success / 4625 failure) in the super-timeline. Good for tracing lateral movement and spotting risky logons, because plain low-severity 4624 events never reach the forensic timeline but are exactly what lateral-movement analysis needs. Edges are aggregated per (account, host, logon type, outcome) with a count, first/last-seen, and a risk flag; clicking an edge fetches the underlying events. Fully deterministic — it re-parses descriptions importers already rendered; no AI, no re-import.

- ⚙ **⟳ Refresh** — rebuilds the graph by re-querying the whole super-timeline. More than a refetch: it re-parses every row's rendered logon description with an injection guard (it rejects a logon marker appearing after the first ` - ` separator, so attacker-controlled command-line text can't plant a fake account→host edge).
- ⚙ **Hide machine / system-session accounts** (checkbox) — hides nodes the server tagged as noise (machine `name$` accounts, `DWM-*`/`UMFD-*` session accounts, `ANONYMOUS LOGON`). SYSTEM / LOCAL SERVICE / NETWORK SERVICE are deliberately **not** treated as noise.
- ⚙ **Show failed logons (4625)** (checkbox) — reveals failed-logon edges (dashed). Success/failure is parsed from the event, not AI. (Edges also turn orange for "medium risk" when a backing logon is risky — e.g. external-source RDP, cleartext, or runas /netonly.)

### Evidence Chain

The causal view of the incident — instead of "which IOC touched which host" (Assets) or "what happened when" (Timeline), this shows **how** it happened: process spawn trees, lateral movement, file lineage, and network flows. Every edge carries a confidence level, the rule that derived it, a human-readable basis, and backing event IDs, so each causal claim is auditable. Fully deterministic — derived on read from fields the importers already populate. No AI.

- ⚙ **Process trees** (toggle) — parent→child edges from each event's `processName`/`parentName` on the same host; process nodes keyed by (asset, name) so excel→powershell→cmd chains into one tree without PID guessing.
- ⚙ **Lateral movement** (toggle) — edges where the same binary hash appears on ≥2 hosts (high confidence) or the same account is active on ≥2 hosts (medium confidence).
- ⚙ **File lineage** (toggle) — wrote→executed chains: a file written then executed with the same hash, with the file artifact as a middle node.
- ⚙ **Network flows** (toggle) — directed src→dst connections (srcIp/host → dstIp:port) from Suricata/Zeek network events.
- ⚙ **Sev (min-severity)** — declutter filter that hides nodes below the chosen severity (each node carries the worst severity of its backing events).

### Beacon Candidates

Surfaces periodic outbound C2-style channels — connections whose inter-arrival intervals are too regular to be human traffic. It groups outbound connections by (source host → destination IP : port) and flags tuples with low interval jitter. A hunting lead, not a verdict (legitimate software also polls on a timer) — the panel always carries that caveat. Fully deterministic statistics over network events already in the timeline; no AI, no network calls.

- ⚙ **The panel is the smart output** (no smart buttons). The rule: it excludes inbound connections, requires ≥5 events per tuple (`DFIR_BEACON_MIN_COUNT`), computes the median inter-arrival interval and its median-absolute-deviation (robust stats, so a few missed check-ins don't hide a periodic channel), and flags a tuple when jitter ≤ 20% of the median (`DFIR_BEACON_MAX_JITTER_PCT`). Severity is High for a public-IP destination (likely external C2), else Medium; sorted external-first, then most-regular, then most-frequent.

### Timeline Anomalies

Flags assets whose event rate spikes in a time bucket — "the host that suddenly went crazy" — without reading thousands of routine rows. It uses two baselines: a **peer** baseline (an asset far busier than other assets in the same bucket) and a **self** baseline (a normally-quiet asset that bursts relative to its own history, which importing unrelated telemetry can't mask). A triage lead, not a verdict. Fully deterministic; no AI.

- ⚙ **The panel is the smart output** (no smart buttons). Events are bucketed by (asset, 15-minute window — `DFIR_ANOMALY_BUCKET_MINUTES`). Peer pass flags a bucket count ≥ 5× (`DFIR_ANOMALY_SPIKE_FACTOR`) the median across other assets; self pass flags ≥ 5× (`DFIR_ANOMALY_SELF_FACTOR`) the median of the asset's own buckets. A bucket flagged by both is reported once. Severity: Critical ≥10×, High ≥7×, else Medium. Configurable via the `DFIR_ANOMALY_*` env vars.

### GeoIP Map

Plots the case's IP IOCs on a world map, colored by severity, using coordinates from GeoIP enrichment that was already fetched — so the map is empty until IP IOCs are enriched (map tiles load on demand from OpenStreetMap when you open it). Good for seeing where malicious infrastructure sits and drawing victim↔attacker flows. Deterministic derivation on read; no AI, no *new* enrichment calls when you open it.

- ⚙ **Flows** (checkbox) — draws lines between two geo-resolved IP endpoints for src→dst pairs in the timeline, classifying each flow (by RFC1918 internal/external) as outgoing, incoming, or lateral. Off by default.
- ⚙ **Marker color / placement** — a rule, not a filter: Critical/High → red, Medium → orange, Low → yellow, legitimate/whitelisted IPs → gray. Coordinates come from the first enrichment carrying lat/lon; if only a country is known it falls back to the country centroid and marks the marker "approximate."

---

### IOCs (Indicators of Compromise)

Central table of every indicator (IPs, domains, hashes, URLs, files, processes) extracted from evidence, plus any you add. It layers on threat-intel verdicts, corroboration counts, provenance (detection-linked vs telemetry-only), and a composite risk tier, with lens filters to cut noise. Most controls are display-only lenses that delete nothing. This panel makes external calls **only when you explicitly enrich**; false-positive and exclude actions are local/offline.

- 🌐 **🔬 Enrich** (bulk / selected) — sends the selected IOCs to the threat-intel providers enabled for the case: external SaaS (VirusTotal, AbuseIPDB, Shodan, CIRCL hashlookup, Hunting.ch → MalwareBazaar/ThreatFox/URLhaus/YARAify, CrowdStrike, RockyRaccoon) and self-hosted/local (MISP, YETI, OpenCTI), plus passive context (GeoIP, reverse DNS, RDAP, lookalike-domain check). Each returns a normalized malicious/suspicious/harmless verdict. External providers are opt-in per case because sending an indicator out can tip off an adversary.
- ⚙/🤖 **🚫 Mark False Positive** — excludes the IOC(s) from analysis (offline). The modal adds two extras: a 🤖 **🔎 Ask AI for similar** button (one AI call proposing other IOCs/events matching the same pattern to mark in one batch, alongside a deterministic similarity list), and — for a single IOC — an **Also add to the global whitelist** checkbox so the value is auto-suppressed in future cases.
- ⚙ **🗑 Exclude** — permanently removes the IOC value(s) from this case; never re-imported or re-enriched. Per-case, offline. The "Exclude" domain-rule menu (suffix/exact/regex) does the same by matching rule.

### Customer Exposure

Breach/leak and internet-exposure check for the **customer's own** domains and emails (not the case IOCs). Case hostnames and case emails under a customer domain are added automatically as "auto" chips. It tells you whether the victim organization's credentials or assets are already exposed publicly. Off until you run it, because it sends the customer's domains/emails to third parties.

- 🌐 **Check Exposure** — queries the configured external providers: **LeakCheck** and **DeHashed** (credential/breach records by domain and email), **Have I Been Pwned** (breach membership), and **Shodan** (exposed hosts/services and CVEs). Results flag whether a secret/password was present in each record — but raw passwords are **never stored** (only a `passwordPresent` flag). No AI.

### Key Investigative Questions

The open questions the AI is tracking for the case (e.g. "was data exfiltrated?"), each with a status (answered / partial / unknown) and an answer that updates as evidence accumulates. Questions are generated during synthesis; a deterministic reconsider step re-opens or marks them stale when a supporting finding is later marked false-positive, and flags answers "contradicted by timeline" when ATT&CK-tagged events conflict with a negative answer.

- 🌐 **⬇ Collect on \<host\>** — appears on an unanswered question when the AI attached a collection directive (a specific host + Velociraptor artifact expected to answer it) *and* that host is known to Velociraptor in this case. Launches that collection; otherwise degrades to a manual-collection hint.

### Hunting Profile

A read-only view of the case's hunt feedback loop: every hunt deployed (fleet / playbook / technique / triage bundle) with a tally of hit / no-results / pending and whether each found new evidence. Use it to track coverage and avoid running the same hunt twice. No AI.

- 🌐 **↻ Collect now / ↻ Re-collect** — pulls the hunt's current results from Velociraptor and imports them, recording the outcome. The button persists because fleet results trickle in as endpoints check in, so it re-pulls stragglers; a hit is never downgraded.
- 🌐 **▸ results** (expand) — fetches the hunt's actual result rows live from Velociraptor for preview. For a not-yet-imported hunt it shows a "live preview — not imported yet" note plus an inline **↻ Collect now to import** button.

### Investigation Threads

Open leads the AI tracks across re-synthesis runs (e.g. "unexplained outbound beacon to X") — hypotheses that aren't yet findings. Threads are created by the AI during synthesis and closed automatically once the evidence resolves them (closed threads show struck-through). A display panel driven by AI-produced state.

*No smart buttons* (only per-thread comment/tag chips, which are trivial collaboration controls).

### MITRE ATT&CK

Lists the ATT&CK techniques the case exhibited, each linked to its attack.mitre.org page and to the finding IDs that evidence it. The technique set is produced by the AI during synthesis; the panel just renders it as offline links.

*No smart buttons* (technique-level hunting is offered from Adversary Hints, not here).

### Adversary Hints

Offline "who typically uses these techniques, and what would they do next?" fuel. It scores the overlap between the case's ATT&CK techniques and every group in a bundled MITRE ATT&CK Groups dataset (sub-technique aware, weighting exact matches above base-technique matches), and derives each matched group's **likely next techniques** the case hasn't shown yet, ranked TF-IDF-style by distinctiveness rather than popularity. Explicitly framed as statistical technique overlap, **not attribution**. The whole panel is offline and deterministic — no AI, no network. (Update the data with `npm run data:update-attack`.)

- 🤖 **⌖ hunt this** (on a "likely next technique" row) — the one exception: one AI call generates a Velociraptor VQL hunt for that specific technique, then drops the proposed VQL into the **Suggested Fleet Hunts** panel for review before deploying.

### Mitigation & Defensive Countermeasures

For the case's identified techniques: the concrete MITRE ATT&CK mitigations (M-code "courses of action," ranked by how many techniques each addresses) plus the MITRE D3FEND defensive techniques that harden/detect/isolate each one (grouped into "harden now" — Prevent/Detect/Contain — and "this incident & context" — Evict/Restore/Model/Deceive). Both mappings are static committed datasets resolved offline — no AI, no network.

- 🤖 **✨ Generate remediation plan** — the only AI control. One AI call reads this case's findings plus the derived ATT&CK mitigations and D3FEND countermeasures and writes a concrete, incident-specific, prioritized plan (Contain / Eradicate / Harden / Recover / Verify) that references real hosts, CVEs, and IOCs. Requires a synthesis provider; output is labeled "review before acting."

### Suggested Fleet Hunts

AI-proposed proactive Velociraptor VQL hunts derived from the case findings — queries to run across every enrolled endpoint to find the same tradecraft elsewhere. Suggestions are ephemeral and the VQL is editable before deploying. Requires a synthesis provider; deploying additionally requires the Velociraptor API.

- 🤖 **✨ Suggest hunts** — one AI call over the findings returning proposed hunts, each with a title, severity, rationale, mapped ATT&CK techniques, and ready-to-run VQL.
- 🌐 **▶ Deploy hunt (all clients)** — launches the (possibly hand-edited) VQL as a hunt across all enrolled clients, recorded in the hunt feedback loop. Disabled until Velociraptor is configured.
- 🤖 **↻ Regenerate** — asks the AI for a *different* VQL for that finding (passing the current VQL as an exclusion), e.g. when the proposed query won't compile, and swaps just that card.

---

### False Positives (excluded from analysis)

Every event, IOC, or finding you've marked as excluded, with its reason code and note, most-recent first. Marked items are hidden from the timeline/findings and fed to the next synthesis so they're dropped or suppressed. It also surfaces "learned patterns" the AI uses to down-weight look-alike activity.

- ⚙ **un-mark** (per row) — reinstates the item: it returns to the timeline and analysis, and the reversal is recorded in the Investigation Log.
- ⚙ **Learned patterns** (display, no button) — recurring reasoned dismissals distilled into a per-case ledger (signature + reason + recurrence count). This is *not* a suppression list: on the next synthesis, new look-alikes are still surfaced but at **lower confidence unless independently corroborated** — down-weighted, never auto-excluded.

### Source Trust

Every known evidence source (tool) with its built-in default trust weight (0–1) and a per-case override you can type — e.g. lowering a hunt that was noisy on this engagement. Overrides take effect on the next synthesis. Trust steers which tool's wording wins when the same event is merged across sources, and caps the confidence of findings supported only by low-trust sources.

- ⚙ **Save trust overrides** — persists the per-case override map (each value validated into 0–1; blanks fall back to the default). The scoring logic: each tool has a default tier (EDR like CrowdStrike/Defender = 1.0; Sigma engines like Hayabusa/Chainsaw/THOR = 0.95; DFIR collectors like Velociraptor/Sysmon = 0.85; SIEM/network sensors ≈ 0.8; intel/screenshots ≈ 0.75; generic log/CSV = 0.6; unknown = 0.7). An event's trust is the **maximum** across its sources (one high-trust corroborator lifts the whole event). Correlation prefers the highest-trust event's description as canonical, and finding-confidence is only ever **capped downward** for low-trust-only findings — it never boosts.

### Hypotheses

Testable explanations for the observed activity, each moving from open → supported / refuted / unknown. Hypotheses are both auto-generated on every synthesis (badged "auto") and analyst-authored; both survive synthesis and are never wiped. Open hypotheses are fed into synthesis to steer the AI.

- 🤖 **✨ Generate** — forces a full synthesis now, which regenerates the auto hypotheses from the current timeline. Your edited/authored hypotheses are preserved.
- 🤖 **🔎 Review** — an AI "falsification review" that weighs the evidence for and against each **open** hypothesis and recommends a status. Strictly advisory — nothing changes until you click **Apply → \<status\>** on a result. Results are ephemeral.
- ⚙ **Add hypothesis** — manually author one (title, expected outcome, status). Feeds synthesis context and survives re-synthesis.

### Analyst Notebook

Free-form notes and open questions that survive synthesis and are never wiped. Supports Markdown, per-case. Entries can be fed into AI context and promoted to hypotheses.

- ⚙ **Include notebook in AI synthesis context** (checkbox) — when on, your current notes and open questions are handed to the AI on each synthesis.
- ⚙ **→ Hypothesis** (per entry) — promotes a note/question into a status-bearing hypothesis and jumps to the Hypotheses panel. The notebook→hypothesis bridge.

### Investigation Log

A read-only, chronological merge of import events and AI notes with your quick-action audit lines — a single time-ordered narrative of what was imported, what the AI noted, and what you did.

*No smart buttons (display-only).*

### Activity Log

A read-only audit table of every security-relevant action on the case (timestamp, category, actor, detail, error outcome) — the accountability/audit trail.

*No smart buttons* (the category dropdown is a plain filter).

### Case Details (for report)

The human-authored sections of the incident report (company/org, incident ID, investigators, executive summary, business impact, limitations, goals, conclusions, recommendations, revisions, distribution, glossary, logo, and the report-template selector). Values are saved per case and merged into the report at generation time; blank fields fall back to auto-derived values or "to be completed" placeholders.

- ⚙ **Override fields** — there are no ✨ buttons in this panel, but several fields are logic-backed overrides: **Executive Summary** and **Narrative** are AI-generated in *their own* panels and written here as overrides; **Glossary** is auto-derived from the report at generation time (fill only to override); **Recommendations / Conclusions / Investigation goals** are override fields too (e.g. goals left blank are derived from the case's key questions). Filling a field overrides the auto/AI output in the report; leaving it blank uses the auto value.

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
| **Encrypted case archive** | Password-protected archive of the ENTIRE case, evidence included |
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

Hypotheses survive synthesis (unlike findings, which are replaced each time) and are included in the encrypted case archive export.

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

**Export an encrypted case archive before closing.** It's a complete, portable record of the case — evidence included — findings, timeline, IOCs, playbook, notes, hypotheses, screenshots, raw imports. Store it with your case documentation.

**Use the Query Translator early.** When you're not sure what VQL to write for a hunt, describe what you're looking for in plain English. It's faster than looking up VQL syntax.

**For presentations, filter by severity first.** Set the severity filter to `high+` before opening Presentation mode. You get a clean executive deck that covers the most important findings and events without the noise of Info/Low items.

**The Diagnostic page is your first stop when something breaks.** Settings → Diagnostics shows the AI error count by type (auth errors = wrong key, billing errors = quota exceeded, rate limit = slow down), the processing queue state, and integration health — without ever showing your API key.

---

*For technical details, see the `companion/README.md` and `CLAUDE.md` files in the repository.*
