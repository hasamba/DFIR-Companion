# Analyst Walkthrough

This page walks through a complete investigation from start to finish. Think of it as the recommended workflow for every new case.

---

## Step 1 — Create a case

Open the dashboard. Click **+ New case** in the top toolbar. Fill in:

- **Case ID** — a short slug (e.g. `ir-2026-001`). Must be unique.
- **Case name** — human-readable title.
- **Investigator** — your name.

Click **Create**. The case is selected and the dashboard is ready.

---

## Step 2 — Capture screenshots as you investigate

As you work through your SIEM, EDR console, Velociraptor, or any browser-based tool:

1. Select your case in the extension popup (click the extension icon).
2. Press `Ctrl+Shift+S` to enable capture mode.
3. A floating **Push chip** button appears on the page. Click it to send the current screenshot to the Companion.
4. A green confirmation toast confirms receipt.

!!! tip "Use the push chip in Velociraptor, Splunk, or any browser console"
    When you're looking at hunt results in Velociraptor's web GUI, a Splunk search result, or any other tool, activate capture mode with `Ctrl+Shift+S` and click the floating Push chip. You don't need to switch windows or save a screenshot manually — one click sends exactly what's on screen to the Companion and attaches it to your case.

For specifically recognised consoles (Security Onion Alerts/Hunt, Kibana, SO-CRATES), the extension also injects **per-row push buttons** automatically, so you can push individual events or alerts without enabling capture mode and without a full-page screenshot.

**What gets captured:** the full visible tab content (a screenshot) plus the URL and tab title. Evidence is stored to disk immediately — before any AI analysis.

---

## Step 3 — Import artifact files

While screenshots are great for consoles, you should also import raw artifact exports whenever possible. Raw exports give the AI more structured data.

Click the **Import** button (toolbar, top of dashboard). A file picker opens. Drag or select any of the supported file types (see [Importing Evidence](reference/importing.md) for the full list). The server auto-detects the format and imports it.

**Recommended imports for a Windows IR case:**

- Chainsaw/Hayabusa hunt results (JSON or CSV)
- Velociraptor collection export (JSON or artifact map)
- KAPE/Eric Zimmerman tool outputs (CSV)
- THOR scanner report (JSONL)
- Suricata/Zeek network logs
- Memory image analysis (Volatility 3 JSON or text)
- Phishing email samples (.eml)

---

## Step 4 — Let the AI analyze

After each import (and after enough screenshots accumulate), click **AI Analyze** in the toolbar to run extraction over any unprocessed evidence. The server reads each batch of screenshots and structured files, then emits raw forensic events into the timeline.

When you want findings and an attacker narrative, click **AI Re-synthesize**. This runs one text-only AI call over the entire forensic timeline and produces:

- **Findings** — named conclusions (e.g. "Credential dumping via LSASS access")
- **MITRE ATT&CK techniques** — mapped to each finding
- **Attacker path** — a narrative paragraph connecting the dots
- **Kill chain** — which phases are covered

!!! note
    Synthesis is smart: it skips re-running if nothing changed since last time. Force it with the **Force re-synthesize** option.

---

## Step 5 — Review the dashboard

Walk through the dashboard panels (see [Dashboard Panels](reference/dashboard.md) for each one in detail):

1. **Findings** — do these make sense? Any false positives?
2. **Forensic Timeline** — scan for gaps, anomalies, and events that look out of place.
3. **MITRE ATT&CK** — which techniques? What's missing?
4. **Compromised Assets & IoC Graph** — which machines and accounts were touched?
5. **IOCs** — run enrichment on suspicious indicators (see [IOC Enrichment](reference/ioc-enrichment.md)).
6. **Adversary Hints** — any known threat groups match this technique set?

---

## Step 6 — Mark false positives and known-good items

Every finding, IOC, and forensic event has a **🚫 Mark False Positive** button. Click it, pick a reason (known-good tool, authorized test, detection misfire, duplicate, or other), and confirm to exclude the item from analysis. It moves to the **False Positives** panel. You can reverse the decision any time. Marking a finding/event also suggests similar items in the case to mark in the same action; marking a single IOC can also promote it to the global IOC whitelist.

For bulk exclusions (e.g. an entire internal IP range), use **Settings → IOC Whitelist** to add a CIDR rule. Any IOC matching the rule is automatically marked false-positive on import.

---

## Step 7 — Hunt for more evidence

The **Recommended Next Steps** and **Key Investigative Questions** panels suggest what to look for next. If you have Velociraptor connected, the dashboard surfaces **AI-generated VQL hunt queries** — click the deploy button to launch a fleet hunt. Results auto-import into the case.

Use the **Query Translator** panel to write plain English ("show me all PowerShell executions in the last 24 hours") and get it translated to VQL, KQL, ES|QL, SPL, Sigma, YARA, or Suricata.

---

## Step 8 — Work the Response Playbook

The **Playbook** panel lists response tasks auto-generated from your findings. Each task has:

- Status (pending / in progress / done / deferred)
- Assignee and due date
- Notes

Mark tasks as you complete them. Enable **IR Templates** in Settings → Velociraptor to expand each Critical/High finding into phase-based response steps (Contain → Investigate → Eradicate → Recover).

---

## Step 9 — Generate the report

Click **Export → Report (Word)** (or Markdown, HTML) to download the full IR report. The report contains every finding, the timeline, IOCs, MITRE mapping, attacker path narrative, and recommended countermeasures.

Customise the report's cover page, accent color, and section order in **Settings → Report Templates**.

---

## Step 10 — Hand off

- **Present mode** (`▶ Present` toolbar button) — a slide deck for executive briefings. Navigate with arrow keys or use fullscreen.
- **Export encrypted case archive** — a password-protected .dfircase file containing the ENTIRE case (evidence and screenshots included) you can share with another analyst.
- **Push to DFIR-IRIS / Timesketch / Notion / ClickUp** — export to integrated platforms.

---

!!! tip "See also"
    - [Case Management](reference/cases.md) — creating, switching, archiving cases
    - [Importing Evidence](reference/importing.md) — supported formats
    - [Reports & Exports](reference/reports.md) — report formats and customisation
