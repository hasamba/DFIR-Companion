# DFIR Companion — User Manual

> Plain-English guide for security analysts, incident responders, and anyone who wants to understand what the tool does, how to reach every feature, and how to get the most out of it.

---

## What Is DFIR Companion?

DFIR Companion is a **localhost** web application that sits on your analysis workstation and helps you go from a pile of raw forensic evidence to a finished incident-response report.

In plain terms, it does three things:

**1. Collects evidence.** You capture screenshots of your investigation tools — SIEM dashboards, EDR consoles, Velociraptor hunt results, log viewers — by pressing a hotkey in the browser extension. You can also drag-and-drop or upload artifact files directly (CSV exports, JSON reports, log files, memory images, network captures, cloud audit logs, email files, and many more).

**2. Analyzes the evidence with AI.** The server reads the evidence and builds a structured **forensic timeline** of real events with real timestamps. It then runs a second AI pass to produce **findings** (what the attacker did), **MITRE ATT&CK technique mappings**, and an **attacker-path narrative** (the story of the intrusion from first foothold to last known activity).

**3. Helps you understand and communicate.** It surfaces the timeline in a dashboard with filters, graphs, and derived panels (kill chain, asset graph, adversary hints, defensive countermeasures, hunting leads). It generates a Word/HTML/Markdown/CSV report, a presentation slide deck, and can push the findings to your SIEM, Notion, ClickUp, or DFIR-IRIS.

!!! info "Privacy"
    Everything runs on your machine. Evidence never leaves your network unless you explicitly opt in to a third-party enrichment service.

---

## What It Is NOT

Understanding this avoids confusion:

- **It is NOT a detection engine.** It does not run Sigma rules, YARA rules, or write detections. That is your SIEM/EDR/Chainsaw/Hayabusa's job. DFIR Companion consumes *their* results and makes sense of them.
- **It is NOT a SIEM.** It does not ingest raw events in real time (except via the optional push-ingest webhook). It is a case-analysis layer that runs *after* your detection tools have already fired.
- **It is NOT a replacement for analyst judgment.** The AI assists. Every finding, timeline entry, and IOC is shown to you so you can confirm, reject, or mark it legitimate.

---

## Quick Overview

```
Your tools            DFIR Companion              Output
─────────────────     ──────────────────────      ─────────────────
SIEM / EDR       ──►  Ingest evidence             IR Report (Word/HTML)
Velociraptor     ──►  Build timeline              Presentation deck
Chainsaw/Hayabusa──►  AI extracts events    ──►  Snapshot (JSON)
KAPE/EZ Tools    ──►  AI synthesizes findings     Push to IRIS/Notion
Volatility       ──►  Dashboard for review        Push to ClickUp
Network logs     ──►  Hunt for more               IOC block-list
Cloud audit logs ──►  Report & hand off
Screenshots      ──►
```

Ready to get started? Head to [Getting Started](getting-started.md) to install and configure DFIR Companion.
