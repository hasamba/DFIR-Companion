# Investigate a Ransomware Incident with DFIR Companion

**DFIR Companion** is an open-source, localhost-first post-detection analysis tool. It ingests evidence from the tools you already run — Velociraptor, Chainsaw, Hayabusa, EDR/SIEM exports, memory forensics, network logs — correlates everything into one forensic timeline, and synthesises findings, MITRE ATT&CK techniques, and an attacker path.

> **The environment is being set up in the background.** While you read this, Docker is pulling the pre-built DFIR Companion image and starting the server. This takes about **1 minute**. Watch the terminal — it will print **"DFIR Companion is ready!"** when done.
>
> Once ready, open the dashboard: click the **top-right icon (⇒) → Traffic / Ports**, enter port **4773**, and press **Access**.

---

## The Case: GlobalTech Industries — BEC & Ransomware Precursor

You are responding to an incident at **GlobalTech Industries**, a mid-sized manufacturing firm. On **May 15, 2026**, the SOC received an alert from the EDR for a Cobalt Strike beacon on `WORKSTATION-04`. The DFIR team collected evidence over the following week.

This environment has a pre-loaded demo case with:

- **45+ forensic events** spanning May 15–22, 2026
- **17 IOCs** — C2 IPs, domains, malware hashes, credentials
- **10 findings** (2 Critical, 3 High) with MITRE ATT&CK mappings
- Pre-enriched threat intel (VirusTotal, AbuseIPDB, ThreatFox verdicts)
- Analyst comments, triage tags, and a full investigation notebook

## What you'll do

| Step | What you'll explore |
|------|-------------------|
| 1 | Open the dashboard and orient yourself |
| 2 | Walk the forensic timeline from initial access to ransomware attempt |
| 3 | Review AI-synthesised findings mapped to ATT&CK |
| 4 | Examine IOCs and pre-run threat intel enrichment |
| 5 | Trace the attacker's lateral movement path |

## Key concepts

**Post-detection, not detection.** DFIR Companion doesn't run Sigma or YARA rules. It ingests the *output* of your detection tools and synthesises the "so what" — the narrative, the findings, the report.

**One import button.** Drop a Chainsaw JSON, a Velociraptor export, a THOR report, or a network Suricata log — the tool auto-detects the format and routes it to the right importer.

**All local.** In production, the server binds to `127.0.0.1` and never sends evidence to external services without explicit opt-in. Here it binds to `0.0.0.0` so KillerCoda's browser panel can reach it.

---

> ⚠️ **AI features require an API key.**
> The demo case is fully pre-populated — findings, timeline, IOCs, and threat intel are all already there and require no AI. However, if you want to use live AI features (re-synthesise findings, "Ask the case", generate a narrative, or run a second opinion), you will need to provide your own API key:
>
> 1. Open the dashboard → **Settings** → **AI Provider**
> 2. Enter your API key and select a model (OpenAI, Anthropic, or any OpenRouter-compatible provider)
> 3. Save — AI features activate immediately, no restart needed
>
> Without a key, all pre-computed results remain fully visible; only the live AI buttons will return an error.

---

*When the terminal prints "DFIR Companion is ready!", click **Start** to begin.*
