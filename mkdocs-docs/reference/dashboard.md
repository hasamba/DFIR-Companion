# Dashboard Panels — Reference

All panels are visible by default. Some are collapsed until they have data. Use **Settings → Dashboard Views** to show/hide panels per role or phase.

---

## Summary Bar

The top of the dashboard shows:

- Case name and investigator
- Screenshot count and last capture time
- Last synthesis time and what changed
- Last import time and how many new events/IOCs it added
- A severity summary badge (Critical / High / Medium counts)

---

## Findings

Your primary conclusions. Each finding has:

- **Title** — what happened
- **Severity** — Critical / High / Medium / Low / Info
- **Confidence** — a 0–100% badge (color-coded: ≥80% high, ≥50% medium, else low) — the AI's certainty
  this finding is real attacker activity rather than a false positive, weighing evidence strength,
  corroboration from multiple tools, and its own certainty. Hover the badge, or expand the finding's
  evidence details, for the one-line **reason** behind the score. A deterministic auto-flagged finding
  (backfilled from an uncovered Critical/High event — see below) always shows 100%.
- **MITRE techniques** — linked to attack.mitre.org
- **Supporting events** — click to jump to each event in the timeline
- **Supporting IOCs** — the indicators that back this finding
- **🚫 Mark False Positive** — exclude from analysis

The finding list is sorted worst-first. Click a finding to expand it. The **Min confidence** box above
the list hides findings below the chosen floor (findings with no confidence score always show); the
floor is a per-case setting, so it's remembered the next time you open the case.

---

## Attack Path

A narrative paragraph written by the AI describing the full attacker journey — from initial access through the kill chain to last known activity. Plain English.

---

## Kill Chain

Shows which **Cyber Kill Chain phases** are covered by the evidence: Reconnaissance, Weaponization, Delivery, Exploitation, Installation, Command & Control, Actions on Objectives.

Phases with evidence are highlighted. Gaps may indicate coverage blind spots.

---

## Forensic Timeline

The core of the investigation. A table of all forensic events, sorted by timestamp (or severity — click the column header to sort).

Each row shows a compact title line (timestamp, severity badge, description, source tool(s), asset, `NEW` badge if added in the last import); a **[details ▶]** toggle expands the full description, MITRE, related findings, decoded payloads, evidence link, and the raw tool message in one shared panel below the row. Row actions:

- **💡 Explain** button — AI explains this event, gives ATT&CK context, and suggests pivot queries
- **🚫 Mark False Positive** — excludes this event from analysis

### Filters

- **Severity** — Critical / High / Medium / Low / Info
- **Source** — show/hide by tool (e.g. hide all Chainsaw, show only Velociraptor)
- **Origins** — one level more specific than Source: show/hide by the exact artifact that produced the event (e.g. `DetectRaptor.Windows.Detection.MFT`)
- **Date range** — filter by time window (or use the **Scope** bar to set the investigation scope)
- **🔍 Screenshot text** — full-text search across OCR'd screenshots
- **Exclude** — chip-list control next to the toolbar search bar; hides timeline events / IOCs / findings matching any of several exclude terms
- **Corroboration lens** — show only events observed by 2+ or 3+ distinct tools (see below)
- **Pagination** — 100 / 250 / 500 / All rows per page; the Prev/Next bar sits above the event rows

!!! tip
    Drag a time range on the **Timeline Swimlane** (below) to instantly scope the timeline to that window.

### Row Display

**Settings → General → Timeline row display** lets you choose which sub-elements appear on each row (action icons, tag pills, badges, host chip, MITRE, related findings, evidence links). Timestamp and message always show. Per-browser, applies immediately.

---

## Host & Account Ranking

Ranks every host and account by **signal**, not volume: severity-weighted events + ATT&CK techniques + connective IOCs. Chatty-but-benign hosts sink; the entities actually carrying the attack rise to the top.

A one-click **suggested scope** button sets the investigation scope window to cover the top-ranked hosts' activity. The top hosts also feed the synthesis prompt so an automatic run over a noisy multi-host timeline anchors its narrative on the right hosts instead of the loudest one.

---

## Attack Phases

Groups the forensic timeline into temporal **bursts** — clusters of activity separated by periods of silence. Each burst is labeled with the dominant MITRE tactic (Initial Access, Execution, Persistence, etc.).

This shows the *when* axis: not just what happened, but which phase of the attack was most active at what time.

No AI — derived deterministically from the timeline data.

---

## Timeline Swimlane

A visual chart with:

- **Y-axis:** compromised assets (hosts)
- **X-axis:** time
- **Color:** event severity

Useful for spotting lateral movement (events jumping between assets) and attack timing. Drag a time range to scope the timeline to that window. Exports as SVG.

---

## Timeline Anomalies

Detects assets whose event rate spikes in a time bucket, using two baselines (shown in the **Type** column):

- **peer** — the asset is far busier than *other* assets in the same bucket (count ≥ spike-factor × the per-bucket median across assets).
- **self** — the asset is bursting above *its own* typical rate (count ≥ self-factor × the median of that asset's own per-bucket counts). Catches a normally-quiet host (a DC, a file server) that suddenly bursts, even when its absolute volume is low — the peer method can miss those, and importing unrelated telemetry can't mask them.

A burst flagged by both is shown once as `peer + self`. Useful for spotting data exfiltration, log flooding, or initial-access beachheads. No AI — purely statistical.

Configure thresholds via `DFIR_ANOMALY_BUCKET_MINUTES` (default 15), `DFIR_ANOMALY_SPIKE_FACTOR` (peer, default 5), `DFIR_ANOMALY_SELF_FACTOR` (self, defaults to the peer factor), `DFIR_ANOMALY_MIN_EVENTS`.

---

## Beacon Candidates

Outbound network connections that are *too regular to be human* — suggesting automated beaconing (C2 keepalives, malware checking in). Ranked by periodicity. A hunting lead, not a verdict.

---

## MITRE ATT&CK

Shows all ATT&CK techniques identified across findings and events, grouped by tactic. Click a technique to jump to the events that evidence it.

---

## Compromised Assets & IoC Graph

A graph showing:

- **Known compromised assets** (hosts, accounts)
- **IoCs that touched each asset**

Assets are derived from events' `asset` field plus account mentions (DOMAIN\user, UPN). Click an asset to see all events and IOCs linked to it.

You can manually add assets or links using the **+** button.

---

## Evidence Chain

A causal graph showing:

- **Process trees** (parent → child process spawns)
- **File lineage** (file written then executed)
- **Lateral movement** (shared hashes or accounts across hosts)
- **Network flows** (host → IP connections)

This is the "how did we get here" graph — tracing the attack path through actual artifact relationships, not just the AI narrative. No AI — derived from structured event fields.

Filters: severity floor, SVG export.

---

## IOCs (Indicators of Compromise)

Every indicator extracted from all evidence:

- IP addresses
- Domains
- URLs
- File hashes (MD5, SHA-1, SHA-256)
- File paths
- Process names

**Filters:** by type (ip/domain/url/hash/file/process/other), by flagged-only, text search, corroboration lens (see below), plus three composable noise-reduction toggles (default on, per-browser): **Hide FP/no-intel** (drops IOCs marked false-positive or with no enrichment result), **Hide OS system paths** (drops `file` IOCs under well-known system-binary directories), and **🎯 Signal only** (narrows to flagged, corroborated, or enriched IOCs).

Each IOC shows:

- **Verdict badge** — reputation from enrichment providers (malicious / suspicious / clean / unknown)
- **Source badge** — how many tools corroborated this indicator (e.g. ⊕ 3 sources)
- **🚫 Mark False Positive** — known-good, excludes from analysis
- Click to run enrichment on demand

---

## Corroboration Filter (Lens)

**Forensic Timeline**, **IOCs**, and **Findings** each have an independent corroboration lens in their title bar: show only items observed by **2+** or **3+** distinct tools, cutting single-source noise (internet scanners, benign per-tool telemetry) so the multi-source attack path stands out.

It's a **lens, not a gate** — nothing is dropped from state. Single-source evidence (a Sysmon-only process, a syslog-only logon) still shows at the default "any" setting. Each section's choice is remembered independently.

On the timeline, the lens composes with the **Source** filter: it counts only distinct sources still checked, and while active the Source menu lists only the tools present on corroborated events.

---

## Recommended Mitigations & Defensive Countermeasures

Two-part panel, fully AI-free and offline:

**ATT&CK Mitigations (M-codes):** Concrete MITRE-recommended mitigations for the case's techniques, ranked by how many techniques each mitigation addresses. Start with the highest-leverage mitigation.

**D3FEND Defensive Countermeasures:** MITRE D3FEND countermeasures grouped into two bands:

- *Harden now* — Prevent, Detect, Contain actions
- *This incident & context* — Evict, Restore, Model, Deceive actions

**✨ Generate remediation plan** button — one AI call produces an incident-specific, prioritized plan (Contain / Eradicate / Harden / Recover / Verify) grounded in the actual findings, ATT&CK mitigations, and D3FEND countermeasures. References real hosts, CVEs, and IOCs from your case.

---

## Adversary Hints

Compares the case's ATT&CK techniques against the MITRE ATT&CK Groups database to find groups with the highest technique overlap. Shows:

- Group name, aliases, and description
- How many techniques overlap (and which ones)
- **Likely next techniques** — techniques that matched groups use that haven't appeared in this case yet, ranked by how distinctive they are to those groups

!!! warning "This is a hypothesis, not attribution"
    Use it to guide hunting — if a matched group tends to pivot via RDP, that's worth looking for. Never use this as attribution evidence.

Offline, no AI, no network calls at runtime.

---

## Key Investigative Questions

Open questions the AI thinks you should be pursuing based on the current evidence — gaps, unknowns, and unexplained events.

---

## Recommended Next Steps

Prioritised list of concrete investigation actions: what files to check, what hunts to run, what questions to answer. Synthesis-generated.

---

## Ask the Case

A free-text question box. Type any question in natural language:

- "When did the attacker first access the domain controller?"
- "What credentials were likely stolen?"
- "List all C2 IP addresses and their first-seen times."

The AI answers using the full forensic timeline plus the **evidence-chain graph** — so it can trace multi-hop paths.

---

## Query Translator

Type a plain-English description of what you want to hunt for. Select the output query language:

| Language | Notes |
|----------|-------|
| **VQL** | Velociraptor — can be deployed as a fleet hunt in one click |
| **KQL** | Kibana/Elastic |
| **ES\|QL** | Elasticsearch |
| **SPL** | Splunk |
| **Sigma** | Cross-SIEM |
| **YARA** | File/memory |
| **Suricata** | Network IDS |

---

## Investigation Threads

Open and closed investigation threads — chains of related events grouped by the AI. Useful for multi-stage attack sequences.

---

## Hypotheses

Status-tracked investigation hypotheses:

- Auto-generated by AI from the evidence
- Manually added by the analyst
- Promoted from Analyst Notebook notes

Each hypothesis has a status: **Open / Supported / Refuted / Unknown**. Open hypotheses are fed into synthesis to steer the AI's analysis. Hypotheses with evidence links survive re-synthesis.

---

## Response Playbook

A trackable checklist of response tasks:

- Auto-generated from findings (Critical/High findings generate response steps)
- Analyst-added custom tasks

Each task has: status, assignee, due date, notes.

**IR Templates mode** (Settings → Velociraptor → IR Templates): expands each Critical/High finding into phase-based steps (Critical → Contain / Investigate / Eradicate / Recover; High → Investigate / Contain). The Investigate step is tailored to the finding's dominant ATT&CK tactic.

Push the playbook to **ClickUp** with one click (toolbar → Export → Push playbook to ClickUp).

---

## Hunting Profile

Shows what has been hunted in this case and whether each hunt found anything:

- Hunt title and VQL fingerprint
- Status (hit / miss / deployed / pending)
- Result row count and new events added to the case
- **Re-collect** button to pull fresh results
- **Expand** to view hunt rows inline

Used to track your hunting coverage and avoid running the same hunt twice.

---

## Analyst Notebook

Free-text notes. Supports Markdown. Notes are per-case and survive re-synthesis. Notes can be promoted to Hypotheses.

---

## Investigation Log

A durable log of every synthesis run — what the AI concluded each time and what changed. Useful for tracking how the investigation evolved.

---

## Customer Exposure

Check whether the victim organisation's own domains and email addresses appear in breach databases.

Configure customer domains in this panel. Click **Run exposure check** to query your configured providers (LeakCheck, HIBP, DeHashed, Shodan for attack surface).

!!! info
    Raw passwords from breach results are **never stored** — only a `passwordPresent` flag.

---

## Case Details (for Report)

Human-authored report metadata:

- Distribution / classification
- Business impact assessment
- Executive summary
- Recommendations section
- Glossary
- Custom report sections

These fields appear verbatim in the generated report.

---

## Geographic IP Map

Plots all IP IOCs on an interactive world map:

- Markers colored by severity
- Flow lines showing victim → attacker direction
- Country statistics panel
- Timeline sync (filter map by time range)
- CSV export

Requires GeoIP enrichment to be configured and enabled.

---

## Super-Timeline

A Timesketch-style complete record of **every** imported event, kept separately from the forensic timeline so the AI never synthesizes it — the forensic timeline stays detections-focused while nothing is ever lost.

- **Filter** by time, origin (artifact), or label — e.g. hide Sigma/YARA/Hayabusa detections to see only raw host artifacts
- **Save named timeframes** for quick recall
- **Label** events for your own triage
- **Promote** selected events into the forensic timeline so AI synthesis picks them up
- Each row can expand a **[details ▶]** toggle for the full untruncated message, and a Velociraptor-sourced row shows a **↗ Velociraptor** link back to the originating hunt/flow

A **"Super-Timeline Triage"** Velociraptor bundle collects raw Windows host artifacts (MFT, USN, EVTX, registry, Prefetch, Amcache, LNK, browser history, RecycleBin, scheduled tasks, ActivitiesCache) directly into the super-timeline only.

!!! info "Why events don't all reach the forensic timeline"
    Info-severity telemetry routes to the super-timeline only by default (the forensic timeline keeps Low+ graded signal) so synthesis isn't swamped by raw noise. Configure the floor via **Settings → General** (`DFIR_FORENSIC_MIN_SEVERITY`) globally, with a per-case override. Promoting an event always bypasses the gate, and IOCs are still extracted from every event regardless.

---

## False Positives (Excluded from Analysis)

Everything you have marked as a false positive or known-good. Shows findings, events, and IOCs with their exclusion reason and analyst attribution. Click any item to reinstate it.

Marking an item asks for a **structured reason** (known-good tool / authorized test / detection misfire / duplicate / other) and offers ranked **"find similar items"** suggestions (shared MITRE technique, process, hash, asset, or IOCs) so the same recurring pattern can be dismissed in one pass — deterministic by default, or AI-assisted for less obvious matches. Marking a single IOC can also **one-click-promote** it to the global IOC whitelist so future imports auto-exclude it.
