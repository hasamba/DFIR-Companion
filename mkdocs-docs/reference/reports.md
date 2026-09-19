# Reports & Exports

## Report Formats

Click **Export** in the toolbar to see all options:

| Format | Description |
|--------|-------------|
| **Word (.docx)** | Full formatted report with cover page, table of contents, findings, timeline, IOCs, MITRE matrix, attacker path, countermeasures |
| **HTML** | Same content as Word, rendered in the browser — printable |
| **Markdown** | Plain text report |
| **CSV** | IOC export (all indicators with enrichment verdicts and sources) |
| **IOC block-list** | Plain TXT, CSV, or STIX indicators — ready to load into a firewall or SIEM |
| **Presentation deck** | Slide-by-slide offline HTML file (see below) |
| **Encrypted case archive** | Password-protected archive of the ENTIRE case, evidence included |
| **Redacted case package** | The full case with anonymized AI input — shareable for model debugging without exposing evidence |

Generating a report also writes `custody-manifest.json` beside it, and the encrypted case archive
carries one inside — a signed record of every artifact's chain of custody. See
[Chain of Custody](chain-of-custody.md).

### Indicators are defanged, and the export checks itself

Every human-readable export — the HTML, Markdown and Word reports, the interactive HTML report and
the presentation deck — renders indicators inert (`hxxp://evil[.]example`, `203[.]0[.]113[.]9`) so a
reader cannot click through to attacker infrastructure. Machine exports (CSV, STIX, JSON, the IOC
block-list, case archives) keep the live values because the tools that read them match on them.

Before one of those files is handed over, the Companion checks the finished file against the case's
own recorded indicators and evidence text. If a live indicator or an unescaped piece of evidence
made it through — an exporter defect, not something you did — the export still ships, with a
warning in three places: a banner at the top of the document itself, a line on the case activity
log, and the report status line in the dashboard. Fix the cause and regenerate before the file
leaves the team.

### IOC block-list

The block-list is an acting export: a firewall or SIEM will block what it lists. Four filters
are always applied, whatever the dialog options say:

- **Scope** — an indicator cited only by findings outside the investigation scope is left out.
- **False-positive** — indicators you marked legitimate are left out.
- **Retired** — a finding you retired in the Intel Retirement Review keeps its own IOCs off the
  list (an IOC another, non-retired finding relates stays).
- **Client-reported** — a value read from a header the sender controls (an email's
  `X-Originating-IP`) is a claim, not an observation. It is left out whatever the intel verdict
  says, so a forged header can never put a real address on a block-list.

The TXT header names the applied filters on its `# Filters:` line. The minimum severity and
the IOC types are yours to choose in the dialog.

---

## Report Customisation

**Settings → Report Templates** lets you:

- Change the cover title, subtitle, running header/footer
- Set an accent colour
- Show/hide the company logo and name
- Reorder or disable report sections

Multiple templates can be saved (e.g. "Executive" with fewer sections vs. "Technical" with full detail). Assign a template per case.

---

## What's in the Report

1. Cover page (title, date, classification, investigator)
2. Executive summary (AI-generated or analyst-written)
3. Investigation narrative (attacker path, written prose)
4. Forensic timeline (with severity colour coding)
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
18. Attacker Sessions — the timeline re-threaded as per-host chapters (see [Dashboard → Attacker Sessions](dashboard.md#attacker-sessions)); included in the Standard and Technical Detail templates, left out of the Executive Brief as operator-level detail
19. Compliance Impact — control failures and regulatory notification obligations for confirmed findings, with the same "not legal advice" disclaimer and framework editions as the dashboard panel (see [Dashboard → Compliance Impact](dashboard.md#compliance-impact))
20. Handoff Brief — what the case holds, what is open, what to check next, and the outgoing analyst's Handoff notes from the notebook (see [Dashboard → Handoff Brief](dashboard.md#handoff-brief)); opt-in everywhere — the Technical Detail template switches it on, the Standard and Executive templates never carry it

Sections are enabled/disabled per template — see **Report Customisation** above.

---

## AI-Generated Executive Summary

Click **✨ Generate executive summary** (in Case Details → Executive Summary field). One AI call produces a non-technical summary suitable for management.

## AI-Generated Narrative

Click **✨ Generate narrative**. Produces a flowing prose description of the incident suitable for the "Investigation Narrative" report section.

---

## Presentation Mode

A read-only, step-through slide deck for handoff briefings and executive walkthroughs.

**Open:** toolbar → **▶ Present** (opens in a new tab).

**Export offline:** Export → Presentation deck. Produces a self-contained HTML file that works with no server.

### What's in the Deck

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

### Severity Filter

Set a **minimum severity** filter before opening — only findings/events at or above that level are included. Useful for an executive deck (Critical/High only) vs. a technical deck (everything).

!!! tip
    The deck inherits the **report template** branding (accent colour, cover title, company name) of the current case.
