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
| **Investigation snapshot** | Portable JSON of the entire investigation state |
| **Redacted case package** | The full case with anonymized AI input — shareable for model debugging without exposing evidence |

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
