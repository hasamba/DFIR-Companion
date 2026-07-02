# Advanced Features

## Anonymisation

Enabled by default for external AI providers. Tokenises PII and IOC values before sending to the model. The mapping is maintained per-case, so your timeline and findings always show real values.

Categories tokenised: IPs, hostnames, usernames, domains, file paths, hashes, PowerShell encoded blobs, Windows SIDs (well-known ones like SYSTEM are preserved).

Toggle: **Settings → AI → Anonymisation**, or the per-case AI control panel.

---

## Investigation Scope

Set a time window for the investigation. Only events within the scope window are fed into synthesis. Events outside scope are preserved in the timeline but grayed out and excluded from findings/attacker path.

**Set scope:** the scope bar at the top of the forensic timeline (date pickers), drag on the swimlane, or `POST /cases/:id/scope`.

!!! tip
    Use scope when a case has pre-incident background noise, or you're narrowing focus to a specific attack window.

---

## Correlation Profile

Controls how aggressively the system deduplicates events from multiple tools.

Settings → Per-case → Correlation Profile:

| Profile | What it does |
|---------|--------------|
| **Strict** | Only exact duplicates are merged (same timestamp + description) |
| **Moderate** (default) | Also merges events with the same hash or path within a short time window |
| **Aggressive** | Wider time windows for path/hash matches |

Use Aggressive when you have many tools all logging the same events differently. Use Strict when tools legitimately report the same artifact at different times for different reasons.

---

## State Backups & Restore

The server automatically backs up all per-case state (findings, timeline, IOCs, playbook, etc.) before each synthesis run and every hour.

View and restore backups in **Settings → Diagnostics → Per-case backup list**. One click restores to any saved state.

Configure: `DFIR_STATE_BACKUP_RETAIN` (how many per-synthesis backups to keep), `DFIR_STATE_BACKUP_INTERVAL_MS` (timer interval).

---

## Preflight Diagnostics

On startup, the server runs a self-test and logs OK/WARN/CRITICAL for:

- AI provider (live probe)
- Velociraptor (live probe)
- Local enrichment instances — MISP, YETI, OpenCTI (live probe)
- Other configured providers (reported as "configured" but not probed — OPSEC: no automatic third-party calls)

A red banner appears in the dashboard if a critical check fails (typically: AI not configured or key invalid).

Re-run on demand: Settings → Diagnostics → Pre-flight check.

Disable permanently: Settings → Diagnostics → disable pre-flight (for setups without AI).

---

## Exfiltration Correlation

A deterministic pass stitches archive **staging** (Compress-Archive/zip/tar/7z) to a subsequent **upload** on the same host within a bounded window (6 hours by default). The sequence — not the destination — is the signal: a lone upload to routine SaaS/cloud infrastructure is never escalated, but staging followed by upload anywhere raises the upload to **High** and tags it `[confirmed exfiltration: …]`.

Synthesis is told to give a confirmed staging→upload pairing its own dedicated **"Data Exfiltration"** finding (with T1041, plus the named cloud service's technique if applicable) instead of folding it into a generic C2/beacon finding.

---

## Phishing → Initial-Access Correlation

When a host later contacts a domain that a phishing email linked to, that contact event is tagged as initial access (upgraded from T1566.002 to **T1204.002**) and raised to at least Medium severity. This gives synthesis a real entry-vector root instead of concluding "began via an unknown vector."

The correlation uses only the link domains extracted from the email — never sender or recipient domains — and is conservative and idempotent.

---

## Hypothesis-Driven Mode

The **Hypotheses** panel lets you track explicit investigation hypotheses. Open hypotheses are fed into synthesis as context, steering the AI to look for supporting or refuting evidence.

Auto-generated hypotheses come from: synthesis conclusions, timeline-gap analysis, and adversary-hints next-technique suggestions.

Analyst-added hypotheses: click **+ Add hypothesis** in the panel.

Hypotheses survive synthesis (unlike findings, which are replaced each time) and are included in investigation snapshots.

---

## CISA KEV Cross-Reference

Enable in **Settings → KEV**. CVEs mentioned in findings and events are cross-referenced against the CISA Known Exploited Vulnerabilities catalog. KEV-listed vulnerabilities are highlighted and mentioned in synthesis context, nudging the AI to treat them with appropriate urgency.

---

## Demo Mode

Set `DFIR_DEMO_MODE=true` in `.env`. All mutating routes are blocked. A demo case is pre-seeded. The demo case auto-resets hourly (`DFIR_DEMO_RESET_HOURS`). Useful for training or public demonstrations.

---

## Mobile Companion

A read-only installable PWA (Progressive Web App) at **http://127.0.0.1:4773/mobile**.

Add it to your phone's home screen for a quick-glance view of the active investigation:

- Findings (worst first)
- Recent forensic events (most severe / most recent)
- IOCs (flagged first, with worst threat-intel verdict)
- Severity and entity counts

Lists are capped for mobile performance but the totals are shown. No editing, no AI calls — read only.
