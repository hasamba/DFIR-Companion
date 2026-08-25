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

**Cross-tool command-line correlation** — process-creation events that describe the *same* creation but come from different tools (e.g. Sysmon and an EDR) with different pids and no shared file hash are merged into one timeline row when they share a normalized command line + parent process + host within a window (default 60s, `cmdlineWindowSeconds`). A same-tool corroboration guard keeps genuinely distinct commands from one tool separate, so kill-chain steps are never collapsed into each other. Deterministic, no AI.

---

## Content-Based Event Tagger

A Timesketch-style rule engine (`tags.yaml`) that matches events on any real field (`contains` / `equals` / `regex` / `exists`) and, on a match, tags the event, raises its severity, and unions in MITRE techniques. Runs automatically after every import, or on demand from **Super-Timeline → Content tagger**.

**AI-assisted rule authoring** — describe a rule in plain English and the AI drafts a valid `tags.yaml` rule you can preview (live match count against the open case), edit, and add. Includes per-rule remove (including shipped defaults) and a reset-to-defaults button. Uses the ejectable prompt `tagger-rule.txt` (`npm run prompts:eject`). AI-gated — falls back cleanly with no provider configured.

---

## Detection Passes

Deterministic, no-AI passes that run automatically during import and grade or tag matching events:

- **SSH brute-force-success detection (ATT&CK T1110.001)** — the syslog importer correlates sshd auth lines and flags a successful login (`Accepted password/publickey`) that follows a burst of failures (default ≥5 within 60 minutes, `DFIR_SSH_BRUTEFORCE_MIN_FAILS` / `DFIR_SSH_BRUTEFORCE_WINDOW_MIN`) from the same source IP as **Medium**, with the failure count and source IP in the description.
- **Windows logon-type risk grading** — successful-logon (4624) events decode the logon-type code into a readable name (e.g. "RemoteInteractive/RDP from 203.0.113.9") and grade the risky shapes: external RDP (type 10 from a public IP) and internet-facing network logons (type 3) → **Medium** (T1021.001/T1078), plus NetworkCleartext (8) and NewCredentials/`runas /netonly` (9) → **Medium** (T1078/T1550.002). Internal interactive logons stay Low. Applies across the SIEM/EVTX, Chainsaw, and Velociraptor import paths.
- **Lookalike / typosquat domain detection** — an offline "Lookalike Domain" enrichment provider flags domain IOCs that imitate a bundled list of commonly-impersonated brands (Microsoft, Google, Okta, PayPal, banks, crypto exchanges…) via homoglyph-skeleton matching (including IDN/punycode and Cyrillic/Greek confusables), edit distance, and brand-token impersonation → `suspicious` verdict (T1566/T1583.001). Runs entirely on-box — nothing is sent anywhere — so it's on by default. Add your own domains via `DFIR_LOOKALIKE_EXTRA_DOMAINS`.
- **NTFS timestomp detection (ATT&CK T1070.006)** — MFT imports (`Windows.NTFS.MFT` via Velociraptor, MFTECmd via KAPE) compare a file's `$STANDARD_INFORMATION` and `$FILE_NAME` creation times on the same row and flag likely timestomping as **Medium**: when `$SI` is backdated more than the threshold before `$FN` (default 10 minutes, `DFIR_TIMESTOMP_THRESHOLD_MINUTES`), or `$SI`'s sub-second precision is zeroed while `$FN`'s isn't. The tag shows on the event in the Forensic/Super Timeline.

---

## Investigation-Guidance Passes

Automated passes that steer the investigation itself, not just grade individual events:

- **Second-look loop** — after synthesis, open hypotheses/questions plus a model-issued list of evidence requests are resolved against the *complete* super-timeline (not just the sampled window), promoting matching not-yet-analyzed events and triggering one bounded re-synthesis — reaching raw rows the sampler never showed the model.
- **Immediate false-positive cascade** — marking a finding/IOC/event false positive synchronously re-evaluates every key question, next-step, and hypothesis that depended on it, badging them "stale — re-synthesis queued" / "needs review" instead of waiting for the next async synthesis run.
- **Rabbit-hole detection** — findings are scored connected / disconnected / undetermined against the main corroborated evidence-graph component. A disconnected finding (a planted red herring, an unrelated benign event) is demoted and badged "possible rabbit hole" in the Findings panel instead of ranking alongside real leads.
- **ACH-style hypotheses** — hypotheses (see [Hypothesis-Driven Mode](#hypothesis-driven-mode)) now track contradicting evidence, a discriminating host+artifact, and an "exhausted" flag (set once enough linked hunts come back empty), and are ranked fewest-contradictions-first — the classic Analysis-of-Competing-Hypotheses fix for a red herring winning unopposed.
- **Per-case prevalence baseline + FP-pattern propagation** — the case tracks how often each normalized activity pattern occurs across its timeline, so rare events earn a selection seat over common noise during synthesis. After each import, new events that reproduce an already-dismissed false-positive pattern are flagged for one-click bulk dismissal.
- **Learn from dismissed findings** — repeated reasoned dismissals of the same activity pattern accumulate into a per-case ledger; new activity resembling a repeatedly-dismissed pattern surfaces with lowered (not zero) confidence unless independently corroborated. Shown in the **False Positives** panel.
- **Per-source noise/trust scores** — every event source carries a trust weight (CrowdStrike/Defender detections > Sigma-engine hits > raw Velociraptor artifacts > generic logs), used to pick the canonical wording when correlating duplicate detections and to cap confidence on findings supported only by low-trust sources. Analysts can override a source's trust per case in the dashboard.

---

## Synthesis Grouping & Budget

How the AI synthesis prompt decides which events earn one of its limited row seats, on a detection-heavy or multi-host case where the raw event count can outrun any reasonable per-call budget.

- **`DFIR_SYNTH_GROUP`** (default on) — repeated hits of the same detection collapse into one prompt entry with hit count/host spread/time span instead of one row per hit; `DFIR_SYNTH_GROUP_GAP_SECONDS`/`DFIR_SYNTH_GROUP_MIN_REPEATS` tune the collapse window/threshold. Affects the AI prompt only — the case, timeline, and findings are untouched.
- **`DFIR_SYNTH_INCLUDE_INFO`** (default off) — Info-severity events no longer compete with graded detections for prompt seats; set to `1` to restore the old behaviour.
- **`DFIR_AI_SYNTH_MAX_EVENTS`** (default 600, raised from 300) — the per-run synthesis event cap; grouping roughly halves the row count, so 600 now covers about what 300 used to.

See also [Deep Pass](dashboard.md#deep-pass) for the analyst-triggered batched run that reads every graded event regardless of this per-call budget.

---

## State Backups & Restore

The server automatically backs up all per-case state (findings, timeline, IOCs, playbook, etc.) before each synthesis run and every hour.

View and restore backups in **Settings → Diagnostics → Per-case backup list**. One click restores to any saved state.

A restore overwrites the live state wholesale, so it is refused while an import, synthesis, enrichment, or deep pass is running for that case — the job would save over the restored state moments later. Cancel the job from the **jobs badge in the top toolbar** (or let it finish), then restore.

Configure in the same tab: `DFIR_STATE_BACKUP_RETAIN` (max backups kept per case, oldest pruned; default 24 — 0 asks for no limit but is capped at 100, since each backup is a full copy of the case state and an uncapped dir will fill the disk), `DFIR_STATE_BACKUP_PRE_SYNTH_RETAIN` (how many pre-synthesis backups are preserved on top of that cap, so interval backups can't crowd them out; default 10), `DFIR_STATE_BACKUP_INTERVAL_MS` (time-based backup interval; default 1h, 0 = off), `DFIR_STATE_BACKUP_MAX_BYTES` (disk budget for one case's backups; default 10 GiB, 0 = no byte cap).

The two retention numbers bound how *many* backups a case keeps, not how much disk they take — a single bundle can run to hundreds of megabytes, so 34 of them is tens of gigabytes. `DFIR_STATE_BACKUP_MAX_BYTES` bounds the total: once a case's backups exceed it, the oldest are evicted until they fit. Two are never evicted — the newest backup, so a case always keeps a recovery point, and the newest pre-synthesis backup, so the rollback path survives. That means a case whose newest snapshot alone exceeds the budget stays over it; **Settings → Diagnostics → State backups** reports the budget and flags any case in that position. The budget is per case, not per host: a global one would delete one investigation's snapshots because a different case grew. For host-level disk pressure see `DFIR_DISK_WARN_PCT`.

---

## Restart-safe Background Jobs

The jobs badge in the top toolbar is rebuilt from a durable ledger whenever the dashboard connects.
It shows queued and running work plus recent outcomes, progress, speed, ETA, warnings, and the last
committed checkpoint.

A row that an AI model drives also names that model — synthesis, Deep Pass, and CSV/log imports,
all of which run the text model (`DFIR_AI_SYNTH_MODEL`, falling back to the vision model). The name
is recorded when the job is queued, not read back from Settings when the row is drawn, so a finished
run still names the model that produced it after you point synthesis somewhere else. Rows with no
model named run none: enrichment is HTTP lookups, a non-CSV/log import parses locally, and an MCP
run uses whatever model the Claude Code CLI defaults to unless `DFIR_MCP_MODEL` sets one.

If the server stops during an import or Deep Pass, the old running row becomes **interrupted** on
startup instead of disappearing. A **Resume** button appears only when that job saved restart-safe
parameters and still has retry attempts left. CSV/log imports continue after the last evidence batch
that reached durable case storage; Deep Pass continues after its last saved observation batch.
Resuming reuses the same job ID and does not append a second custody receipt for the evidence.

Cancellation is final for that attempt. Work already committed before a cancellation remains in the
case; queued work is cancelled before it can start. Other failures explain whether they are retryable.
Use `DFIR_JOBS_CONCURRENCY` and `DFIR_JOBS_PER_CASE` under **Settings → Diagnostics** to tune capacity;
the default per-case limit reserves room for other investigations.

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

Hypotheses survive synthesis (unlike findings, which are replaced each time) and are included in the encrypted case archive export.

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
