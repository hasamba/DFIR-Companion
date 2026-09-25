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
- **NTFS timestomp detection (ATT&CK T1070.006)** — MFT imports (`Windows.NTFS.MFT` via Velociraptor, MFTECmd via KAPE) compare a file's `$STANDARD_INFORMATION` and `$FILE_NAME` creation times on the same row and flag likely timestomping as **Medium**: when `$SI` is backdated more than the threshold before `$FN` (default 10 minutes, `DFIR_TIMESTOMP_THRESHOLD_MINUTES`), or `$SI`'s sub-second precision is zeroed while `$FN`'s isn't. The tag shows on the event in the Forensic/Super Timeline. DetectRaptor `*.Detection.MFT` rows get the same check.
- **Copied-binary lead** — an MFT row whose `$SI` last-modified time is earlier than its `$SI` created time (by more than the same threshold) is a file that was **copied** here: NTFS gives the copy a fresh created time but keeps the source's modified time. A renamed `cmd.exe` or a dropped tool looks exactly like this. The row carries `copied file, not timestomp ($SI Created = $FN Created; modified time inherited from the source): modified <t>, created <t>`, but only when the same row shows no timestomping. It changes no grade and adds no technique — the location and name rules already grade attacker tools. When two or more copied files in one import share one modified second, each also carries `[shared source mtime: N copies of one source file, not timestomping]`: they are copies of one source file, such as several tools renamed from one `cmd.exe`.
- **Ransomware note / renamed-file detection (ATT&CK T1486)** — MFT/USN and file-listing imports flag a ransom-note filename or a file renamed with a known ransomware family's extension, aggregated per host and guarded against system-directory false positives so a single note or a mass-renamed share reads as one finding, not thousands. Graded above Info so it survives the most-severe-first event cap. Extend the built-in extension list with `DFIR_RANSOM_EXTS`.
- **RDP lateral-movement detection (ATT&CK T1021.001)** — the `Custom.DFIR.RDPLateralMovementDetection` Velociraptor artifact's explicit-credential logons (EID 4648) are graded **Medium** only when a real user authenticates to a genuinely remote target; local `UMFD-0 → localhost` session-manager noise stays Info so it never manufactures lateral movement that didn't happen.
- **Drive-by download and cloud-exfil tool detection (ATT&CK T1189 / T1567.002)** — an internet-zone (ZoneId 3) runnable or container download is tagged T1189 alongside T1204.002, and `rclone`/`restic`/`megasync`/`megacmd` execution recorded in Prefetch is graded **Medium** with T1567.002 from the process name alone, catching cases where no command-line argument survived collection.
- **Contextual YARA severity** — a YARA hit is graded by where and what it matched, not a flat High: a hit inside the scanning tool's own binary reads as Info, a page-file or memory-dump string as Low (aggregated per host), a broad heuristic rule as Medium (Low on a signed OS binary), and only a named malware family matched on a real on-disk path stays High.
- **Mentioned vs observed indicators** — a hash, IP, domain or URL scraped from free text (a PowerShell script block, a command line, a log message) carries a *mentioned* mark. A value read from a structured column (`Hashes`, `SHA256`, `DestinationIp`, netstat, DNS) is *observed* and wins when both arrive. A mentioned hash is never a file on the host — the synthesis context, the risk score and the STIX label say `mentioned … no file with this hash was observed`; a mentioned address is *referenced*, never *contacted* — no geo flow line, a dashed `referenced` edge in the asset graph, and `referenced in free text; no network record` on every network surface. A Cyber Triage *Active Connection* and a Plaso browser-history or firewall row are network records, so their addresses are *observed*. A mentioned hash or address never counts as behaviourally corroborated in the synthesis context or the risk score — nor does the event that mentions it add severity or cross-tool points (the factors read *mentioned in a High-severity event* / *referenced in events from N tools*), and the IOC table's ⊕ corroboration badge and lenses treat such a value as referenced, not corroborated — and the dashboard IOC table, Notion, MISP and IRIS exports carry the same `mentioned` mark.
- **The case's own collector is not evidence** — a download from the Velociraptor server named in Settings (`DFIR_VELOCIRAPTOR_GUI_URL` / the API config), the client's MSI install and `Velociraptor Service`, tools the client runs from `Program Files\Velociraptor\` (THOR, Hayabusa, …), and a Sysmon *file creation time changed* by `msiexec.exe` (an MSI artifact, not timestomping) are annotated `[DFIR collector …]` and graded Info. Matching is root-anchored; a bare `velociraptor.exe` elsewhere is untouched, and only the system `msiexec.exe` (`\Windows\System32` or `SysWOW64`) counts as the installer. A loopback server address (`localhost`, `127.0.0.1`, `::1`) is never treated as the collector server — from a client's point of view loopback is itself — so a Companion that runs on the Velociraptor server keeps every local connection at its grade. The rules read Hayabusa rows as well as native Windows event rows.
- **Collector-tool and sample-corpus noise suppression** — detection content a tool unpacks to run itself (Sigma rule files, attack-sample event logs it ships, PowerShell modules Windows generates from cdxml) is demoted to Info across the YARA, THOR, ThorZIP, Chainsaw and native-Hayabusa import paths instead of reading as an intrusion on the case host. The collector-root check matches only the collector's own root path, never an attacker-forgeable path component. A row that carries the collector's own identity (a Velociraptor `Fqdn`) is never treated as a sample: a differing `Computer` name on it is the machine's **former hostname** (Vagrant-built images log their provisioning under the box's build name, `WIN-UK1GV882OK6`), noted on the row and summarised once per import as `Host X was named Y until <time>`. The sample-hostname demotion applies only to rows with no collector identity; extend that list with `DFIR_SAMPLE_HOSTS`.

---

## Investigation-Guidance Passes

Automated passes that steer the investigation itself, not just grade individual events:

- **Second-look loop** — after synthesis, open hypotheses/questions plus a model-issued list of evidence requests are resolved against the *complete* super-timeline (not just the sampled window), promoting matching not-yet-analyzed events and triggering one bounded re-synthesis — reaching raw rows the sampler never showed the model.
- **Immediate false-positive cascade** — marking a finding/IOC/event false positive synchronously re-evaluates every key question, next-step, and hypothesis that depended on it, badging them "stale — re-synthesis queued" / "needs review" instead of waiting for the next async synthesis run.
- **Rabbit-hole detection** — findings are scored connected / disconnected / undetermined against the main corroborated evidence-graph component. A disconnected finding (a planted red herring, an unrelated benign event) is demoted and badged "possible rabbit hole" in the Findings panel instead of ranking alongside real leads.
- **ACH-style hypotheses** — hypotheses (see [Hypothesis-Driven Mode](#hypothesis-driven-mode)) now track contradicting evidence, a discriminating host+artifact, and an "exhausted" flag (set once enough linked hunts come back empty), and are ranked fewest-contradictions-first — the classic Analysis-of-Competing-Hypotheses fix for a red herring winning unopposed.
- **Diagnostic evidence** — each hypothesis says which of its observations actually *distinguish* it from a named alternative and which fit every explanation; a supported conclusion names its distinguishing evidence, the alternatives considered and what is unresolved; an analyst can exclude an observation from one assessment with an audit trail, and a frozen judgment whose footing changes is flagged for review with the reason (see [Evidence assessment](#evidence-assessment-does-an-observation-distinguish-the-explanations)).
- **Per-case prevalence baseline + FP-pattern propagation** — the case tracks how often each normalized activity pattern occurs across its timeline, so rare events earn a selection seat over common noise during synthesis. After each import, new events that reproduce an already-dismissed false-positive pattern are flagged for one-click bulk dismissal.
- **Learn from dismissed findings** — repeated reasoned dismissals of the same activity pattern accumulate into a per-case ledger; new activity resembling a repeatedly-dismissed pattern surfaces with lowered (not zero) confidence unless independently corroborated. Shown in the **False Positives** panel.
- **Negative answers name their evidence** — before synthesis, the code builds a collection inventory from what the case actually holds: per host, which evidence (execution, file activity, network, persistence) was collected raw, which sources are only detection feeds, which logs were cleared and when, and what recent Velociraptor hunts returned (no rows, failed, partial, archive only). The model judges every "not observed" answer against it. A key-question answer that denies an activity the case could not have seen is saved as **partial**, says so in its own text, and gets one collection step naming the Velociraptor artifact — or a search-and-promote step when the evidence sits in the archive. A next step that asks for a log the case shows as cleared is demoted and flagged with the clear time. A Velociraptor hunt that came back empty settles an evidence class only when it went to every client (no label, OS, time-window or result filter), and only for the hosts on which it finished without error. Each collect records those hosts, and the hunt's scheduled, finished and failed client counts. A client that never checked in is never scheduled, so the hunt says nothing about it: a "not observed" answer about that host stays partial. A Windows artifact settles only on Windows clients. A hunt collected before this release has no host list, so it settles nothing: collect it again, then re-synthesize.
- **Other commands in this session** — a synthesis names findings by theme, so a lone discovery or staging command (`net view /all`, `tasklist /v`, a dropped `!start.cmd`) can fit no finding. After each synthesis the code lists every such command on the closest finding. It reads only the forensic timeline. A command qualifies when its row is graded Low or higher, carries a command line (or writes a script or binary file), and falls inside an attack session: on a host, the time span of the rows that Medium-or-higher findings cite, split where two cited rows are more than 2 hours apart and widened by 15 minutes on each side. A command that a finding already names is skipped. The closest finding is the one on the same host whose cited rows are nearest in time, then the one that shares the account. The note is not evidence the finding claims, and an entry is hidden while its row is outside the scope window or marked a false positive.
- **Prompt seats for session commands** — the synthesis prompt holds a limited number of events. Before synthesis, a share of those seats is kept for quiet commands: at most a tenth of the cap, never more than 40 rows. A row qualifies when it is graded Low or Medium, carries a command line, and falls inside a session on its own host. Here a session is the span of that host's Critical/High rows and of the rows that Medium-or-higher findings from an earlier run cite, split and widened as above. Each command line gets one seat per host, nearest to a session row first, and hosts take turns so one busy host cannot use every seat. These rows are shown as ordinary rows, not as background context. The evidence mix line reads `N session commands`. When the budget is tight, the seats come first from the context and spread fills, then from the earliest rows, and last from the lowest-ranked Critical/High rows — which still become findings through the high-severity safety net.
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

An alias such as `sonnet` can map to a newer model without any Settings change. When the provider
reports the model that answered, the row shows it after an arrow: `sonnet → Sonnet 5`. A queued or
running row that has no answer yet shows the version this alias answered with most recently:
`sonnet (last run: Sonnet 5)`. Today only the Claude Code provider reports this. Other providers show
the alias alone, because nothing is guessed. Model IDs the dashboard does not recognise, such as an
OpenRouter `vendor/model` path, are shown exactly as the provider sent them. Each synthesis run record
also stores this served model as `resolvedModel`, so a later review of the case can tell which model
version wrote its conclusions.

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

### Evidence assessment — does an observation distinguish the explanations?

Each hypothesis card carries an **evidence assessment**, read across the whole set of hypotheses
from the supporting and contradicting links alone. Every linked observation has one bearing:

- **separates this from '…'** — it supports this hypothesis and contradicts a named alternative.
  This is the only bearing that argues for one explanation over another, and it always names the
  alternative.
- **consistent with the alternatives that assessed it** — it supports this hypothesis and every
  alternative that assessed it. It fits them all and chooses none. Ten of these do not outrank one
  observation that separates.
- **contradiction — supports '…'** — it contradicts this hypothesis and supports a named alternative.
- **contradiction — against every explanation that assessed it** — no hypothesis that assessed it
  accounts for it; the set of explanations may be incomplete. It still counts as a contradiction of
  each hypothesis that lists it.
- **not assessed against the alternatives** — only this hypothesis assessed it. Silence about the
  others is not a judgment about them, so it is never called distinguishing.
- **assessed both ways** — the same hypothesis lists it as support and as contradiction; it counts
  for nothing until you settle it.

The alternatives are every live (not refuted, not exhausted) hypothesis, or the ones you name with
**name the alternatives** on the card when a title is not a real competitor (a different kill-chain
phase, a duplicate). A supported hypothesis with no distinguishing observation, or with no
alternative offered, says so next to its status word — in the panel and in the report, which lists
the distinguishing evidence, the alternatives considered and what is unresolved (a conclusion resting on
one observation names that observation's own recorded uncertainty: an inferred year, a clock
adjustment, no named source artifact).

Ranking within a status group is by fewest active contradictions, then by distinguishing support;
support that fits every alternative ranks nothing. Every number is a count of observations. Nothing
here is a probability that the explanation is true, and nothing should be read as one.

**Exclude** an observation from one hypothesis's assessment when it does not bear on that question
(the reason is required — it is the audit trail). The event stays in the timeline, the link stays
on the hypothesis, every other hypothesis reads the observation as before; **restore** puts it
back and the exclusion stays as history. Unlinking an excluded observation closes the exclusion;
relinking it later needs a new one.

A hypothesis you have edited is frozen against synthesis rewrites. When its footing changes — an
excluded observation now separates it from a new alternative, the observations a supported
conclusion rested on stop distinguishing, a contradiction now supports an alternative, or the
latest synthesis withdrew a support or added a contradiction the frozen copy does not carry — it is
flagged **review required** with the reason. A status change or **✓ reviewed** clears the flag;
editing the notes or the assignee does not.

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

---

## Missed Evidence Review

The deterministic content tagger gets one chance to raise an imported row above `Info`, and it only
raises what its rule set names. Anything it does not recognise stays `Info`, leaves the forensic
timeline, and never reaches the AI — and a tagger rule written next week cannot reach back for it.

This review grades those left-behind rows with **Jev**, a decision model that returns a grade and a
confidence instead of prose. It is fast and cheap enough to read a whole case's archive: about a
thousand rows in a few seconds, for roughly a penny.

**Grading writes nothing.** Running the review changes no case data; the run's cost is the only
thing it records. What you tick is another matter — see *Promoting what it finds* below.

**Run it:** the *Missed evidence review* panel. The table is ranked by grade, highest first.

**Read it with the confidence column.** The grade says what; the confidence says whether to trust it.
A Medium at 0.9 is worth your time; a Medium at 0.3 is the model telling you it is guessing.

**Filter the tooling.** The most common false positive is your own collection kit: the agent's
binary and service, and the detection packs' rule files, whose names read like the tools they hunt
(`proc_access_win_pypykatz_cred_dump_lsass_access.yml` is a rule, not Mimikatz). The panel scores
each row for this and hides the obvious ones by default.

**Coverage is always stated.** The caption gives the true number of matching rows, how many were
read, how many were skipped as already analysed, and how many were graded. Each is a separate fact,
because only some of them have a single cause — a shortfall is not evidence the cap was reached.

**Promoting what it finds.** Tick the rows worth keeping and promote them into the forensic
timeline — the record the AI reads. A promoted row takes **the severity the model gave it**, because
an `Info` row is invisible to synthesis and a promotion that kept the old grade would change
nothing. The row is stamped with the review, the grade, the confidence and the model that gave it,
so a model's severity can never be mistaken for a tagger rule's or an analyst's own. A promotion can
only raise a severity, never lower one. Rows already in the timeline are skipped rather than
refused, and the reply says what was skipped and why; sandbox rows are refused outright. Promoting
does not re-run the AI — press **AI Re-synthesize** when you have finished picking.

**Read every row** when you want a full pass. An ordinary press stops at `DFIR_JEV_MAX_ROWS`; the
panel offers an uncapped run that pages through the whole archive and says so in the caption. On a
large case that costs more and takes longer, so the panel estimates both before it starts.

!!! note "Masking applies"
    Row text goes through the same anonymisation gate as every other model call. There is no
    un-masking step and none is needed — a Jev answer is a number, so no real value can travel back
    inside it. Tokenising paths and addresses barely affects the grades, because what makes a row
    suspicious is the action, not the hostname.

### Settings

| Setting | Default | What it does |
|---|---|---|
| `DFIR_JEV_ENABLED` | off | Turns the panel on. |
| `DFIR_JEV_PROVIDER` | `openrouter` | `openrouter` or `typesafe`. |
| `DFIR_JEV_MODEL` | `typesafe/jev-1.13` | `jev-latest` on the `typesafe` provider. |
| `DFIR_JEV_KEY` | blank | Blank on OpenRouter inherits your existing OpenRouter key. Required on `typesafe`. |
| `DFIR_JEV_MAX_ROWS` | 2000 | Rows one ordinary press reads. A default, not a ceiling — the panel can read every row. |
| `DFIR_JEV_BATCH_SIZE` | 40 | Rows per request. |

!!! warning "The model id is versioned"
    On OpenRouter the id is `typesafe/jev-1.13`. `typesafe/jev-latest` does not exist there and
    returns a 400 — the `latest` alias only works against TypeSafe's own endpoint.
