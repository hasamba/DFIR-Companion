# Changelog

All notable changes to DFIR Companion are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Maintainer note:** update this file **with every version tag**. Add the changes
> under `[Unreleased]` as you go, then on release rename that section to the new
> version + date, bump the version in `companion/package.json`, `extension/package.json`,
> and `extension/manifest.json`, and create an annotated `vX.Y.Z` tag on the same commit.

## [Unreleased]

### Added
- **Process-chain validation (RockyRaccoon)** — when enrichment is on, parent→child process
  relationships on the forensic timeline (e.g. THOR ProcessCheck's process + parent) are checked
  against ~346M execution events. An **unobserved chain** (like `excel.exe → powershell.exe`) is
  flagged on the event with a red "⚠ unusual parent" badge + note; a seen chain gets a green "⛓
  chain seen". Deduplicated per distinct (parent,child) pair, throttled/capped/cached like IOC
  enrichment. THOR import now captures `processName`/`parentName` (basenames) on events.
- **Threat-intel IOC enrichment** — look up the case's IOCs (hashes/IPs/domains/URLs) on
  **VirusTotal** (hash/IP/domain/URL), **MalwareBazaar** (hash), **AbuseIPDB** (IP), and **MISP**
  (your own instance — `DFIR_MISP_URL` + `DFIR_MISP_KEY`), and **RockyRaccoon** (Windows
  **process** behavioral intel — prevalence / LOLBIN / risk level / expected parent / ATT&CK,
  `DFIR_ROCKYRACCOON_KEY`; the first source that can enrich the process IOCs we extract),
  annotating each IOC with a verdict (malicious/suspicious/harmless/unknown), score, classification tags, and a
  permalink — shown as colored badges on the dashboard and in the IOC CSV. **OPSEC-first: it is a
  per-case toggle, default OFF** (`GET/POST /cases/:id/enrich-control`, **Enrich: ON/OFF** button) —
  nothing is queried until the analyst opts in (with a confirm prompt). Turning it **on** enriches the
  current IOCs and **auto-enriches IOCs added later** (imports/synthesis). Keys are per-provider env
  vars (`DFIR_VT_KEY`, `DFIR_MB_KEY`, `DFIR_ABUSEIPDB_KEY`); results are cached on the IOC, throttled
  (`DFIR_ENRICH_DELAY_MS`), and capped (`DFIR_ENRICH_MAX`, hashes/IPs first). A manual one-shot
  `POST /cases/:id/enrich` (with `{ force }`) is also available. Providers use an injectable fetch
  (no network in tests).
- **Cross-source correlation & duplicate collapsing** — the same real-world artifact is now
  merged into a single forensic event instead of duplicating. Three deterministic match rules:
  an **exact duplicate** (same event time + description — collapses **re-imports of the same
  file** and any event type), a shared file **hash** (sha256/md5, from structured fields or
  extracted from the description), or the same **path within a time window**
  (`DFIR_CORRELATE_WINDOW_S`, default 2s). Correlation runs on **every merge** (so importing a
  report twice no longer doubles the timeline — not just during synthesis). The merged event
  takes the most-severe level and unions every tool as a `source`, so two tools flagging one
  file drive **one finding** (with both as evidence). The dashboard shows a `⊕ N sources`
  corroboration badge; reports gain a `sources` column. Forensic events gained optional
  `sha256`/`md5`/`path`/`sources` fields (THOR populates them; sources show the real tool name). Sources show the
  **real tool name** — detected from the import filename or the captured browser tab title
  (e.g. "Velociraptor", "CrowdStrike Falcon", "Splunk", "Sysmon") rather than the generic
  import type — so corroboration reads "Velociraptor + THOR".
- **THOR (Nextron) scanner import** — `POST /cases/:id/import-thor` and an **Import THOR**
  dashboard button accept a THOR JSON-Lines report (`thor --jsonfile`). Findings map
  **deterministically** to the timeline + IOCs (no AI extraction call): `level` → severity
  (Alert→Critical / Warning→High / Notice→Medium), each finding's own artifact time is read
  (process create / file mtime, not the scan time), hashes/files/processes/IPs become IOCs,
  and identical findings collapse with a count. Scan noise is dropped by default —
  `level:"Info"` rows and lifecycle modules (`Init`, `Startup`, `Control`, `ThorDB`, `Report`)
  — e.g. a 1416-line report reduces to ~177 real findings. An optional **severity floor**
  (`minLevel`: `alert` / `warning` / `notice`, prompted in the dashboard) trims volume
  further — on that report, 177 → 154 (Warning+) → 22 (Alert only).

### Fixed (continued)
- **Correlation no longer shows a bogus "2 sources" / "unknown source".** A source-less event
  (from a build before the `sources` field existed) was being labelled `unknown source` and
  counted toward corroboration, so a single-tool (THOR-only) event wrongly showed `⊕ 2 sources`.
  Source-less events now contribute no source; the badge counts only real tools. Also stopped
  mutating the event description with a `[corroborated by …]` note (it was ugly and, worse,
  changed the dedup key so re-imports stopped collapsing) — corroboration is shown only via the
  `sources` field/badge. Old polluted descriptions self-heal on the next merge/synthesis.
- **Tolerate truncated AI JSON responses.** A large synthesis (e.g. from a THOR import)
  could exceed `max_tokens` and get cut off mid-array → `Expected ',' or ']' after array
  element` parse error. The parser now repairs a truncated response (trims to the last
  complete object, closes open brackets) so the findings that did arrive are kept — and the
  high-severity backfill fills any dropped finding. Also raised the default `max_tokens`
  16000 (from 8192) to reduce truncation while staying bounded against the 402 issue.

### Changed
- **Bounded AI requests to fix spurious OpenRouter `HTTP 402`.** Provider calls now send
  `max_tokens` (default 8192, `DFIR_AI_MAX_TOKENS`) — without it OpenRouter reserves the
  model's full max output in its per-request credit check and can 402 a large request
  (e.g. THOR synthesis) even when the account has credits. The synthesis prompt is also
  capped to the most-severe N events (default 300, `DFIR_AI_SYNTH_MAX_EVENTS`) and echoes
  at most 150 existing findings, keeping big imports affordable and within context. The
  Critical/High safety net still creates findings for any event omitted from the prompt.
- **Synthesis now preserves IOCs** instead of wiping them. IOCs are observed indicators
  (often hundreds of hashes from a deterministic import like THOR that the text-only
  synthesis can't re-derive), so they are kept and merged (deduped by value); scope and
  legitimate filtering still apply at projection. Findings/MITRE/attacker-path are still
  replaced each synthesis.

### Fixed
- **EDR/XDR _and_ SIEM detections now reliably enter the timeline & findings.** The extraction
  prompt was Velociraptor-centric and the "navigating a dashboard isn't an event" rule was making
  the model dismiss a CrowdStrike/Defender-for-Endpoint/SentinelOne *detections console* — and
  equally a Splunk/Elastic/Sentinel/QRadar *alerts console* — as navigation. Generalized the
  evidence sources, added an explicit "EDR/XDR & SIEM detection = evidence (extract each detection/
  alert/notable/offense as an event + finding)" rule with CrowdStrike and Splunk/Elastic examples,
  and narrowed the navigation exclusion to bare empty tool pages. Extended the incident-signal
  allowlist (EDR vendors, IOA/"malicious file"/"parent process killed", MITRE technique ids like
  T1110, SIEM alert content — notable event / correlation rule / sigma / offense / brute force,
  and common LOLBins) so a real detection is never dropped, while bare navigation ("Access to
  Splunk") still is.

## [0.2.0] - 2026-06-02

Pre-1.0 feature milestone. Localhost forensics companion + MV3 capture extension.

### Added
- **Mark a forensic timeline event legitimate** — a per-event ⚑ action (like findings/IOCs).
  Reversible: the event is hidden from the timeline view and excluded from synthesis input,
  but the raw event is preserved in state, so un-marking fully restores it. Reports honor it too.
- **Severity-aware findings** — a Critical/High Severity/Level/Criticality column (e.g. a
  Microsoft Defender / EDR detection) is treated as a finding by default. A deterministic
  safety net auto-creates a finding (`f-auto-<eventId>`, **AUTO** badge in the dashboard) for
  any in-scope, non-legitimate Critical/High event that synthesis left uncovered, so a severe
  detection can never be silently missed.
- **Configurable server port** via `DFIR_PORT` (default `4773`; validated, falls back with a warning).
- **Captured tab title in screenshot filenames** (`000123_<ts>_<slug>.webp`) — slugified,
  OS-reserved characters stripped, capped length, clean fallback when the title has no safe chars.
- **Expanded README CLI reference** — every `DFIR_*` env var, all npm scripts and flags, and
  runnable examples.

### Changed
- **Log import is now deduplicated + AI-triaged.** Repetitive lines (firewall/VPN/syslog) are
  deterministically collapsed into counted patterns *before* the AI sees them; the model then
  emits **one aggregated event only for security-relevant patterns** and skips routine noise.
  Forensic events gained optional `count` / `endTimestamp`; the dashboard shows a `×N` badge and
  time span, and reports include the new columns. (Previously: one timeline row per log line.)
- **Extraction prompt rebalanced** to extraction-first, with an explicit "Critical/High row ≈ a
  finding" rule and a "describe events by what happened, not the tool you saw them in" rule.

### Fixed
- **Analyst-workflow narration** ("data collection with Velociraptor", "Surveying the DFIR
  Companion Dashboard", "analysis completed") no longer enters the forensic timeline.
- **Tool/UI navigation narration** ("Access to VolWeb", "VolWeb access observed", "Access to
  Syslog Dashboard - Elastic") no longer enters the forensic timeline.
- **Real threats are never dropped** — an incident-signal allowlist (malware/tooling names,
  exe/script paths, IPs, hashes, logons, Defender/Sysmon/EDR verdicts) overrides the work-log
  filter, so a genuine detection survives even if the model phrases it with a tool name.

## [0.1.0] - 2026-06-01

Initial baseline.

### Added
- **Localhost companion server** (`127.0.0.1:4773`) and **MV3 capture extension** that POSTs
  active-tab screenshots as evidence.
- **Evidence-first ingest** — screenshots written to disk with an append-only `captures.jsonl`
  audit line before any analysis; perceptual-hash duplicate detection.
- **Two-phase AI analysis** — cheap per-window vision **extraction** into a forensic timeline,
  then a strong text-only **synthesis** pass producing findings, IOCs, MITRE ATT&CK, attacker-path
  narrative, key investigative questions, and investigation threads.
- **Provider abstraction** (OpenAI, OpenRouter, Ollama Cloud, Gemini) with injectable fetch and
  configurable timeout; **two-tier models** (`DFIR_AI_MODEL` extraction / `DFIR_AI_SYNTH_MODEL`
  synthesis); high-detail image tiling (`DFIR_AI_IMAGE_DETAIL`) for small-text OCR.
- **Investigation scope** (time window) with deterministic re-projection; **mark findings/IOCs
  legitimate**; **per-case AI on/off** with capture-only mode and backfill on resume.
- **CSV (Velociraptor/EDR) import**; live **dashboard** over WebSocket; **Markdown / CSV / JSON**
  report exports.
- Scripts: `dev`, `reanalyze`, `synthesize`, `coverage`, `verify:ai`, `clean-timeline`.

[Unreleased]: https://github.com/hasamba/DFIR-Companion/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/hasamba/DFIR-Companion/releases/tag/v0.1.0
