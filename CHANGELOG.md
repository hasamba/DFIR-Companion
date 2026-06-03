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
- **THOR (Nextron) scanner import** — `POST /cases/:id/import-thor` and an **Import THOR**
  dashboard button accept a THOR JSON-Lines report (`thor --jsonfile`). Findings map
  **deterministically** to the timeline + IOCs (no AI extraction call): `level` → severity
  (Alert→Critical / Warning→High / Notice→Medium), each finding's own artifact time is read
  (process create / file mtime, not the scan time), hashes/files/processes/IPs become IOCs,
  and identical findings collapse with a count. Scan noise is dropped by default —
  `level:"Info"` rows and lifecycle modules (`Init`, `Startup`, `Control`, `ThorDB`, `Report`)
  — e.g. a 1416-line report reduces to ~177 real findings.

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
