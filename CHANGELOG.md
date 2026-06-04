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
- **`npm run yeti -- <indicator>` CLI lookup.** Quickly check one or more indicators (IP / domain / hash /
  URL) against your YETI instance from the command line, using the same auth + search path as the
  companion (reads `DFIR_YETI_*` from `.env`, so no key copy-pasting). Prints verdict, tags, and the
  observable link — handy for confirming YETI connectivity and triaging indicators outside a case.
- **Timestamped server log + per-call enrichment audit lines.** Every server console line now starts
  with an ISO-8601 timestamp (e.g. `2026-06-04T17:54:26Z [req] POST /captures -> 201`). Each outbound
  threat-intel API call is logged as `[enrich] <case> <provider> <kind> <indicator> -> hit|miss|error
  (<detail>) <ms>` — so you can watch exactly which provider (MISP / YETI / …) was hit, for which
  indicator, the result/verdict (or the error message), and the latency. Each enrichment run also logs a
  `START`/`DONE` summary line. The pure `enrichService` exposes this via an injectable `onLookup` hook;
  the previously-swallowed provider error message is now surfaced.

### Fixed
- **YETI tags are now parsed correctly (v2 object shape).** YETI v2 returns an observable's tags as an
  array of objects (`{ name, fresh, … }`), but the provider stringified them — so badges showed
  `[object Object]` and, worse, the malicious-tag check ran against that string and **never matched**, so
  a YETI hit was always capped at `suspicious` and could never escalate to `malicious`. The parser now
  reads each tag's `name` (still tolerating the legacy string / dict shapes), so real tag names show and
  a `malware`/`trojan`/`c2`/… tag correctly escalates the verdict.
- **A failed enrichment call is no longer cached as "checked."** Previously every provider in a run was
  recorded in the IOC's `enrichedBy` — even ones whose call *threw* — so a transient outage or a
  misconfiguration (e.g. an `https://` URL on a plain-HTTP YETI host) permanently suppressed that
  provider until a forced re-run. Now only providers whose call **succeeded** (hit or miss) are recorded;
  an errored provider stays un-checked and is retried automatically on the next run. A provider's
  last-known hit is also preserved if a later (forced) re-query errors, instead of being wiped.
- **`EPERM` on state save in a synced folder.** When `cases/` lives inside Dropbox / OneDrive (or
  with some antivirus), the client briefly locks `investigation.json` while syncing, so the atomic
  `rename(tmp → target)` failed with `EPERM` mid-analysis. All per-case writes now go through a shared
  `atomicWrite` that **retries the rename through a transient lock** (`EPERM`/`EBUSY`/`EACCES`) with a
  short backoff. (Tip: for best results, point `DFIR_CASES_ROOT` at a path **outside** your synced
  folder — case data is local/gitignored anyway.)

### Changed
- **Per-source enrichment selection (OPSEC).** Enrichment is no longer all-or-nothing: each source is
  **local** (your own MISP / YETI instance — queries stay on-box) or **external** (VirusTotal, AbuseIPDB,
  MalwareBazaar, RockyRaccoon — sends indicators off-box). The dashboard **Enrich** button opens a
  per-source picker grouped Local/External with a clearer OPSEC explanation; the **default is local-only**
  (so enabling enrichment is OPSEC-safe by default), and turning on an external source still prompts a
  confirm. **Enabling a source re-checks every IOC on it** — enrichment now caches per (IOC, provider) via
  a new `enrichedBy` field, so a newly-added source queries all existing IOCs while already-checked ones
  (hit or not) are skipped. Legacy `{ enabled }` controls still load. New control shape:
  `GET/POST /cases/:id/enrich-control` exchange `{ providers: [{ name, scope, enabled }] }`.

## [0.5.0] - 2026-06-04

### Changed
- **Synthesis is cheaper and smarter.** (1) **Skip-if-unchanged** — the live, debounced synthesis
  no longer re-calls the model when the in-scope timeline / IOCs / scope / legitimate markers are
  identical to the last run (the explicit **Synthesize** button still forces a run). (2) **Stratified
  event selection** — instead of "top-N by severity", the prompt keeps all Critical/High events, the
  earliest (initial-access) events, and an even time-spread sample, in chronological order, for better
  kill-chain coverage. (3) **Grounded context** — a compact *compromised assets ← IoCs* and
  *threat-intel verdicts* digest is added to the synthesis prompt so findings/attacker-path are based
  on corroborated structure, not blind inference.

### Added
- **Investigator comments (collaboration)** — attach comments to any case entity (forensic event,
  finding, IOC, key question, thread) via a 💬 chip that opens a thread to read/add/delete comments.
  Each comment carries an author (a per-browser "your name" field) and timestamp. Stored per case in
  `state/comments.json` (never wiped by synthesis); changes broadcast over the WS so collaborators see
  them live. Endpoints `GET`/`POST /cases/:id/comments` and `DELETE /cases/:id/comments/:commentId`.
- **Drag-to-reorder dashboard sections** — each section header has a ⠿ grip; drag to reorder, and
  the layout persists per-browser (localStorage) across reloads. Default order now leads with
  **Ask the AI** (first), with Compromised Assets above Investigation Threads.
- **Ask the AI about the case** — a dashboard panel (and `POST /cases/:id/ask`) to ask free-form
  questions ("was data exfiltrated?", "was a USB connected?"). Single-shot, grounded in the case's
  evidence digest (assets, IOCs+verdicts, attacker path, findings, timeline); returns an answer + a
  status (answered/partial/unknown) and, when unknown, **concrete collection guidance** — which
  artifact to examine and where (registry keys, event-log channels, log sources, Velociraptor
  artifacts). An **Add to open questions** button (`POST /cases/:id/questions`) pins the question to
  the case's key questions; synthesis preserves pinned questions and **auto-answers them** once the
  evidence supports it (race-safe: a question added during a synthesis is re-merged at save time).
  `ASK` joins the customizable prompts.
- **Import external screenshots** (dashboard) — an *Import Screenshots* button with **multi-select**
  sends each image (PNG/JPEG/WebP) through the same `POST /captures` ingest path the extension uses,
  so they're stored as evidence, logged in `captures.jsonl`, and analyzed (when AI is on). The batch
  is windowed normally and the last image flushes the trailing window. Reports imported / duplicate /
  failed counts.
- **Customizable AI prompts** — override any of the four built-in prompts (`SYSTEM` per-screenshot
  extraction, `CSV`, `LOG`, `SYNTH` holistic synthesis) from `companion/.env`: `DFIR_AI_<NAME>_PROMPT`
  for inline text, or `DFIR_AI_<NAME>_PROMPT_FILE` to point at a file. The file is re-read on every
  AI call, so editing it applies on the next analysis with **no server restart**; an empty/unreadable
  file falls back to the built-in prompt with a warning. `npm run prompts:eject` writes the four
  defaults to `./prompts` to start from.

## [0.4.0] - 2026-06-04

### Added
- **Compromised assets + asset↔IoC graph** — forensic events now carry the **affected host**
  (`asset`), populated deterministically from THOR (scanned hostname) and from CSV/Velociraptor
  imports + screenshots via the model. A new `assetGraph` module derives the victim **assets**
  (hosts, plus accounts parsed from `DOMAIN\user`/UPN) and the **IoCs that touched each**. The
  dashboard gains a **Compromised Assets** section (names only — hosts and users) and an interactive
  **asset ↔ IoC graph** with per-type toggles (Host / Account / Service), **Fullscreen**,
  **Horizontal / Vertical / Radial** layouts, **zoom** (in/out/fit buttons + mouse-wheel), and
  click-a-node-to-focus / click-again-to-reset;
  the report gets a **Compromised assets** section (4.2). New endpoint `GET /cases/:id/asset-graph`.
  _Deferred:_ embedding the interactive graph in the HTML export, manual asset/link editing, and
  service-type extraction.
- **Keyboard shortcut to toggle capture** (extension) — `Ctrl+Shift+S` (macOS `Cmd+Shift+S`)
  starts/stops screenshot capture without opening the popup. Turning it on takes one capture
  immediately and flashes the toolbar badge `REC`/`off`; the popup shows the current binding and
  a **rebind** link to `chrome://extensions/shortcuts`.
- **Self-hosted TLS trust for MISP / YETI** — connect to intel instances on an internal-CA or
  self-signed certificate. Point `DFIR_MISP_CA` / `DFIR_YETI_CA` at a PEM bundle to trust a
  private CA (verification stays on), or set `DFIR_MISP_INSECURE` / `DFIR_YETI_INSECURE` to skip
  verification for a lab (insecure; logs a warning). Scoped per provider via an injected
  undici dispatcher — the VirusTotal/AbuseIPDB/AI calls keep the default verified trust store.
- **Full incident-report template** — `report.md` now follows the
  [AnttiKurittu incident-report-template](https://github.com/AnttiKurittu/incident-report-template)
  structure (title page, revisions, distribution, disclaimer/reading guide, intended audience,
  executive summary, business impact, limitations, goals, glossary, incident + investigation
  timelines, investigation, conclusions/recommendations, attachments). Technical sections are
  auto-filled from the investigation state; human-authored sections are edited in a new dashboard
  **Report Details** panel (persisted per case in `state/report-meta.json`), override the derived
  content where provided, and show a "to be completed" placeholder where empty. New endpoints
  `GET`/`PUT /cases/:id/report-meta`.
  - Title page supports **multiple investigators** plus an optional **reviewer** and **incident manager**.
  - **Incident ID**, the **distribution list**, and the **Business Impact Analysis** are optional —
    omitted from the report entirely when left blank (no placeholder).
  - **Glossary** is **auto-calculated** from the report text against a curated DFIR dictionary; a
    human-authored glossary overrides it.
  - **Report revisions** auto-seed a `1.0` row (dated from the case, authored by the investigators)
    when none are entered.
  - **Export as Markdown or HTML** — `report.html` is generated alongside `report.md` (standalone,
    print-friendly, "Print → Save as PDF"). The dashboard shows Open-HTML / Download-HTML /
    Download-Markdown links after generation. Served via `GET /cases/:id/report/report.{md,html}`
    (`?download=1` forces a save). Raw HTML in untrusted DFIR data is escaped in the HTML export.
  - Report trimmed to the essentials: the **incident timeline drops its Evidence column**, and the
    **investigation timeline**, **investigation threads**, the conclusions' **answered-questions**
    block, and the **attachments** section are no longer included.
  - **One-click incident-timeline CSV export** — an *Export Timeline CSV* button (and
    `GET /cases/:id/incident-timeline.csv`) downloads just the incident (forensic) timeline,
    generated on demand with the same scope/legitimate filtering as the report.

## [0.3.0] - 2026-06-04

### Added
- **Process-chain validation (RockyRaccoon)** — when enrichment is on, parent→child process
  relationships on the forensic timeline (e.g. THOR ProcessCheck's process + parent) are checked
  against ~346M execution events. An **unobserved chain** (like `excel.exe → powershell.exe`) is
  flagged on the event with a red "⚠ unusual parent" badge + note; a seen chain gets a green "⛓
  chain seen". Deduplicated per distinct (parent,child) pair, throttled/capped/cached like IOC
  enrichment. THOR import now captures `processName`/`parentName` (basenames) on events.
- **Threat-intel IOC enrichment** — look up the case's IOCs (hashes/IPs/domains/URLs) on
  **VirusTotal** (hash/IP/domain/URL), **MalwareBazaar** (hash), **AbuseIPDB** (IP), **MISP**
  (your own instance — `DFIR_MISP_URL` + `DFIR_MISP_KEY`), **YETI** (your own instance, two-step
  JWT auth — `DFIR_YETI_URL` + `DFIR_YETI_KEY`), and **RockyRaccoon** (Windows
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

[Unreleased]: https://github.com/hasamba/DFIR-Companion/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/hasamba/DFIR-Companion/releases/tag/v0.1.0
