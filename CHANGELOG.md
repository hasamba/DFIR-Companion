# Changelog

All notable changes to DFIR Companion are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Maintainer note:** keep entries concise (one line each). Add changes under `[Unreleased]`
> as you go; on release, rename it to the version + date, bump `companion/package.json`,
> `extension/package.json`, `extension/manifest.json` (+ both `package-lock.json`), and tag `vX.Y.Z`.

## [Unreleased]

## [0.18.0] - 2026-06-11

### Added
- **MITRE ATT&CK Navigator layer** export — JSON layer, techniques colored by severity, drops into the Navigator (closes #43).
- **STIX 2.1 bundle** export — report + IOC indicators + ATT&CK + malware/identities with `indicates` links; deterministic ids, no library; drops into any TIP (closes #45).
- **Email / `.eml` / `.msg` import** — deterministic phishing/BEC importer: event at the message's `Date:`, severity from SPF/DKIM/DMARC + spoof heuristics, IOCs harvested (T1566) (closes #44).
- **Adversary group hints** — known ATT&CK groups ranked by technique overlap (offline, not attribution); sub-technique-aware (exact matches weighted + highlighted); dashboard panel + report §4.6.1 (closes #46).

## [0.17.0] - 2026-06-11

### Added
- Dashboard warns when screenshots are arriving for a different case than the one you're viewing (closes the case-mismatch footgun).
- Anonymization auto-discovery now learns entities from screenshots (OCR), grouped by type; each is removable (✕ stops anonymizing it, ↺ restores).
- Leveled logging to file — global session log + per-case audit trail; `DFIR_LOG_LEVEL` (+ live Settings toggle), `DFIR_LOG_DIR`. `debug` traces AI calls, captures, OCR, anonymization, enrichment.
- Timeline events show the affected host chip and clickable finding links; report §3.1 gains a Host column.
- Local OCR screenshot anonymization — Tesseract redacts matching text in-memory before sending to an external vision model (closes #19).
- Timeline Swimlane view — interactive asset/time chart with selection, scope-to-view, and PNG/SVG export (closes #33).
- Global full-text filter + time-range filter behind a toolbar icon.
- Analyst Notebook entries record their author; multi-investigator real-time sync over WebSocket (closes #29).
- IOC bulk select + batch actions, an IOC whitelist (auto-mark known-good), and "⊕ N sources" corroboration badges (closes #35).

### Changed
- Anonymization modal: clearer auto-detected panel + dropped the stray scrollbar.
- Dashboard "Search" relabelled "Filter" (it filters in place); magnifier + `/` shortcut kept.
- Responsive toolbar — settings gear pinned top-right, action buttons auto-collapse to icons.

### Fixed
- Duplicate detection now uses an exact SHA-256 content hash (was a fuzzy perceptual hash that collapsed different-but-similar log pages); `DFIR_DEDUP=off` disables it.
- Search placeholder no longer truncated (full hint moved to the tooltip).
- OCR redaction was a silent no-op (`tesseract.js` default export) — screenshots had been sent un-redacted.
- "AI on — catching up…" status no longer hangs when there's nothing to analyze.

### Security
- Added `SECURITY.md` (localhost posture, reporting, and the deferred dev-only `vitest` audit advisories).

## [0.16.0] - 2026-06-11

### Added
- Response Playbook — turns AI next steps + Critical/High findings into a trackable checklist; optional IR-templates expansion (issue #36).
- Push the Playbook to DFIR-IRIS and to ClickUp (idempotent re-push).

### Changed
- Every `DFIR_*` env var is now configurable from Settings.
- The Playbook takes the prominent dashboard slot; Recommended Next Steps is hidden by default.

### Fixed
- Hunt-pivot VQL uses `OSPath` instead of the deprecated `glob()` `FullPath`.

## [0.15.0] - 2026-06-10

### Added
- Velociraptor triage bundles — pick artifacts → run as a fleet hunt → auto-import + synthesize (closes #30).
- Export a case to Notion, new or existing page (closes #31).
- IOCs: "⚠ Flagged only" filter (show only malicious/suspicious verdicts).

### Changed
- Analyst Notebook section is now reorderable/hideable and sits after Confirmed Legitimate.

### Fixed
- Velociraptor bundle collection survives a too-large artifact (skips it, larger collect cap) and supports concurrent hunts; deep links include `?org_id=`.

## [0.14.0] - 2026-06-09

### Added
- Anthropic prompt caching for the extraction system prompt (closes #18).
- Analyst Notebook — per-case scratchpad for hypotheses/notes/questions, optionally fed to synthesis (closes #8).
- Narrative Timeline — prose story-mode view of the incident.
- Case templates — start a case pre-loaded with investigation questions + artifact hints.
- Per-provider enrichment throttle (`DFIR_ENRICH_DELAY_MS_<PROVIDER>`).
- Configurable companion host/port in the extension Options page (closes #12); `_execute_action` popup shortcut.
- Manual editing of assets and asset ↔ IoC links (persisted, survives synthesis).
- Settings → General: drag-to-reorder dashboard sections; added the missing TLS skip-verify fields.

## [0.13.0] - 2026-06-09

### Added
- Settings modal — all configuration (general, AI, enrichment, exposure, integrations) in one tabbed place.
- Attack Phases — temporal burst detection over the timeline, labelled by dominant ATT&CK tactic.
- Confidence scoring on findings (badge + min-confidence filter).
- Evidence Chain graph phase 2 — file-lineage and network-flow edges.
- MISP export — push IOCs + MITRE techniques to a MISP instance (idempotent).

## [0.12.0] - 2026-06-08

### Added
- Evidence Chain graph — the causal view (process trees + lateral movement), derived deterministically.
- Drag-to-reposition nodes in the asset ↔ IoC graph (positions persist per case).

## [0.11.0] - 2026-06-08

### Added
- Customer exposure / credential-leak check (separate from IOC enrichment) — LeakCheck, HIBP, DeHashed, Shodan; strict customer-only boundary, no raw passwords stored.
- CrowdStrike Falcon threat-intel enrichment provider (Threat Intelligence only).
- Hunting.ch (abuse.ch) enrichment — one key fans out across MalwareBazaar / ThreatFox / URLhaus / YARAify.
- Import change tracking — "📥 last import N ago / +N events / +N IOCs" banners + `NEW` row highlights.
- Hunt-pivot generator adds Elastic ES|QL, YARA, and Suricata; `DFIR_HUNT_PLATFORMS` trims the platform list.
- Safety-net periodic flush so a lone screenshot still gets analyzed.
- Timeline triage controls — star, multi-select, and bulk actions.

### Changed
- Velociraptor pivot offers a runnable notebook query alongside the hunt; asset-graph nodes show a type icon.
- Findings moved above the Forensic Timeline; Kill Chain tactics open in a full-width panel.

### Fixed
- Sub-millisecond timestamp precision preserved through UTC conversion.
- Hunt-pivot harvests indicators from network/IDS event text (no longer "nothing to pivot on").
- CSV/log import respects the per-case "AI off" toggle.
- Hayabusa `json-timeline` (concatenated JSON) now imports; a relative path like `Zip\7z.exe` is no longer mis-read as an account.
- Triage-tag icon visibility, "Mark legitimate" button on rows, and bulk-tag race fixed.

## [0.10.0] - 2026-06-06

### Added
- Run hunts across all endpoints via the Velociraptor API.
- Hunt-pivot query generator (Velociraptor VQL, Defender/Sentinel KQL, Splunk SPL, Sigma) — deterministic, offline.
- AI executive summary (management-facing) for the report.
- Synthesis freshness + what-changed diff ("🧠 last synthesized N ago").
- Analyst triage tags on any entity.
- Kill Chain tactic-phase view.

### Fixed
- Asset-graph labels no longer clip at the canvas edge.

## [0.9.1] - 2026-06-06

### Fixed
- `GET /` redirects to the dashboard; Docker image starts on Node 22.
- Windows portable EXE starts correctly (bundled `sharp` runtime deps) and shows the app icon.

## [0.9.0] - 2026-06-06

### Added
- Native Anthropic API provider; per-provider model recommendations in `.env.example`.
- Cyber Triage timeline import.
- Portable Windows EXE (Node SEA) + Docker / Docker Compose install options.
- One-click PDF and Word (.docx) report export; optional company name + logo branding.
- Forensic Timeline: live event count, severity filter checkboxes, and a severity colour legend.

### Changed
- Terminology "Attacker Path" → "Attack Path"; "Synthesize" button → "AI Re-synthesize"; "Ask the AI" → "Ask the LLM".
- Velociraptor importer: verdict-first detection mapping with cleaner descriptions/timestamps.
- README: explicit "as-is" / no-liability disclaimer.

### Fixed
- Deterministic imports work without an AI provider; imports don't run synthesis when AI is off.
- Anonymizer auto-detection no longer floods "internal domains" with generic words.
- Velociraptor exports no longer mislabel as "SIEM event"; no `[enrich] health … DOWN` spam while off.

### Security
- [P1] Path-traversal guard on case IDs; markdown link/image injection blocked in the HTML report.

## [0.8.0] - 2026-06-05

### Added
- New deterministic importers: Chainsaw/EVTX, Hayabusa, Velociraptor native JSON, Suricata/Zeek, KAPE/EZ Tools, Microsoft 365 / Entra ID, AWS CloudTrail, GCP/Azure activity, Plaso, and malware-sandbox (CAPEv2 / Falcon Sandbox).

### Changed
- One "Import" button (server auto-detects the file type); one "Export" menu and one "Push" menu.

## [0.7.0] - 2026-06-05

### Added
- AI-input anonymization (reversible tokenization; default on).
- SIEM / EDR JSON import; LiteLLM / any OpenAI-compatible endpoint.
- Timesketch timeline export & push.
- Case creation moved to the dashboard; new-case dialog auto-suggests the next `INC-YYYY-NNN`.
- Enrichment reachability gate (skip a down MISP/YETI).

### Changed
- All forensic timestamps normalized to UTC; AI analysis defaults to OFF per case; captures to an unknown case are rejected.

### Fixed
- Large imports no longer fail with HTTP 413; AI prompts no longer overflow the context window; manual event time no longer shifted by local timezone.

### Removed
- The extension no longer creates cases.

## [0.6.0] - 2026-06-04

### Added
- License: GNU AGPL-3.0; project logo + favicons.
- Manually add an event or IOC the AI missed.
- Push a case to DFIR-IRIS; MITRE techniques link to attack.mitre.org.
- `npm run yeti` CLI lookup; timestamped server log with per-call enrichment audit lines.

### Changed
- Per-source enrichment selection (OPSEC — local-only by default).

### Fixed
- YETI v2 tag parsing; failed enrichment no longer cached as "checked"; `EPERM` on state save in a synced folder.

## [0.5.0] - 2026-06-04

### Added
- Investigator comments; drag-to-reorder dashboard sections; "Ask the AI about the case"; import external screenshots; customizable AI prompts.

### Changed
- Synthesis is cheaper and smarter (skip-if-unchanged, stratified event selection).

## [0.4.0] - 2026-06-04

### Added
- Compromised assets + asset ↔ IoC graph; keyboard shortcut to toggle capture; self-hosted TLS trust for MISP/YETI; full incident-report template.

## [0.3.0] - 2026-06-04

### Added
- Threat-intel IOC enrichment; process-chain validation (RockyRaccoon); cross-source correlation & duplicate collapsing; THOR (Nextron) scanner import.

### Changed
- Bounded AI requests (fixes spurious OpenRouter HTTP 402); synthesis preserves IOCs.

### Fixed
- EDR/XDR and SIEM detections reliably enter the timeline & findings; tolerate truncated AI JSON; no bogus "2 sources" / "unknown source".

## [0.2.0] - 2026-06-02

### Added
- Mark a forensic event legitimate; severity-aware findings; configurable server port; captured tab title in screenshot filenames.

### Changed
- Log import is deduplicated + AI-triaged; extraction prompt rebalanced.

### Fixed
- Analyst-workflow / tool-navigation narration kept out of the timeline; real threats are never dropped.

## [0.1.0] - 2026-06-01

### Added
- Localhost companion server; evidence-first ingest; two-phase AI analysis; provider abstraction; investigation scope; CSV (Velociraptor/EDR) import.

[Unreleased]: https://github.com/hasamba/DFIR-Companion/compare/v0.18.0...HEAD
[0.18.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.17.0...v0.18.0
[0.17.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.16.0...v0.17.0
[0.16.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.15.0...v0.16.0
[0.15.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.14.0...v0.15.0
[0.14.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.9.1...v0.10.0
[0.9.1]: https://github.com/hasamba/DFIR-Companion/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/hasamba/DFIR-Companion/releases/tag/v0.1.0
