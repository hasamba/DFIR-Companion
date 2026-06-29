# Changelog

All notable changes to DFIR Companion are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Maintainer note:** keep entries concise (one line each). Add changes under `[Unreleased]`
> as you go; on release, rename it to the version + date, bump `companion/package.json`,
> `extension/package.json`, `extension/manifest.json` (+ both `package-lock.json`), and tag `vX.Y.Z`.

## [Unreleased]

### Changed
- **Global search filter now spans event-derived views** — the toolbar search + time-range filter now also narrows **Kill Chain** and **Attack Phases** (not just the timeline/IOCs/findings), so searching e.g. an IP scopes every event-based section to the matching events; Kill Chain shows a "Filtered to N of M" note, Attack Phases shows per-phase "N of M match" and hides phases with no matches.
- **Kill Chain — T1078 logons no longer inflate Initial Access** — a Valid-Accounts (`T1078`) event whose description shows credential *reuse* (EID 4648 explicit credentials, SSH/RDP/WinRM, psexec/wmiexec, pass-the-hash) is now bucketed under **Lateral Movement** instead of Initial Access, so internal host-to-host logons stop padding the Initial Access lane and contradicting an "entry vector unknown" synthesis; the panel gains a "categorization, not a confirmed stage" caption.
- **Timeline anomalies — default bucket 15 min** — the per-asset spike bucket default dropped from 60 to 15 minutes (`DFIR_ANOMALY_BUCKET_MINUTES`); a concentrated burst is no longer averaged across a quiet hour and diluted below the threshold (part of #175).
- **Timeline host de-duplication** — when the affected-host chip (🖥) is shown on a timeline event, the redundant trailing `@ <host>` that importers append to the description is now stripped, so the hostname isn't shown twice.
- **Chocolatey package** — removed `tools/LICENSE.txt` and `tools/VERIFICATION.txt`; those files are not required for packages that embed no binaries (per Chocolatey moderator feedback).

### Added
- **ECAR (EDR telemetry) import** — dedicated deterministic importer for the EDR Common Activity Record NDJSON (`object`/`action`/`properties`, epoch-ms `timestamp_ms`): maps process/flow/logon/registry/module/file/remote-thread events, surfaces process command lines as real tradecraft (LOLBin/encoded bump → T1059), scrapes PUBLIC IPs as IOCs (internal RFC1918 skipped to avoid noise), conservative Info-by-default severity. Fixes raw ECAR feeds being mis-imported as undated generic "SIEM event" rows by the generic SIEM path. No AI, deterministic.
- **SIEM import — IOCs scraped from message text** — the generic SIEM/EDR importer now also extracts indicators embedded INSIDE a record's free-text message (e.g. an SSH auth line `Failed password … from 10.44.20.20 …`), not only from dedicated `ip`/`src_ip`/`hash`/`url`-named fields — so an IP/URL/domain/hash that only appears in the message becomes an IOC instead of showing in the timeline alone. Internal RFC1918 IPs are kept; `.local`/internal hostnames and filename-looking tokens are skipped to avoid IOC-list noise.
- **Hypotheses — on-demand ✨ Generate button** — the Hypotheses panel now has a Generate button that runs a forced synthesis to (re)generate the auto hypotheses from the current timeline, instead of only emitting them as a synthesis byproduct; analyst-touched/authored hypotheses stay frozen. Empty-state copy clarified that hypotheses regenerate automatically after each import (part of #140).
- **Evidence drop folder (auto-import inbox)** — every case now has a `drop/` folder (created on case creation); anything copied in — at any depth, subfolders included — is auto-detected and imported via the same chain as the Import button, with images ingested as screenshot evidence. A background poller waits for each file to settle (Dropbox/OneDrive-safe), then moves it to `drop/_processed/` or `drop/_failed/`. Failures are reported in the dashboard 📥 Drop banner (`GET /cases/:id/drop-status`) and any configured Slack/Teams/email channel. Default on; `DFIR_DROP_ENABLED` / `DFIR_DROP_POLL_S` / `DFIR_DROP_MAX_BYTES`.
- **Timeline anomalies — self-baseline detection** — alongside the existing peer baseline (an asset busier than other assets in the same bucket), the panel now also flags an asset bursting above **its own** typical rate (median of its per-bucket counts, needs ≥3 active buckets), so a normally-quiet host that bursts is caught even when its absolute volume is low and broad telemetry can't mask it. A **Type** column shows `peer` / `self` / `peer + self`; tunable via `DFIR_ANOMALY_SELF_FACTOR` (part of #175).
- **Remember import severity** — the minimum-severity import prompt is now a dialog with a *Remember this choice — don't ask again* checkbox; checking it skips the prompt on future imports and uses the saved floor. Manage/clear it via Settings → General → Import severity. Per-browser, no server round-trip.
- **Timeline row display toggles** — Settings → General now has a *Timeline row display* control to choose which sub-elements appear in each forensic-timeline event row (action icons / tag pills / badges / host chip / MITRE / related findings / evidence links); the timestamp and message are always shown. Per-browser, applies immediately, no server round-trip.
- **Linux shell history import** — `.bash_history` / `.zsh_history` (and sh/ash/ksh/fish) are now a recognized artifact: one forensic event per command at the artifact's own time (bash `HISTTIMEFORMAT` `#epoch` lines + zsh extended history), the account derived from the filename, Info by default with a conservative bump on attacker tradecraft (reverse shells, download-and-execute, credential access, log/history tampering, lateral SSH) and IP/URL/domain IOC extraction. No AI, deterministic.
- **Windows Event Log XML import** — the Import button now ingests event logs saved as XML (Event Viewer "Save As XML", `wevtutil qe /f:xml`, `Get-WinEvent … ToXml()`); the regular `<Events><Event>` envelope is parsed deterministically and run through the same per-EID Windows/Sysmon mapping as the SIEM/EVTX-JSON paths (derived severity, MITRE, IOC/asset extraction, aggregation). No AI, dependency-free parser.
- **Screenshot OCR full-text search** — captured screenshots are OCR'd locally (Tesseract, in the background after capture) into a per-case index, so an analyst can full-text search the text seen in consoles (a hostname, "mimikatz", a hash, an error) and jump straight to the screenshot. Filter-bar search box → `GET /cases/:id/ocr-search`; backfill older captures with `npm run ocr-index -- <case>`; opt out with `DFIR_OCR_SEARCH=off`. Local-only, no AI (closes #176).
- **Presentation / timeline-replay mode** — a read-only, step-through slide deck (cover → summary/narrative → key findings worst-first → timeline events one at a time) for handoff briefings and executive walkthroughs. Big readable cards (timestamp, severity, source, description, asset, supporting IOCs with verdicts, evidence screenshot); keyboard nav (←/→/space/Home/End), auto-advance, fullscreen, severity filter. Inherits the case's report-template branding; export a self-contained offline HTML deck. `/cases/:id/present`, `GET /cases/:id/presentation`, `GET /cases/:id/present/export`; dashboard **▶ Present** button + Export → Presentation deck (closes #177).
- **Actionable mitigations** — the *Defensive Countermeasures* panel now leads with concrete **MITRE ATT&CK Mitigations** (M-codes) for the case's techniques, ranked by how many techniques each addresses (highest-leverage first), each with its per-technique detail; offline from `data/attack-mitigations.json` (`npm run data:update-attack-mitigations`). Plus a **✨ Generate remediation plan** button — one AI call writes a concrete, incident-specific plan (Contain/Eradicate/Harden/Recover/Verify) grounded in the findings + those mitigations. `GET /cases/:id/attack-mitigations`, `POST /cases/:id/remediation-plan` (part of #178).
- **D3FEND defensive countermeasures** — for each identified ATT&CK technique, the MITRE D3FEND countermeasures as an action-first checklist: two bands (*Harden now* = Prevent/Detect/Contain vs *This incident & context* = Evict/Restore/Model/Deceive), plain-English "what to do" per action, and a definition-on-hover per countermeasure. Offline + AI-free from the bundled `data/d3fend-map.json` (`npm run data:update-d3fend`); `GET /cases/:id/d3fend-countermeasures`, dashboard *Defensive Countermeasures* panel (in the Analyst/Lead/Executive/Deep-Dive/Hunt-Prep view profiles) + toggleable report section (closes #178).
- **Startup pre-flight diagnostics** — non-blocking self-test on server start: live-probes the AI provider + local enrichment instances (MISP/YETI/OpenCTI `probe()`) + Velociraptor, and reports every other configured provider (VirusTotal, AbuseIPDB, CrowdStrike, Hunting.ch, Shodan, …) as "configured" without any outbound call (OPSEC: no automatic third-party traffic); logs OK/WARN/CRITICAL; red dashboard banner for AI failures; `GET /diagnostics/preflight` (cached 30 s) + `POST` (re-run); user-toggleable disable persisted to `preflight/control.json` via `…/preflight/control` (closes #179).
- **Automatic state backup / rotation** — the server snapshots all per-case state files before each synthesis and on a 1-hour timer; configurable via `DFIR_STATE_BACKUP_RETAIN` / `_PRE_SYNTH_RETAIN` / `_INTERVAL_MS`; Settings → Diagnostics shows per-case backup list with one-click restore (closes #180).
- **Setup wizard** — a guided, multi-step dashboard overlay (auto-shown first-run when AI is unconfigured; also launchable from Settings → General / Settings → AI) for every config that has no default: AI, Velociraptor, DFIR-IRIS, Timesketch, Notion, ClickUp, push ingest, NSRL, the threat-intel enrichment + customer-exposure providers, and a Slack/Teams/Mattermost/Discord notification webhook (add + test). Each step saves to `.env`, applies live via the new allowlisted `POST /settings/reload`, and tests via the integration's reconnect/status route; a left rail shows ✓/○ per step from the new `GET /setup/status`. Adds `POST /timesketch/reconnect` (hot reconnect, no restart) + `irisEnabled`/`timesketchEnabled` health flags. Fully dismissible — everything is optional (closes #181).
- **Declared Node engine requirement** — `companion/package.json` now has `engines.node: ">=20"`; READMEs note the **NSRL RDS SQLite backend** (and full test suite) need Node 22.5+ for `node:sqlite`, the rest runs on Node 20 (closes #185).
- **Full-pipeline integration test** — new `companion/tests/fullPipeline.test.ts` exercises capture → artifact import → synthesis → enrichment → report → snapshot export → snapshot restore, with mocked AI and enrichment providers so the suite runs offline and in CI (addresses #182).
- **10k-event performance/load test** — new `companion/tests/analysis/loadTest.test.ts` builds a synthetic 10 000-event case and benchmarks `selectSynthesisEvents`, `buildSynthesisContext`, `correlateEvents`, `filterEventsByScope`, `applyLegitimate`, and `renderMarkdownReport` with timing + heap-growth assertions; catches scalability and memory regressions (closes #183).
- **Timeline Anomalies panel** — deterministic, AI-free per-asset event-rate spike detection; assets whose bucket count exceeds N× the per-bucket median are ranked by severity and linked back to their events in the timeline; configurable via `DFIR_ANOMALY_BUCKET_MINUTES` / `_SPIKE_FACTOR` / `_MIN_EVENTS`; surfaced in the dashboard, report §3.4, and `GET /cases/:id/anomalies` (closes #175).

### Changed
- **Demo case** — added a realistic DC01 AD-enumeration burst (May 16 09:00, between the Mimikatz dump and the log-clearing) so the new Timeline Anomalies panel shows a Critical event-rate spike out of the box (part of #175).

### Fixed
- **Timeline Anomalies "view N events" now shows all N** — the link filtered the forensic timeline to exactly the bucket's events (with a clearable "Showing N of N" chip) instead of just jumping to the first, so the analyst can see precisely which events drove the spike (part of #175).
- **IOC "Flagged only" / timeline "Starred" filters collapsed their section** — clicking these in-header filter toggles also bubbled to the section's collapse-on-`h2`-click handler, hiding the list they had just filtered (symptom: "1 flagged" in the title but an empty list); the collapse handler now ignores clicks on interactive header controls.
- **AI status badge always visible** — in the tight (icons-only) toolbar the AI status badge was hidden, yet "(see AI status)" messages pointed at it; it now stays visible as a compact colored pill (grey off/unknown, green idle, yellow analyzing, red error) with the full text on hover.
- **Import into a non-existent case** — the `import` + `import-file` routes now 404 a missing case (parity with `/captures`/`/state`) instead of orphaning the bytes; dashboard shows "create the case first".

## [0.27.0] - 2026-06-24

### Added
- **Timeline brushing + evidence-graph filters** — drag a time-range on the swimlane to scope correlated events; evidence graph gains a severity floor + SVG export to declutter/share large graphs (#122).
- **Dashboard view presets** — toolbar ⊞ menu of Analyst/Lead/Executive (role) + Triage/Report/Deep-Dive/Hunt-Prep (phase) layouts that reorder panels, apply a severity floor + top-N cap, and link a report template; per-case, fully editable in Settings → Dashboard Views (closes #142).
- **Persistent case memory** — synthesis logs each run to a durable Investigation Log; a *known-unknowns* block (gaps, uncovered ATT&CK phases, lookalike actors' next techniques) grounds synthesis + hunt suggestions; opt-in `DFIR_SYNTH_ADVERSARY_HINTS` feeds candidate actors as hypotheses (closes #165).
- **Skip AI for disabled report sections** — executive-summary + narrative generators no longer spend tokens when their section is disabled in the report template (409 with the reason); saved content preserved (closes #168).
- **IOC filter by type** — IOC panel "▾ Types" facet (ip/domain/url/hash/file/process/other) with per-type counts, composing with the flagged-only + search filters (closes #169).
- **Geographic IP map** — dashboard 🌍 Leaflet panel plotting geo-located IP IOCs (severity colors, victim→attacker flows, country stats, timeline sync, CSV export) + report §4.10; from GeoIP enrichment, no new auto-calls (closes #133).
- **Geo country-centroid fallback** — IPs with a country but no city coords fall back to the country centroid, shown as a faint dashed "country-level (approx)" marker; regenerate via `npm run data:update-geo` (part of #133).
- **Hypothesis-driven investigation mode** — Hypotheses panel for status-tracked hypotheses (open/supported/refuted/unknown), auto-generated + analyst-authored, with evidence/technique links + report section; open ones steer synthesis, notebook notes promote in, survive synthesis + snapshots (closes #140).
- **Supporting events & IOCs per finding** — each finding lists the events that back it (click to jump, even across pagination) plus its supporting IOC values, derived client-side (part of #139).
- **Hunting feedback loop** — deployed hunts record their outcome per case (new evidence + counts, survives restart); suggestions skip an already-run VQL and pivot on what hit, with a "Hunting Profile" panel of hunted/hit/missed + auto-collect + per-hunt re-collect (closes #157).
- **Regenerate a suggested fleet hunt** — per-card ↻ Regenerate on AI fleet-hunt cards for a fresh VQL when one won't compile (part of #57).

### Fixed
- **Asset↔IoC over-linking on IP substrings** — the asset-graph scan now matches IP IOCs with a digit/dot boundary, so `1.1.1.1` no longer links inside `11.1.1.10`, preventing inflated associations (#133).
- **Hunt VQL `hash()` signature** — fleet/playbook hunt prompts now teach the real `hash(path=…).SHA256` form (no invented `hashselect=` arg) and avoid full-disk globs, cutting "did not launch the hunt" errors (part of #57/#70).
- **`spawn EPERM` launching a hunt** — the velociraptor launch retries a transient Windows lock (`DFIR_VELOCIRAPTOR_SPAWN_RETRIES`, default 6); a persistent EPERM/EACCES (AV/EDR blocking a credential-dump-flavored VQL) now reports an actionable message (add an AV exclusion, or run from the GUI).
- **Corrupted `investigation.json` on concurrent saves** — `atomicWrite` now uses a unique per-call temp file (was a fixed `.tmp`), so two concurrent saves no longer interleave into a malformed file that 500'd every state-loading endpoint; worst case is a lost update.
- **Lost-update on manual add during synthesis** — a per-case `StateLock` serializes load→save critical sections and synthesis re-reads the latest state before persisting, so an event/IOC added mid-synthesis is no longer clobbered.

## [0.26.0] - 2026-06-21

### Added
- **Chocolatey package** — `choco install dfir-companion` installs the portable Windows build and bundles the capture extension on disk for offline "Load unpacked"; `packaging/chocolatey/` template + `build-choco.mjs` fill in both download URLs + SHA256s, data is redirected to `%LOCALAPPDATA%\DFIR-Companion`, and a CI `chocolatey` job packs + attaches the `.nupkg` and pushes once `CHOCOLATEY_API_KEY` is set (part of #137).
- **Chrome Web Store packaging (extension)** — static store icons (16/32/48/128 from the Companion logo) wired into the manifest, a `PRIVACY.md` policy, and a CI `chrome-webstore` job that publishes the built zip on each `v*` tag once OAuth secrets are set (part of #138).

### Changed
- **Extension manifest (extension)** — renamed to "DFIR Companion — Evidence Capture & Push" with a description that discloses the DFIR-console data push, for the listed Web Store submission (part of #138).

## [0.25.0] - 2026-06-20

### Added
- **Demo mode** — `DFIR_DEMO_MODE=true` blocks all mutating API routes (new cases, imports, AI calls, deletions), seeds the demo case on startup, and auto-resets it every hour (`DFIR_DEMO_RESET_HOURS`); `railway.toml` added for one-click Railway deployment.
- **Timeline source filter** — faceted dropdown beside the severity legend to show/hide forensic-timeline events by the tool/source that produced them (built from the distinct `sources`); a multi-source event stays visible unless all its sources are hidden, and the filter respects pagination/search (#131).
- **Enhanced redaction** — tokenize PowerShell encoded-command blobs (`-enc <base64>`/`FromBase64String`) + victim user SIDs (`S-1-5-21-…`) before the AI; new `CMD`/`REG` anon categories, well-known SIDs preserved (closes #128).
- **Draggable push button (extension)** — injected button can be dragged anywhere on the page; position remembered and always clamped on-screen.
- **Security Onion adapter (extension)** — recognizes SOC event views (Alerts/Hunt/Dashboards) and SO's bundled Kibana; one-click Push of individual events (Detections/Cases excluded).
- **Security Onion importer (companion)** — deterministic: `severity_label`→severity, ECS threat→MITRE, source/dest/dns/url/hash→IOCs; detected ahead of Velociraptor/SIEM to fix `_Source` mis-routing.
- **SO-CRATES adapter (extension)** — recognizes the SO-CRATES `socrates.html` page; one-click Push of its network/file events (`/api/events`) and Sigma detections (`/api/sigma-alerts`).
- **SO-CRATES importer (companion)** — deterministic: Suricata `alert` (reuses the network importer), YARA `filealerts`→file-match events + hash IOCs, Sigma→verdict-first severity/MITRE overlaid on the matched Sysmon event (CommandLine/ParentImage/ParentCommandLine + process/hash IOCs via `mapWindows`); tagged `SO-CRATES`, detected ahead of Velociraptor's `_Source` catch-all.
- **Linux AppImage** — single-file build attached to every release; `DFIR_ENV_FILE` override for `.env` outside a read-only mount (#127).
- **Update notice** — opt-in dashboard banner for newer GitHub releases; `DFIR_UPDATE_CHECK` env + Settings toggle, never auto-installs (#127).
- **CI build + test gate** — `.github/workflows/ci.yml` runs `build + test` for `companion/` and `extension/` on every PR and push to master (#126).
- **Scheduled-task mapper** — Velociraptor `TaskScheduler/Analysis` artifacts → `taskscheduler` kind with well-known SID expansion (SYSTEM/LOCAL SERVICE/NETWORK SERVICE).
- **MFT detection `InUse` field** — `DetectRaptor.Windows.Detection.MFT` rows append `[deleted]` when `InUse` is false.
- **Evidence-of-download mapper** — Velociraptor `BrowserDownloads`/`EvidenceOfDownload` → `download` kind; `HostUrl` + `ReferrerUrl` added as URL IOCs.
- **Startup-items mapper** — Velociraptor `StartupItems`/`Autorun` → `startup` kind with T1547; enabled=Low, disabled=Info.
- **CIRCL hashlookup enrichment** — keyless known-file lookup (NSRL-derived + distro packages); `external` scope, `DFIR_HASHLOOKUP_URL` override (closes #154).
- **Timeline pagination** — 100/250/500/all rows per page, user-selectable (#125).
- **Correlation profile** — per-case Strict/Moderate/Aggressive merge-window setting; `PUT /cases/:id/correlation-profile` (#125).
- **Synthesis performance metrics** — `synth-meta.json` records `durationMs`/`eventCount`/`iocCount`; dashboard banner shows them with ⚠ advisory above 5 000 events (#125).

### Fixed
- **Large Plaso import OOM** — files over 200 MB now streamed line-by-line via `import-file` route + `parsePlasoFromLines`; a 555 MB file imports at ~1.3 GB peak RSS instead of OOMing.
- **`DFIR_DISK_WARN_PCT=0` ignored** — setting to 0 now correctly disables the disk-space warning.
- **Import progress bar** — thin strip at the top of the dashboard shows browser-read then server-side import progress.
- **Playbook task flood from burst detections** — `backfillHighSeverityFindings` groups uncovered Critical/High events by short title before creating auto-findings.
- **Velociraptor pslist/pstree import** — NDJSON exports without `_Source`/`Artifact` now route to the Velociraptor importer via `CallChain`+`Pid` presence.
- **Velociraptor netstat import** — `Windows.Network.Netstat` exports now route to a dedicated `mapNetstat` formatter; ESTABLISHED external IP added as IOC.
- **WebSocket over HTTPS** — dashboard now uses `wss://` when served over HTTPS (KillerCoda/Railway proxy); constructor errors caught so a blocked WebSocket doesn't surface as a modal alert.
- **Extension offline message** — Refresh Cases now shows "companion offline — check URL" instead of always reporting success when the companion is unreachable.
- **Enrichment picker** — all 13 known providers always listed; unconfigured ones dimmed with `(key missing: ENVVAR)` hint instead of being hidden.
- **KillerCoda scenario** — switched to pre-built Docker image (~1 min setup); suppressed bash verbose echo; corrected hamburger icon; added port-access instructions.

### Changed
- **Consistent event-field separator** — extension-pushed imports (SIEM/Sysmon, Velociraptor, Security Onion, SO-CRATES, Suricata/Zeek) now join description fields with a single ` - ` (no more mixed `|`/em-dash/space); `ParentCommandLine` added to the standard Windows subject fields.
- **Graph-grounded fleet-hunt suggestions** — `suggestHunts` feeds the causal evidence graph so hunts target relationships fleet-wide, not just leaf indicators (#124).

## [0.23.0] - 2026-06-17

### Added
- **Mattermost & Discord notifications** — two new webhook channels alongside Slack/Teams/Telegram/SMTP; test button + secret redaction (closes #136).
- **Explain This Event** — 💡 button per timeline row fires a focused AI explanation with ATT&CK mapping and 1–3 pivot queries; ephemeral, copy buttons per query (closes #141).
- **IP-infrastructure enrichment** — four IP-only providers: Reverse DNS (keyless), WHOIS/RDAP (keyless), GeoIP (`DFIR_GEOIP_URL`), Shodan (reuses key); all opt-in, `unknown`-verdict badges (closes #134).
- **Chain-of-Thought synthesis** — opt-in extended thinking on synthesis via `DFIR_AI_SYNTH_THINKING_TOKENS` or the 🧠 deep dashboard checkbox; applies to primary + second-opinion passes (#121).
- **Adversary emulation — likely next techniques** — techniques matched groups use that the case hasn't observed, ranked by TF-IDF distinctiveness; ⌖ hunt this generates VQL; `DFIR_ADVERSARY_NEXT_MAX` (closes #121).
- **Case lifecycle & archiving** — open/closed status, ZIP archive with SHA-256 manifest, disk-space banner, toolbar lifecycle menu (closes #119).
- **Custom declarative importers** — drop a JSON importer spec to auto-detect + import like a built-in; LLM-authorable via a built-in prompt, user-selectable precedence.
- **Health / Diagnostics page** — Settings → Diagnostics: disk usage, case count, queue, AI config, importer stats, live AI connectivity test (closes #118).
- **OpenCTI enrichment** — local-scope IOC lookup against a self-hosted OpenCTI instance via GraphQL (closes #152).

## [0.22.0] - 2026-06-15

### Fixed
- **Extension push button on remote / modern Kibana** — handles async-search strategy envelope, bfetch shapes (NDJSON, bfetch compression), and React re-renders via MutationObserver.
- **Pushed Elastic rows from `_source`-disabled indices** — flattens `fields` arrays; SIEM mapper now reads `desc` and summarizes salient fields instead of Elasticsearch metadata.
- **MemProcFS `timeline_all.csv` Net IOCs** — fixed invalid `"network"` IOC type (now correctly `ip`).

### Added
- **Second LLM opinion** — on-demand non-destructive re-synthesis by a second model; per-item analyst accept/reject; accepted deltas survive re-synthesis; `DFIR_AI_SECOND_OPINION_MODEL` (closes #116).
- **Velociraptor data from Elasticsearch** — `detectImportKind` routes `artifact_*` indices and `Detection.*` CSV columns to `importVelociraptor`; normalizes ES-reshaped rows + Kibana display-format timestamps.
- **MemProcFS `timeline_all.csv` importer** — deterministic: ShTask/Net/PROC/WEB rows → severity + ATT&CK; auto-detected by unified Import.
- **MemProcFS `findevil` importer** — deterministic: finding types → severity + ATT&CK (YR_HACKTOOL→Critical/T1588.002, etc.); bulk PRIVATE_RWX pages grouped; auto-detected.

## [0.21.0] - 2026-06-15

### Added
- **GraphRAG for "Ask the case"** — evidence-chain graph serialized as causal edges grounds multi-hop answers; `DFIR_ASK_GRAPH_MAX_EDGES` (closes #98).
- **Memory-forensics "Next-Step" agent** — AI reads Volatility evidence and proposes the exact next `vol` command; ✨ button in a *Memory Next Steps* panel (closes #101).
- **Volatility 3 text-output import** — default `vol <plugin>` TEXT/grid renderer ingested alongside `-r json`; hexdump continuation lines skipped (#101).
- **Natural-language Query Translator** — plain-English → VQL/KQL/ES|QL/SPL/Sigma/YARA/Suricata; VQL one-click deploys via hunt flow (closes #100).
- **One-click artifact push from the browser extension** — MAIN-world fetch/XHR hook on recognized DFIR consoles POSTs to `/import`; cross-case dashboard warning on mismatch (closes #102).
- **Timeline-gap hypotheses & shadow-artifact hunting** — AI hypothesizes silent periods; catalog of shadow artifacts (USN/SRUM/Prefetch/…) each deployable as a Velociraptor collection (closes #96).
- **Sort timeline by date or severity** — per-column ▲/▼ sort arrows; client-side, persisted across reloads (closes #104).
- **Payload deobfuscation** — auto-decodes base64/`-EncodedCommand` PowerShell; extracts hidden IOCs; expandable [Decoded] block per event (closes #97).
- **CISA KEV integration** — cross-reference CVEs against the CISA KEV catalog; surfaces in synthesis context + report §4.5.1; opt-in (closes #99).
- **Import from DFIR-IRIS** — pull IRIS assets/IOCs/timeline into a Companion case; toolbar chooser + `npm run iris:import`; Settings reconnect without restart (closes #88).
- **Webhook push ingest** — `POST /cases/:id/push` with token auth; same import→diff→synthesize pipeline, 202-async (closes #84).
- **Velociraptor live monitoring** — CLIENT_EVENT artifact stream, one endpoint or all; auto-monitor; persisted cursor; 🔴 LIVE badge (closes #84).
- **Velociraptor reconnect** — Settings → Reconnect re-reads `DFIR_VELOCIRAPTOR_*` without restart; startup retry with backoff (#84).
- **IOC block-list export** — plain TXT/CSV/STIX-indicators; min-severity + type filters; `GET /cases/:id/export/ioc-blocklist` (closes #87).
- **Wazuh importer** — `rule.level`→severity, MITRE, asset, IP/hash/URL IOCs; auto-detected (closes #85).
- **TheHive importer** — TheHive 5 case/alert/observable exports; severity from 1–4 scale, MITRE from ATT&CK tags (closes #86).
- **Log gap analysis** — complete all-source silences flagged High, single-source gaps Medium; derived on read; `DFIR_GAP_MIN_MINUTES` (closes #83).
- **Beacon / C2 detection** — median/MAD periodicity check on outbound connections; High for public destinations; `DFIR_BEACON_MIN_COUNT` (closes #82).

### Changed
- **Customer Exposure shows found results only** — hides clean "no breach" rows; providers/targets summary still shown.
- **Demo case enriched** — `seed-demo` adds a ~16h complete-silence gap + seeded narrative/notebook entries for demo coverage.

### Fixed
- **Extension case selection saves without pressing Start** — case dropdown auto-saves on change; floating Push button hides when no case is connected.
- **Demo Customer Exposure rows rendered half-empty** — `seed-demo` rewritten to current `StoredCustomerExposureResult` schema.
- **Velociraptor live-monitor discovery on real servers** — artifact type filtering moved to TypeScript; auto-monitor uses correct VQL `get_client_monitoring()`; new `/velociraptor/diag` endpoint.
- **`seed-demo` now honours `DFIR_CASES_ROOT`** — seed script now loads `.env` before writing the demo case.

## [0.20.0] - 2026-06-13

### Added
- **Import undo/redo** — roll case state back to before an import; per-case stack (`DFIR_IMPORT_UNDO_DEPTH`, default 10); Undo/Redo buttons next to Import (closes #76).
- **AI-suggested playbook hunts** — propose a Velociraptor hunt per endpoint-related Playbook task; host-specific → single-client collection, else fleet hunt (closes #70).
- **Velociraptor client inventory** — enrolled fleet snapshot at startup/on-demand; single-endpoint collections resolve by hostname (#70).
- **Collection results in the dashboard** — single-endpoint collection rows rendered inline with auto-poll, like fleet hunts (#70).
- **Dedicated Velociraptor hunt model** — `DFIR_AI_VELO_PROVIDER`/`_MODEL` for VQL generation, separate from analysis model; configurable in Settings → AI (#70).
- **Persistent + incremental hunt suggestions** — generated hunts survive refresh; re-generate sends only new/changed tasks; `force:true` regenerates all (#70).
- **Playbook task short IDs** — stable `T001`/`T002` display IDs stored in the task record; existing tasks back-filled.
- **Telegram notifications** — Telegram bot channel for findings/playbook/milestone notifications (closes #75).

### Fixed
- **Playbook delete button for auto-derived tasks** — delete now marks task `skipped` instead of silently removing it (closes #78).
- **Playbook-hunt VQL grounded in real artifacts** — prompt lists the server's actual CLIENT artifact names; correct plugin args; no SQL JOIN; `DFIR_PBHUNT_MAX_EVENTS` (#70).
- **Endpoint-side collection errors surfaced** — flow `ERROR` status now shown in the dashboard instead of polling forever (#70).

## [0.19.0] - 2026-06-12

### Added
- **Linux evidence importers** — deterministic auditd, journald, and sysdig/Falco ingest, auto-detected by the unified Import button (closes #62).
- **Mobile companion** — installable read-only PWA at `/mobile` (findings, timeline, IOC verdicts); `/cases/:id/mobile-summary` endpoint, `DFIR_MOBILE_MAX_*` caps (closes #59).
- **AI-suggested fleet hunts** — generate proactive Velociraptor VQL hunts from case findings; review + one-click deploy across all endpoints (closes #57).
- **Memory forensics import** — deterministic Volatility 3 (JSON) + Rekall: pslist/pstree → process tree, netscan → connections, malfind → injected code (T1055), cmdline/svcscan → evidence (closes #61).
- **Investigation snapshot** — one shareable JSON exports/imports the full case (timeline, findings, IOCs, analyst decisions) with no AI keys or machine config (closes #56).
- **Redacted case export** — shareable ZIP: report/CSVs/state tokenized, secrets redacted, screenshot EXIF stripped + PII blurred (closes #54).
- **Dark / light theme** — full-coverage theme toggle; follows OS preference by default, manual choice persists (closes #53).
- **Custom report templates** — global branded layouts (accent colour, header/footer, section reorder); built-ins editable; selected per case; flows to Markdown/HTML/Word (closes #60).
- **Notifications** — Slack/Teams webhooks + SMTP for findings/playbook/milestones; per-channel severity thresholds + event toggles; opt-in (closes #58).
- **NSRL known-good hash checking** — auto-marks matching events + IOCs legitimate on import. Two backends: flat hash set and direct NSRL RDS SQLite query (`DFIR_NSRL_DB`); keys on sha256/md5 (closes #63).

### Changed
- Dashboard: removed **Mobile** toolbar button — navigate to `/mobile` directly.
- Dashboard: finding tag chips reordered; case ID input fixed-width; removed ellipsis from Import button labels.

## [0.18.0] - 2026-06-11

### Added
- **MITRE ATT&CK Navigator layer** export — JSON layer, techniques colored by severity (closes #43).
- **STIX 2.1 bundle** export — report + IOC indicators + ATT&CK + malware/identities; deterministic ids, no library (closes #45).
- **Email / `.eml` / `.msg` import** — deterministic phishing/BEC importer: event at `Date:`, severity from SPF/DKIM/DMARC + spoof heuristics, IOCs (T1566) (closes #44).
- **Adversary group hints** — known ATT&CK groups ranked by technique overlap, offline; sub-technique-aware; dashboard panel + report §4.6.1 (closes #46).

## [0.17.0] - 2026-06-11

### Added
- Dashboard warns when screenshots arrive for a different case than the one you're viewing.
- Anonymization auto-discovery learns entities from screenshots (OCR), grouped by type; each removable.
- Leveled logging to file — global session log + per-case audit trail; `DFIR_LOG_LEVEL` + live Settings toggle.
- Timeline events show affected host chip and clickable finding links; report §3.1 gains a Host column.
- Local OCR screenshot anonymization — Tesseract redacts matching text before sending to the vision model (closes #19).
- Timeline Swimlane view — interactive asset/time chart with selection, scope-to-view, PNG/SVG export (closes #33).
- Global full-text filter + time-range filter behind a toolbar icon.
- Analyst Notebook entries record their author; multi-investigator real-time sync over WebSocket (closes #29).
- IOC bulk select + batch actions, IOC whitelist (auto-mark known-good), and "⊕ N sources" corroboration badges (closes #35).

### Changed
- Anonymization modal: clearer auto-detected panel + dropped the stray scrollbar.
- Dashboard "Search" relabelled "Filter"; responsive toolbar — settings gear pinned top-right, action buttons auto-collapse.

### Fixed
- Duplicate detection now uses exact SHA-256 content hash (was fuzzy perceptual hash); `DFIR_DEDUP=off` disables it.
- OCR redaction was a silent no-op — screenshots had been sent un-redacted.
- "AI on — catching up…" status no longer hangs when there's nothing to analyze.

### Security
- Added `SECURITY.md` (localhost posture, reporting, and deferred dev-only `vitest` audit advisories).

## [0.16.0] - 2026-06-11

### Added
- Response Playbook — turns AI next steps + Critical/High findings into a trackable checklist; optional IR-templates expansion (closes #36).
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
- Customer exposure / credential-leak check — LeakCheck, HIBP, DeHashed, Shodan; strict customer-only boundary, no raw passwords stored.
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
- Hunt-pivot harvests indicators from network/IDS event text.
- CSV/log import respects the per-case "AI off" toggle.
- Hayabusa `json-timeline` (concatenated JSON) now imports; relative paths no longer mis-read as accounts.
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
- Terminology "Attacker Path" → "Attack Path"; "Synthesize" → "AI Re-synthesize"; "Ask the AI" → "Ask the LLM".
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

[Unreleased]: https://github.com/hasamba/DFIR-Companion/compare/v0.27.0...HEAD
[0.27.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.26.0...v0.27.0
[0.26.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.25.0...v0.26.0
[0.25.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.23.0...v0.25.0
[0.23.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.22.0...v0.23.0
[0.22.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.21.0...v0.22.0
[0.21.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.20.0...v0.21.0
[0.20.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.19.0...v0.20.0
[0.19.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.18.0...v0.19.0
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
