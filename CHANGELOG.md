# Changelog

All notable changes to DFIR Companion are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Maintainer note:** keep entries concise (one line each). Add changes under `[Unreleased]`
> as you go; on release, rename it to the version + date, bump `companion/package.json`,
> `extension/package.json`, `extension/manifest.json` (+ both `package-lock.json`), and tag `vX.Y.Z`.

## [Unreleased]

### Added
- **CIRCL hashlookup enrichment** — keyless known-file lookup for hash IOCs against CIRCL's hashlookup DB (NSRL-derived + distro packages); the known-good angle that complements VirusTotal/Hunting.ch (high-trust hit → harmless, low-trust → unknown, `KnownMalicious` → malicious), `external` scope (opt-in per case), base overridable via `DFIR_HASHLOOKUP_URL` (closes #154).
- **Timeline pagination** — timeline renders 100/250/500 or all rows per page (user-selectable); page counter in the event count and prev/next controls at the bottom of the table (#125).
- **Correlation profile** — per-case named profile (Strict/Moderate/Aggressive) exposes the cross-source event merge window in the dashboard toolbar; `PUT /cases/:id/correlation-profile`; `DFIR_CORRELATE_WINDOW_S` env override still wins when set (#125).
- **Synthesis performance metrics** — `synth-meta.json` now records `durationMs`, `eventCount`, and `iocCount` from each synthesis run; dashboard "last synthesized" banner surfaces these, plus a ⚠ advisory when the case exceeds 5 000 events (#125).

### Fixed
- **Velociraptor pslist/pstree import** — NDJSON exports without `_Source`/`Artifact` markers (e.g. `F.<flowId>.H.json`) were mis-detected as SIEM, leaving all events undated and losing CommandLine; `CallChain`+`Pid` presence now correctly routes them to the Velociraptor importer with a dedicated `mapPslist` formatter showing `Name (pid) ← ppid: CommandLine`.
- **Velociraptor netstat import** — `Windows.Network.Netstat` exports were mis-detected as SIEM; `Laddr`+`Lport`+`Status` presence (and artifact-name fast-path) now routes them to a dedicated `mapNetstat` formatter showing process, protocol, status, and full `src:port → dst:port` with ESTABLISHED external connections promoted to Low severity and remote IP added as an IOC.

### Changed
- **Graph-grounded fleet-hunt suggestions** — `suggestHunts` now feeds the deterministic causal evidence graph (process spawn chains, file lineage, lateral-movement edges) into the prompt, so hunts target the *relationship* (parent→child chain, the binary/account that moved between hosts) fleet-wide instead of just the leaf indicator the flat timeline carries (#124).

## [0.23.0] - 2026-06-17

### Added
- **Mattermost & Discord notifications** — two new notification channels alongside Slack/Teams/Telegram/SMTP: Mattermost (Slack-compatible coloured attachment) and Discord (rich embed, severity-coloured, clickable case link); both webhook-based, with the test button + secret redaction (closes #136).
- **Explain This Event** — 💡 button on every forensic timeline row fires a focused AI call that explains the event in context: what happened, why it matters, normal-vs-suspicious assessment, ATT&CK mapping, 1–3 runnable pivot queries (Velociraptor VQL / KQL / SPL), and evidence for/against maliciousness; ephemeral (no state change), overlay panel with copy buttons on each query (closes #141).
- **IP-infrastructure enrichment** — four new IP-IOC providers surface the "where from / who owns it / what's hosted" context layer as `unknown`-verdict badges: **Reverse DNS** (PTR hostnames, keyless), **WHOIS** over RDAP (`DFIR_RDAP_URL`, keyless — netblock/CIDR/country/ASN/abuse-contact), **GeoIP** (`DFIR_GEOIP_URL`/`DFIR_GEOIP_KEY`, keyless default — country/city/ASN/org), and **Shodan** host (reuses `DFIR_SHODAN_KEY` — hosted domains/ports/services/CVEs); all opt-in per case (default OFF, OPSEC-safe), cached + throttled like every provider, surfaced in IOC badges + CSV export (closes #134).
- **Chain-of-Thought synthesis (extended thinking)** — lets the model reason step-by-step before writing findings on complex cases; maps to Anthropic extended thinking and OpenRouter's unified `reasoning` (other providers ignore it), applies to the synthesis call only, prompt-caching/OPSEC invariants intact. Enable globally via `DFIR_AI_SYNTH_THINKING_TOKENS` (≥1024) **or** per-run via the dashboard **🧠 deep** checkbox next to AI Re-synthesize / 2nd opinion (no restart; flows into both the primary and second-opinion passes) (#121, feature 1).
- **Adversary emulation — likely next techniques** — from the matched ATT&CK groups, surfaces the techniques they're known to use that the case *hasn't* observed yet (base-level), with **human names** ("T1114.002 Remote Email Collection") and ranked by **distinctiveness** (TF-IDF: matched-group consensus × global rarity) — ubiquitous tradecraft dropped above a prevalence cap and pre-compromise (recon / resource-dev) tactics excluded — so it points at telling, huntable tradecraft (email/clipboard collection, web-service C2) not "everyone does recon". Each suggestion has a **⌖ hunt this** button that generates a runnable, fleet-wide Velociraptor VQL hunt to proactively detect it (`POST …/adversary-hints/hunt-technique`). Predictive hunt priorities, still hypothesis fuel not attribution; offline ranking/`DFIR_ADVERSARY_NEXT_MAX` (10) / `DFIR_ADVERSARY_NEXT_MAX_PREVALENCE` (0.33); dashboard *Adversary Hints* panel + report §4.6.1 (closes #121).
- **Case lifecycle & archiving** — cases can be marked open/closed (`PATCH /cases/:id/status`); closed cases can be compressed to a ZIP archive (`POST /cases/:id/archive`) with a per-file SHA-256 manifest; disk-space warning banner in the dashboard when the cases-root filesystem reaches configurable thresholds (`DFIR_DISK_WARN_PCT`, default danger at 85%); toolbar lifecycle menu for close/reopen/archive (closes #119).
- **Custom declarative importers** — drop a JSON importer definition in the importers folder (or paste in Settings → Importers) and a matching file auto-detects + imports like a built-in; LLM-authorable via a built-in prompt, with user-selectable built-in/custom precedence.
- **Health / Diagnostics page** — Settings → Diagnostics surfaces operator system state in one place (disk usage, case count, capture/synthesis queue, redacted AI config + a live "Test AI connectivity" button, importer attempts 24h/7d + recent failures); fast `GET /diagnostics` (no recursive scan) with compute-on-demand `GET /diagnostics/sizes` (per-case/largest-file sizes), `POST /diagnostics/ai-test`, and a key-free copy-to-clipboard blob (closes #118).
- **OpenCTI enrichment** — local-scope IOC lookup against a self-hosted OpenCTI instance via GraphQL (closes #152).

## [0.22.0] - 2026-06-15

### Fixed
- **Extension push button on remote / modern Kibana** — the Elastic adapter now reads the **async-search strategy** envelope (`/internal/search/ese` → hits under `response.hits.hits`, the ES `_async_search` body), which recent Kibana Discover uses; the hook intercepted the response but `extractRows` didn't recognise the shape, so the button stayed gray / "No results". Also handles the other shapes `/internal/bsearch` emits — single JSON, streamed NDJSON, and **bfetch compression** (remote/Cloud, each line `base64(deflate(JSON))`, decompressed in-browser via `DecompressionStream`) — and re-injects the floating button after React re-renders the page body (`MutationObserver`) so it survives a refresh on SPA consoles.
- **Pushed Elastic rows from `_source`-disabled indices** — when an index has `_source` off (common for high-volume timeline data), Kibana returns docvalue `fields` (each value an array) instead of `_source`; the adapter now flattens those into scalar rows, so the import sees real fields (`@timestamp`, `desc`, …) instead of a raw hit. The generic SIEM mapper now reads `desc` as the description and summarizes **salient** fields (detections, rule hits, command lines) instead of dumping Elasticsearch metadata (`_index`/`_version`/`_ignored`) — fixing "undated" events with no meaningful description.
- **MemProcFS `timeline_all.csv` Net IOCs** — used an invalid `"network"` IOC type (broke `tsc`; only `vitest`'s no-typecheck transpile let it pass); now correctly typed as `ip`.

### Added
- **Second LLM opinion** — an on-demand QA cross-check that runs a *different* model independently over the same case (non-destructive re-synthesis), then a reconcile pass surfacing where it disagrees with the primary synthesis (findings it adds/drops, severity, ATT&CK technique) with a rationale + recommendation for per-item analyst accept/reject; accepted deltas are durable across re-synthesis; `DFIR_AI_SECOND_OPINION_MODEL` (off until set), `POST/GET /cases/:id/second-opinion` + `…/apply` (closes #116).
- **Velociraptor data from Elasticsearch routes to the Velociraptor importer (JSON push + CSV export)** — when Velociraptor/DetectRaptor output is indexed into Elastic and either pushed from Kibana (JSON) or downloaded as a Discover **CSV export**, `detectImportKind` now recognises it (the `artifact_<name>` index or flattened `Detection.*`/`Artifact` columns) and routes to `importVelociraptor` for full severity + MITRE + Sigma/YARA classification, instead of the generic AI CSV / SIEM path — so it works with AI off. The importer parses the CSV (dropping Kibana's `-` empty-cell placeholder) and normalizes the ES-reshaped rows back to native form (un-flatten dotted keys, collapse `.keyword`/`.text` multi-fields, derive the artifact from the index name) — gated so native Velociraptor JSON is untouched — reads DetectRaptor keyword-hit verdicts from `Detection.StringHit`/`HitString`, and parses Kibana display-format timestamps (`May 7, 2026 @ 16:31:04.000`) to UTC ISO.
- **MemProcFS timeline_all.csv importer** — deterministic parser for the full-system kernel timeline (Time,Type,Action,PID,Value32,Value64,Text,Pad); ShTask CRE/DEL → Medium/T1053.005|T1070, Net TCP → Low/T1071, WEB DOWNLOAD → Low/T1105, PROC → Info; NTFS CRE with exec extensions → file IOCs; 254k REG + THREAD rows dropped; auto-detected by the unified Import button.
- **MemProcFS findevil importer** — deterministic parser for the `findevil` finding-report table; maps finding types to severity + ATT&CK (YR_HACKTOOL → Critical/T1588.002, PEB_MASQ → High/T1036.005, PE_PATCHED → High/T1055, THREAD SYSTEM_IMPERSONATION → High/T1134, etc.); groups bulk PRIVATE_RWX/PRIVATE_RX pages by process; harvests driver/module/patched-DLL paths as file IOCs; auto-detected by the unified Import button.

## [0.21.0] - 2026-06-15

### Added
- **GraphRAG for "Ask the case"** — the Ask prompt is now grounded with the deterministic evidence-chain graph (process spawns, file lineage, lateral movement, network flows) serialized as causal edges with backing event ids, so multi-hop questions ("trace the path from the phishing email to the Domain Controller") are answered by following real graph relationships instead of the flat timeline; edge count capped by `DFIR_ASK_GRAPH_MAX_EDGES` (default 120, highest-severity first), pure + no extra AI call (closes #98).
- **Memory-forensics "Next-Step" agent** — when a case has Volatility 3 / Rekall output imported, one AI call reads the memory evidence (process tree, `malfind`, connections, command lines), spots anomalies (e.g. `svchost.exe` without a `services.exe` parent, injection, suspicious connections), and proposes the exact next Volatility command to run (`vol -f <image> windows.malfind --pid 1234`); a **✨ Suggest next steps** button in a *Memory Next Steps* panel shown only when memory evidence exists, ephemeral, `POST /cases/:id/memory/next-steps` (closes #101).
- **Volatility 3 text-output import** — the memory importer now also ingests the **default `vol <plugin>` TEXT/grid renderer** (banner + TAB-separated table), not just the `-r json` renderer; `malfind`/`pstree` hexdump+disasm continuation lines are skipped and rows are parsed into the same shape as the JSON path, so `malfind.txt`/`pslist.txt` etc. import directly via the unified Import button (#101).
- **Natural-language Query Translator** — a dashboard search bar that turns a plain-English hunting request ("PowerShell downloading a file and then executing it", "outbound RDP from this host") into a runnable query for each enabled platform — Velociraptor VQL, Defender/Sentinel KQL, Elastic ES|QL, Splunk SPL, Sigma, YARA, Suricata — grounded in each platform's real schema; one AI call, ephemeral, the Velociraptor query one-click-deploys via the existing hunt flow; platforms gated by `DFIR_HUNT_PLATFORMS`, `POST /cases/:id/translate-query` (closes #100).
- **One-click artifact push from the browser extension** — on recognized DFIR consoles (Splunk / Velociraptor / Elastic-Kibana / CrowdStrike) the extension injects a **Push to DFIR-Companion** button that intercepts the clean JSON the tool already fetched (a MAIN-world `fetch`/`XHR` hook, injected only on recognized tools) — or scrapes the visible results table as a fallback — and POSTs it to the selected case's unified `/import` route on explicit analyst click; per-tool site adapters, no-op on unrecognized sites. Pushed artifacts trigger the same **cross-case dashboard warning** as screenshots when they land in a case the dashboard isn't viewing, and turning AI on now synthesizes evidence imported while it was off (closes #102).
- **Timeline-gap hypotheses & shadow-artifact hunting** — for each flagged silent period, one AI call hypothesises what the attacker did during the silence (grounded in the events bracketing the gap) and pairs every gap with a deterministic catalog of *shadow artifacts* (USN Journal, SRUM, Prefetch, Amcache, ShimCache, BAM, MFT, UserAssist, LNK) — each a deployable Velociraptor collection to reconstruct the missing window; a **✨ Hypothesize gaps** button in the *Timeline Gaps* panel, ephemeral, `POST /cases/:id/timeline-gaps/hypothesize` (closes #96).
- **Sort timeline by date or severity** — per-column ▲/▼ sort arrows in the Forensic Timeline header: sort by **date** (oldest/newest first) from the Timestamp column and by **severity** (most/least severe first) from the Message column; client-side only, persisted across reloads, no server round-trip (closes #104).
- **Payload deobfuscation** — automatically detects and decodes base64-obfuscated PowerShell (`-enc`/`-EncodedCommand`) and `[Convert]::FromBase64String` payloads in the forensic timeline; extracts hidden IOCs (URLs, IPs, hashes, domains) from decoded content; shows an expandable **[Decoded]** block per event in the dashboard; applied deterministically (no AI) on every import and push-ingest, and on demand via `POST /cases/:id/deobfuscate` (closes #97).
- **CISA KEV integration** — cross-reference CVEs found in the forensic timeline and IOCs against the CISA Known Exploited Vulnerabilities catalog; KEV-matched CVEs are surfaced in the synthesis context (initial-access signal) and in a new report §4.5.1; load the catalog from the CISA feed URL or a local file via Settings → KEV; deterministic, no AI, opt-in (closes #99).
- **Import from DFIR-IRIS** — pull an existing IRIS case's assets/IOCs/timeline into a Companion case (the reverse of the push); deterministic `importIris` / `irisImport.ts` maps timeline events (severity from colour, MITRE/asset/hash from tags+content), IOCs (type from the IRIS ioc-type or value shape), and assets → evidence events; a compact **"Import case"** toolbar icon opens a chooser (Investigation snapshot or From DFIR-IRIS) + `npm run iris:import`; **Settings → DFIR-IRIS "Test / reconnect"** rebuilds the client from `.env` and pings so config (or IRIS coming back online) applies without a restart (closes #88).
- **Webhook push ingest** — `POST /cases/:id/push` lets external tools (SIEM webhooks, custom scripts) push alerts into a case in real time; token auth (`X-DFIR-Key`: global `DFIR_PUSH_TOKEN` and/or a per-case token in Settings), `importDetect` routing, same import → diff → re-synthesize pipeline, 202-and-async (closes #84).
- **Velociraptor live monitoring** — stream a CLIENT_EVENT artifact (e.g. `Windows.Events.ProcessCreation`) into a case as events fire, from **one endpoint or all enrolled clients**; one-click **auto-monitor** starts an all-clients monitor for every artifact already enabled in Velociraptor's Client Monitoring table; server-side poller (`DFIR_VELO_MONITOR_POLL_S`, default 30s) with a persisted cursor (`state/velo-monitor.json`) so a restart never re-ingests; Settings → Velociraptor → Live Monitoring + a 🔴 LIVE dashboard badge (closes #84).
- **Velociraptor reconnect** — `POST /velociraptor/reconnect` (Settings → Velociraptor → **Reconnect**) re-reads `DFIR_VELOCIRAPTOR_*` from `.env`, rebuilds the client, and refreshes the inventory (the reachability probe), so configuring Velociraptor after boot — or the server coming back online — applies without a companion restart; the startup inventory refresh now **retries with backoff** so a Velociraptor that comes up shortly after boot self-heals (#84).
- **IOC block-list export** — one-click block-list for network/firewall teams via Export → IOC block-list…; three formats: plain TXT (grouped by type), minimal CSV, and STIX-indicators-only bundle; filters by min severity (default Medium), IOC type, and verdict-confirmed-only; `GET /cases/:id/export/ioc-blocklist` (closes #87).
- **Wazuh importer** — deterministic import of Wazuh SIEM/EDR alert exports (`alerts.json`, NDJSON, Wazuh API `{ data: { affected_items } }` envelope); `rule.level` → severity, MITRE from `rule.mitre.technique`, `agent.name` → asset, data field IOCs (IP/hash/URL); auto-detected by the unified Import button (closes #85).
- **TheHive importer** — deterministic `importTheHive` / `theHiveImport.ts`; TheHive 5 case, alert, and observable exports → forensic events + IOCs; severity from TheHive's 1–4 scale, MITRE from ATT&CK-tagged tags, TLP/PAP labels prepended, observables mapped by `dataType`; Elasticsearch hit-wrapper guard (closes #86).
- **Log gap analysis** — flag suspiciously long silent periods in the forensic timeline; a gap where **every source went dark** (High, earns a finding) is the classic cleared-logs/stopped-collector signature, a single tool going quiet while others log is partial (Medium). Density-aware so naturally-sparse timelines aren't noisy; optional `DFIR_GAP_ACTIVE_HOURS`. Derived on read, no AI; dashboard *Timeline Gaps* panel + report §3.3; thresholds `DFIR_GAP_MIN_MINUTES`/`DFIR_GAP_DENSITY_FACTOR` (closes #83).
- **Beacon / C2 detection** — flag outbound connection channels (host → dest:port) whose inter-arrival intervals are too regular to be human traffic; robust **median/MAD** period estimate so a missed beacon or operator burst doesn't hide a real channel. Derived from the network timeline, severity High for public destinations, a hunting lead not a verdict. Dashboard *Beacon Candidates* panel + report §4.9; thresholds `DFIR_BEACON_MIN_COUNT`/`DFIR_BEACON_MAX_JITTER_PCT` (closes #82).

### Changed
- **Customer Exposure shows found results only** — the dashboard panel and report §4.5 now hide clean "checked, no breach" rows (shared `hasExposureFinding` guard: keep rows with a breach, exposed data, or credential material); the providers/targets lines still record what was checked.
- **Demo case enriched for every section** — `seed-demo` now seeds a deliberate anti-forensics blackout (cleared DC01 event logs + EDR tampering → a ~16h complete-silence gap with finding f010) so the *Timeline Gaps* panel and the new **Hypothesize gaps** (#96) feature have compelling material, plus a seeded narrative timeline and investigator-notebook entries so those sections render too.

### Fixed
- **Extension case selection saves without pressing Start** — the extension popup's case dropdown now auto-saves on change (keeping screenshot-capture state unchanged), so switching cases or clearing the case applies immediately; the floating "📤 Push" button on DFIR consoles now only appears when a case is connected and hides dynamically when the case is cleared.
- **Demo Customer Exposure rows rendered half-empty** — `seed-demo`'s `customer-exposure.json` used a stale schema (`input`/`kind`/`breachNames`/`exposedFields`) so the dashboard (reading `target`/`targetType`/`breach`/`exposedData`) showed only `HIBP · :`; rewritten to the current `StoredCustomerExposureResult` shape (one row per HIBP breach, one per Shodan host, plus `providers`/`targets`/`errors`).

### Fixed
- **Velociraptor live-monitor discovery on real servers** — the CLIENT_EVENT artifact picker and **Auto-monitor configured events** came back empty on actual Velociraptor: the artifact `type` is now filtered in **TypeScript** (fetch all `artifact_definitions()`, normalize the type string) instead of a VQL `=~`/`lowercase()` filter that missed `CLIENT_EVENT` across versions, and the monitoring-table read returns the raw `GetClientMonitoringState()` proto and extracts names in TS (walks `artifacts.artifacts` + `specs` + `label_events`, casing-tolerant). The picker auto-populates when Velociraptor is connected; a new **`GET /velociraptor/diag`** endpoint dumps the real artifact-type counts + raw monitoring-state shape. **Auto-monitor** now uses the correct VQL function **`get_client_monitoring()`** (the previous `GetClientMonitoringState()` is the Go/gRPC name and returns null as a VQL call — confirmed against a real server via `/velociraptor/diag`); still overridable via `DFIR_VELOCIRAPTOR_MONITORED_VQL` (#84).
- **`seed-demo` now honours `DFIR_CASES_ROOT`** — the seed script didn't load `.env` (every other script does), so it wrote the demo to `companion/cases` while the server read from the configured root, and the dashboard showed no case.

## [0.20.0] - 2026-06-13

### Added
- **Import undo/redo** — roll the whole case (findings, IOCs, timeline, MITRE, attacker path) back to exactly before an import that floods the dashboard, and redo; restores the snapshot verbatim with no AI call. A per-case stack keeps multiple levels (`DFIR_IMPORT_UNDO_DEPTH`, default 10), surfaced as Undo/Redo buttons next to the Import button (closes #76).
- **AI-suggested playbook hunts** — propose a Velociraptor hunt for each endpoint-related Playbook task; a task tied to one host deploys as a single-endpoint collection (`collect_client`), otherwise a fleet hunt; suggestions render inline under each task and collapse (closes #70).
- **Velociraptor client inventory** — snapshot the enrolled fleet (host/FQDN ↔ client id) into `velociraptor/clients.json` at startup, on demand (Settings → Velociraptor → Refresh client list), and when playbook hunts are generated (so a client enrolled mid-investigation is resolvable); single-endpoint collections resolve the host from it (short-name⇄FQDN tolerant), self-healing on a miss (#70).
- **Collection results in the dashboard** — a single-endpoint collection now pulls its rows back inline (Refresh + auto-poll, rendered as a table) like a fleet hunt, instead of only deep-linking to the Velociraptor GUI; `POST /velociraptor/collect-results` (#70).
- **Dedicated Velociraptor hunt model** — a separate LLM just for generating Velociraptor VQL hunts (`DFIR_AI_VELO_PROVIDER`/`_MODEL`/`_KEY`/`_BASE_URL`, default `openrouter` / `anthropic/claude-haiku-4.5`), since many models botch VQL; editable in Settings → AI (#70).
- **Persistent + incremental hunt suggestions** — generated playbook hunts survive a page refresh (`state/playbook-hunts.json`); a suggestion is kept while its task is unchanged and dropped once the task is reworded/deleted. Pressing Generate again only sends NEW or CHANGED tasks to the model, never regenerating hunts that already exist (`force:true` regenerates all) (#70).
- **Playbook task short IDs** — each task gets a stable sequential display ID (`T001`, `T002`, …) stored in the task record; shown at the bottom-left of each card in the same blue monospace style as IOC and Finding IDs; existing tasks are back-filled on the next sync.
- **Telegram notifications** — Telegram bot channel for findings/playbook/milestone notifications; configure via bot token + chat ID in Settings → Notifications (closes #75).

### Fixed
- **Playbook delete button for auto-derived tasks** — deleting a next-step or finding task now marks it `skipped` (persists across re-syncs) instead of silently removing it and having syncPlaybook re-add it immediately (closes #78).
- **Playbook-hunt VQL grounded in the server's real artifacts** — the prompt now lists the Velociraptor server's actual CLIENT artifact names (fetched per generation) and forbids referencing any `Artifact.<Name>` not in that list, so the model stops inventing artifacts (e.g. `Windows.EventLogs.Sysmon`) that don't exist and fail to compile. Also: correct plugin args (`parse_evtx(filename=…)`, `handles(pid=…)`), prefer raw plugins, no SQL `JOIN` (use `foreach`), `timestamp(string=…)` for absolute times; per-call timeline trimmed (`DFIR_PBHUNT_MAX_EVENTS`/`DFIR_PBHUNT_MAX_ARTIFACTS`) (#70).
- **Endpoint-side collection errors surfaced** — when a collection launches but its flow ends in `ERROR` (e.g. a bad plugin arg), the dashboard now shows Velociraptor's error message instead of polling "no results yet" forever; the no-flow-id error for both collections and hunts now points at the VQL (a non-existent artifact/plugin can't compile) rather than blaming the api_client role (#70).

## [0.19.0] - 2026-06-12

### Added
- **Linux evidence importers** — deterministic auditd (`audit.log`/`ausearch`/`aureport`), journald (`journalctl -o json`), and sysdig/Falco (alert + `-j` event JSON) ingest, auto-detected by the unified Import button (closes #62).
- **Mobile companion** — installable read-only PWA at `/mobile` (case status, worst findings, severe/recent timeline, IOC verdicts) for quick glances during IR; navigate directly to `http://127.0.0.1:4773/mobile`; `/cases/:id/mobile-summary` endpoint, `DFIR_MOBILE_MAX_*` caps (closes #59).
- **AI-suggested fleet hunts** — generate proactive Velociraptor VQL hunts from the case findings, review the VQL + rationale, one-click deploy across all enrolled endpoints (closes #57).
- **Memory forensics import** — deterministic Volatility 3 (JSON renderer) + Rekall importer: pslist/psscan/pstree → process tree, netscan → connections, malfind → injected code (T1055), cmdline/svcscan/modules → evidence (closes #61).
- **Investigation snapshot** export/import — one shareable JSON (timeline, findings, IOCs, graph state, analyst decisions, evidence references) restores a case on another machine, with no AI keys or machine config (closes #56).
- **Redacted case export** — shareable ZIP for external parties: report/CSVs/state tokenized (internal IPs/hosts/users/emails/paths → consistent `ANON_*`), secrets redacted, screenshot EXIF stripped + PII text blurred (OCR); AI keys/config excluded (closes #54).
- **Dark / light theme** — full-coverage theme toggle in the dashboard header; follows the OS `prefers-color-scheme` by default, manual choice persists in `localStorage` across sessions; every panel, graph and the swimlane canvas themed via CSS variables (closes #53).
- **Custom report templates** — global branded report layouts (accent colour, cover title/subtitle, running header/footer with `{{placeholder}}` interpolation, and per-section enable/reorder), built-ins editable in place, selected per case; flows to Markdown/HTML/Word (closes #60).
- **Notifications** — Slack / MS Teams webhooks + SMTP email channels for new/escalated findings, playbook updates, and investigation milestones, with per-channel severity thresholds + event toggles; opt-in, secrets redacted; Settings → Notifications (closes #58).
- **NSRL known-good hash checking** — auto-marks matching forensic events + IOCs legitimate on import (reversible) to cut false positives. Two backends: a flat hash set (paste / server file / `DFIR_NSRL_FILE`) for custom lists, and **direct query of the full NSRL RDS SQLite database** (`DFIR_NSRL_DB` or connect in-UI) — the real ~160 GB set, never loaded into memory. Keys on sha256/md5; Settings → NSRL (closes #63).

### Changed
- Dashboard: removed **Mobile** toolbar button — navigate to `/mobile` directly in your browser.
- Dashboard: finding tag chips reordered — tag icon after comment chip, tag labels after confidence score (matches timeline layout).
- Dashboard: case ID input fixed-width to fit `INC-YYYY-NNN`.
- Dashboard: removed ellipsis from **Import** and **Import snapshot** button labels.

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

[Unreleased]: https://github.com/hasamba/DFIR-Companion/compare/v0.23.0...HEAD
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
