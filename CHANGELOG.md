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
- **Dashboard: global full-text search + time-range filter, tucked behind a search icon.** A single magnifier-icon button (line-art, matching the toolbar action icons) sits in a slim bar under the header; clicking it (or pressing `/` anywhere outside a text field) reveals the search box + *from/to* time-range pickers — they're no longer always on screen. The text search filters the forensic timeline, findings, and IOCs as you type (300 ms debounce; mirrors `analysis/searchFilter.ts`); the time-range filter bounds the timeline to a UTC window; a match-count (`N of M events shown`) appears while filtering. `Esc` in the box clears the query, then a second `Esc` collapses the bar; the icon keeps an accent while any filter is active, so a collapsed bar still signals the view is filtered. Clear buttons reset each control independently, and switching cases collapses the bar and clears all filters.

## [0.15.0] - 2026-06-10

### Changed
- **Dashboard: the Analyst Notebook section now sits directly after _Confirmed Legitimate_ by default**, and is registered in the section reorder/visibility list (`SECTION_DEFS`) so it can be hidden or dragged like every other section (it was previously fixed after _Investigation Log_ and not manageable from Settings → General).

### Fixed
- **Velociraptor bundle collection no longer fails on a large artifact (e.g. Hayabusa/THOR).** Collecting a hunt used to abort the whole import the moment one artifact's output exceeded the 50 MB query cap (`"output exceeded 52428800 bytes"`), so a bundle containing a heavy artifact couldn't be imported at all. Three changes: (1) **resilient collection** — each artifact is fetched independently and one that's too large is **skipped (logged)**, not fatal, so the rest still import (and a skipped artifact's uploaded JSON is still picked up); (2) **`hunt_results` is now `LIMIT`-bounded** at the source (`maxRows+1`) so a huge result set can't blow the cap before it's capped anyway; (3) a **larger, separate cap for collection** — `DFIR_VELOCIRAPTOR_COLLECT_MAX_OUTPUT` (default **256 MB**, vs the 50 MB interactive cap) is used for hunt-results + the uploaded-JSON read, and the upload VQL skips any single file bigger than the cap at the source. The cap error message now points at the env vars to raise.
- **Velociraptor triage now supports multiple concurrent bundle hunts.** Starting a second hunt while a first was still running used to overwrite it — its status, countdown, auto-collect timer, and "Collect now" button all vanished, stranding the first hunt. Hunts are now tracked as a per-case **list** keyed by hunt id (`state/velo-hunt.json` is an array; old single-object files load as a one-element list), each with its **own** auto-collect timer (keyed by hunt id) and its **own** status card + **Collect now** button (`POST …/collect` takes `{ huntId }`). `GET …/hunt-job` → `GET …/hunt-jobs` (returns the newest-first list).
- **Velociraptor "open in Velociraptor" hunt deep links now include `?org_id=`** (before the `#` fragment, where the GUI's SPA router reads it) — without it the link opened the wrong/empty org. Defaults to the `root` org; override with `DFIR_VELOCIRAPTOR_ORG` (also surfaced as a **GUI org** field in Settings → Integrations). Applies to both the bundle-hunt and pivot-hunt deep links.

### Added
- **IOCs: "⚠ Flagged only" filter.** A toggle in the IOCs section header shows only IOCs that came back **malicious or suspicious** from *any* enrichment engine (VirusTotal, Hunting.ch, AbuseIPDB, CrowdStrike, MISP, YETI, …), with a count of how many are flagged — so after enrichment you can jump straight to the indicators that matter and hide the clean/unknown noise. Pure client-side filter over the existing `enrichments[].verdict`; resets on case switch.
- **Velociraptor triage bundles — pick artifacts → run as a hunt → auto-import + synthesize (closes #30).** A dedicated **Velociraptor** tab in **Settings** turns the existing fleet-hunt plumbing into a repeatable, one-click triage workflow (it's a configuration/action surface, so it lives in Settings — the results land on the dashboard timeline/IOCs). **Browse server artifacts** queries the configured Velociraptor server on demand (`GET /velociraptor/artifacts` → `artifact_definitions()` filtered to collectable `CLIENT` artifacts) and lists them grouped by family. From that list you assemble and save named **bundles** (a.k.a. blueprints/triage packs) — stored **globally** (shared across cases) alongside `cases/` in a `bundles/` dir. A single **Best Practice** built-in (a cross-platform "quick wins" detection sweep — DetectRaptor + Velociraptor detection/triage artifacts) ships by default. **All bundles, built-ins included, are editable in place** (an edit saves an override under the same id; **Reset to default** discards it); custom bundles can be duplicated and deleted. Running a bundle launches a **hunt over the chosen artifacts** across all enrolled clients, optionally scoped by **include/exclude labels + OS** (Velociraptor's own hunt conditions), a **minimum-severity import floor** chosen at run time (keeps low-value telemetry out), and a **per-collection timeout** set on the bundle (passed to the hunt's `timeout` and applied automatically on every run, so slow artifacts like THOR can run past Velociraptor's 600 s default). Bundles can also carry **per-artifact parameters** (passed to the hunt's `spec`) so a heavy artifact emits less **at the source** — the Best Practice built-in ships with **Hayabusa pinned to `RuleLevel`=Critical/High/Medium + `RuleStatus`=Stable+Experimental** so it doesn't flood the import with 10k+ low-value rows; an optional, collapsed **Advanced → parameters** JSON editor in the bundle builder lets you set params for any artifact (only what you set is sent; everything else uses the artifact's defaults). Bundles can likewise carry per-artifact **exclude filters** — a VQL `WHERE` expression applied to that artifact's `hunt_results` **before** the row cap, so noisy rows are dropped at the source (kept rows are the relevant ones, not the first N pre-filter). Best Practice ships filters that drop **pagefile YARA hits** (`DetectRaptor.Generic.Detection.YaraFile`) and an in-development Evtx rule; set your own in the same Advanced editor. Because a hunt stays open until its expiry, the run **doesn't wait** — it schedules an **auto-collect after a configurable delay** (default **10 min**, `DFIR_VELO_HUNT_WAIT_MIN` / per-bundle default; clamped 1–1440), then ingests **both** the result rows (the `{ "Artifact.Name": [rows] }` artifact-map the deterministic **Velociraptor importer** consumes) **and any uploaded JSON reports** — for collector artifacts like `Generic.Scanner.ThorZIP` / `Windows.Hayabusa.Rules` the rows don't matter, the uploaded JSON does: it's read server-side and **auto-detected + dispatched** to the right importer (THOR/Hayabusa/etc.), HTML uploads ignored (override the upload VQL per Velociraptor version with `DFIR_VELOCIRAPTOR_UPLOAD_VQL`). The collection records **one combined import-meta diff** (so the "📥 last import / +N events / +N IOCs" banner lights up), then triggers **AI synthesis** — the same path a manual import takes. A persisted per-case job (`state/velo-hunt.json`) survives a server restart, so the dashboard shows a live status card with a countdown and a **Collect now** button to pull results early (or re-pull stragglers). New routes: `GET /velociraptor/artifacts`, `GET/POST/DELETE /bundles`, `POST /cases/:id/velociraptor/run-bundle`, `GET /cases/:id/velociraptor/hunt-job`, `POST /cases/:id/velociraptor/collect`. New `VelociraptorClient` methods (`listClientArtifacts`, `launchArtifactHunt`, `huntResultsByArtifact`, `huntUploads`) reuse the injectable VQL runner with strict name/label sanitization (no VQL-string injection); the `ArtifactBundleStore` (global) and `VeloHuntStore` (per-case) are pure + unit-tested, and route-level tests exercise the launch→collect→import→imported flow (rows and uploaded-JSON) end-to-end with a mock runner.
- **Export to Notion (closes #31).** A new **Export to Notion** option in the dashboard's *Push to…* menu (and `npm run notion:push -- <caseId>`) pushes a case's structured content — executive summary, findings, forensic timeline, IOCs (with verdicts), MITRE ATT&CK, attacker path, key questions, next steps, and the human-authored report sections — into a Notion page so multiple investigators can collaborate around it. The option asks whether the target is a **new page** or an **existing page**: *new* creates the page as a row in a Notion database (`DFIR_NOTION_DATABASE_ID`, the "ongoing investigation template") or under a parent page (`DFIR_NOTION_PARENT_PAGE_ID`); *existing* updates a page you paste (URL or ID). **The Companion writes ALL its content inside ONE managed toggle block it owns on the page**; a re-export archives that block's children and re-appends the latest case data, so anything you wrote *outside* the block (your own notes, pasted finding screenshots) is **never read or touched**. Notion has no find-by-name, so the target page + managed-container id are remembered per case in `state/notion-export.json`; if you delete the managed block, the next export recreates it. Enabled by `DFIR_NOTION_TOKEN` alone (share the target page/database with the integration). Hand-rolled `NotionClient` over an injectable `fetchFn` (no network in tests), a pure `notionBlocks.ts` state→blocks renderer, and a pure `pushCaseToNotion` orchestrator behind a structural `NotionClientLike` interface — all unit-tested. Content is scope/legitimate-filtered to match the report; screenshots are referenced by filename (you keep pasting the images yourself); large timelines/IOCs are batched to respect Notion's 100-block/append limit.

## [0.14.0] - 2026-06-09

### Added
- **Anthropic prompt caching for the extraction system prompt (closes #18).** The `AnthropicProvider` now marks the static system prompt as the cacheable prefix (`cache_control: ephemeral`), so it's billed once and read cheaply across the many per-screenshot extraction calls instead of re-sent in full each time. The cache breakpoint sits on the system prompt **only** — the case content (user message + screenshots) follows it and is **never** cached, so no forensic evidence is retained provider-side for the cache TTL (OPSEC). Token usage (`cache_creation_input_tokens` / `cache_read_input_tokens`) is parsed back from the response and exposed on `AnalyzeResult.usage`; set `DFIR_AI_DEBUG_USAGE=1` to log per-call cache read/write and confirm it fires (a prefix under the model's minimum — 1024 tokens, 2048 on Haiku — silently no-ops). Anthropic-only: OpenAI/OpenRouter cache automatically; Ollama/litellm/local don't cache. Synthesis (a single, often-skipped call) is deliberately not cached — no reuse, no benefit.
- **Analyst Notebook — per-case scratchpad for hypotheses, notes, and open questions.** A new collapsible **Analyst Notebook** panel in the dashboard lets investigators write free-form hypotheses, working notes, and open questions as they move through a case. Entries are typed (`hypothesis` / `note` / `question`) with colored type badges, can be edited or deleted, and are stored in `state/notebook.json` — a side file that **survives synthesis resets** just like comments and tags, never wiped by AI re-analysis. When the analyst opts in (checkbox in the panel → `ai-control.json` `includeNotebook: true`), the notebook entries are **appended to the synthesis prompt** so the AI can incorporate investigator thinking into its findings and attacker-path reconstruction. Notebook changes are included in the skip-if-unchanged hash, so adding a new entry always triggers a fresh synthesis when the option is on. When the case report is generated, entries appear in an **Analyst Notebook appendix** (Markdown + HTML). API: `GET/POST /cases/:id/notebook`, `PATCH /cases/:id/notebook/:entryId`, `DELETE /cases/:id/notebook/:entryId`; the existing `POST /cases/:id/ai-control` also accepts `{ includeNotebook: boolean }`. Pure store logic (`analysis/notebookStore.ts`) is fully unit-tested. Closes #8.
- **Narrative Timeline — prose story-mode view of the incident.** A new **Narrative Timeline** section in the dashboard (and report §3.2) generates a flowing, chronological prose narrative of the incident written for management and non-technical stakeholders: "At [time], the attacker gained initial access by… This was followed by…" The narrative is generated as part of synthesis (stored in `state.narrativeTimeline`, re-generated on each synthesis run alongside the `attackerPath`). A **✨ Generate** button on the dashboard triggers a standalone AI call (saves automatically). An **✏ Edit** button opens an inline textarea so the analyst can refine the narrative before export (saved via `PUT /cases/:id/narrative`). The report always includes §3.2 even when the narrative is absent (placeholder text guides the analyst to generate it). No new prompt-override env var is needed — the narrative output is added to the existing `SYNTH` prompt; `DFIR_AI_SYNTH_PROMPT` / `DFIR_AI_SYNTH_PROMPT_FILE` overrides apply. A standalone `NARRATIVE_PROMPT` (overridable via `DFIR_AI_NARRATIVE_PROMPT`) drives the Generate-button path when re-generating without a full synthesis.
- **Case templates — start new cases pre-loaded with investigation questions and artifact hints.** A new **Template (optional)** selector in the *+ New case* modal lets you pick from five built-in templates (Ransomware, BEC/Email Compromise, Insider Threat, Web App Intrusion, General Malware) or any custom template you have saved. Selecting a template shows a brief description + recommended import types and hunt platforms; creating the case pre-populates the **Key Questions** section with template-specific investigation questions (pinned, so synthesis can answer them over time). Templates are served from `GET /templates` (built-ins always present) and saved to a `templates/` directory alongside `cases/`. Custom templates can be saved from the Export menu's **Save as Template…** option — it captures the current case's key questions plus a name and description. The API also supports `GET /templates/:id`, `POST /templates`, and `DELETE /templates/:id` (built-ins are read-only). Built-in templates: **Ransomware** (chainsaw/hayabusa/thor/velociraptor/kape, High severity floor), **BEC/Email Compromise** (m365/siem, Medium), **Insider Threat** (siem/kape/m365/aws, Medium), **Web App Intrusion** (network/siem/chainsaw/hayabusa, Medium), **General Malware** (thor/chainsaw/hayabusa/velociraptor/sandbox, High). The template store is pure + unit-tested (`TemplateStore`, `buildInitialQuestions`).
- **Per-provider enrichment throttle (`DFIR_ENRICH_DELAY_MS_<PROVIDER>`).** Each enrichment provider now runs at its own configurable rate instead of sharing a single `DFIR_ENRICH_DELAY_MS` global. Fast providers (AbuseIPDB, CrowdStrike, MISP, YETI) proceed at their own pace while slow-rate ones (RockyRaccoon free tier: 10/min → 6 000 ms; VirusTotal free tier: 4/min → 15 000 ms) wait independently. Set `DFIR_ENRICH_DELAY_MS_ROCKYRACCOON=6000`, `DFIR_ENRICH_DELAY_MS_VIRUSTOTAL=15000`, etc.; unset providers fall back to `DFIR_ENRICH_DELAY_MS`. The per-provider delay also applies to the RockyRaccoon process-chain validation pass.
- **Configurable companion host/port in the extension (closes #12).** The companion URL (host + port) is now configurable via the extension's **Options page** (right-click the extension icon → Options, or chrome://extensions → Details → Extension options). The URL is persisted in `chrome.storage.local` and shared with the popup's existing Companion URL field. The manifest's redundant `http://127.0.0.1:4773/*` host permission has been removed (the already-present `<all_urls>` covers any custom host/port). A `normalizeCompanionUrl()` helper strips trailing slashes so a URL like `http://host:port/` doesn't produce a double-slash in POST paths.
- **`_execute_action` keyboard shortcut to open the extension popup.** Added the Chrome MV3 reserved `_execute_action` command to the extension's `manifest.json` `commands` block — Chrome natively opens the popup when the user triggers it. No suggested default key is set so the shortcut stays conflict-free; configure it at `chrome://extensions/shortcuts`. Complements the existing `Ctrl+Shift+S` capture-toggle shortcut.
- **Manual editing of assets and asset ↔ IoC links.** Analysts can now correct the auto-derived asset graph: **rename** a misidentified host or account, **add** new assets not visible in the timeline, **suppress** a false-positive asset or link, and **add** manual links between assets and IoCs. All edits persist per case in `state/asset-overrides.json` — a side file outside `InvestigationState`, so **synthesis never wipes them** (same pattern as comments and tags). Applied via a pure `applyAssetOverrides()` function on top of `buildAssetGraph()`, so the deterministic baseline is always preserved; the dashboard graph, report section 4.2, and markdown/HTML exports all reflect the overrides. Dashboard controls: a **+** toggle on the Compromised Assets section header opens add-asset and link-management forms; each asset chip in the list gains pencil (rename) and × (suppress) buttons, and suppressed assets are shown with a ↺ restore button. API: `GET /cases/:id/asset-overrides`, `PUT .../assets/:assetId` (rename), `POST .../assets` (add), `DELETE .../assets/:assetId` (suppress/delete), `POST .../assets/:assetId/restore`, `POST .../links` (add link), `DELETE .../links?asset=...&ioc=...` (suppress link). WS push: `asset_overrides_changed` refreshes the dashboard graph on every write.
- **Settings → General: drag-to-reorder dashboard sections.** Section rows are now draggable (HTML5 drag-and-drop, braille-dot handle). The new order is persisted in `localStorage` (`dfir.sectionsOrder`) and applied to the live dashboard immediately on drop. New sections introduced in future releases are appended after the saved order. **Select all / Deselect all** buttons above the list make it easy to show or hide everything at once.
- **Settings → Enrichment/Integrations: missing TLS skip-verify fields.** `DFIR_MISP_INSECURE`, `DFIR_YETI_CA`, `DFIR_YETI_INSECURE`, `DFIR_IRIS_INSECURE`, `DFIR_TIMESKETCH_CA`, and `DFIR_TIMESKETCH_INSECURE` were already supported in the server (`tlsFetchFor`) and documented in `.env.example` but had no corresponding UI fields. All six are now surfaced in their respective settings tabs.

## [0.13.0] - 2026-06-09

### Added
- **Settings modal** — a ⚙ Settings button in the header opens a tabbed modal that consolidates all configuration in one place. **General tab**: investigator name (moved from the header), per-section visibility toggles (18 sections, stored in `localStorage`) and server-side tuning knobs (`DFIR_CORRELATE_WINDOW_S`, `DFIR_PHASE_GAP_S`, `DFIR_ANONYMIZE`, `DFIR_FLUSH_INTERVAL_MS`, `DFIR_CASES_ROOT`, `DFIR_MAX_BODY_MB`). **AI tab**: provider, model, API key, base URL, token limits, image detail, and two-tier synthesis model. **Enrichment tab**: all threat-intel provider keys (VirusTotal, AbuseIPDB, Hunting.ch, RockyRaccoon, CrowdStrike, MISP, YETI) and throttle settings. **Exposure tab**: customer-exposure provider keys (LeakCheck, HIBP, DeHashed, Shodan). **Integrations tab**: DFIR-IRIS, Timesketch, and Velociraptor connection details. Server-side fields are written to the `.env` file via `GET/POST /settings/env`; a restart reminder is shown after saving. Secret values are masked in transport (returned as `••••••••`); leaving a password field empty on save skips it so existing secrets are not cleared.
- **Temporal burst / attack-phase detection on the forensic timeline.** A real intrusion arrives in bursts — a dense cluster of events within minutes (initial access), a gap, then another burst (persistence, lateral movement, exfil) — but the raw timeline is strictly chronological, leaving the analyst to eyeball the clusters. A new **Attack Phases** dashboard panel (and report section **3.2 Attack phases**) groups the timeline into phases by the time gap *between* consecutive events: events closer together than the threshold (`DFIR_PHASE_GAP_S`, default **5 minutes**) belong to the same phase; a larger gap starts a new one. Each phase is labelled with its **dominant ATT&CK tactic** (reusing the canonical `tacticForTechniques` mapping the kill-chain view and IRIS export already use) and shows its time window, worst severity, event count, and the union of MITRE techniques — click a phase to expand its events. This is the **temporal** axis (when activity clustered), complementary to the existing categorical **Kill Chain** view (which tactic). Fully **deterministic — a time-gap algorithm, no AI call**. Backed by pure, unit-tested `analysis/burstDetect.ts` (`buildAttackPhases(events) → AttackPhase[]`), derived on read with the same scope/legitimate filtering as the report (`GET /cases/:id/phases`, like the asset/evidence graphs).
- **Confidence scoring on findings.** Each AI-generated finding now carries a `confidence` (0–100) field — the model's certainty the finding represents real attacker activity, not a false positive. Synthesis and extraction prompts request confidence; deterministic auto-backfill findings default to 100 (the source detection tool already made the call). Dashboard: color-coded confidence badge (green ≥80 / yellow 50–79 / red <50) next to each severity label, plus a "Min confidence" filter input that hides findings below the chosen threshold in real time. Report: confidence shown inline in the Markdown finding heading and in the `confidence` column of the findings CSV export. Older states without the field are handled gracefully (badge omitted, no filter applied).
- **Evidence Chain graph — Phase 2: file-lineage and network-flow edges.** Two new edge types in the Evidence Chain graph and report §4.8: **`file_lineage`** (a file written then executed with the same hash — a `file` node sits in the middle so the artifact is visible, with `wrote-file` and `executed-file` edges connecting the write-context and execute-context); and **`network_flow`** (src→dst: events with `srcIp`/`dstIp`/`port` produce `network` nodes and a directed flow edge; when `srcIp` is absent the event's asset is the source as a `host` node). Backed by two new optional fields on `ForensicEvent` (`action?: "write"|"execute"|"network_send"|"network_receive"` and `srcIp?`/`dstIp?`/`port?`) — propagated through `responseSchema.ts`, `stateMerge.ts` (both branches), and `correlate.ts` `mergeGroup`. Dashboard toggles and legend updated (green = file lineage, cyan = network flow); file nodes render as diamonds, network nodes as filled circles. Report §4.8 adds **File lineage** and **Network flows** tables.
- **MISP export — push IOCs and findings from a case to a MISP instance.** A new **Push to MISP** option in the dashboard's Push menu (gated on `DFIR_MISP_URL` + `DFIR_MISP_KEY`) and a CLI script (`npm run misp:push -- <caseId>`) export the case's IOCs as MISP attributes (type-mapped: `ip-dst`, `domain`, `md5`/`sha1`/`sha256`, `url`, `filename`) and MITRE techniques from findings as `mitre-attack:T*` tags. The push is **idempotent**: each case is tagged `dfir-companion:case-{id}` so re-pushing finds the existing MISP event and adds only new attributes (deduplicated by value). The event's threat level is derived from the worst finding severity (Critical/High → 1, Medium → 2, Low → 3). Distribution defaults to "org only" (0 — OPSEC-safe); override with `DFIR_MISP_DISTRIBUTION`. Uses the existing `DFIR_MISP_CA` / `DFIR_MISP_INSECURE` TLS env vars for self-hosted instances. Pure orchestrator with injectable client (`MispPushClientLike`) — unit-tested with a mock (no network).

## [0.12.0] - 2026-06-08

### Added
- **Drag-to-reposition nodes in the Compromised Assets ↔ IoC graph** — the same direct-manipulation the Evidence Chain graph has, now on the asset graph. Drag any node to lay it out the way it reads best; manual positions are **pins** that persist per case (`localStorage`, survive reload) and sit *on top of* the chosen Horizontal/Vertical/Radial layout — non-pinned nodes still re-flow when you switch layout, so you can tidy a few key nodes without losing the auto-arrangement of the rest. A pinned node's label is tinted, its label tracks the node, edges follow live, and **↺ Reset layout** clears the pins. A press without movement is still a focus toggle (click-to-focus preserved).
- **Evidence Chain graph — the causal view of an incident (process trees + lateral movement).** Alongside the chronological forensic timeline and the (associative) asset↔IoC graph, the dashboard now has an **Evidence Chain** panel — and the report a **§4.8 Chain of evidence** section — that answers *how it happened*, not just *what happened when*. Three edge types, all **derived deterministically from fields the importers already populate (no AI call, no new store):** **`spawned`** (parent→child from each event's own `processName`/`parentName`, keyed by `(asset, name)` so `excel.exe → powershell.exe → cmd.exe` chains into one tree through the shared node); **`lateral_move`** (the same binary **hash** on ≥2 hosts → host↔host, **high** confidence; the same **account** active on ≥2 hosts → account→host star, **medium** confidence); and **`ran_on`** (host → the **root** of each process tree). That last one is the **bridge** that makes it *one* graph instead of two disconnected halves: with each tree hung off its host node, the `lateral_move` host↔host edges stitch per-host trees into a single **cross-host attack graph** — `evil.exe` runs on HOST-A → (same hash) moves to HOST-B → spawns there — so you can trace the whole path end to end. Every edge carries its **confidence**, the **rule** that produced it, a human **basis** line, and the **backing event ids** — a causal claim is auditable, because a wrong causal edge misleads in a way a wrong association edge does not. The account-lateral rule **filters Windows virtual principals** (DWM-*/UMFD-*/MSI namespaces, `Global\…`, service accounts) so it doesn't manufacture host↔host edges from machine noise that every host has. Derived **on read** with the same scope/legitimate filtering as the report (`buildEvidenceGraph`, pure + unit-tested; `GET /cases/:id/evidence-graph`). Dashboard panel reuses the asset-graph chrome — process-tree / lateral-movement toggles, confidence legend (solid = high, dashed = medium), a layered left→right SVG layout with directional arrowheads, zoom (buttons + wheel), fullscreen, and click-a-node-to-focus. **Nodes are drag-to-reposition** — drag any node to lay the graph out the way it makes sense to you; positions **persist per case** (in `localStorage`, so they survive reload), a moved node's label is tinted, edges follow live, and **↺ Reset layout** clears the manual positions back to the auto layout. (A press without movement is still a focus toggle.)

## [0.11.0] - 2026-06-08

### Added
- **Customer exposure / credential-leak check — a NEW feature separate from IOC enrichment.** A dashboard **Customer Exposure** panel (and report section **4.5 Customer exposure**) checks the *victim org's own* domains and emails against breach/leak/exposure databases — **LeakCheck** (`DFIR_LEAKCHECK_KEY`), **Have I Been Pwned** (`DFIR_HIBP_KEY`), **DeHashed** (`DFIR_DEHASHED_KEY`), and **Shodan** (`DFIR_SHODAN_KEY` — a customer domain's internet attack surface: exposed hosts/ports/services/CVEs; no email lookup). **Pick which sources to run** per case (a checkbox per provider, like the enrichment per-source picker — selection persists; a `providers` list on the check request overrides for a one-off run). Domains/emails are entered as **removable chips** (type + Enter, × to remove; auto-saved so a new item is active immediately), and emails the investigation surfaces under a customer domain appear as dashed **"auto"** chips — always included. Provider errors now surface the service's **real message** (LeakCheck's 403 reason — "Active plan required" vs "Limit reached" — instead of a guessed "needs Enterprise tier"; DeHashed bodies too). The analyst stores the customer's domains/emails per case (`state/customer.json`); a domain search returns the leaked accounts and an email search returns each address's breaches. **Strict customer boundary (OPSEC):** domain lookups use **only the manually entered customer domains** — adversary domains collected as IOCs are *never* queried — and emails auto-discovered from the case timeline are checked **only when their domain is one of those customer domains** (and never an email that is itself an IOC). Results persist **without raw leaked passwords** (`state/customer-exposure.json` keeps only a *credential-material-present* flag + exposed field names). Opt-in: a provider is configured by key and the analyst runs the check explicitly (`POST /cases/:id/customer-exposure/check`, throttled by `DFIR_EXPOSURE_DELAY_MS`, `501` when no key is set). Pure target/result logic (`customerExposure.ts`, `customerStore.ts`) + four injectable-`fetchFn` provider adapters, all unit-tested — including the IOC-domain boundary and the no-raw-secrets guarantee.
- **CrowdStrike Falcon threat-intel enrichment provider (`DFIR_CROWDSTRIKE_CLIENT_ID` + `_SECRET`) — Threat Intelligence only, no endpoint/SIEM.** Adds CrowdStrike's commercial intel as an enrichment source, scoped deliberately to the **Threat Intelligence** APIs (it never touches Hosts/Detects/Incidents/Insight/RTR/NG-SIEM). Like Hunting.ch it fans out and returns **one separate result per back-end**: a **hash** is looked up on **Falcon Intelligence Indicators** (adversary-attributed IOC intel) *and* **MalQuery** (CrowdStrike's malware sample corpus); an **IP/domain/URL** on Falcon Intelligence Indicators. The Indicators verdict comes from `malicious_confidence` (high → malicious, medium/low → suspicious) with the **malware family**, **adversary/actor**, and **threat types** as tags; MalQuery contributes the sample's family + file type. Auth is **OAuth2 client-credentials** (Client ID + Secret → short-lived bearer, cached and auto-refreshed on expiry/401), with the tenant **cloud region** configurable (`DFIR_CROWDSTRIKE_CLOUD` = `us-1`/`us-2`/`eu-1`/`gov-us-1`/`gov-us-2`, or an explicit `DFIR_CROWDSTRIKE_BASE_URL`). Needs an API client with the **Indicators (Falcon Intelligence): Read** scope (+ **MalQuery: Read** for hashes) and the Falcon Intelligence subscription; a missing scope on one back-end (403) still returns the other's result. **External** source (opt-in per case; OPSEC default stays local-only). Pure provider with an injectable `fetchFn` (no network in tests) + unit tests for the token exchange, hash fan-out, Intel-only routing for non-hashes, confidence→verdict mapping, not-found → `[]`, credential-auth error, partial-scope resilience, and cloud→base-URL resolution.
- **Hunting.ch (abuse.ch) threat-intel enrichment provider (`DFIR_HUNTINGCH_KEY`) — one integration, results from every abuse.ch platform.** Adds the abuse.ch **hunting platform** (<https://hunting.abuse.ch/>) as a single enrichment source that, for one indicator, fans out across **every abuse.ch back-end that knows its kind** and returns **one separate, clickable result per platform** — mirroring `hunting.abuse.ch/hunt/<ioc>/`. A **hash** is looked up on **MalwareBazaar** (known sample), **ThreatFox** (tracked C2/payload IOC), **URLhaus** (malware-distribution payload), and **YARAify** (which YARA rules / ClamAV sigs matched); an **IP/domain** on ThreatFox + URLhaus (host); a **URL** on ThreatFox + URLhaus (url). Each result keeps its own verdict, tags (malware family / rule names / threat type), and a deep link to that platform's report, so the dashboard shows them as distinct badges (e.g. *MalwareBazaar*, *YARAify*, *ThreatFox*, *URLhaus*) rather than one merged line. All back-ends share the **one unified abuse.ch Auth-Key** (same key as MalwareBazaar; get one at <https://auth.abuse.ch/>) — `DFIR_HUNTINGCH_KEY` is optional and **falls back to `DFIR_MB_KEY`**, so an existing MalwareBazaar key enables the unified hunt with no extra config. The **standalone MalwareBazaar enrichment source has been removed** — MalwareBazaar is now one of Hunting.ch's back-ends (so it's no longer a separate badge/toggle); `DFIR_MB_KEY` still works (it supplies Hunting.ch's key). On re-enrich, a fresh Hunting.ch *MalwareBazaar* result replaces any stale badge left by the old standalone source rather than duplicating it. If one platform is rate-limited, down, or auth-blocked, the platforms that **did** answer are still returned (e.g. YARAify needs no key, so it shows even when a missing key 401s the rest), rather than one failure discarding the whole result. It's an **external** source (opt-in per case; OPSEC default stays local-only) and slots into the existing per-source picker, caching, throttle (`DFIR_ENRICH_DELAY_MS`), and cap (`DFIR_ENRICH_MAX`). To support a source that returns several results, `EnrichmentProvider.lookup` may now return an **array** (each result stamped with its owning provider so re-checks/dedup stay correct); single-source providers are unchanged. Pure provider with an injectable `fetchFn` (no network in tests) plus unit tests covering the hash fan-out, per-kind routing, not-found→`[]`, shared-key auth error, and partial-outage resilience.
- **Import change tracking on the Forensic Timeline and IOCs — "what was added in the last import".** Mirroring the Findings "🧠 Last synthesized N ago / what-changed" view, the Forensic Timeline now shows a **📥 Last import N ago — +N new events** banner (with the source file + detected kind, and an expandable list of exactly what was added) and the IOCs section shows a matching **+N new IOCs** banner — and the events/IOCs the last import brought in are **highlighted in their lists with a green accent + a `NEW` badge** — so after dropping in a new artifact you can immediately see what it contributed instead of hunting through a re-sorted timeline. Backed by pure, unit-tested `diffTimeline()` (matches events by normalized time + description — the key correlation uses) and `diffIocs()` (matches by exact value — the key `mergeDelta` dedupes on), so a re-import of the same file shows *no* new events/IOCs rather than rows reappearing under fresh ids, plus a new `ImportMetaStore` (`state/import-meta.json`) that the unified `/import` route writes after each import completes (before re-synthesis, which preserves both); read via `GET /cases/:id/import-meta`, pushed live to the dashboard over the WS (`import_meta_changed`). The detail lists are capped at 500 (the banners still show the true totals); the per-row highlights clear on the next import.
- **Limit which hunt-query platforms the 🔍 generator offers (`DFIR_HUNT_PLATFORMS`).** With seven platforms the hunt modal can be larger than a given team needs. A new server env var trims it to an allowlist — `DFIR_HUNT_PLATFORMS=velociraptor` shows only Velociraptor; `velociraptor,sigma,yara` shows just those three; unset shows all (unchanged behavior). Comma/space/semicolon separated, case-insensitive, with forgiving aliases (`vql`/`kql`/`esql`/`spl`/`snort`/`kibana`/…); unknown tokens are ignored and an all-typo value safely falls back to all. Resolved by a pure, unit-tested `resolveHuntPlatforms()` (`analysis/huntPlatforms.ts`), exposed on `/health.huntPlatforms`, and applied client-side so disabled cards never render (with a message pointing at the env var when an entity's only platforms are disabled).
- **Hunt-pivot generator now also emits Elastic ES|QL, YARA, and Suricata.** The 🔍 hunt-query generator previously produced four outputs (Velociraptor VQL, Defender/Sentinel KQL, Splunk SPL, Sigma skeleton); it now adds three more: **Elastic / Kibana ES|QL** (a single piped query over ECS fields — `process.hash.*`/`process.name`/`source.ip`/`destination.ip`/`dns.question.name`/`url.*`/`file.path`, process names lowercased via `TO_LOWER` — runnable in Kibana Discover / Security; distinct from the Microsoft Kusto KQL card); a **YARA retro-hunt rule** (hash-gated — keys on the sample's fingerprint via the `hash` module, `hash.sha256/sha1/md5(0, filesize) ==`, so you can retro-hunt the exact sample fleet-wide with Velociraptor `yara()`/THOR, with a guided spot to add real sample strings for variant coverage); and **Suricata network rules** (IP/domain/URL-gated — `alert ip` to a confirmed IP, plus `dns.query`/`tls.sni`/`http.host`/`http.uri` content rules for domains and parsed URLs, with the four content metacharacters hex-escaped and local-range sids). All deterministic client-side templates (no AI, no server round-trip, no cost); each card only renders when the entity carries a relevant indicator, consistent with the post-detection principle (pivot off a confirmed indicator, don't author detections).
- **Safety-net periodic flush so a lone screenshot still gets analyzed.** Captures are analyzed in windows (default 4); a `timer`/`click` capture buffers until the window fills, and only a page `navigation` or `tab_switch` flushes early — so a single screenshot (e.g. one snapped with the hotkey, then idle) could sit unanalyzed indefinitely. A background sweep now drains any non-empty per-case buffer every `DFIR_FLUSH_INTERVAL_MS` (default 5 min; set `0` to disable), analyzing whatever is pending even if it's just one. The sweep is a no-op on empty buffers and only touches AI-enabled cases (pausing AI still clears the buffer); evidence persistence is unchanged (screenshots are always saved on ingest regardless). New `flushIntervalMs` `AppOptions`, `unref()`'d so it never blocks shutdown.
- **Timeline event triage controls — star, multi-select, and bulk actions.** The Forensic Timeline is now a compact table: per-row controls (select checkbox · ★ star · 💬 comment · 🏷 tag · 🔍 hunt) sit at the **start** of the line, before the timestamp column, with the tag pills and message after it (matching common timeline-tool layouts). New per-row **★ star** (persisted per case in `localStorage`) plus a **☆ Starred** header toggle to show only starred events. New **multi-select**: a row checkbox + select-all header checkbox, and when any events are selected a bulk-action bar offers **★ Toggle Star**, **🏷 Modify Tags** (applies one label to every selected event), and **⚑ Mark Legitimate** (excludes all selected from analysis). Bulk legitimate uses a new **`POST /cases/:id/legitimate/batch`** endpoint that writes all markers in a single read-modify-write and triggers **one** re-synthesis (instead of N racing single-marker calls).

### Changed
- **Velociraptor hunt-pivot now offers a runnable notebook query (and the old card is labelled "hunt").** The 🔍 generator's Velociraptor output was bare client-side VQL (`glob()`/`pslist()`/`netstat()`) labelled "notebook VQL" — but pasted into a Velociraptor notebook cell it runs server-side and finds nothing. That VQL is only meaningful as a **hunt artifact source** (what the "Run hunt (all clients)" button packages), so it's now labelled **"Velociraptor — hunt (all clients)"** (unchanged behavior, still the editable + runnable card). A new **"Velociraptor — notebook (one client)"** card emits a genuinely notebook-runnable query using the documented `collect_client → watch_monitoring(System.Flow.Completion) → source()` idiom: it collects the right built-in artifact on one client (processes/hashes → `Windows.System.Pslist` with a collection-side `ProcessRegex` / `Hash.SHA256` filter, files → `Windows.Search.FileFinder` glob, on-disk hash → FileFinder + `Calculate_Hash`, IPs → `Windows.Network.Netstat`), waits for the flow, then reads the rows. Copy-only (it's a notebook query, not a server-side hunt). Dashboard-only change.
- **Asset-graph nodes now show a type icon instead of a plain dot.** Hosts render as a monitor, accounts as a person, and services as a gear, so you can tell an asset's type at a glance; the node color still encodes compromise state (red = compromised, blue = clean), giving two independent dimensions (shape = type, color = compromise). IoCs stay as small verdict-colored circles. The same icons appear next to the Show: Hosts / Accounts / Services toggles as a legend (dashboard-only change).
- **Findings moved above the Forensic Timeline, with row icons aligned to the other sections.** The Findings section now sits with the other synthesis outputs (Executive Summary → Next Steps → Attack Path → **Findings**) immediately before the raw Forensic Timeline, and is full-width. Each finding row now leads with its comment 💬 + tag 🏷 chips at the **start** of the line (before the severity badge), matching IOCs / Key Questions / Investigation Threads instead of burying the chips after `[severity]`.
- **Kill Chain tactic events now open in a full-width panel.** Clicking a tactic card previously expanded its events *inside* the narrow (~100px) card column, so each alert wrapped to many lines and needed both vertical and horizontal scrolling. The selected tactic's events now render in a single full-width detail panel below the strip — one wide, naturally-wrapping line per alert (timestamp · description · MITRE), with a `60vh` scroll cap — so the full alert text is readable at a glance. Clicking the active card again collapses the panel (dashboard-only change).

### Fixed
- **Sub-millisecond timestamp precision was silently dropped when converting a timezone offset to UTC.** Timeline times that carried a numeric offset (e.g. Suricata eve.json's `2026-02-02T17:49:22.789338+0000`) were normalized through JavaScript's `Date`, which is millisecond-resolution — so the microseconds were truncated (`…789Z`), while the same event imported from a CSV already in UTC kept its full `…789338Z`. Two views of the same instant showed different precision. Since a timezone offset only shifts whole minutes, the fractional seconds are invariant under the conversion: `toUtcIso` now re-attaches the original sub-second digits after the UTC round-trip, so microsecond/nanosecond precision survives for every importer that shares it (Suricata/Zeek `timestamp`, SIEM/EDR offsets, …). Millisecond-or-coarser sources are unchanged (`.000`/`.120` as before); already-UTC and naive times were already preserved. (Zeek's *epoch-float* `ts` still resolves to milliseconds — a float can't reliably carry sub-millisecond precision.)
- **Hunt-pivot generator said "nothing to pivot on" for network/IDS events that clearly carried indicators.** The 🔍 hunt modal built its queries only from an event's *structured* fields (`sha256`/`md5`/`path`/`processName`/`asset`) — but a Suricata/Zeek alert (and many others) carries its real indicators in the free-text description (e.g. `Suricata alert: ET EXPLOIT_KIT … (soulversr .com) — 10.2.2.37:62121 → 10.2.2.1:53 UDP`) and as linked case IOCs, none of which are structured event fields. So the modal showed "This entity carries no hash / IP / domain / path / process to pivot on" even with a domain and two IPs right there. Event hunts now also **harvest indicators from the description**: refang it (`evil[.]com` / `evil(dot)com` / `soulversr .com` / `hxxp://`), regex out the unambiguous types (IPv4 / hash / URL), and match any case IOC whose value appears in it (boundary-checked, so `10.2.2.1` doesn't match inside `10.2.2.10`) — reusing the deterministic, correctly-typed IOC extraction so a defanged domain in the text maps to its clean IOC. The Suricata/Velociraptor/Defender/Splunk/Elastic cards now render for these events. Dashboard-only change (served fresh — just reload).
- **CSV/log import ignored the per-case "AI off" toggle (ran the LLM + claimed it was analyzing while AI was off).** Turning AI off pauses screenshot analysis and synthesis, but the unified `/import` route only checked whether a provider was *configured* (`hasAiProvider()`), never the per-case toggle — so importing a CSV/log with AI off still sent the file to the model for extraction, and the dashboard showed "processing screenshots… importing (csv) — analyzing" even though AI was supposedly off (a cost + OPSEC surprise: data left for the model when the user had paused it). CSV/log are the only AI-dependent importers; they now respect the toggle exactly like screenshot analysis and synthesis — with AI off the raw file is still saved as evidence (evidence-first) but **not** sent to the model, the route returns `{ analyzed: false, reason: "ai-off" }`, and the dashboard says "saved as evidence but NOT analyzed — AI is off (turn AI on, then re-import)". Deterministic imports (THOR/SIEM/Chainsaw/Hayabusa/Velociraptor/network/KAPE/Cyber Triage/M365/AWS/cloud/Plaso/sandbox) have no LLM call and keep populating the timeline + IOCs regardless. Also fixed the misleading status label — it now reads "processing evidence…" instead of "processing screenshots…" (it covers imports too).
- **Hayabusa `json-timeline` default output failed to import ("unrecognized").** `hayabusa json-timeline` (without `-J`) emits pretty-printed JSON objects concatenated together — no array wrapper, no commas between objects, each object spanning many lines. That's neither a single JSON document nor NDJSON, so both the import detector and the parser found 0 records and rejected the file. Added `parseConcatenatedJson()` (a brace-depth scanner that's string-literal aware) to `siemImport`, used as a fallback in `extractRecords` and the import detector — so concatenated pretty-printed JSON now parses. Benefits every JSON importer that shares `extractRecords` (Hayabusa, Chainsaw, SIEM/EDR, Velociraptor). Verified on a 123-record Hayabusa APT-sample timeline (→ 94 events, 19 IOCs). (Tip: `hayabusa json-timeline -J` writes true JSONL, which also worked before.)
- **A relative file path like `Zip\7z.exe` was misclassified as a user account in the asset graph.** The account extractor (`extractAccounts` in `analysis/assetGraph.ts`) treats `DOMAIN\user` strings as accounts; a single-segment path such as `Zip\7z.exe` matches that shape, and the existing path-segment guard only skipped well-known folder names (`Users`, `Windows`, …), not arbitrary folders like `Zip`. Now the right-hand side is rejected when it ends in a known file extension (`.exe`/`.dll`/`.ps1`/`.zip`/… — a curated list, so legitimate dotted usernames like `CORP\first.last` are still extracted). Fixes the graph, the "Known compromised assets → Users" list, the synthesis context digest, the report, and IRIS push — all derive accounts the same way, so the correction applies everywhere on the next graph build (no re-synthesis needed).
- **The 🏷 triage-tag icon was nearly invisible on timeline rows.** On Windows the tag emoji was rendered without the emoji variation selector (U+FE0F), so it fell back to a faint monochrome glyph that took the dim button text color instead of the colored emoji (the sibling 💬 and 🔍 default to color, which is why only the tag vanished). Appended U+FE0F to force colored-emoji presentation and brightened the `.tag-add` resting color to match the comment chip as a fallback.
- **"Mark legitimate" button was invisible on timeline rows** — the reveal-on-hover CSS still targeted the old `.finding` row class after the timeline became a `.ev-row` table; added `.ev-row:hover` so the ⚑ button shows again.
- **Bulk tagging only tagged one event** — the dashboard fired the per-event tag POSTs concurrently, and `TagsStore.add()` is read-modify-write on `tags.json`, so concurrent requests clobbered each other (last write wins). Bulk tag POSTs are now serialized; bulk legitimate uses the new single-write batch endpoint.

## [0.10.0] - 2026-06-06

### Added
- **Run hunts across all endpoints (Velociraptor API)** — with a Velociraptor `api_client` config set (`DFIR_VELOCIRAPTOR_API_CONFIG`), the hunt-pivot modal's Velociraptor card becomes an editable VQL box with a **▶ Run hunt (all clients)** button that packages the pivot VQL as a CLIENT artifact (`artifact_set`) and launches a **hunt on every enrolled endpoint** (`hunt`) — not a server-side query — so "find this file" searches all clients. Results stream back into an inline table (with each row's source endpoint hostname) as clients check in, via `hunt_results` (addressed as `artifact/source`); a manual ↻ refresh plus a short auto-poll. Optional `DFIR_VELOCIRAPTOR_GUI_URL` deep-links to the hunt in the GUI. New `VelociraptorClient` (`integrations/velociraptor/velociraptorApi.ts`) drives it by shelling out to the `velociraptor` binary with `--api_config` (the binary handles gRPC + mTLS) via an injectable runner — no new dependency, no network/process in tests. Routes `POST /velociraptor/hunt` + `/velociraptor/hunt-results` (and a server-side `POST /velociraptor/run`); `/health` reports `velociraptorEnabled` (gates the button). Off by default (opt-in); localhost + analyst-driven; spawned without a shell (each VQL statement is a single argv — no command injection); ids validated before interpolation; per-query timeout + row/output caps. 22 unit tests.
- **Hunt-pivot query generator** — a 🔍 chip on every forensic event and IOC opens a generator that emits ready-to-adapt hunt/pivot queries for the tools analysts already run: **Velociraptor notebook VQL** (paste-into-a-cell pivot queries — listed first), **Microsoft Defender / Sentinel KQL**, **Splunk SPL**, and a **Sigma** rule skeleton. Queries are templated deterministically from the entity's structured fields (sha256/md5, IP, domain, URL, path, process, parent process, affected host) — no AI call, no cost, fully offline — each with one-click copy-to-clipboard. File paths are normalized (the `\\.\` / `\\?\` device prefix that Sysmon/EDR attach to image paths is stripped; Velociraptor globs use forward slashes) so the queries actually run; process/IP matches are exact (not regex). Consistent with the post-detection product principle: these pivot off a confirmed indicator, they don't author detections. Pure client-side (no server change).
- **AI executive summary** — a ✨ Generate button on the Executive Summary section runs one text-only AI call over the synthesized case and returns a management-facing, plain-language summary (no ATT&CK ids / hashes / tool names); the analyst reviews it and saves it into `report-meta.executiveSummary`, which overrides the auto-derived summary in the generated report. New 6th customizable prompt (`EXEC_SUMMARY_PROMPT` + `getExecSummaryPrompt()`, env overrides `DFIR_AI_EXEC_PROMPT` / `…_PROMPT_FILE`, ejected by `prompts:eject`), new `pipeline.executiveSummary()` method (uses the synthesis provider), and route `POST /cases/:id/executive-summary`.
- **Synthesis freshness & what-changed diff** — the Findings section now shows when synthesis last actually ran ("🧠 Last synthesized N ago") and how the findings changed since the prior run (**+N new / −M dropped / ↕ K severity-changed**, with an expandable list of titles), so a re-synthesis visibly shows its effect instead of findings silently reshuffling. Backed by a pure `diffFindings()` (matches by normalized title, since synthesis re-ids findings each run) and a new `SynthMetaStore` (`state/synth-meta.json`) that `pipeline.synthesize()` writes on each real run (not a skipped no-op); read via `GET /cases/:id/synth-meta`.
- **Analyst triage tags** — investigators can now hand-label any case entity (forensic event, finding, IOC, key question, investigation thread) with short triage labels — `confirmed-malicious`, `false-positive`, `needs-review`, `key-evidence`, `pivot-point`, `c2-comms`, … — independently of the AI-assigned severity/MITRE. Tags render inline as color-coded pills (threat=red, benign=green, review=yellow, evidence=blue) next to a 🏷 chip that opens an editor with a one-click suggested-label palette plus a free-form input. Labels are normalized (lowercased, hyphenated) and deduped per entity. Backed by a new `TagsStore` (`state/tags.json`) that mirrors the comments side-file pattern — never wiped by synthesis, atomic-write persisted, and synced live to every dashboard client over the WebSocket (`tags_changed`). New routes: `GET`/`POST /cases/:id/tags`, `DELETE /cases/:id/tags/:tagId`.
- **Kill Chain tactic-phase view** — a new dashboard section below the Forensic Timeline shows all 12 ATT&CK tactics as phase cards in kill-chain order (Initial Access → … → Impact). Each card displays the count of events mapped to that tactic and is color-coded by the highest severity present; empty tactics are shown dimmed. Clicking any active card expands the events inline. Events are classified by their MITRE T-codes first (the same technique→tactic mapping used for IRIS export), with a keyword-heuristic fallback for events without T-codes; unclassified events appear in an Uncategorized bucket.

### Fixed
- **Asset graph labels no longer clip at the canvas edge** — the IoC graph now estimates each node label's width and pads/widens the canvas (shifting nodes uniformly, without changing spacing or radius) so far-left labels in the Radial layout — and top-corner labels in the Vertical layout — render in full instead of having their leading characters cut off.

## [0.9.1] - 2026-06-06

### Fixed
- **Root URL now redirects to dashboard** — `GET /` returns a 302 to `/dashboard` instead of 404, so navigating to `http://localhost:4773` works as expected.
- **Docker image now starts on Node 22** — bumped all three Dockerfile stages from `node:20-slim` to `node:22-slim` to match the `undici` v8 requirement (`webidl.util.markAsUncloneable` is only available in Node 22+).
- **Windows portable EXE now starts correctly** — the SEA package script was missing `detect-libc` and seven other transitive runtime dependencies of `sharp` (`color`, `semver`, `color-convert`, `color-string`, `color-name`, `simple-swizzle`, `is-arrayish`), causing an immediate `MODULE_NOT_FOUND` crash on startup. All of sharp's runtime deps are now staged into `dist-sea/node_modules/`.
- **Windows portable EXE now shows the DFIR Companion icon** — the build pipeline creates an ICO (16/32/48/256 px, with the same background-removal as `make-icons`) and embeds it into the EXE with `rcedit`, replacing the generic Node.js icon in Windows Explorer.

## [0.9.0] - 2026-06-06

### Added
- **Native Anthropic API provider** (`DFIR_AI_PROVIDER=anthropic`). Uses the Anthropic Messages API
  directly (`x-api-key` + `anthropic-version: 2023-06-01` headers, `system` as a top-level field,
  base64 image blocks with `source.type=base64`). HTTP 529 overloaded maps to `rate_limit` so callers
  get the same retry behaviour as a 429. Registered alongside `openai` / `gemini` / `openrouter` /
  `ollama` / `litellm`.
- **Per-provider model recommendations in `.env.example`.** The two-tier section now documents the
  recommended extraction and synthesis models for OpenAI (`gpt-4o-mini` / `gpt-4o`), Gemini
  (`gemini-2.5-flash` / `gemini-2.5-pro`), and Anthropic (`claude-haiku-4-5-20251001` /
  `claude-sonnet-4-6`), with copy-paste two-tier setup examples for each provider. Default extraction
  model changed from `gpt-4o` to `gpt-4o-mini`.
- **Live event count in the Forensic Timeline title.** The section heading now shows `(N events)` —
  updated on every render (import, synthesis, manual add, live poll). When a severity filter is active
  it reads `(X of N events)` so the total is always visible.
- **Severity filter checkboxes on the Forensic Timeline legend.** Each severity label (Critical / High
  / Medium / Low / Info) is now a checkbox. Unchecking a severity instantly hides matching events and
  dims/strikes the label — no server round-trip. The `accent-color` of each checkbox matches its
  severity colour.

### Security
- **[P1] Path-traversal guard on case IDs** — `caseStore.ts` now exports `isValidCaseId()` (regex
  allowlist `^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$` + `..` rejection). `POST /cases` and the capture
  ingest schema both validate the supplied `caseId` before any filesystem join, returning 400 for
  path-like values (e.g. `../outside`). Prevents an adversarial browser page from escaping `casesRoot`
  via the wide-open CORS + Private-Network-Access headers.
- **[P1] Markdown link/image injection blocked in HTML report** — `renderHtmlReport` in `html.ts` now
  overrides the `marked` `link` and `image` renderers. Only `http:`, `https:`, and `mailto:` hrefs are
  passed through; everything else (e.g. `javascript:alert(1)`) is rendered as escaped plain text
  `[label]` / `![alt]` — eliminating the XSS vector from untrusted finding descriptions and
  attacker-path narrative.

### Fixed
- **[P2] Deterministic imports work without an AI provider** — `AnalysisPipeline` now accepts an
  optional `provider`; a `hasAiProvider()` method guards extraction, synthesis, CSV/log analysis, and
  Ask. `startServer` always wires a pipeline (via `buildRuntimePipeline`) and passes `aiConfigured` so
  the server routes that genuinely need the LLM return 501 while THOR, SIEM/EDR, Chainsaw, Hayabusa,
  Velociraptor, network, KAPE, Cyber Triage, M365/Entra, AWS, GCP/Azure, Plaso, and sandbox imports
  remain fully usable with no API key configured.
- **[P2] Correlation no longer drops process-chain validation metadata** — `mergeGroup()` in
  `correlate.ts` now carries `processName`, `parentName`, and `chainCheck` through from any event in
  the merged group (primary-preferring, first-non-null fallback), so chain-anomaly badges are not
  silently lost when two tools report the same artifact.

### Added
- **Minimum-severity import floor — restored for the single Import button, generalized to every
  importer** (`analysis/severityFloor.ts`). The old dedicated THOR import used to ask *"which minimum
  severity?"*; the unified Import button (which replaced the per-format buttons) had silently dropped
  that prompt, so noisy imports flooded the timeline. The Import button now asks once per batch
  (`critical` / `high` / `medium` / `low` / `info`, default `info` = everything) and the floor is
  applied across **all** import kinds — THOR, SIEM/EDR, Chainsaw, Hayabusa, Velociraptor, network,
  KAPE, Cyber Triage, M365/Entra, AWS, GCP/Azure, Plaso, sandbox, and the AI CSV/log paths. It is
  **gate-aware** (`applySeverityFloor`): an import that grades severity keeps only events at/above the
  chosen floor (below-floor + Info rows drop), but an import that carries **no** severity — every event
  is Info, e.g. KAPE/Plaso host triage and plain telemetry — is **kept in full** ("if there are no
  severities, import everything"). The gate is computed at runtime from the produced events, so mixed
  importers (Velociraptor detections + EventLog Info; Cyber Triage scored + unscored) and any future
  importer behave correctly. Threaded through the unified `POST /cases/:id/import` route (`minSeverity`
  in the body, normalized + echoed back); the per-format `import-*` routes keep their own floor. +10
  helper unit tests, +2 route tests (THOR floor; KAPE all-Info kept whole).
- **Cyber Triage timeline import** (`importCybertriage` → `cybertriageImport.ts`) — the thirteenth
  deterministic ingest path (no AI call), the host-triage counterpart to KAPE. Reads a Cyber Triage
  (Sleuth Kit Labs) timeline export in **JSONL** (richest), **JSON array**, or **CSV** form.
  **Verdict-first** (Cyber Triage already scores items): scored rows (`Notable_Normal`=Bad /
  `LikelyNotable_Normal`=Suspicious, or the CSV `threat_level`) map to events with severity derived
  from the verdict + a keyword bump on the reason (lsass-dump/mimikatz/ransomware→Critical;
  RAS/AnyDesk/PsExec/YARA→High), `scoreDescription` leading the description, MITRE from the reason
  (T1003.001 / T1219 / T1053.005 / T1548.002), and the process chain / path / host / args carried
  through. The export is mostly raw filesystem telemetry, so the feed is **split**: unscored
  Process + Scheduled-Task rows → Info evidence; the unscored File MFT super-timeline is dropped by
  default (`fileTelemetry` opts it in); Active-Connection remote IPs become IOCs. Events tagged
  **Cyber Triage**; aggregates + caps; optional `minSeverity` floor. Wired into `importDetect.ts`
  (JSON `epoch_timestamp`+`timestamp_desc`+verdict and the `event_timestamp,epoch_timestamp,
  timestamp_description` CSV header both auto-route), the unified `/import` button, and a per-format
  `POST /cases/:id/import-cybertriage` route. *(The CSV form is lossy — no host, no process chain;
  prefer JSONL. The Excel incident report is a formatted human deliverable and is not ingested.)*
- **Portable Windows EXE (Node SEA) release artifact.** A new `npm run package:sea` script
  (`companion/scripts/build-sea.mjs`) bundles the server with esbuild, generates a Node
  SEA blob, injects it into a copy of the node binary via `postject`, and stages a
  `dist-sea/` folder containing `dfir-companion.exe`, the `public/` dashboard assets, the
  native `sharp` runtime (`node_modules/sharp` + `@img/sharp-*`), and a sample `.env`.
  Double-click the EXE and open `http://127.0.0.1:4773/dashboard`; `.env` and `cases/`
  live next to the binary. A new GitHub Actions workflow
  (`.github/workflows/release-artifacts.yml`) builds the Windows EXE zip **and** the
  Chrome/Comet extension zip on every `vX.Y.Z` tag and attaches both to the matching
  GitHub Release, alongside the existing GHCR Docker image. Server runtime resolution
  (`dashboard.html`, favicons, `.env`, `cases/`) is now SEA-aware via a small
  `serverAssets.ts` helper — dev/Docker paths are unchanged.
- **Docker / Docker Compose install option.** A single-image build (`Dockerfile` + `docker-compose.yml`
  at the repo root) runs the companion server, the dashboard, and the browser add-on — **without
  bundling Ollama or LiteLLM** (for AI you point `DFIR_AI_*` at any OpenAI-compatible endpoint; with AI
  unset, full capture + all deterministic importers still work). Multi-stage build (`tsc` → `dist`,
  pruned to prod deps; the extension is built and packaged); evidence/state persist in `./cases`; the
  pre-built add-on is copied to `./addon` for *Load unpacked*. **Localhost-only is preserved:** the
  container binds `0.0.0.0` internally while Compose publishes the port to `127.0.0.1` on the host. New
  **`DFIR_HOST`** env var (default `127.0.0.1`) controls the bind interface; the server entry point now
  also boots from the compiled `dist/server.js`. A GitHub Actions workflow publishes the image to
  **GHCR** (`ghcr.io/hasamba/dfir-companion`, multi-arch amd64/arm64) on every `vX.Y.Z` tag.
- **One-click PDF report export.** A new **Generate report (PDF)** option in the dashboard's **Export**
  menu (and a *Print / Save as PDF* link alongside the existing report links) generates the report and
  opens the print-styled HTML, auto-triggering the browser's print dialog where the destination is set to
  **Save as PDF**. Zero new dependencies and fully offline/air-gap safe — it reuses the HTML export's
  existing `@media print` stylesheet rather than bundling a headless browser. Served via
  `GET /cases/:id/report/report.html?print=1`, which injects a screen-only print trigger on the fly (the
  on-disk `report.html` and its download are never modified, so the saved PDF stays clean).
- **Company name + logo on reports (optional branding).** Two new optional fields in the dashboard's
  **Case Details** panel: a *company name* (the investigating firm) and a *company logo* upload
  (PNG / JPG / GIF / WebP, ≤ ~750 KB). The logo is stored inline as a base64 data URI in
  `state/report-meta.json` (so the report stays self-contained — no side file, no extra route) and
  both render at the top of the report's title page in `report.md` and the HTML export. Both are
  omitted when blank. The logo is server-validated to raster formats only (SVG is rejected so an
  uploaded logo can't carry script into the rendered HTML report) and length-capped.
- **Severity colour legend on the Forensic Timeline.** A small inline legend next to the section's
  `+` button explains what the event-timestamp colours mean (Critical / High / Medium / Low / Info),
  reusing the same `.sev-*` colours the timestamps and finding tags already use.
- **Word (.docx) report export** via the dashboard's **Export** menu (clean defaults, no
  template — analyst applies branding in Word). Generated on demand from the canonical
  `report.md`, with the same scope/legitimate filtering as the HTML and Markdown exports.
  Served via `GET /cases/:id/report.docx`. Implemented in `companion/src/reports/docx.ts`
  via `marked`'s token stream → the `docx` library.

### Changed
- **Terminology: "Attacker Path" → "Attack Path" across the UI, reports, and DFIR-IRIS push.**
  The dashboard section header, the `report.md` `### 4.1 Attack path` heading (and its "not yet
  reconstructed" placeholder), and the DFIR-IRIS note title now read **Attack Path** (the standard
  term). The internal field name (`attackerPath`) and the AI JSON key are unchanged, so existing
  saved cases keep working.
- **Dashboard: the "Synthesize" toolbar button is now "AI Re-synthesize".** Clearer that the button
  runs an LLM pass over the timeline (deriving findings / MITRE / attack path) and is the way to
  produce conclusions after an AI-off import — the endpoint and behavior are unchanged.
- **Velociraptor importer: verdict-first detection mapping (DetectRaptor + friends).** The Velociraptor
  importer already handled Sigma/YARA verdict rows; now it also recognizes the broader **detection-artifact
  shape** every DetectRaptor `*.Detection.*` artifact (and similar packs) carries: a `Detection` field — a
  bare string (`"Cobalt Strike: trick_ryuk.profile"`) or an object with a rule `Name` (+ optional
  `Criticality`/`Severity`) — or a `RuleName`/`RuleID`. Per the post-detection principle these are consumed
  as VERDICTS: the verdict text leads the description, its own criticality drives severity (else a
  keyword bump — `cobalt strike`/`mimikatz`/`webshell` → High, ransomware families → Critical, an
  `IN DEVELOPMENT` rule or `BAU` baseline → Low, otherwise Medium), and any `Txxxx` ids in the title/tags
  become MITRE. When a parsed Windows event sits underneath (DetectRaptor's `Evtx`), the verdict is
  **overlaid** on the per-EID Windows mapping rather than flattened — so a Mimikatz rule firing over EID
  4688 keeps both the rule name and the process-create context. Pipe/path/process/parent + file hashes
  become structured fields and IOCs; **URLs/IPs/SHA hashes embedded in free text** (the matched
  PowerShell `Line`, file `Content`, EVTX `Message`) are now scraped, so the C2 IP or download URL the
  rule fired on actually surfaces in the asset↔IoC graph.
- **Velociraptor importer: cleaner descriptions and timestamps for generic detection rows.** Generic
  artifact rows (no Sigma/YARA/Detection verdict) now lead with meaningful columns —
  `Category`/`KeyPath`/`DisplayName`/`PipeName` — instead of dumping the first eight raw `key=value`
  pairs, and the description skips large/noisy values (rule regexes, PE internals, file content blobs).
  Time resolution reaches nested forensic times: MFT `SITimestamps.LastModified0x10`/`Created0x10`,
  `FNTimestamps.Created0x30`, `FileInfo.Mtime`/`Ctime`/`Btime`, and `KeyLastWriteTimestamp` — so registry
  / MFT / file-info rows show their real time instead of `—` or the `_ts` collection time. The flat
  Windows-event shape (top-level `Channel`/`EventID`/`EventData`, no `System` wrapper) is recognized.
  When a row carries no `_Source`, the importer uses the **Velociraptor-named filename** as the fallback
  artifact label, so generic events show their source (`Velociraptor [DetectRaptor.Windows.Detection.NamedPipes]: …`).
- **README: explicit "as-is" / no-liability disclaimer.** Added a professional **Disclaimer**
  section (before License) stating the software is provided "as is" without warranty, that its
  output may overstate results (false positives / inflated severity) or miss incidents entirely
  (false negatives) and must be independently verified by a qualified investigator, and that the
  author and contributors accept no liability for any results or decisions arising from its use.

### Changed
- **Renamed the "Ask the AI" dashboard panel to "Ask the LLM".** Same free-form Q&A feature
  (`POST /cases/:id/ask`) — clearer wording that it queries the configured LLM. The panel is keyed
  by its content id, so saved section order / collapse state are unaffected.

### Fixed
- **Anonymizer auto-detection no longer floods "internal domains" with generic, non-customer words**
  (`analysis/anonymize.ts`). `deriveKnownEntities()` derives the per-case "internal domains" from the
  accounts `extractAccounts()` parses out of event text, but that `DOMAIN\user` regex mis-reads three
  big non-account sources — **registry hives** (`HKU\Software` → `hku`), **Windows well-known principals**
  (`BUILTIN\Administrators` → `builtin`, `NT AUTHORITY\SYSTEM` → `authority`, `FONT DRIVER HOST\…`), and
  **EVTX-ATTACK-SAMPLES tactic folders** (`Execution\…`, `Persistence\…`, `Discovery\…`) plus tool/generic
  folder names (`Defender`, `Tools`, `Samples`, `Code`, `vgauth`, `ransomware`…). Each was being promoted
  to an "internal domain", which both polluted the analyst's anonymization list *and* — because
  `anonDomains()` does a word-boundary replace — tokenized those ultra-common words ("access", "code",
  "files", "execution") all over the timeline, degrading the text the model reads. A new noise filter
  (`isNoiseDomain` / `isNoiseAccount` + the `NON_VICTIM_DOMAINS` set: Windows principals, registry hives,
  the 14 ATT&CK tactics, bare LAN suffixes, and common tool/folder words) drops these at derivation time.
  Real victim domains are kept: any **dotted FQDN** (`windomain.local`) is always preserved, and real
  single-label NETBIOS domains (`acme`, `artifacts-main`) survive. Analysts can still add anything the
  filter is too aggressive about via the custom-entities list. +3 unit tests.
- **Imports no longer run AI synthesis when AI is off for the case.** Every import (and manual
  event / "mark legitimate" / scope change) triggered a background `synthesize()` — an LLM call —
  regardless of the per-case AI toggle, so importing a *deterministic* artifact (THOR / Cyber Triage /
  SIEM / …) with **AI: OFF** still kicked off "AI: synthesizing findings…". The post-import
  re-synthesis now respects the AI toggle exactly like the `/captures` path does: with AI off, a
  deterministic import populates the **forensic timeline + IOCs only** and findings / attack path /
  MITRE wait until AI is turned on and the case is re-synthesized. Threat-intel **enrichment** is a
  separate, independently-gated feature (not an LLM call) and still runs regardless of the AI toggle.
- **"Ask the LLM" now stays the first dashboard section by default.** The drag-to-reorder feature
  appended any section missing from a browser's saved order to the *end*, so analysts whose
  `dfir.sectionOrder` predated the Ask panel saw it dumped at the bottom instead of first. Sections
  absent from a saved order now stay **anchored at their natural HTML slot** (the saved order only
  reshuffles the sections it actually names), so the default-first Ask panel shows first again
  without clearing localStorage — while an explicit drag of the Ask section is still honored.
- **Velociraptor exports no longer mislabel as "SIEM event".** Two common Velociraptor artifact outputs
  were falling through to the SIEM importer: the **`Windows.Hayabusa.Rules`** artifact (Hayabusa verdict rows
  that use `Title`/`EID` and render `Details` as a `¦`-separated string, so `isHayabusaJson` missed them and
  the `Channel` field routed them to SIEM) and **detail/triage artifacts with no content signature** (e.g.
  `Windows.Triage.HighValueMemory` — process memory dumps), which hit the generic SIEM fallback. Now
  `importDetect` recognizes the Velociraptor-Hayabusa shape (rule `Title` + `Level` + `Channel`/`EID`/`RecordID`)
  and routes it to the **Hayabusa** importer (verdict-first: rule title → description, `Level` → severity, MITRE
  from the detail fields), and a **Velociraptor-named export** (`Velociraptor-…` or a dotted artifact name like
  `Windows.Triage.HighValueMemory`) that only matched the SIEM fallback is routed to the **Velociraptor** importer
  instead. The Hayabusa importer also now accepts the `EID` alias and parses a `¦`-delimited string `Details`
  cell so Proc/Parent/Tgt fields and their IOCs are extracted.
- **No more `[enrich] health … DOWN` log spam while enrichment is off.** The background reachability
  poller used to re-probe every known-down provider (MISP/YETI) every 60s indefinitely — once they'd been
  probed once (e.g. opening the enrichment panel), they were logged as DOWN every minute even when no case
  had enrichment enabled. The poller now runs only while a case is actually waiting on a down provider to
  recover (its sole purpose), and stale "waiting" marks are cleared when a case's enrichment is turned off,
  so an idle/off Companion stays quiet.

## [0.8.0] - 2026-06-05

### Changed
- **One "Import" button — the server auto-detects the file type.** The dashboard's ~15 per-format
  import buttons are replaced by a **single Import button** (multi-file). Each uploaded file is **sniffed
  server-side** (`importDetect.ts` → new `POST /cases/:id/import`) — JSON object/array/NDJSON vs CSV vs
  line-oriented log, then per-format key/header signatures — and routed to the right importer (THOR, SIEM/EDR,
  Chainsaw/EVTX, Hayabusa, Velociraptor, Suricata/Zeek, KAPE/EZ, M365/Entra, AWS, GCP/Azure, Plaso, sandbox,
  or the AI CSV/log path); **images are stored as screenshots**. The detected kind is returned and shown, so a
  mis-route is visible. The per-format `POST /cases/:id/import-*` routes remain for programmatic use.
- **One "Export" menu and one "Push" menu.** The separate Generate-report / Timeline-CSV / Timesketch-JSONL
  buttons are now an **Export** dropdown (report, forensic-timeline CSV, Timesketch JSONL, full case-state JSON),
  and the Push-to-IRIS / Push-to-Timesketch buttons are a **Push** dropdown whose options appear only when that
  target is configured. The dashboard toolbar is dramatically decluttered without losing any capability.

### Added
- **Malware-sandbox report import (CAPEv2 + CrowdStrike Falcon Sandbox).** A new **Import Sandbox** button (and
  `POST /cases/:id/import-sandbox`) ingests a sandbox detonation report — the twelfth deterministic ingest path
  (no AI call), and the cleanest "ingest a verdict" case. One importer auto-detects **CAPEv2** (`report.json`:
  `info` + `target` + `signatures`) and **CrowdStrike Falcon Sandbox** / Hybrid Analysis (`verdict` + `sha256`
  + `threat_score`/`vx_family`/`mitre_attcks`). The sandbox already detonated the sample and emitted its
  verdict, so we consume it: the **sample verdict** maps to one event (severity from CAPE `malscore`/10 or the
  Falcon `verdict` — malicious→High, suspicious→Medium), and **each behavioural signature** maps to its own
  event with its **own severity** (CAPE `severity` 1–3 → Low/Medium/High; Falcon `threat_level_human`) and
  **MITRE** (CAPE signature `ttp`, Falcon `mitre_attcks`/per-signature `attck_id`). Every artefact is harvested
  as an IOC: the sample + **dropped** files + CAPE **payloads** + Falcon **extracted_files**/**processes**
  hashes, and the **network** indicators (CAPE `network.hosts`/`domains`/`http`, Falcon `hosts`/`domains` —
  IPs/domains/URLs, with a domain validator and an octet-bounded IP check). An array of reports is accepted
  (e.g. CAPE + Falcon mixed). Events are tagged **CAPEv2** / **Falcon Sandbox** for cross-source correlation;
  identical signatures aggregate and cap; optional `minSeverity` floor keeps just the malicious findings.
  Evidence-first (raw report persisted + audit-logged before analysis). Pure mapper (`sandboxImport.ts`) reuses
  `siemImport`'s `aggregateEvents` + IOC sink; unit-tested with no network.
- **Plaso / log2timeline (psort CSV) import.** A new **Import Plaso** button (and `POST /cases/:id/import-plaso`)
  ingests a `psort` super-timeline — the eleventh deterministic ingest path (no AI call). It header-detects both
  psort CSV flavours: the **dynamic** default (`datetime,timestamp_desc,source,source_long,message,parser,
  display_name,tag`) and the legacy **l2tcsv** (`date,time,timezone,MACB,source,sourcetype,type,user,host,
  short,desc,…`). Like KAPE these are evidence rows with no verdict, so each maps to an **Info** event read at
  its **own time** (dynamic ISO datetime with µs truncated to ms; l2tcsv `MM/DD/YYYY`+time+timezone combined to
  UTC). **IOCs are scraped from the free-text message** — SHA256/SHA1/MD5 hashes, `http(s)` URLs, and IPv4
  (with an octet-bounded regex so version strings like `10.0.22000` aren't mistaken for IPs) — plus the source
  file path (the `display_name`/`filename` `TYPE:`-prefix like `TSK:`/`OS:` is stripped); the l2tcsv `host`
  attributes the event for the asset↔IoC graph. Events are tagged **Plaso**; repetitive rows aggregate into
  counted rows (long digit runs — timestamps/sizes/inodes — normalized out of the key) and cap, so a large
  timeline doesn't flood (filter the psort output first). Evidence-first (raw CSV persisted + audit-logged
  before analysis). Pure mapper (`plasoImport.ts`) reuses `csvImport`'s `parseCsv` and `siemImport`'s
  `aggregateEvents` + IOC sink; unit-tested with no network.
- **GCP Cloud Audit Logs + Azure Activity Log import.** A new **Import GCP/Azure** button (and
  `POST /cases/:id/import-cloud-activity`) ingests the other two major clouds — the tenth deterministic ingest
  path (no AI call), completing AWS/GCP/Azure. One importer auto-detects per record: a **GCP** Cloud Logging
  LogEntry (the `protoPayload` AuditLog, or a `cloudaudit` logName) and an **Azure** Activity Log entry
  (`operationName` + `caller`/`resourceId`), handling both the native REST/az camelCase form (incl. nested
  `{value}` operation/status objects) and the flat Log-Analytics PascalCase shape (`OperationNameValue`,
  `Caller`, `CallerIpAddress`, …). Like AWS these are API calls with no verdict, so severity is **derived from
  the action** via per-cloud regex rule tables: service-account keys / IAM role grants
  (`CreateServiceAccountKey`→T1098.001, GCP/Azure `SetIamPolicy`/`roleAssignments/write`→T1098.003), logging
  tampering (GCP `sinks.delete`, Azure `diagnosticSettings/delete`→T1562.008), firewall opens→T1562.007, storage
  exposure (`storage.setIamPermissions`→T1530), secret/key access (GCP `AccessSecretVersion`, Azure KeyVault &
  `storageAccounts/listKeys`→T1552.001), snapshot/image sharing→T1537, VM run-command→T1059. A non-OK
  GCP `status.code` or a Failed Azure status (a denied probe) bumps severity to ≥ Medium. The caller IP
  (GCP `requestMetadata.callerIp` / Azure `httpRequest.clientIpAddress`/`CallerIpAddress`) becomes an IOC, and
  the principal email (`authenticationInfo.principalEmail` / `caller`) is surfaced in the description for the
  asset↔IoC graph. Events are tagged **GCP Audit** / **Azure Activity**; repetitive calls aggregate into
  counted rows and cap; optional `minSeverity` floor. Evidence-first (raw file persisted + audit-logged before
  analysis). Pure mapper (`cloudActivityImport.ts`) reuses `siemImport`'s `aggregateEvents` + IOC sink;
  unit-tested with no network.
- **AWS CloudTrail import.** A new **Import AWS CloudTrail** button (and `POST /cases/:id/import-aws`) ingests
  CloudTrail logs — the ninth deterministic ingest path (no AI call), extending cloud IR to AWS. It reads the
  native `{ "Records": [ … ] }` envelope, NDJSON (CloudTrail Lake / Athena), or a plain array. Each record is an
  API call with no maliciousness score, so severity is **derived from the action** via a curated table + the
  same deterministic pattern as the SIEM/M365 importers: IAM persistence/priv-esc (`CreateAccessKey`→T1098.001,
  `Attach*Policy`/`Put*Policy`/`CreatePolicyVersion`→T1098.003, `CreateLoginProfile`/`UpdateAssumeRolePolicy`,
  MFA removal→T1556), logging/detection tampering (`StopLogging`/`DeleteTrail`/`PutEventSelectors`/
  `DeleteFlowLogs`→T1562.008, GuardDuty `DeleteDetector`→T1562.001), exfil/exposure (`PutBucketPolicy`/
  `PutBucketAcl`→T1530, `ModifySnapshotAttribute`/`ModifyImageAttribute`→T1537), secrets access
  (`GetSecretValue`→T1552.001), and recon (`GetCallerIdentity`→T1087). On top of the table, a present
  **`errorCode`** (AccessDenied / UnauthorizedOperation = a probe/priv-test) bumps severity to ≥ Medium,
  **`userIdentity.type == Root`** doing anything mutating is treated as notable, and a **failed ConsoleLogin**
  (`responseElements.ConsoleLogin == Failure`) is a brute-force signal (root console login → High). The caller
  `sourceIPAddress` becomes an IOC (AWS-service callers like `ec2.amazonaws.com` are ignored), and the acting
  principal (IAM user name, or the assumed-role's `sessionIssuer`) is surfaced in the description. Events are
  tagged **AWS CloudTrail**; repetitive calls aggregate into counted rows and cap; optional `minSeverity` floor
  drops routine read calls. Evidence-first (raw file persisted + audit-logged before analysis). Pure mapper
  (`awsImport.ts`) reuses `siemImport`'s `aggregateEvents` + IOC sink; unit-tested with no network.
- **Microsoft 365 / Entra ID import.** A new **Import M365/Entra** button (and `POST /cases/:id/import-m365`)
  ingests cloud & identity audit data — the eighth deterministic ingest path (no AI call), opening
  business-email-compromise and cloud IR. It auto-detects and maps three sources: the **M365 Unified Audit
  Log** (`Search-UnifiedAuditLog` CSV/JSON or the Office 365 Management Activity API — the rich `AuditData`
  JSON string is parsed and merged over the outer row), **Entra ID sign-in logs**, and **Entra directory audit
  logs** (Graph schema). Like Windows event logs these records carry no maliciousness score, so severity is
  **derived from the operation type** — a curated table + keyword heuristics flag BEC/abuse tradecraft
  (`New/Set-InboxRule`→T1564.008, `Add-MailboxPermission`→T1098.002, `Add member to role`→T1098.003, `Add
  service principal credentials`/`Consent to application`→T1098.001/T1528, `Set-Mailbox` forwarding→T1114,
  password resets, `UserLoginFailed`→T1110) — the same deterministic approach as the SIEM importer's per-EID
  table, **not** a detection engine. **Entra's own `riskLevelDuringSignIn`/`riskState`** (Identity Protection)
  is a real verdict and drives severity directly; failed sign-ins (`status.errorCode != 0`) map to Medium. The
  source IP (de-bracketed/de-ported from M365 `ClientIP` forms like `[1.2.3.4]:443`) becomes an IOC, and the
  UPN is surfaced in the description so the asset↔IoC graph captures the compromised account. Events are tagged
  **Microsoft 365** / **Entra ID** for cross-source correlation; repetitive operations aggregate into counted
  rows and cap; optional `minSeverity` floor drops routine Info activity. Evidence-first (raw file persisted +
  audit-logged before analysis). Pure mapper (`m365Import.ts`) reuses `siemImport`'s `aggregateEvents` + IOC
  sink and `csvImport`'s `parseCsv`; unit-tested with no network.
- **KAPE / Eric Zimmerman Tools CSV import.** A new **Import KAPE/EZ** button (and `POST /cases/:id/import-kape`)
  ingests an Eric Zimmerman Tools CSV — the host-forensics counterpart to the EDR/network connectors, and the
  seventh deterministic ingest path (no AI call). The producing tool is **detected from the CSV header**, then
  each row maps to a forensic event reading the **artifact's own time** (program last-run, file MAC time,
  deletion time…) plus file/hash/process IOCs. Supported artifacts: **Prefetch** (PECmd), **Amcache**
  (AmcacheParser — including the SHA1, with its Amcache leading-zero prefix stripped), **ShimCache /
  AppCompatCache** (AppCompatCacheParser, incl. the `Executed` flag), **LNK** (LECmd), **JumpLists** (JLECmd),
  **UsnJrnl $J** & **$MFT** (MFTECmd — files only, directories skipped), **SRUM** network usage (SrumECmd),
  **Recycle Bin** (RBCmd), and **Shellbags** (SBECmd). These are evidence rows (no maliciousness verdict) so
  severity is Info — their value is the super-timeline + cross-source correlation (synthesis + the
  high-severity backfill still escalate anything that lines up with a real detection). The .NET min-date
  sentinel (`0001-01-01`/`1601-01-01`) is dropped; 7-digit fractional seconds are truncated to ms; events are
  tagged by artifact name (Prefetch/Amcache/…) so two artifacts showing the same binary corroborate; repetitive
  rows aggregate into counted rows and cap; optional `minSeverity` floor. Evidence-first (raw CSV persisted +
  audit-logged before analysis). Pure mapper (`kapeImport.ts`) reuses `csvImport`'s `parseCsv` and
  `siemImport`'s `aggregateEvents` + IOC sink; unit-tested with no network.
- **Suricata / Zeek network-log import.** A new **Import Suricata/Zeek** button (and
  `POST /cases/:id/import-network`) ingests network-monitor logs — Suricata `eve.json` and Zeek (Bro) JSON
  logs, the network side of Security Onion / Corelight — as the sixth deterministic ingest path (no AI call).
  It reads NDJSON (the native form), a JSON array, or an Elastic-style wrapper, routing each record by shape
  (Suricata has `event_type`, Zeek has `_path`). Per the post-detection principle the **timeline is built only
  from the detections**: Suricata **`alert`** records (signature → description, category, `alert.severity`
  priority → severity, `alert.metadata.mitre_technique_id` → MITRE, with the flow 5-tuple) and Zeek
  **`notice`** records (the notice framework's `note`/`msg`). The surrounding **telemetry** (`dns`/`http`/
  `tls`/`fileinfo`/`files`/`ssl`/`x509`) is **not** added to the timeline — that would flood it with raw flow
  records — but it **contributes observed IOCs**: DNS/SNI/HTTP-host **domains**, HTTP **URLs**, transferred-file
  **hashes** (Suricata `fileinfo`, Zeek `files`), and the alert/notice **IPs**. Events are tagged **Suricata** /
  **Zeek** for cross-source correlation; the artifact's own time is used (Suricata's offset timestamp, Zeek's
  epoch `ts`); repetitive alerts aggregate into counted rows and cap; an optional `minSeverity` floor drops
  low-priority alert events while telemetry IOCs are kept regardless. Evidence-first (raw file persisted +
  audit-logged before analysis). Pure mapper (`networkImport.ts`) reuses `siemImport`'s `aggregateEvents` +
  IOC sink; unit-tested with no network.
- **Velociraptor native JSON import.** A new **Import Velociraptor** button (and
  `POST /cases/:id/import-velociraptor`) ingests [Velociraptor](https://docs.velociraptor.app/) collection
  results / hunt exports — the fifth deterministic ingest path (no AI call). It reads a JSON array, **JSONL**
  (the native collection-results form), a single object, an Elastic-style wrapper, or a Velociraptor
  **multi-artifact map** (`{ "Artifact.Name": [rows], … }`). Because VQL artifacts emit completely different
  columns per artifact, each row is **classified and mapped** accordingly: a **Sigma** detection
  (`*.Detection.Sigma`, or a `Rule:{Title,Level}` over a parsed event) is **verdict-first** — the matched
  rule's level drives severity, its title leads the description, its tags become MITRE — layered over the same
  per-EID Windows mapping the SIEM/Chainsaw paths use; a **YARA** hit (`*.Detection.Yara.*`, or a string `Rule`
  + Strings/Meta/Namespace) becomes a **High** detection carrying the rule name + scanned file/process + hash;
  a parsed **EVTX** row (`System`+`EventData`, EventID as a number or `{Value}`) reuses `mapWindows`; and any
  **other** artifact (pslist / netstat / file listing / registry…) falls back to field auto-detection. Crucially
  it reads the **artifact's own time** (`System.TimeCreated`, file MAC times, `EventTime`…) and only uses the
  `_ts` collection time as a last resort. IOCs (hashes/IPs/files/processes) are pulled from every column; events
  are tagged **Velociraptor** for cross-source correlation; repetitive rows aggregate into counted rows and cap;
  optional `minSeverity` floor drops the Info-level raw-collection rows. Evidence-first (raw file persisted +
  audit-logged before analysis). Pure mapper (`velociraptorImport.ts`) reuses `siemImport`'s `mapWindows` +
  `aggregateEvents` + IOC extractors; unit-tested with no network.
- **Hayabusa import.** A new **Import Hayabusa** button (and `POST /cases/:id/import-hayabusa`) ingests a
  [Hayabusa](https://github.com/Yamato-Security/hayabusa) (Yamato Security) Sigma-over-EVTX detection timeline —
  the sister of the Chainsaw path and the fourth deterministic ingest path (no AI call). It accepts both a
  **`json-timeline`** (`hayabusa json-timeline [-J]`, a JSON array or NDJSON) and the default **`csv-timeline`**
  (`.csv`, whose `Details`/`ExtraFieldInfo` cells are `Key: value ¦ …` strings — parsed back into fields).
  Unlike Chainsaw, Hayabusa does not embed the raw EVTX node, so the mapping is **verdict-first**: the matched
  rule's **`Level` drives severity**, its **`RuleTitle` leads the description**, and its `MitreTactics`/`MitreTags`
  (`Txxxx` ids) become **MITRE techniques**. IOCs (hashes/IPs/files/processes), the affected **host**, and the
  **process→parent chain** are pulled from the rendered detail fields (Proc/CmdLine/ParentProc/Hashes/TgtIP/…)
  with the same generic extractors the SIEM importer uses, so the timeline still corroborates and feeds the
  asset↔IoC graph. Both abbreviated and spelled-out levels (`crit`/`critical`, `med`/`medium`) are accepted; the
  timestamp's offset is honored to UTC; events are tagged **Hayabusa** for cross-source correlation; repetitive
  events aggregate into counted rows and cap; optional `minSeverity` floor. Evidence-first (raw file persisted +
  audit-logged before analysis). Pure mapper (`hayabusaImport.ts`) reuses `siemImport`'s `aggregateEvents` +
  IOC extractors and `csvImport`'s `parseCsv`; unit-tested with no network.
- **Chainsaw / EVTX import.** A new **Import Chainsaw/EVTX** button (and `POST /cases/:id/import-chainsaw`)
  ingests Windows event logs the way IR teams carry them — the third JSON ingest path besides THOR and SIEM,
  and the richest for Windows IR. It accepts **[Chainsaw](https://github.com/WithSecureLabs/chainsaw) hunt
  output** (`chainsaw hunt --json`/`--jsonl`, a JSON array or NDJSON of detections) and a **raw `evtx_dump`
  JSON/NDJSON** dump, auto-detected per record. For a Chainsaw detection the matched **Sigma/built-in rule**
  is the gold: the rule name **leads the event description**, its **level drives severity** (a genuine
  maliciousness verdict, unlike a bare Windows log where severity must be derived), and its `attack.tXXXX`
  **tags become MITRE techniques** — layered on top of the same per-EID Windows/Sysmon mapping +
  IOC/asset/hash/process-chain extraction the SIEM importer already does, run against the **embedded EVTX
  event** the detection fired on (`document.data.Event` / aggregate `documents[]`). A raw `evtx_dump`
  record (`{ Event: { System, EventData } }`, named EventData **or** the `Data[{@Name,#text}]` form) has no
  verdict, so it falls back to the **per-EID severity/MITRE derivation**. Two different rules on the same
  underlying event stay **separate** events; the same rule firing repeatedly **aggregates** into a counted
  row; aggregate detections expand per embedded document. Each event is tagged **Chainsaw / EVTX** as its
  `sources` for cross-source correlation, `::ffff:` IPs are unwrapped, Sysmon `Hashes` parsed, and the
  artifact's **own time** is used (Sysmon `UtcTime` / `System.TimeCreated`). Evidence-first: the raw file is
  persisted + audit-logged before analysis; optional `minSeverity` floor drops low/info noise. The valuable
  Windows mapping, aggregation, sort and cap are **shared with `siemImport.ts`** (refactored to a reusable
  `mapWindows` + `aggregateEvents`); the new pure mapper (`chainsawImport.ts`) is unit-tested with no network.

## [0.7.0] - 2026-06-05

### Fixed
- **AI prompts no longer overflow the model's context window.** On a big case an AI call
  could exceed the model's limit and fail (`OpenRouter HTTP 400 — maximum context length is
  128000 tokens. However, you requested about 251167 tokens`). The tool now budgets every
  prompt to fit `DFIR_AI_CONTEXT_TOKENS` (default **128000**, raise for Claude 200k / Gemini
  1M): the **synthesis & ask** timelines are trimmed to fit (re-selected so the kept events
  stay the most important — the high-severity backfill still covers any dropped Critical/High
  event); **CSV / log imports** are batched by a token budget, not just a fixed row/pattern
  count, so a few very wide rows (long EDR/SIEM command-lines) no longer pack one oversized
  request; and `buildStateSummary` (prepended to every import batch) is **bounded** to the most
  recent findings/IOCs instead of dumping hundreds. As a backstop, the provider runs a
  **pre-flight context guard** — it shrinks the reserved output to fit, or fails fast with an
  actionable "reduce the input / raise DFIR_AI_CONTEXT_TOKENS" message — and an upstream 400
  about context length is rewritten to that same guidance. New pure `promptBudget` helpers
  (estimate / budget / batch-by-budget) are unit-tested, alongside the provider guard and the
  bounded summary.

### Added
- **AI-input anonymization (default on):** sensitive victim data (internal IPs, usernames,
  hostnames, internal domains, emails, user-profile paths) is tokenized — and secrets
  (passwords/API keys/tokens) one-way-redacted — before any text is sent to the LLM, then
  the real values are restored before they reach the timeline/IOCs/findings. Adversary
  indicators (public IPs, malware hashes, attacker domains) are preserved so threat signal
  and enrichment survive. Per-case toggle + category picker in the dashboard; an entity view
  shows the auto-derived list (grows with the case) and lets you add custom entities the
  detection missed; `DFIR_ANONYMIZE` env default. Screenshots are best-effort (pixels can't
  be tokenized; the dashboard warns when the vision model is external — a local Ollama vision
  model keeps them on-box).
- **New-case dialog auto-suggests the next `INC-YYYY-NNN` id** (highest NNN among this year's
  existing INC cases + 1), pre-filled and selected so it's still editable in one keystroke.
- **Enrichment reachability gate (don't blast a down MISP/YETI).** A self-hosted threat-intel
  instance can be offline (server off, TLS broken, auth 405) — and a case can carry hundreds of
  IOCs. Previously enrichment fired one doomed request *per IOC* at the dead server (the log filled
  with `… -> error (fetch failed)` / `(YETI auth HTTP 405)`). Now each provider is **health-probed
  before any IOC is sent** — a cheap call (MISP `GET /servers/getVersion`; YETI a fresh API-token
  exchange) — and the verdict is **cached ~60s** (`DFIR_ENRICH_HEALTH_TTL_MS`), so a down instance
  is tested **at most once a minute** regardless of IOC count. A provider probed *down* is skipped:
  no requests sent, **not** recorded as "checked" (so it's retried later), and reported in the run
  summary (`unavailable=[…]`) and the live AI-status line (`skipped MISP, YETI (unreachable — will
  retry)`). A **background poller** (`DFIR_ENRICH_HEALTH_POLL_MS`, default 60s, `=0` to disable)
  re-probes only the servers it last saw down and **auto-resumes enrichment** for the cases it had
  to skip, the moment the instance is reachable again. New `GET /enrich-health` route + **●up/down
  reachability dots** next to each source in the dashboard's enrichment modal. New
  `ProviderHealthCache` (pure, injectable clock) and `EnrichmentProvider.probe()` are unit-tested;
  the gate is exercised in `enrichService` and the route in `server` tests. Providers without a
  `probe()` (external SaaS) are treated as up, keeping their existing per-call error handling.
- **SIEM / EDR JSON import.** A new **Import SIEM/EDR** button (and `POST /cases/:id/import-siem`)
  ingests a JSON export from a SIEM or EDR — the second JSON ingest path besides THOR. It **unwraps the
  common container envelopes** (Elastic/Kibana `{ data: [{ _source }] }`, an Elasticsearch
  `{ hits: { hits } }` response, a plain JSON array, NDJSON, or `{ events\|records\|results\|logs }`) to a flat
  record list, then maps each record to forensic events + IOCs **deterministically** (no AI extraction, like
  THOR). **Windows Event Log + Sysmon** records (the dominant case) get a per-EID mapping: a human label,
  a **derived severity** (Windows logs carry no maliciousness score — failed-logon 4625→Medium, explicit-cred
  4648 / service-install 7045 / account & group changes→High, with a bump for LSASS process-access and
  suspicious LOLBin command-lines, and a downgrade for benign csrss/wininit `CreateRemoteThread`), MITRE
  technique tags, and IOC/asset/account extraction (IPv4-mapped `::ffff:` IPs unwrapped, Sysmon `Hashes`
  parsed, `DOMAIN\user` accounts surfaced for the asset graph). Any **other** SIEM/EDR record falls back to
  field auto-detection (timestamp / host / message / severity), so a CrowdStrike / Defender / SentinelOne
  export still produces dated events + IOCs. Repetitive identical events are **aggregated** into one counted
  row (with a first→last time span) and the total is capped, so an 11k-event export doesn't flood the
  timeline; synthesis + the high-severity backfill still cover everything. Optional `minSeverity` floor
  (the dashboard prompts for it) drops Info noise. Evidence-first: the raw export is persisted + audit-logged
  before analysis. Pure mapper (`siemImport.ts`) unit-tested with no network; the source tool is tagged via
  `detectTool` for cross-source correlation.
- **Local LiteLLM models / any OpenAI-compatible endpoint.** New `DFIR_AI_PROVIDER=litellm`
  provider talks to a self-hosted [LiteLLM](https://docs.litellm.ai/) proxy — an OpenAI-compatible
  gateway over Ollama / vLLM / 100+ backends — so analysis can run **fully on-box** with evidence never
  leaving your network. Defaults its base URL to `http://localhost:4000/v1`; a new **`DFIR_AI_BASE_URL`**
  (and `DFIR_AI_SYNTH_BASE_URL`, plus `--base-url` / `--synth-base-url` on `reanalyze`/`synthesize`)
  overrides the API base URL for any provider, so any OpenAI-compatible local endpoint works. The key may
  be blank for an auth-less proxy or set to its master/virtual key. Provider error messages now use the
  real provider label (LiteLLM / Ollama / OpenRouter / OpenAI) instead of always saying "OpenAI".
  The same `DFIR_AI_BASE_URL` lets `DFIR_AI_PROVIDER=ollama` talk **directly to a local Ollama daemon**
  (`http://localhost:11434/v1`, native OpenAI-compatible API) with no proxy — leave the key blank; when
  unset, the `ollama` provider targets hosted Ollama Cloud (`https://ollama.com/v1`). Use a **vision**
  model (e.g. `llama3.2-vision`) for screenshot extraction.
- **Timesketch timeline export & push.** A new **Export Timesketch JSONL** button (and
  `GET /cases/:id/timeline.jsonl`) downloads the forensic timeline in [Timesketch](https://timesketch.org/)
  import format — `message` / `datetime` / `timestamp_desc` plus every structured field (severity, MITRE,
  asset, hashes, path, process chain) as searchable columns and a `tag` list — for manual upload, needing no
  config. A **Push to Timesketch** button (and `npm run timesketch:push -- <caseId>`, `POST /cases/:id/push/timesketch`)
  pushes it in one click: it logs in via Timesketch local auth (CSRF + session cookie), **find-or-creates the
  sketch by name** (= the Companion case id) and uploads the timeline as Timesketch events. **Idempotent** —
  the managed timeline is **clean-replaced** on re-push so events never duplicate. The exported/pushed timeline
  matches the report (same scope/legitimate filtering). Configure with `DFIR_TIMESKETCH_URL` +
  `DFIR_TIMESKETCH_USER` + `DFIR_TIMESKETCH_PASSWORD` (self-signed/internal-CA via `DFIR_TIMESKETCH_CA`/`_INSECURE`).
  Pure mappers + a structural client interface keep it unit-tested with no network, matching the DFIR-IRIS push.
- **Case creation moved to the dashboard.** A new **+ New case** form in the dashboard (id, name,
  investigator) is now the one place a case is born, backed by a new **`GET /cases`** endpoint that lists
  existing cases. The capture extension's popup replaces its free-text Case ID box + "Create case" button
  with a **dropdown of existing cases** fetched from the companion (with **Refresh cases** and a link to
  open the dashboard) — the extension only **attaches** to a case, it never creates one. This puts case
  metadata where the full UI lives and keeps the extension a pure capture client.

### Changed
- **All forensic timestamps are normalized to UTC.** Ingestion converts any timestamp carrying a
  timezone offset (e.g. `+02:00`) to UTC (`…Z`) at the merge step (`toUtcIso` in `mergeDelta`), so the
  whole timeline is one timezone; already-UTC and timezone-less times are left untouched (a naive time
  is never re-interpreted in the server's local zone). The screenshot / CSV / log extraction prompts
  now tell the model to emit UTC — convert a shown timezone, keep a timezone-less time as UTC with a
  trailing `Z`. The dashboard's scope and manual-event date pickers are now UTC (labeled **(UTC)**,
  and the scope readout shows `… UTC`), and a **"🕑 All timestamps are in UTC"** note sits on the
  Forensic Timeline.
- **Dashboard case-ID field is now a combo box.** It shows a dropdown of existing cases (from
  `GET /cases`, refreshed on focus and when you create a case) while still accepting free text — so
  you can pick a case or type an id, and cases added out-of-band (moved into the cases folder, or
  created elsewhere) appear without a full page reload. Implemented with a native `<datalist>`;
  degrades to plain free-text on an older server / when offline.
- **New dashboard favicon.** Replaced the favicon / apple-touch icon with a dedicated DFIR Companion
  emblem (the "D + magnifier" mark). `npm run icons` now sources `public/DFIR_Companion_favicon.png`,
  flood-fills its light background to transparent, then trims to the mark and `cover`-resizes
  (Lanczos) to 16/32/180 px so the emblem fills the icon edge-to-edge instead of sitting small on a
  white square.
- **Renamed the dashboard "Report Details" panel to "Case Details."** Only the user-facing label
  changed (heading + Save button, and the report's "to be completed" pointer); the `/report-meta`
  endpoint, element ids, and `state/report-meta.json` are unchanged.
- **The companion rejects captures to an unknown case.** `POST /captures` now returns **404** (instead of
  the old confusing 500-then-queue-forever) when the `caseId` doesn't exist — evidence never lands in a
  half-made case, and the extension surfaces it (amber `!` badge, "case missing" diagnostic) instead of
  silently queueing. `POST /cases` returns **409** on a duplicate id so the New case form can't clobber an
  existing case's metadata/evidence.
- **AI analysis now defaults to OFF per case.** A fresh app start or a brand-new case captures
  evidence (screenshots are always stored) but runs no live AI until the analyst turns it on with
  the dashboard's **AI: ON/OFF** button — the same OPSEC/cost-first, opt-in stance as threat-intel
  enrichment. Turning it on still backfills everything captured while it was off. Explicit imports
  (CSV / log / THOR) are unaffected and always analyze. The default lives in `AiControlStore`
  (`enabled: false`); cases that already ran analysis keep their saved on state.

### Fixed
- **Large evidence imports failed with HTTP 413.** The JSON body limit was a fixed 25 MB, so a
  big SIEM/EDR (or CSV/THOR) export was rejected by the body parser before reaching the route. The
  limit is now **256 MB** and configurable via **`DFIR_MAX_BODY_MB`**, and an over-limit upload now
  returns an actionable JSON 413 ("raise DFIR_MAX_BODY_MB … or split the export") instead of a raw
  HTML error. Malformed JSON bodies return a clear 400.
- **Manual event time was shifted by the local timezone.** `buildManualEvent` used
  `new Date(input).toISOString()`, which reinterpreted a timezone-less value in the server's local
  zone (and the dashboard's pickers used the browser's). Both now treat the entered time as UTC, so a
  manually-added event lands at the time the analyst intended.

### Removed
- **The extension no longer creates cases.** Removed the popup's "Create case" button and the
  `CompanionClient.createCase` method — case creation is a deliberate dashboard action.

## [0.6.0] - 2026-06-04

### Added
- **License: GNU AGPL-3.0.** Added a top-level `LICENSE` (GNU Affero General Public License v3.0), set
  `"license": "AGPL-3.0-only"` in both `package.json` files, and a License section + badge in the README.
- **Project logo + crisp dashboard favicons.** Added the DFIR Companion logo to the top of the README, and
  generated sharp **16/32 px favicons + a 180 px apple-touch-icon** from it (cropped to the emblem,
  Lanczos-downsampled via `npm run icons`). The companion serves them (`/favicon-32.png`,
  `/apple-touch-icon.png`, `/favicon.ico`, `/dfir-companion-logo.jpg`) and the dashboard links them.
- **Manually add an event or IOC the AI missed.** The Forensic Timeline and IOCs sections each have a
  collapsible **+ Add … manually** form. A manual **event** (time, description, severity, optional asset /
  MITRE techniques) is appended to the timeline (kept sorted), tagged `sources: ["manual"]`, and
  re-synthesized so it weaves into findings/MITRE (a high-severity one earns a finding via the backfill).
  A manual **IOC** (type + value) is appended (deduped by value) and enriched if enrichment is on. Backed
  by `POST /cases/:id/events` and `POST /cases/:id/iocs` with validated input.
- **MITRE techniques link to attack.mitre.org.** Every technique id in the dashboard (findings, timeline,
  MITRE section), the report, and the IRIS notes is now a link to its official ATT&CK page (sub-techniques
  resolve to `…/Txxxx/yyy/`). Tactic names resolve to their `TAxxxx` tactic pages too.
- **Push a case to DFIR-IRIS.** New **Push to IRIS** dashboard button (and `npm run iris:push --
  <caseId>` / `POST /cases/:id/push/iris`) that pushes a case into a [DFIR-IRIS](https://dfir-iris.org/)
  instance. It **find-or-creates the IRIS case by name** (= the Companion case id) — re-exporting an
  existing case *updates* it — and maps **assets→assets**, **IOCs→IOCs** (IRIS type/TLP resolved at
  runtime; threat-intel verdicts become the description/tags), **forensic timeline→timeline** (events
  linked to their IRIS assets/IOCs), the **executive summary→case summary**, and **all other
  sections→notes** (attacker path, findings, MITRE, key questions, next steps, BIA, recommendations…).
  Idempotent — assets dedupe by name, IOCs by value, events by title+time; the summary and the managed
  "DFIR Companion" notes directory are refreshed each push. Uses the v1 IRIS REST API with an injectable
  `fetchFn` (self-signed / internal-CA IRIS supported via `DFIR_IRIS_CA` / `DFIR_IRIS_INSECURE`).
  Configure with `DFIR_IRIS_URL` + `DFIR_IRIS_KEY` (+ optional `DFIR_IRIS_CUSTOMER_ID` /
  `DFIR_IRIS_CLASSIFICATION_ID`); the button hides itself when IRIS isn't configured.
  - **Recommended Next Steps → IRIS tasks** (status "To do", priority tag), deduped by title — instead of a note.
  - **Timeline events are auto-categorized** by mapping each event's MITRE technique → ATT&CK tactic →
    IRIS event category (with a keyword fallback for events that carry no technique id, e.g. many THOR hits).
  - **Event titles are no longer truncated** (IRIS `event_title` is unbounded) — only a runaway one-line
    description is trimmed on a word boundary.
  - **Richer event↔IOC linking** — events now also link the IOCs referenced through their findings, not
    just IOCs whose value appears in the event text.
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

[Unreleased]: https://github.com/hasamba/DFIR-Companion/compare/v0.15.0...HEAD
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
