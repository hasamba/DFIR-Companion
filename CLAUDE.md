# CLAUDE.md — working on DFIR Companion

Guidance for AI agents (and humans) modifying this codebase. Read this before changing
the server or the analysis pipeline.

## What this is

**Product principle — a post-detection analysis layer, NOT a detection engine.** The Companion
deliberately does **not** run Sigma/YARA or write detection rules. Detection is done by the tools
the analyst already runs (Velociraptor, Security Onion, Chainsaw, Hayabusa, THOR, EDR/SIEM); the
Companion ingests *their* verdicts/hits, correlates across tools into one timeline, and synthesizes
the findings/attacker-path/report — the "so what" layer. When adding an ingest connector, **consume
the tool's output; do not reimplement its detection.** (This is why the Chainsaw/Hayabusa importers
read the matched Sigma rule's level/MITRE rather than evaluating rules themselves.)

A localhost DFIR tool in two projects:
- **`companion/`** — Node 20+/TypeScript, Express server on `127.0.0.1:4773`. The core.
  Ingests screenshots **and** imported artifacts (CSV / generic log / THOR JSON) as
  evidence; AI (and deterministic mappers) analyze them into a per-case
  `InvestigationState`; optionally enriches IOCs against threat intel; serves the
  dashboard + reports. Vitest tests.
- **`extension/`** — Chrome/Comet **MV3** extension (TypeScript + Vite). Captures the
  active tab and POSTs to the companion. `Ctrl+Shift+S` toggles capture. Vitest +
  fake-indexeddb tests.
- **`public/dashboard.html`** — static dashboard served by the companion at `/dashboard`.

## Build / test (always run before committing)

```
cd companion && npm run build && npm test     # tsc must be clean; all tests green
cd extension && npm run build && npm test
```

- Tests import `.ts` modules with **`.js` extensions** (ESM/bundler resolution). This is
  intentional — keep it.
- `npm run build` is `tsc` (type-check). Scripts in `companion/scripts/` are run with
  `tsx` and are NOT in `tsconfig` `include`, so `tsc` won't check them — verify them by running.

## ⚠️ The #1 gotcha: restart the dev server after server changes

`npm run dev` loads server code **once at startup**. Any change to `companion/src/**`
(routes, prompts, pipeline) requires a restart to take effect:

```powershell
Get-NetTCPConnection -LocalPort 4773 -State Listen | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force }
cd companion && npm run dev
```

The dashboard HTML *is* served fresh each request, so dashboard-only edits show on
reload — but its buttons call a possibly-stale server. Symptom of a stale server: new UI
elements exist but their endpoints 404. The dashboard now surfaces "restart the
companion server" messages when this happens; preserve that behavior.

## Architecture you must respect

**Two-phase analysis.** Keep these separate:
1. **Per-window extraction** (`SYSTEM_PROMPT` in `analysis/pipeline.ts`): a cheap vision
   model reads each batch of screenshots and emits **forensic events** (raw dated rows)
   into the timeline. It must NOT guess finding ids (findings don't exist yet) and must
   read each event's timestamp from the **artifact's own time column**, never the capture
   time. EDR/XDR/SIEM detection consoles ARE evidence (extract them); analyst tool-usage /
   navigation is NOT (`workLogFilter.ts`).
2. **Holistic synthesis** (`SYNTHESIS_PROMPT`, `AnalysisPipeline.synthesize`): one
   text-only call over the whole (in-scope) forensic timeline. Produces findings, MITRE,
   attacker path, key questions, and back-links events→findings via `relatedEventIds`.
   **Synthesis replaces the CONCLUSIONS** (findings/MITRE) so out-of-scope/stale ones drop,
   but **PRESERVES the forensic timeline, threads, and IOCs** (IOCs are observed indicators
   — often 100s from a deterministic import the text-only pass can't re-derive). After the
   model returns, `synthesize` runs `correlateEvents` (dedup/merge), the **high-severity
   backfill** (`highSeverityFindings.ts` — every uncovered Critical/High event gets a
   finding), and the scope/legitimate filters. Efficiency/quality (`synthSelect.ts`):
   **skip-if-unchanged** (an in-memory hash of the STABLE inputs — scoped events, IOCs+verdicts,
   scope, legit — skips the AI call when nothing changed; `synthesize(caseId, { force })` and the
   Synthesize button bypass it); **`selectSynthesisEvents`** picks events stratified (all
   Critical/High + earliest/initial-access + even time-spread, chronological) instead of
   severity-only top-N; **`buildSynthesisContext`** prepends a compact *compromised assets ← IoCs* +
   *threat-intel verdicts* digest to ground the model. The hash must stay keyed to INPUTS only —
   never findings/threads/summary, which synthesis rewrites (or it would never skip).

**Evidence import (deterministic + AI).** Besides screenshots, the pipeline ingests:
CSV (`analyzeCsv`), generic logs (`analyzeLog` — `logAggregate.ts` collapses repetitive
lines into counted patterns first, then AI triages only suspicious ones), **THOR**
Nextron JSON (`importThor` → `thorImport.ts`), **SIEM/EDR** JSON (`importSiem` →
`siemImport.ts` — unwraps the container, per-EID Windows/Sysmon mapping, field
auto-detection for other records, aggregation), and **Chainsaw/EVTX** (`importChainsaw` →
`chainsawImport.ts` — Chainsaw hunt JSON or a raw `evtx_dump`; reuses `siemImport`'s
exported `mapWindows`/`aggregateEvents` on the embedded EVTX event and overlays the matched
Sigma rule's level→severity + `attack.tXXXX`→MITRE), and **Hayabusa** (`importHayabusa` →
`hayabusaImport.ts` — Hayabusa `json-timeline`/`csv-timeline`; **verdict-first** since Hayabusa
doesn't embed the raw EVTX node: rule `Level`→severity, `RuleTitle`→description, tactics/tags→MITRE,
IOCs/host/process-chain from the rendered detail fields; reuses `siemImport`'s `aggregateEvents` +
IOC extractors and `csvImport`'s `parseCsv`), and **Velociraptor** native JSON (`importVelociraptor` →
`velociraptorImport.ts` — array/JSONL/artifact-map; classifies each VQL row Sigma/YARA/EventLog/generic,
verdict-first for detections, reuses `siemImport`'s `mapWindows`/`aggregateEvents`, reads the artifact's
own time not `_ts`), and **Suricata/Zeek** network logs (`importNetwork` → `networkImport.ts` — Suricata
`eve.json` + Zeek JSON; the timeline is built from the **detections** only (Suricata `alert` + Zeek `notice`),
while telemetry (`dns`/`http`/`tls`/`files`/…) contributes **IOCs only** so the timeline stays signal-rich),
and **KAPE / Eric Zimmerman Tools** CSV (`importKape` → `kapeImport.ts` — host triage: detects the EZ tool
from the CSV header (Prefetch/Amcache/ShimCache/LNK/JumpLists/UsnJrnl/MFT/SRUM/RecycleBin/Shellbags), maps each
row to an Info evidence event reading the artifact's own time + file/hash/process IOCs; reuses `csvImport`'s
`parseCsv` + `siemImport`'s `aggregateEvents`), and **Microsoft 365 / Entra ID** (`importM365` →
`m365Import.ts` — UAL (parses the `AuditData` blob) + Entra sign-in/audit; severity DERIVED from the operation
(BEC tradecraft table + keyword fallback) like the SIEM per-EID table, or from Entra's own `riskLevel` verdict;
source IP→IOC, UPN→description for the asset graph), and **AWS CloudTrail** (`importAws` → `awsImport.ts` —
`{Records:[]}`/NDJSON/array; severity DERIVED from the API `eventName` (IAM persistence, logging-tampering,
S3 exposure, secrets access table) with bumps for `errorCode`/root/failed-ConsoleLogin; `sourceIPAddress`→IOC),
and **GCP/Azure activity** (`importCloudActivity` → `cloudActivityImport.ts` — auto-detects GCP Cloud Audit
Logs (`protoPayload`) vs Azure Activity Log (`operationName`, native camelCase or flat Log-Analytics); severity
DERIVED from the action via per-cloud regex tables (IAM/role grants, logging-tampering, secret/key access) +
denied bump; caller IP→IOC, principal email→description), and **Plaso** (`importPlaso` → `plasoImport.ts` —
psort CSV, dynamic or l2tcsv; Info evidence events at the artifact's own time, IOCs (hash/URL/IP) scraped from
the free-text message + the `display_name` path; reuses `csvImport`'s `parseCsv` + `siemImport`'s
`aggregateEvents`), and **malware-sandbox reports** (`importSandbox` → `sandboxImport.ts` — auto-detects
CAPEv2 (`report.json`) vs CrowdStrike Falcon Sandbox; the sample verdict + each behavioural signature → events
with their own severity + MITRE, dropped/extracted hashes + network host/domain/URL → IOCs), and **Cyber Triage**
(`importCybertriage` → `cybertriageImport.ts` — Sleuth Kit Labs host triage; JSONL/JSON-array/CSV timeline;
**verdict-first** since Cyber Triage scores items: `score` `Notable_Normal`=Bad/`LikelyNotable_Normal`=Suspicious
(or the CSV `threat_level`)→severity + reason-keyword bump, `scoreDescription`→description, reason→MITRE,
process-chain/path/host/args carried through; the export is mostly MFT telemetry so it **splits the feed** —
unscored Process+Task→Info evidence, unscored File super-timeline **dropped by default** (`fileTelemetry` opts in),
Active-Connection remote IP→IOC; reuses `csvImport`'s `parseCsv` + `siemImport`'s `extractRecords`/`aggregateEvents`).
The last thirteen
are **fully
deterministic, no AI call**, drop noise, map level→severity, and read the artifact's own
time. All feed the same forensic timeline via `mergeDelta`.

**One import button, server-side routing.** The dashboard has a SINGLE **Import** button → `POST /cases/:id/import`;
`importDetect.ts` (`detectImportKind`, pure + tested) sniffs the file (JSON/NDJSON vs CSV vs log, then per-format
key/header signatures, most-specific→generic) and the route dispatches to the matching `pipeline.import*` (or
`analyzeCsv`/`analyzeLog`). Images go to `POST /captures`. The per-format `import-*` routes still exist for
programmatic use. When you add a new importer, **also add its signature to `importDetect.ts` + a dispatch case in
the `/import` route**, or the unified button won't route to it. Export/Push are single dashboard menus too.
The `/import` route also snapshots the forensic timeline + IOCs before/after the importer and records what it added
(`diffTimeline` + `diffIocs` → `ImportMetaStore`, `state/import-meta.json`) so the dashboard can show "📥 last import
N ago / +N new events" and "+N new IOCs" banners + per-row `NEW` highlights above the timeline and IOCs (the import
analog of `synth-meta.json`) — this is at the route level, so the per-format `import-*` routes and script imports
don't record it.

**IOC whitelist (auto-mark known-good legitimate).** A GLOBAL store (`IocWhitelistStore`, `whitelist/ioc-whitelist.json`
next to `cases/`, mirrors `ArtifactBundleStore`/`TemplateStore`) holds known-good patterns: **CIDR** (internal IP
ranges), **exact** (hashes/values), **regex**, each optionally type-scoped. The pure matcher (`analysis/iocWhitelist.ts` —
IPv4 CIDR containment, regex/exact, CSV/JSON parse+serialize, `sanitizeRuleInput`) is unit-tested independently of I/O.
An IOC matching a rule is **auto-marked LEGITIMATE** — it reuses the existing legitimate machinery (writes an `ioc`
`LegitimateMarker`), so it's reversible and synthesis already excludes it (`applyLegitimate`). Applied in the `/import`
route's `.then()` BEFORE re-synthesis (route-level, like import-meta — other import paths use the manual apply), and on
demand via `POST /cases/:id/ioc-whitelist/apply`. Opt-in: the list starts empty (whitelisting internal ranges can hide
lateral movement). Surfaced in **Settings → IOC Whitelist** (CRUD + CSV/JSON import-export). Use a SUBDIR for the file,
not a loose sibling of `cases/` — when `DFIR_CASES_ROOT` is a drive-root child (`C:\cases`) the sibling is `C:\`, where
Windows forbids creating files.

**Cross-source correlation runs in `mergeDelta`** (`correlate.ts`): events describing the
same artifact collapse into one — by exact dup (time+description, so re-imports don't
double), shared hash, or same path within a time window. The merged event unions `sources`
(real tool names via `toolDetect.ts`); 2+ distinct tools = corroboration. Idempotent.

**State** = `InvestigationState` (`analysis/stateTypes.ts`), persisted per case in
`cases/<id>/state/investigation.json`. `ForensicEvent` carries optional structured fields
(`count`, `endTimestamp`, `sha256`/`md5`/`path`, `asset` (the affected host), `sources`,
`processName`/`parentName`, `chainCheck`); `IOC` carries optional `enrichments[]`. The
**asset ↔ IoC graph** (`analysis/assetGraph.ts`, pure) derives compromised assets (hosts from
`event.asset`; accounts from `DOMAIN\user`/UPN in event text) and the IoCs that touched each. The
**temporal attack phases** (`analysis/burstDetect.ts`, pure) group the forensic timeline into bursts by
the time gap between consecutive events (`DFIR_PHASE_GAP_S`, default 5 min), each labelled with its
dominant ATT&CK tactic (reuses `tacticForTechniques`) — the *when* axis, complementary to the categorical
kill chain. Like the graphs, it's **derived on read** (not persisted to state): `ReportWriter.phases` →
`GET /cases/:id/phases`, dashboard *Attack Phases* panel + report §3.2. **IOC corroboration**
(`analysis/iocCorroboration.ts`, pure) is the same shape: IOCs carry no `sources` field, so per-IOC
corroboration (which tools observed each indicator) is **derived on read** by matching the IOC value
against the events' `sources` (indexed exact-token match — boundary-aware so `10.0.0.1` ≠ `10.0.0.10`).
`ReportWriter.iocSources` → `GET /cases/:id/ioc-sources`, the dashboard's *⊕ N sources* IOC badge +
the report/CSV IOC `sources` column. Side files in `state/`:
`ai-control.json`, `legitimate.json`, `scope.json`, `enrich-control.json` (per-source enrichment
selection — the enabled provider names; **default = local-only** (MISP/YETI), external opt-in),
`pending_analysis.json`, `report-meta.json` (human-authored report
sections — title page, distribution, BIA, glossary, recommendations…), `comments.json`
(investigator comments on entities — never wiped by synthesis), `tags.json`
(analyst triage labels on entities — confirmed-malicious/false-positive/key-evidence/… — also never wiped by synthesis),
`synth-meta.json` (when synthesis last actually ran + the findings diff for the "last synthesized N ago" / what-changed view; written by `synthesize` only on a real run, not a skip),
`import-meta.json` (when the last import ran + its kind/file + the forensic-timeline diff AND the IOC diff for the "📥 last import N ago / +N new events / +N new IOCs" banners + per-row `NEW` highlights; written by the unified `/import` route after the importer completes — the import analog of `synth-meta.json`),
`playbook.json` (the **Response Playbook** — a trackable checklist auto-derived from the case's next steps + Critical/High findings (`analysis/playbook.ts` `derivePlaybookTasks`/`mergePlaybook`, pure + idempotent: an auto-task's id IS its source key, so a re-derive REFRESHES its text but PRESERVES the analyst's status/assignee/due/notes/order; a *pristine* untouched auto-task whose source vanished is pruned, a touched one is kept) plus custom tasks; the `GET` route re-syncs write-if-changed against current state, and `synthesize` re-syncs on each run — never wiped by synthesis), `playbook-control.json` (the per-case **IR-templates** toggle `{ useTemplates }`, `PlaybookControlStore`, default off — when on, `derivePlaybookTasks` expands each Critical/High finding into severity-based response phases (Critical → Contain/Investigate/Eradicate/Recover, High → Investigate/Contain), the Investigate step tailored to the finding's dominant ATT&CK tactic via `tacticForTechniques`).

**Per-case stores** follow the same pattern (atomic temp-file rename via `storage/atomicWrite.ts` —
which **retries the rename through a transient `EPERM`/`EBUSY`/`EACCES` lock**, since `cases/` may live
in a synced folder where Dropbox/OneDrive/AV briefly locks the file mid-rename; route every new store's
save through it, never a bare `writeFile`+`rename`): `AiControlStore`,
`LegitimateStore`, `ScopeStore`, `EnrichControlStore`, `ReportMetaStore`, `CommentsStore`, `TagsStore`, `SynthMetaStore`, `ImportMetaStore`, `PlaybookStore`, `PlaybookControlStore`. Pure filters/transforms live next to
them (`applyLegitimate`, `filterEventsByScope`, `isAnalystWorkLog`, `correlateEvents`,
`backfillHighSeverityFindings`, `diffFindings`, `diffTimeline`, `diffIocs`) and are unit-tested independently of I/O.

**Threat-intel enrichment** (`enrichment/`): `EnrichmentProvider`s (VirusTotal, Hunting.ch,
CrowdStrike, AbuseIPDB, MISP, YETI, RockyRaccoon) look up IOCs by kind; `enrichService.ts` routes/
throttles/caps/caches; `chainValidate.ts` checks RockyRaccoon parent→child chains. **Hunting.ch**
(`huntingch.ts`) is the abuse.ch unified hunt — one indicator fans out across MalwareBazaar +
ThreatFox + URLhaus + YARAify (one **abuse.ch Auth-Key**: `DFIR_HUNTINGCH_KEY`, falling back to the
legacy `DFIR_MB_KEY`) and returns **one result per back-end** that hits (there's no standalone
MalwareBazaar provider — it's a Hunting.ch back-end). **CrowdStrike** (`crowdstrike.ts`) is
Threat-Intel-only (NOT endpoint/SIEM): OAuth2 client-credentials (`DFIR_CROWDSTRIKE_CLIENT_ID`/
`_SECRET`, `_CLOUD` region, token cached+refreshed) fanning a hash across **Falcon Intelligence
Indicators + MalQuery** and IP/domain/URL across Indicators only; needs scopes *Indicators (Falcon
Intelligence): Read* (+ *MalQuery: Read*). To allow that, `EnrichmentProvider.lookup` may
return an **array**; `enrichService` flattens it and stamps each result's owning `provider` (distinct
from its display `source`) so re-checks/dedup stay correct and a fresh hit supersedes a stale
same-`source` one. Each provider has a `scope`: **local** (MISP/YETI — your own instance, OPSEC-safe)
or **external** (third-party SaaS).
**OPSEC: per-source selection, default local-only** (`resolveEnabledProviders` in `enrichControl`),
external opt-in per case (`enrich-control` stores the enabled provider names). enrichService caches
per (IOC, provider) via the IOC's `enrichedBy`, so enabling a source re-checks every IOC on it.
Providers use injectable `fetchFn` (no network in tests), configured only when their `DFIR_*` key(s) are set.

**Customer exposure (credential-leak check) is a SEPARATE feature, NOT IOC enrichment** — don't
confuse the two. It checks the *victim org's own* domains/emails against breach DBs
(`analysis/customerExposure.ts` orchestration + `analysis/customerStore.ts` targets, with
`integrations/customerExposureProviders.ts` adapters over LeakCheck/HIBP/DeHashed/**Shodan**, each a
`CustomerExposureProvider` with `lookupEmail`/`lookupDomain` (Shodan, `DFIR_SHODAN_KEY`, is domain-only —
attack surface, exposed hosts/ports/CVEs — no email lookup). Which providers run is **selectable per
case** (`CustomerTargets.providers`, like the enrichment picker): the `/check` route uses the request
body's `providers` if given, else the saved selection, else all configured. **Hard OPSEC boundary
(`buildCustomerExposureTargets`):** domain searches use ONLY the analyst-entered customer domains
(`state/customer.json`) — adversary/IOC domains are NEVER sent — and case-discovered emails are checked
only when their domain is a customer domain AND the email isn't itself an IOC. The saved summary
(`state/customer-exposure.json`, `CustomerExposureStore`) **strips raw passwords** — only a
`secretPresent` flag + exposed field names persist. Routes: `GET /cases/:id/customer-exposure`,
`PUT …/targets`, `POST …/check` (501 when no provider key). Surfaced in the dashboard panel and report
§4.5 (always rendered, placeholder when not run, so section numbering stays stable).

## Conventions / invariants — don't break these

- **Evidence-first:** the ingest path writes the screenshot to disk and appends the
  append-only `captures.jsonl` audit line **before** any analysis. Analysis never gates
  evidence persistence.
- **Localhost only:** the server binds `127.0.0.1`. CORS + Private-Network-Access headers
  are required so the `chrome-extension://` origin can reach it — don't remove them.
- **Graceful AI parsing:** use **`parseJsonLoose`** (`extractJson.ts`) before
  `deltaSchema.parse` — it strips markdown fences/prose AND repairs a **truncated** response
  (model hit `max_tokens` mid-array). Schema enums use **`.catch(fallback)`** so one
  unexpected value does not reject the whole response. Keep enums lenient; keep new
  forensic-event/IOC fields **optional** so partial responses still validate.
- **Bound AI requests:** providers send `max_tokens` (`DFIR_AI_MAX_TOKENS`, default 16000).
  Without it OpenRouter reserves the model's full output in its per-request credit check and
  **402s a large request even with credits**. Synthesis also caps prompt events
  (`DFIR_AI_SYNTH_MAX_EVENTS`); the backfill still covers any omitted Critical/High event.
- **Provider abstraction:** AI calls go through `AIProvider` (`providers/`); enrichment goes
  through `EnrichmentProvider` (`enrichment/`). Both take an injectable `fetchFn` (tests pass
  a mock — **no real network in tests**) and a `timeoutMs` (`DFIR_AI_TIMEOUT_MS`, default 180s).
  HTTP errors map to actionable messages/kinds (402 billing, 401 auth, 429 rate limit).
- **Two-tier + cost:** extraction is high-volume (one call per few screenshots) → cheap
  model; synthesis is one text-only call → can use a strong model. Configure via
  `DFIR_AI_MODEL` / `DFIR_AI_SYNTH_MODEL`. Be mindful of API cost when running
  `reanalyze`/`synthesize` against real cases.
- **Prompt caching (Anthropic) — system prompt ONLY, never case content.** `AnthropicProvider`
  marks the static system prompt as the cacheable prefix (`cache_control: ephemeral`) so it's
  billed once across the many extraction calls. **OPSEC invariant:** the breakpoint must stay on
  the system prompt — the user message + screenshots follow it and must NEVER be the cached region
  (caching retains the prefix provider-side for the TTL; that must never be forensic evidence). Usage
  (`cacheCreationTokens`/`cacheReadTokens`) comes back on `AnalyzeResult.usage`; `DFIR_AI_DEBUG_USAGE`
  logs it (a sub-threshold prefix — 1024 tok, 2048 on Haiku — silently no-ops). OpenAI/OpenRouter
  cache automatically; synthesis (single call) is intentionally not cached.
- **Secrets:** `.env` is gitignored (so are `cases/`). Never commit keys or evidence.
  Config is via `DFIR_*` env vars — see `companion/.env.example`.
- **Immutability:** the merge (`stateMerge.ts`) returns new objects, never mutates input
  state. Keep it pure. `mergeDelta` carries every optional `ForensicEvent` field through both
  branches (update + push) — when you add a field, wire it in BOTH, plus `correlate.ts`
  `mergeGroup`, or it silently drops on merge/dedup.
- **OPSEC:** enrichment is **off by default** and only sends indicators externally after the
  analyst opts in per case. Don't make any third-party lookup automatic.
- **Don't pollute the forensic timeline:** analyst tool-operation / UI navigation must stay
  out (`isAnalystWorkLog`), but the **incident-signal allowlist** (`hasIncidentSignal`) is the
  override — a real detection (malware/exe/IP/hash/logon/EDR verdict) is NEVER dropped even if
  it mentions the tool. Missing a real threat is worse than leaving noise.

## Adding a feature — the usual shape

1. Pure logic + its own unit test in `analysis/` or `enrichment/` (a filter, store, mapper,
   or provider). Providers/mappers take an injectable `fetchFn` and are tested with mocks.
2. Wire it into `AnalysisPipeline` and/or `createApp` routes in `server.ts`; pass any new
   store into the pipeline in `startServer` **and** in `scripts/synthesize.ts` /
   `scripts/reanalyze.ts` (they build their own pipelines). A new enrichment provider
   registers in `buildEnrichmentProviders()` (only when its `DFIR_*` key is set).
3. New `ForensicEvent`/`IOC` field → add to `stateTypes.ts`, `responseSchema.ts` (optional),
   `stateMerge.ts` (both branches), and `correlate.ts` `mergeGroup`. New importer → populate
   the fields and tag `sources`.
4. Surface it in `public/dashboard.html` (plain JS; `esc()` all AI/user text in `innerHTML`;
   fail loudly with a "restart the server" message on a 404).
5. Reflect it in reports (`reports/markdown.ts`, `reports/csv.ts`) when relevant. `report.md` is the
   single source of truth; the HTML export (`reports/html.ts`) renders that Markdown via `marked`
   (raw HTML escaped) — so a Markdown change flows to HTML automatically.
6. Update `companion/README.md` + `.env.example` + `CHANGELOG.md [Unreleased]` + the **Features
   list in the root `README.md`** (and **close the corresponding GitHub issue** if one tracked it —
   planned work lives in GitHub Issues under the `enhancement` label, not a README checklist), then
   run both test suites. Keeping the root README Features section current is a standing instruction —
   it's the living catalogue of what the tool does.

## Git

- Conventional commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`). One focused commit
  per change. Work on `master` is current; create a branch for larger work.
- Commit only when asked, or per the user's standing workflow.

## Versioning & CHANGELOG (do this on every tag)

- **Always keep `CHANGELOG.md` updated.** Add notable changes under `[Unreleased]`
  (Added / Changed / Fixed) as you make them — this is a standing instruction.
- **On every version tag:** move `[Unreleased]` → `[X.Y.Z] - YYYY-MM-DD`, bump the
  version in **all three** of `companion/package.json`, `extension/package.json`, and
  `extension/manifest.json` (keep them in sync; also bump the root `version` in both
  `package-lock.json` files), update the changelog compare links, then create an annotated
  `vX.Y.Z` tag on that commit and push `master` + the tag.
- **Then publish a GitHub Release** (a bare tag is shown truncated on GitHub's Tags page; a
  Release renders the full Markdown notes). Use the matching `CHANGELOG` section as the body:
  `gh release create vX.Y.Z --title vX.Y.Z --notes-file <section.md> --latest`.
- SemVer: pre-1.0 (`0.x`) — new features bump the minor (`0.1 → 0.2`); fixes-only bump
  the patch. The project is not yet stable.

## Useful scripts (in `companion/`)

`npm run dev` · `npm test` · `npm run verify:ai -- <case>` (one-call model smoke test) ·
`npm run coverage -- <case>` (how many screenshots were analyzed) ·
`npm run reanalyze -- <case> [--reset --all --model … --synth-model …]` ·
`npm run synthesize -- <case> [--model …]` · `npm run clean-timeline -- <case> [--apply]` ·
`npm run prompts:eject -- [dir]` (write the 6 default prompts to files for customizing) ·
`npm run yeti -- <indicator>` (CLI YETI lookup) ·
`npm run iris:push -- <case>` (push the case to a configured DFIR-IRIS instance) ·
`npm run timesketch:push -- <case>` (push the case's forensic timeline to a configured Timesketch instance) ·
`npm run notion:push -- <case> --page <urlOrId> | --new [--database <id>]` (export the case into a Notion page).

**External integrations** (`integrations/`) follow the IRIS pattern — a client built from env at
startup (`undefined` when unconfigured), passed into `createApp`, gated routes return 501 when absent:
DFIR-IRIS (`irisClient`), Timesketch, and **Velociraptor API** (`velociraptorClient` →
`integrations/velociraptor/velociraptorApi.ts`; drives the `velociraptor` binary's `--api_config`
through an **injectable runner** — tests never spawn). The dashboard's "Run hunt (all clients)"
button does NOT run server-side: `launchHunt()` packages the pivot VQL as a **CLIENT artifact**
(`artifact_set`) and launches a **hunt** across all endpoints (`hunt`); `huntResults()` reads rows
back addressed as `artifact/source`. Routes `POST /velociraptor/hunt` + `/velociraptor/hunt-results`
(+ server-side `/velociraptor/run`); `/health.velociraptorEnabled` gates the button. VQL statements
are passed as separate positional args with comments stripped (a leading `--` is parsed as a CLI flag).
**Triage bundles** build on the same client+runner: `listClientArtifacts()` (browse `artifact_definitions()`
type CLIENT), `launchArtifactHunt(artifacts, desc, {includeLabels,excludeLabels,os}, {timeoutSeconds, params})` (hunt over a
chosen SET of existing artifacts with Velociraptor's own include/exclude/OS conditions + an optional per-collection
`timeout` override, since some artifacts e.g. THOR run past the 600s default; `params` = per-artifact overrides
→ the hunt's `spec=dict(\`Artifact\`=dict(P='v'))`, only for artifacts in the hunt, so a heavy artifact like
Hayabusa runs constrained — Best Practice ships `RuleLevel`/`RuleStatus`), `huntResultsByArtifact()`
(collect per-artifact into the `{ "Artifact.Name": [rows] }` artifact-map `importVelociraptor` already eats — **resilient**:
returns `{results, skipped}`, an artifact too large to fetch is skipped not fatal; `hunt_results` is `LIMIT`-bounded and reads
use the larger `collectMaxOutputBytes` cap = `DFIR_VELOCIRAPTOR_COLLECT_MAX_OUTPUT`, default 256 MB, since THOR/Hayabusa are big;
a per-artifact `filters` map injects a VQL `WHERE (…)` into `hunt_results` BEFORE the LIMIT so noise is dropped at the source —
Best Practice ships a pagefile filter for YaraFile),
and `huntUploads()` (read a hunt's uploaded `.json` reports server-side — some artifacts, e.g.
`Generic.Scanner.ThorZIP` / `Windows.Hayabusa.Rules`, put their real data in an UPLOADED JSON, not rows; the
upload VQL is version-sensitive and overridable via `DFIR_VELOCIRAPTOR_UPLOAD_VQL`). The collect helper ingests
BOTH rows (→ `importVelociraptor`) AND each uploaded JSON (→ `detectImportKind` + the shared closure-level
`dispatchImport`, the same switch the `/import` route uses — factored out so both paths route identically;
HTML uploads ignored), honoring the run's optional `minSeverity` floor, and records ONE combined import-meta
diff. The Triage UI is its OWN **Settings → Velociraptor** tab (config/action, not a results view).
A **bundle** is a named artifact list — global, shared across cases (mirrors `TemplateStore`): `ArtifactBundleStore`
(`BUILT_IN_BUNDLES` Fast/Full Triage + custom JSON in a `bundles/` dir next to `cases/`). **Built-ins are editable**:
`save()` with a built-in id writes an OVERRIDE file (same id) that `list()`/`get()` return instead of the constant
(flagged `customized`); `delete()` removes the file — deleting a custom bundle, or **resetting** an edited built-in to
its default. The whole triage UI lives in its own **Settings → Velociraptor** tab (it's config/action, not a
results view); the imported events surface on the normal dashboard timeline/IOCs. Running one launches
a hunt and appends a `VeloHuntStore` job to the per-case **list** (`state/velo-hunt.json` is an array keyed by
hunt id — **multiple hunts run concurrently**, a second run doesn't drop the first; old single-object files load
as a one-element list). It survives the #1-gotcha restart, and schedules an **in-memory timer keyed by hunt id**
(`DFIR_VELO_HUNT_WAIT_MIN`, default 10 min, clamped 1..1440) that — best-effort,
recoverable via **Collect now** — runs `importVeloHuntResults` in `createApp`'s closure: it routes results through the
SAME path as the `/import` route (evidence-first persist → `importVelociraptor` → `diffTimeline`/`diffIocs` import-meta
→ `resynthesizeInBackground`). Routes: `GET /velociraptor/artifacts`, `GET/POST/DELETE /bundles`,
`POST /cases/:id/velociraptor/run-bundle` + `…/hunt-jobs` (list) + `…/collect` (`{huntId}`); `onVeloHunt` WS-broadcasts `velo_hunt_changed`.
Server-only (no `scripts/*` pipeline wiring). When you add hunt-condition options, keep the label/name sanitization
in `velociraptorApi.ts` (no VQL-string injection — names match `ARTIFACT_RE`, labels stripped to a safe charset).
**Notion** (`integrations/notion/` — `notionClient` + pure `notionBlocks` renderer + `pushCaseToNotion`
orchestrator + `NotionExportStore`) exports a case into a Notion page (`DFIR_NOTION_TOKEN`; route
`POST /cases/:id/push/notion`, `/notion/status`, `/health.notionEnabled`). The crux: the Companion
owns ONE **managed toggle block** on the target page and writes ALL its content inside it; a re-export
archives that block's children and re-appends — so investigator notes/screenshots OUTSIDE it are never
touched. Unlike IRIS/Timesketch (find-by-name on the remote), Notion has no such lookup, so the target
page + container id are remembered per case in `state/notion-export.json` (recreated if the user deletes
the block). New page = a row in `DFIR_NOTION_DATABASE_ID` (the investigation template) or a child of
`DFIR_NOTION_PARENT_PAGE_ID`; the analyst picks new-vs-existing in a dashboard modal. Screenshots are
referenced by filename (not uploaded). Appends are batched to Notion's 100-block/2-level-nesting limits.

**ClickUp** (`integrations/clickup/` — `clickupClient` + pure `clickupMap` + `pushPlaybookToClickUp`
orchestrator + `ClickUpExportStore`) pushes the **Response Playbook** (issue #36) to a ClickUp list as
tasks (`DFIR_CLICKUP_TOKEN`; route `POST /cases/:id/push/clickup` `{ listId? }`, `/clickup/status`,
`/health.clickupEnabled`). Status is mapped onto the list's REAL custom statuses (`resolveClickUpStatus`
against `listStatuses()`), priority → ClickUp's int (critical→1…low→4). The crux mirrors Notion's
remember-the-target idea but per TASK: each playbook task's ClickUp id is saved in
`state/clickup-export.json` (`ClickUpExportStore`), so a re-push **updates** the task it created
(`updateTask`) instead of duplicating (`createTask`). Like IRIS/Notion the client takes an injectable
`fetchFn` (no network in tests). The playbook is **synced** (honoring the IR-templates flag) before the push.

**Customizable prompts.** The six prompts in `pipeline.ts` are built-in DEFAULTS; the pipeline
consumes them via `getSystemPrompt()`/`getCsvPrompt()`/`getLogPrompt()`/`getSynthesisPrompt()`/`getAskPrompt()`/`getExecSummaryPrompt()`,
which resolve env overrides (`DFIR_AI_<SYSTEM|CSV|LOG|SYNTH|ASK|EXEC>_PROMPT` inline, or `…_PROMPT_FILE` —
re-read each call, so file edits apply with no restart; bad file → warn + fall back to default).
When you change a prompt's wording, keep the example JSON shape it dictates in sync with `responseSchema.ts`.
