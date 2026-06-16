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
Active-Connection remote IP→IOC; reuses `csvImport`'s `parseCsv` + `siemImport`'s `extractRecords`/`aggregateEvents`),
and **email artifacts** (`importEmail` → `emailImport.ts` — `.eml` (RFC 2822/MIME) + best-effort `.msg` (Outlook OLE);
the #1 initial-access vector. ONE event at the message's own `Date:` header; severity DERIVED from the email's own
verdict — SPF/DKIM/DMARC **fail**→High, suspicious sender (From vs different-org Reply-To/Return-Path, or a
display-name spoofing another domain)→Medium, clean→Info; URLs (links + defanged `hxxp` re-fanged) / sender+reply-to
domains / originating IP (`X-Originating-IP` or earliest external `Received` hop) / attachment names+hashes → IOCs;
MITRE T1566 (+`.001` attachment, +`.002` link). The dependency-free `parseMimeEmail` hand-rolls MIME (header
unfolding, RFC 2047 encoded-words, multipart walk, base64/quoted-printable bodies) — no `mailparser`. `.msg` is
BEST-EFFORT: the import pipeline is text-only, so the binary OLE container is scraped for its embedded RFC 822
transport-headers stream + URLs (export `.eml` for full fidelity); reuses `siemImport`'s `addIoc`/`cleanIp`),
and **memory forensics** (`importMemory` → `memoryImport.ts` — **Volatility 3** JSON renderer (an array of row
objects, the `pstree` tree nested under `__children`; also JSONL + a combined `{ "<plugin>": [rows] }` map + the
**default TEXT/grid renderer** `vol <plugin>` with no `-r json` — banner + TAB-separated header + rows, parsed by
`parseVolatilityText`/`looksLikeVolatilityText` into the SAME header-keyed rows as the JSON path so the classifier
+ mappers are reused; malfind/pstree hexdump+disasm continuation lines are skipped) and
**Rekall** JSON (`[directive, payload]` statement list — best-effort, its `_EPROCESS` cells are object-laden). Each
plugin table is identified by its **columns** (not a re-implementation of the tool) and mapped per category:
pslist/psscan/pstree → process-tree events (parent→child links, `CreateTime`), netscan/netstat → connection events
(+ foreign IP/port IOCs, external ESTABLISHED→Low), **malfind → High injected-code (T1055)**, cmdline → command-line
events (bumped on LOLBin/encoded tradecraft via the exported `isSuspiciousCmd`), svcscan/modules/driverscan →
service/driver evidence; dlllist/handles are IOC-only/dropped to stay signal-rich. Tagged **Volatility**/**Rekall**;
reuses `siemImport`'s `aggregateEvents`/`addIoc`/`cleanIp`/`genericIocs` and reads the artifact's own time).
The last fifteen
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

**Custom declarative importers (the external plugin layer).** Analysts can teach the Companion a new file format
WITHOUT code by dropping a JSON **`ImporterSpec`** (`analysis/importerSpec.ts` — Zod schema + `BUILTIN_KINDS` +
`EXAMPLE_IMPORTER_SPEC`) into a folder beside `cases/`. It's **pure data, never executed**: `match` (format +
header/key/filename/`keyEquals` signatures) DETECTS the file and `map` binds each record's columns into a forensic
event + IOCs (timestamp/description-template/severity/asset/user/processName/sha256/.../mitre/iocs, with a small
`transform` set). The interpreter is `declarativeImporter.ts` (`buildImporter` → an `ExternalImporter` with
`detect`/`parse`); the folder store is `importerStore.ts` (`ImporterStore`, GLOBAL, own subdir beside `cases/` like
`IocWhitelistStore`/`NsrlStore`; overridable via `DFIR_IMPORTERS_DIR`; loads `*.json`, a bad file is skipped + surfaced,
NEVER fatal; `config.json` holds the precedence). Detection seam in `importDetect.ts`:
`detectImportKindEx` (built-in kind + whether the match was a CONFIDENT specific importer vs a generic csv/log/siem
fallback) and `detectImportWithCustom(filename, text, importers, precedence)` — the precedence setting
(`builtin-first` default — a confident built-in wins, custom fills the gap; `external-first` — custom tried first).
The `/import` route resolves a custom id and dispatches to `pipeline.importDeclarative`, which feeds the SAME downstream
chain as every built-in: `mergeDelta` → import-meta diff → IOC-whitelist/NSRL auto-legitimate → re-synthesize. The
LLM-authoring prompt is `IMPORTER_PROMPT`/`getImporterPrompt()` (`GET /importers/prompt`, env override
`DFIR_AI_IMPORTGEN_PROMPT`/`_FILE`); routes `GET/POST /importers` + `POST /importers/reload` + Settings → Importers tab.
Security: declarative only (no code), user regexes ReDoS-guarded (length-bounded input), the description template engine
is helper-free (no injection). **INVARIANT: when you add a new built-in `ImportKind`, ALSO add it to `BUILTIN_KINDS`
in `importerSpec.ts`** (kept in sync with `importDetect.ts`) so a custom importer id can't shadow it.

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

**NSRL known-good hashes (#63).** Same shape as the whitelist, but a known-software **hash set** rather than patterns.
A GLOBAL store (`NsrlStore`, `nsrl/known-hashes.txt` next to `cases/`) holds the NIST NSRL / RDS hashes as a compact
newline-delimited, normalized file loaded into an in-memory `Set` (cached, since the set can have millions of entries and
the per-import sweep loads it each time). The pure logic (`analysis/nsrl.ts` — `normalizeHash` (MD5/SHA-1/SHA-256 only),
`parseNsrlText` (NSRLFile.txt RDS CSV / hashdeep CSV / plain hash list), `nsrlMatchIocs`/`nsrlMatchEvents`) is unit-tested
without I/O. A forensic **event** whose `sha256`/`md5` — or an **IOC** of type hash whose value — is in the set is a
**known-good file, auto-marked LEGITIMATE** (event → `event` marker by id so the raw evidence is preserved + reversible;
IOC → `ioc` marker), cutting false positives. Applied in the `/import` route's `.then()` BEFORE re-synthesis (alongside
the whitelist apply) and on demand via `POST /cases/:id/nsrl/apply`. Opt-in: the set starts empty (NSRL is "known", not
strictly "known-good" — some RDS sets include hacktools; a known hash can still be malicious in context). Surfaced in
**Settings → NSRL** (paste import / **load by server file path** / export / clear / apply); large RDS files can also pre-load
at startup from `DFIR_NSRL_FILE` (`;`-separated paths, fire-and-forget, idempotent). The startup pre-load and the
`POST /nsrl/import-file` route share one best-effort-per-file helper (`ingestNsrlFiles`/`splitNsrlPaths` in `nsrlStore.ts`),
so both behave identically; loaded hashes persist (no restart needed, and they survive one). Same SUBDIR-not-sibling
rationale as the whitelist.

**NSRL RDS SQLite backend (#63, second backend).** The flat store above is fine for small curated lists, but the REAL
NSRL RDS is distributed as a SQLite DB (the "modern RDS minimal" `RDS_*.db`) — ~160 GB, hundreds of millions of rows —
that can't be held in memory. So `analysis/nsrlDb.ts` (`NsrlDb`) **queries it on demand** instead of ingesting: opened
READ-ONLY, one indexed point-lookup per hash. It auto-detects the base table (prefers `METADATA`; `FILE` is a view) and
the sha256/md5 columns, samples one row to learn the stored hash case (binds in that case so the equality uses the index),
and keys on **sha256 + md5** (what events/IOCs carry; sha1 is intentionally skipped — no events carry it and indexing it
wastes tens of GB). `node:sqlite` is loaded LAZILY via `process.getBuiltinModule` in `analysis/sqliteRuntime.ts` — NOT a
static `import` — because (a) bundlers (Vitest/Vite) can't yet resolve the newer builtin and (b) it only exists on Node 22.5+,
so a top-level import would crash the Node-20 floor just by being in the graph; opening a DB on old Node throws an actionable
error and the flat store still works. The two backends UNION in `applyNsrlToCase` (known-good if either has the hash). Path
from `DFIR_NSRL_DB` (env-managed → the UI connect is read-only) or, when unset, a UI-set path persisted in `nsrl/db-path.txt`
(`POST`/`DELETE /nsrl/db`, mutable `nsrlDb` in the createApp closure). The analyst must index the queried column(s) first
(`CREATE INDEX … ON METADATA(sha256)` + `ANALYZE`) — see the NSRL section in `companion/README.md`. When bumping
`@types/node` to a version that ships `node:sqlite` types, delete the ambient `src/node-sqlite.d.ts`.

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
**evidence-chain graph** (`analysis/evidenceGraph.ts`, pure) is the *causal* counterpart — process
spawns, file lineage (wrote→executed), lateral movement (shared hash/account), network flows, host
anchors — derived on read from the same structured fields (`ReportWriter.evidenceGraph` →
`GET /cases/:id/evidence-graph`). **GraphRAG for "Ask the case" (#98):** `ask()` serializes that causal
graph into the prompt via `analysis/graphContext.ts` (`buildGraphContext`, pure — edges grouped by type,
ranked worst-severity-first, each line citing its backing `[event ids]`, capped by
`DFIR_ASK_GRAPH_MAX_EDGES`, default 120) so the model traces multi-hop attack paths through real
relationships instead of the flat timeline; the asset↔IoC digest is already fed via `buildSynthesisContext`. The
**temporal attack phases** (`analysis/burstDetect.ts`, pure) group the forensic timeline into bursts by
the time gap between consecutive events (`DFIR_PHASE_GAP_S`, default 5 min), each labelled with its
dominant ATT&CK tactic (reuses `tacticForTechniques`) — the *when* axis, complementary to the categorical
kill chain. Like the graphs, it's **derived on read** (not persisted to state): `ReportWriter.phases` →
`GET /cases/:id/phases`, dashboard *Attack Phases* panel + report §3.2. **IOC corroboration**
(`analysis/iocCorroboration.ts`, pure) is the same shape: IOCs carry no `sources` field, so per-IOC
corroboration (which tools observed each indicator) is **derived on read** by matching the IOC value
against the events' `sources` (indexed exact-token match — boundary-aware so `10.0.0.1` ≠ `10.0.0.10`).
`ReportWriter.iocSources` → `GET /cases/:id/ioc-sources`, the dashboard's *⊕ N sources* IOC badge +
the report/CSV IOC `sources` column. **Adversary group hints** (`analysis/adversaryHints.ts`, pure) are the
same shape: the case's identified ATT&CK techniques (findings + events + the MITRE table) are scored for
overlap against each known MITRE **Groups** entry from a bundled **offline dataset** (`data/attack-groups.json`,
loaded+cached by `analysis/adversaryGroupsData.ts`; regenerate via `npm run data:update-attack` →
`scripts/update-attack-groups.ts`, the only network touch and offline-prep only). Matching is **hybrid /
sub-technique-aware**: both sides keep full ids (T1059.001); an exact sub-technique match scores 1.0, a base-only
match (`BASE_MATCH_WEIGHT`=0.5) scores half — so `score = exactCount + 0.5·(overlapCount−exactCount)` ranks focused
actors above ones sharing only the broad technique, while breadth (`overlapCount`, base-or-better) drives the
`minOverlap` threshold. **No AI, no runtime network** —
hypothesis fuel, NOT attribution (every hint carries the group's total technique count so a diffuse 4-of-150
reads differently from a focused 4-of-12, and the caveat is shown everywhere). `ReportWriter.adversaryHints` →
`GET /cases/:id/adversary-hints`, dashboard *Adversary Hints* panel + report §4.6.1; thresholds
`DFIR_ADVERSARY_MIN_OVERLAP`/`DFIR_ADVERSARY_TOP_N`. The **mobile companion summary**
(`analysis/mobileSummary.ts`, pure) is the same shape: a compact, READ-ONLY projection of the (scope/legit-filtered)
state for the phone PWA — findings worst-first, events most-severe-then-most-recent, IOCs flagged-first with their
worst threat-intel verdict, plus severity/entity counts; heavy lists capped (`DFIR_MOBILE_MAX_FINDINGS`/`_EVENTS`/`_IOCS`)
with a pre-cap `total` so the UI shows "N of M". `ReportWriter.mobileSummary` → `GET /cases/:id/mobile-summary`, served
as the installable PWA at **`/mobile`** (`public/mobile.html` + `manifest.webmanifest` + `sw.js`; routes in `server.ts`
next to `/dashboard`). Read-only — no editing, no AI. Side files in `state/`:
`ai-control.json`, `legitimate.json`, `scope.json`, `enrich-control.json` (per-source enrichment
selection — the enabled provider names; **default = local-only** (MISP/YETI), external opt-in),
`pending_analysis.json`, `report-meta.json` (human-authored report
sections — title page, distribution, BIA, glossary, recommendations…), `comments.json`
(investigator comments on entities — never wiped by synthesis), `tags.json`
(analyst triage labels on entities — confirmed-malicious/false-positive/key-evidence/… — also never wiped by synthesis),
`synth-meta.json` (when synthesis last actually ran + the findings diff for the "last synthesized N ago" / what-changed view; written by `synthesize` only on a real run, not a skip),
`import-meta.json` (when the last import ran + its kind/file + the forensic-timeline diff AND the IOC diff for the "📥 last import N ago / +N new events / +N new IOCs" banners + per-row `NEW` highlights; written by the unified `/import` route after the importer completes — the import analog of `synth-meta.json`),
`playbook.json` (the **Response Playbook** — a trackable checklist auto-derived from the case's next steps + Critical/High findings (`analysis/playbook.ts` `derivePlaybookTasks`/`mergePlaybook`, pure + idempotent: an auto-task's id IS its source key, so a re-derive REFRESHES its text but PRESERVES the analyst's status/assignee/due/notes/order; a *pristine* untouched auto-task whose source vanished is pruned, a touched one is kept) plus custom tasks; the `GET` route re-syncs write-if-changed against current state, and `synthesize` re-syncs on each run — never wiped by synthesis), `playbook-control.json` (the per-case **IR-templates** toggle `{ useTemplates }`, `PlaybookControlStore`, default off — when on, `derivePlaybookTasks` expands each Critical/High finding into severity-based response phases (Critical → Contain/Investigate/Eradicate/Recover, High → Investigate/Contain), the Investigate step tailored to the finding's dominant ATT&CK tactic via `tacticForTechniques`).

**Second LLM opinion (#116).** An on-demand QA cross-check: a DIFFERENT model
(`DFIR_AI_SECOND_OPINION_MODEL` — ideally a different *provider*, since same-provider models share blind
spots) independently re-synthesizes the case, and we surface where it disagrees with the primary synthesis
for per-item analyst accept/reject. **Three passes** (`AnalysisPipeline.secondOpinion`): Pass 0 freshens the
PRIMARY synthesis via a plain `synthesize(caseId)` (skip-if-unchanged → no AI call when A is already current)
so model A reflects the CURRENT timeline — otherwise a stale saved A vs a fresh B yields deltas that are
staleness artifacts (deterministic gap/backfill findings) not real model disagreements; Pass 1 runs
`synthesize(caseId, { dryRun:true, force:true, provider })` — the NEW **`dryRun`** flag returns model B's
conclusions WITHOUT any side effect (no save / synth-meta / notify / accepted-delta re-apply), so it's
**non-destructive**; Pass 2 builds the deterministic delta set (`analysis/secondOpinion.ts`, pure —
`diffFindings` for findings-by-title + a MITRE set-diff → `b_only`/`a_only`/`severity`/`mitre_added`/`mitre_removed`
deltas, each carrying the relevant Finding) and an AI **reconcile** call (`RECONCILE_PROMPT`/`getReconcilePrompt`,
lenient `reconcileResponseSchema`) annotates each with a rationale + recommendation (`accept_b`/`keep_a`/`review`).
Stored in `state/second-opinion.json` (`SecondOpinionStore`). **Durability:** findings are DERIVED (synthesis
rewrites them), so `applyAcceptedSecondOpinion` (pure, idempotent) re-applies every ACCEPTED delta — used in
BOTH `applySecondOpinion` (the apply route, on the live state) AND `synthesize`'s post-processing (right after
the high-severity backfill) — so a confirmed model-B finding/severity/technique is never lost on the next
synthesis. NON-destructive until the analyst accepts; **deliberately excluded from `SNAPSHOT_STATE_FILES`**
(transient QA scratch — accepted deltas already live in `investigation.json`). Routes
`POST/GET /cases/:id/second-opinion` + `…/apply` (one delta) + `…/apply-all` (`{ accept }` — bulk over the
still-pending deltas via `setAllPendingStatus`; single + bulk share `persistSecondOpinion`); `/health.secondOpinionEnabled` gates the dashboard **2nd
opinion** button; `onSecondOpinion` WS-broadcasts `second_opinion_changed`. Two text-only AI calls per run;
same caching/anonymization invariants as synthesis. Server-only (no `scripts/*` pipeline wiring).

**Per-case stores** follow the same pattern (atomic temp-file rename via `storage/atomicWrite.ts` —
which **retries the rename through a transient `EPERM`/`EBUSY`/`EACCES` lock**, since `cases/` may live
in a synced folder where Dropbox/OneDrive/AV briefly locks the file mid-rename; route every new store's
save through it, never a bare `writeFile`+`rename`): `AiControlStore`,
`LegitimateStore`, `ScopeStore`, `EnrichControlStore`, `ReportMetaStore`, `CommentsStore`, `TagsStore`, `SynthMetaStore`, `SecondOpinionStore`, `ImportMetaStore`, `PlaybookStore`, `PlaybookControlStore`, `ReportTemplateControlStore` (`state/report-template.json` `{ templateId }`). Pure filters/transforms live next to
them (`applyLegitimate`, `filterEventsByScope`, `isAnalystWorkLog`, `correlateEvents`,
`backfillHighSeverityFindings`, `diffFindings`, `diffTimeline`, `diffIocs`, `buildSecondOpinionDeltas`, `applyAcceptedSecondOpinion`) and are unit-tested independently of I/O.

**Custom report templates (#60).** A report is rendered through a **report template** that controls
**branding** (accent colour, cover title/subtitle, running header/footer — all with a tiny, safe
Handlebars-style `{{placeholder}}` + `{{#if}}` engine, NO helpers/injection — and show/hide logo+name) and
**section layout** (which of the canonical MAJOR sections appear and in what order). Pure logic lives in
`reports/reportTemplate.ts` (schema, `BUILT_IN_REPORT_TEMPLATES` — `standard` reproduces the historical
fixed-format report byte-for-byte — `normalizeSections`, `renderTemplateString`, `buildBrandingContext`).
Templates are **GLOBAL** (`ReportTemplateStore`, `report-templates/` dir beside `cases/`, built-ins editable
via override files — mirrors `ArtifactBundleStore`); the per-case choice is `ReportTemplateControlStore`. The
**Markdown renderer is template-driven** (keyed section builders iterated per `orderedEnabledSections`), so the
HTML (accent → stylesheet) and Word (accent → heading colour) exports inherit it — keep `report.md` the single
source of truth. `ReportWriter.loadTemplate` resolves the per-case template (falls back to default on a dangling
id), threaded through `renderContents` so the redacted export honors it too. When you add a report section, add
its key+label to `REPORT_SECTION_DEFS`, a builder case in `renderMarkdownReport`, and the dashboard `RT_SECTIONS` list.

**Investigation snapshot (portable case export/import, #56).** `GET /cases/:id/export/snapshot` bundles a
case into ONE shareable JSON — case meta + the **allowlisted** `state/*.json` files + evidence *references*
(capture/import audit rows, no bytes) + headline counts — and `POST /snapshots/import` restores it as a NEW
case on another machine (`{ snapshot, targetCaseId? }`; 409 on id collision, 400 on a non-snapshot). Pure rules
in `analysis/snapshot.ts` (`buildSnapshot`/`parseSnapshot`/`prepareImport` + `SNAPSHOT_STATE_FILES` allowlist),
I/O in `analysis/snapshotIo.ts`. The allowlist is the trust boundary, applied on BOTH export and import: it
carries investigation data + analyst decisions only — **no AI keys** (they live in `.env`, never in case state)
and **no machine/account config** (`ai-control`, `enrich-control` (external-enrichment opt-in stays off so the
recipient re-opts-in), `notion`/`clickup-export` ids, `velo-hunt` jobs, the anon maps, `pending_analysis` are
excluded). **When you add a new per-case store, decide if it belongs in `SNAPSHOT_STATE_FILES`** — investigation
data/analyst decisions go in; anything machine/account/transient stays out (the allowlist means a new store is
NOT shared until deliberately added, so nothing leaks by default).

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
- **Keep entries concise — ONE line each.** A CHANGELOG bullet is a scannable summary
  (what it does + the issue ref), NOT the PR description. Put the mechanism/detail in the
  PR and commit body, not here. Lead with the **bolded feature name**, then a short clause,
  then `(closes #N)`. Condense any verbose bullets before tagging a release.
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
`npm run iris:import -- <case> <irisCaseIdOrName>` (import an existing DFIR-IRIS case into the case) ·
`npm run timesketch:push -- <case>` (push the case's forensic timeline to a configured Timesketch instance) ·
`npm run notion:push -- <case> --page <urlOrId> | --new [--database <id>]` (export the case into a Notion page).

**External integrations** (`integrations/`) follow the IRIS pattern — a client built from env at
startup (`undefined` when unconfigured), passed into `createApp`, gated routes return 501 when absent:
DFIR-IRIS (`irisClient` — push via `irisPush.ts`/`irisMap.ts`; **import is the reverse** (#88):
`integrations/iris/irisImportFetch.ts` pulls a case's assets/IOCs/timeline rows through the client's
read methods (`listCases`/`getRawAssets`/`getRawIocs`/`getRawTimeline`), the PURE `analysis/irisImport.ts`
maps them deterministically — timeline→events (severity from `event_color`, MITRE/asset/hash from
tags+content), IOCs→IOCs (type from the IRIS ioc-type name or value shape), assets→evidence events — and
`pipeline.importIris` merges via `mergeDelta`; routes `GET /iris/cases` + `POST /cases/:id/iris-import`,
surfaced via the compact **"Import case"** toolbar icon → chooser (Investigation snapshot or From DFIR-IRIS).
The IRIS timeline LIST endpoint is `case/timeline/events/list/filter/0` (0 = all events) — NOT the bare
`/case/timeline/events`, which is single-event-by-id and 404s. The client is held in a **mutable
closure var** (`let irisClient`) so `POST /iris/reconnect` (Settings → DFIR-IRIS "Test / reconnect")
can re-read `DFIR_IRIS_*` from `.env` (`reloadEnvPrefix`), rebuild via the injectable `rebuildIrisClient`,
and ping — applying config or IRIS coming back online WITHOUT the #1-gotcha restart), Timesketch, and
**Velociraptor API** (`velociraptorClient` →
`integrations/velociraptor/velociraptorApi.ts`; drives the `velociraptor` binary's `--api_config`
through an **injectable runner** — tests never spawn). Like IRIS, it has a **reconnect**: `POST
/velociraptor/reconnect` (Settings → Velociraptor → Reconnect) `reloadEnvPrefix("DFIR_VELOCIRAPTOR_")` →
rebuild via the injectable `rebuildVelociraptorClient` (reassigns `options.velociraptorClient`, which every
route reads at call time) → refresh the inventory (doubles as the reachability probe) → re-arm monitors —
applying newly-saved config or the server coming back online WITHOUT the #1-gotcha restart. The startup
inventory refresh **retries with backoff** for the same reason (Velociraptor down at boot self-heals). The
dashboard's "Run hunt (all clients)"
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

**Real-time push ingest + Velociraptor live monitoring (#84).** Two ways to stream alerts into a case as they
happen, both routed through the SAME `importDetect` → import → diff → re-synthesize pipeline as the Import button,
factored into a shared `ingestStreamed` helper in `createApp` (persist → `dispatchImport` (awaited) → import-meta
diff *only on a non-empty diff* → whitelist/NSRL → background synthesis; NO undo checkpoint — streaming would flood
the stack). (1) **`POST /cases/:id/push`** (`analysis/pushAuth.ts` + `pushPayload.ts`, pure): an external tool POSTs
any importDetect-routable payload (`{source,events}`, artifact-map, raw text…) with an `X-DFIR-Key` token; **OFF
until a token is configured** (`DFIR_PUSH_TOKEN` global and/or a per-case `PushTokenStore`, `state/push-token.json`),
403 disabled / 401 bad key (constant-time compare), 202-and-async. (2) **Velociraptor CLIENT_EVENT monitors**
(`integrations/velociraptor/monitorPoller.ts` pure poll loop + `VeloMonitorStore`, `state/velo-monitor.json`):
per-monitor self-rescheduling `setTimeout` poller (in the `createApp` closure, like `veloHuntTimers`) reads a
client-monitoring artifact's new rows via `client.monitorResults` — `source(client_id=,artifact=,start_time=,end_time=)`
for one client, or the **all-clients** variant `foreach(clients())`+`source()` when `clientId` is the `ALL_CLIENTS`
(`*`) sentinel (`monitor.allClients`). A one-click **auto** route (`…/monitors/auto`) reads `get_client_monitoring()`
(`listMonitoredArtifacts`) and starts an all-clients monitor per artifact already enabled in Velociraptor's Client
Monitoring table (422 when none). All three VQLs are overridable (`DFIR_VELOCIRAPTOR_MONITOR_VQL`/`_MONITOR_ALL_VQL`/`_MONITORED_VQL`).
It wraps the rows as a `{ [artifact]: rows }` artifact-map and feeds
`ingestStreamed` as kind `velociraptor` (monitor creation goes through one shared `createVeloMonitor` helper). The
**cursor (last-seen epoch) is persisted per monitor** so a restart
resumes without re-ingesting (`resumeVeloMonitors()` re-arms at `createApp` time); a poll error does NOT advance the
cursor (retried next tick). `DFIR_VELO_MONITOR_POLL_S` default 30. Routes `…/velociraptor/monitors[/:mid][/stop|start|poll]` + `…/monitors/auto`
+ `GET /velociraptor/event-artifacts`; `onVeloMonitor`/`onPushToken` WS-broadcast `velo_monitor_changed`/`push_token_changed`;
dashboard 🔴 LIVE badge + Settings → Velociraptor → Live Monitoring + Settings → Integrations → Push ingest. Both
stores are **machine/transient — deliberately NOT in `SNAPSHOT_STATE_FILES`** (a push token is a secret; a monitor
cursor is machine state). Server-only (no `scripts/*` wiring).
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

**Notifications** (issue #58 — `analysis/notifications.ts` pure core + `analysis/notificationStore.ts` +
`integrations/notify/*`) push three signal classes — **new/escalated findings**, **playbook updates**,
**investigation milestones** — to **Slack**/**MS Teams** webhooks + **SMTP email**. The model is pure: a
`NotificationEvent`, a `NotificationChannel` (type + `minSeverity` threshold + per-kind `events` toggles),
and the filter `shouldNotify` (enabled ∧ kind-toggle ∧ severity≥threshold; **milestones bypass the
threshold**). Event builders are deterministic — `findingEventsFromDiff` turns a synthesis `FindingsDiff`
into one event per ADDED finding (at its own severity) + each ESCALATION (natural dedup: synthesis re-ids
findings, the diff is by title, so a persisting finding isn't re-announced); `playbookTaskEvent` /
`milestoneEvent` for the others. Formatters are per-type + pure (`slackFormat` Block Kit, `teamsFormat`
MessageCard, `emailFormat` + a dependency-free RFC 5322 builder — mirrors the hand-rolled email IMPORT, **no
`nodemailer`**); senders take injectable transports (`webhookSender` an injectable `fetchFn`; `smtpClient`'s
dialog — EHLO/STARTTLS/AUTH LOGIN/MAIL-RCPT-DATA/dot-stuffing — runs through an injectable `SmtpConnect` so
the whole state machine is unit-tested with a scripted fake socket and **never opens a real connection in
tests**). `notifyDispatch` routes an event to the matching channels best-effort (a send failure is captured
per-channel, never thrown — notifications are a SIDE channel and must not break the triggering request);
`createNotifier` loads the store + dispatches. **GLOBAL store** (`notifications/config.json` next to `cases/`
in its own subdir, Windows drive-root-safe — and **gitignored**, it holds webhook URLs + SMTP passwords);
**OPSEC: opt-in** — the list starts empty, secrets are **redacted** in every route response (`redactChannel`)
and preserved on a blank-field edit (`applyChannelPatch` / `parseChannelInput(raw, existing)`). Triggers:
the pipeline's new `onSynth` hook (fired after a REAL synthesis run with the diff + state) for findings; the
playbook add/PATCH-status routes; case-create + report-generate for milestones. Routes
`GET /notifications/status`, `GET/POST/PUT/DELETE /notifications`, `POST /notifications/test`;
`/health.notificationsEnabled`. Settings → Notifications (CRUD + per-channel test). `DFIR_PUBLIC_URL`
deep-links back to the case; `DFIR_NOTIFY_CA`/`_INSECURE` for a self-hosted webhook host. Server-only (no
`scripts/*` pipeline wiring — `onSynth` is optional, so CLI synthesize/reanalyze just omit it).

**Customizable prompts.** The prompts in `pipeline.ts` are built-in DEFAULTS; the pipeline
consumes them via `getSystemPrompt()`/`getCsvPrompt()`/`getLogPrompt()`/`getSynthesisPrompt()`/`getAskPrompt()`/`getExecSummaryPrompt()`/`getNarrativePrompt()`/`getHuntSuggestPrompt()`/`getPlaybookHuntPrompt()`/`getGapHypothesisPrompt()`/`getMemoryNextStepPrompt()`/`getQueryTranslatePrompt()`/`getReconcilePrompt()` (the `RECONCILE_PROMPT` lives in `analysis/secondOpinion.ts`),
which resolve env overrides (`DFIR_AI_<SYSTEM|CSV|LOG|SYNTH|ASK|EXEC|NARRATIVE|HUNTS|PBHUNTS|GAPHYP|MEMNEXT|QUERYXLATE|RECONCILE>_PROMPT` inline, or `…_PROMPT_FILE` —
re-read each call, so file edits apply with no restart; bad file → warn + fall back to default).
When you change a prompt's wording, keep the example JSON shape it dictates in sync with `responseSchema.ts`.
When you add a prompt, also add its `<NAME>` token to `resolvePrompt`'s union type.
