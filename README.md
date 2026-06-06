<p align="center">
  <img src="public/dfir-companion-logo.jpg" alt="DFIR Companion logo" width="240" />
</p>

# DFIR Companion

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)

> **AI-assisted DFIR triage — on your machine.** Turns investigation screenshots and imported
> artifacts into a forensic timeline, findings, IOCs, an asset↔IoC graph, and shareable reports;
> ask the case questions in plain English and collaborate with other investigators.

A localhost digital-forensics / incident-response companion. A browser extension
captures screenshots of your investigation (Velociraptor, EDR/SIEM dashboards, Security Onion, Splunk4DFIR, VolWeb, VirusTotal, etc.) as
evidence; a local server stores them, runs **windowed AI vision analysis** into an
accumulating per-case investigation state, and serves a **live dashboard** plus
exportable reports.

Everything runs on your machine — the companion binds to `127.0.0.1` only, evidence
stays on disk, and the AI provider is yours to choose.

> **Where it fits — a post-detection analysis layer.** DFIR Companion is **not** a detection
> engine and deliberately does not run Sigma/YARA itself. Your detection tools already do that:
> **Velociraptor** (Sigma/YARA hunts), **Security Onion** (Suricata/Zeek/Elastic), **Chainsaw**,
> **Hayabusa**, **THOR**, your EDR/SIEM. The Companion is the layer **after** detection — it
> ingests *their* verdicts and hits, correlates them across tools into one forensic timeline,
> and synthesizes the findings, attacker path, IOCs, and report. The value is the **"so what"**,
> not re-deriving alerts. New ingest connectors should consume a tool's output; they should not
> reimplement its detection.

## What it produces

For each case the AI builds and keeps up to date:

- **Forensic timeline** — real incident events with their *true* timestamps read from
  the artifacts (process create, logon, network connection, file MAC times…), sorted
  chronologically. Distinct from the capture/analysis log.
- **Findings** — granular, per-technique analytic conclusions, each with severity and
  MITRE ATT&CK mapping.
- **IOCs**, **MITRE ATT&CK** coverage, and an **attacker-path** narrative (kill chain).
- **Compromised assets** — the victim hosts and user accounts, with an interactive
  **asset ↔ IoC graph** showing which indicators touched each.
- **Key investigative questions** — initial access, lateral movement, compromised
  users/hosts, exfiltration, dwell time… each with an answer and a pointer to where to
  find/confirm it (or what to collect next).
- **Investigation threads** — open leads and resolved ones.
- **Reports** — a full incident-report in **Markdown, HTML, and PDF** (one-click print-to-PDF),
  plus CSV and JSON exports.

## Features

A living catalogue of what the tool does today. (Keep this updated as features land.)

### Capture & evidence
- **MV3 browser extension** — timer + event-driven capture (navigation, tab switch, click);
  lossless full-resolution PNG; offline queue + auto-sync; per-case Start/Stop; **`Ctrl+Shift+S`
  hotkey** to toggle capture; captured tab title baked into the screenshot filename. It
  **attaches to an existing case** picked from a server-provided dropdown — case creation is a
  deliberate dashboard action, never an extension side effect.
- **Case management in the dashboard** — a **+ New case** form is the one place cases are born
  (id, name, investigator); the companion rejects captures to an unknown case so evidence never
  lands in a half-made one.
- **Evidence-first ingest** — screenshot written to disk + append-only `captures.jsonl` audit
  line **before** any analysis; perceptual-hash duplicate detection.
- **Import external screenshots** — dashboard **Import Screenshots** button (multi-select PNG/JPEG/WebP)
  feeds images from any other tool through the same ingest path as the extension, so they're stored
  and analyzed identically.
- **Localhost only** — server binds `127.0.0.1`; CORS + Private-Network-Access so the
  `chrome-extension://` origin can reach it.

### Evidence import (beyond screenshots)
- **One Import button — the server auto-detects the type.** Drop in any file (JSON / NDJSON / CSV / log,
  multi-select; images too) and the companion **sniffs it** (structure + per-format signatures) and routes it
  to the right importer below — no need to pick the format. The detected kind is shown back so a mis-route is
  visible. Images are stored as screenshots. (Each importer also has a dedicated `POST /cases/:id/import-*`
  endpoint for programmatic use.)
- **CSV import** — Velociraptor / EDR result exports → forensic events + IOCs.
- **Generic log import** — firewall / syslog / sshd / IIS·Apache·nginx / VPN. Repetitive lines
  are **deduplicated into counted patterns**, then the AI **triages only the suspicious ones**
  (aggregated "20× …" with a time span) so the timeline stays signal-rich.
- **THOR (Nextron) import** — JSON-Lines, **deterministic** (no AI call). Drops scan info/
  lifecycle noise, optional **severity floor** (`minLevel`), maps level → severity, reads each
  finding's own artifact time.
- **SIEM / EDR JSON import** — any JSON export, **deterministic** (no AI call). **Unwraps** the
  common containers (Elastic/Kibana `data[]._source`, an Elasticsearch `hits.hits` response, a
  plain array, NDJSON, `events`/`records`/`results`), maps **Windows Event Log + Sysmon** events
  per-EID (label, **derived severity**, MITRE, IOC + asset/account extraction — `::ffff:` IPs
  unwrapped, Sysmon hashes parsed), and **auto-detects** timestamp/host/message/severity for any
  other SIEM/EDR record. Repetitive events are **aggregated** into counted rows and capped;
  optional `minSeverity` floor.
- **Chainsaw / EVTX import** — Windows event logs the way IR teams actually carry them, **deterministic**
  (no AI call). Ingests **[Chainsaw](https://github.com/WithSecureLabs/chainsaw) hunt output**
  (`chainsaw hunt --json`/`--jsonl`) — the **matched Sigma rule** leads the description, its **level
  drives severity** (a real maliciousness verdict, unlike a bare Windows log) and its `attack.tXXXX`
  **tags become MITRE techniques** — *on top of* the same per-EID mapping + IOC/asset/hash/process-chain
  extraction as the SIEM path on the **embedded EVTX event**. Also ingests a **raw `evtx_dump` JSON/NDJSON**
  dump (`{ Event: { System, EventData } }`, named or `Data[]` form) with the per-EID severity fallback.
  Events are tagged **Chainsaw / EVTX** for cross-source correlation; repetitive events aggregate and cap;
  optional `minSeverity` floor.
- **Hayabusa import** — [Hayabusa](https://github.com/Yamato-Security/hayabusa) (Yamato Security) Sigma-over-EVTX
  detection timelines, **deterministic** (no AI call). Ingests both a **`json-timeline`** (`.json`/`.jsonl`) and
  the default **`csv-timeline`** (`.csv`, with its `Key: value ¦ …` detail cells). Verdict-first like Chainsaw:
  the matched **rule title** leads the event, its **level drives severity**, and its **tactics/tags** (`Txxxx`)
  become MITRE techniques; **IOCs, the affected host, and the process→parent chain** are pulled from the rendered
  detail fields. Tagged **Hayabusa** for cross-source correlation; aggregates + caps; optional `minSeverity` floor.
- **Velociraptor native JSON import** — [Velociraptor](https://docs.velociraptor.app/) collection results / hunt
  exports, **deterministic** (no AI call). Reads a JSON array, **JSONL** (the native collection-results form), or a
  multi-artifact map (`{ "Artifact.Name": [rows] }`). Because VQL artifacts emit wildly different columns, each row is
  **classified**: **Sigma** detections map verdict-first (rule level→severity, title→description, tags→MITRE) over the
  parsed event; **YARA** hits become High detections with the rule + scanned file/process + hash; parsed **EVTX** rows
  reuse the per-EID Windows mapping; any other artifact (pslist / netstat / file listing…) **auto-detects the
  artifact's own time** (not the `_ts` collection time), host, and IOCs. Tagged **Velociraptor** for cross-source
  correlation; aggregates + caps; optional `minSeverity` floor (drops the Info-level raw-collection rows).
- **Suricata / Zeek import** — network-monitor logs (Security Onion's network side), **deterministic** (no AI
  call). Reads **Suricata `eve.json`** and **Zeek JSON** logs (NDJSON or array). The timeline is built only from
  the **detections** — Suricata `alert` records (signature, category, priority→severity, ATT&CK metadata→MITRE)
  and Zeek **`notice`** records — so it stays signal-rich; the surrounding **telemetry** (`dns`/`http`/`tls`/
  `files`/`conn`…) is **not** dumped into the timeline but **contributes IOCs** (domains, URLs, file hashes, and
  the alert/notice IPs). Tagged **Suricata** / **Zeek** for cross-source correlation; aggregates + caps; optional
  `minSeverity` floor on the alert events (telemetry IOCs are kept regardless).
- **KAPE / Eric Zimmerman Tools CSV import** — host-forensics triage, **deterministic** (no AI call). Upload a
  single EZ-tool CSV and the producing tool is **auto-detected from the header**, then each row becomes a
  super-timeline event reading the **artifact's own time** + file/hash/process IOCs. Supports **Prefetch**
  (PECmd), **Amcache** (AmcacheParser — incl. SHA1), **ShimCache/AppCompatCache** (AppCompatCacheParser),
  **LNK** (LECmd), **JumpLists** (JLECmd), **UsnJrnl $J** & **$MFT** (MFTECmd), **SRUM** (SrumECmd),
  **Recycle Bin** (RBCmd), and **Shellbags** (SBECmd). Tagged by artifact name for cross-source correlation;
  aggregates + caps; optional `minSeverity` floor.
- **Microsoft 365 / Entra ID import** — cloud & identity IR (incl. business-email-compromise), **deterministic**
  (no AI call). Ingests the **M365 Unified Audit Log** (`Search-UnifiedAuditLog` CSV/JSON or the Management
  Activity API — the `AuditData` blob is parsed and merged), **Entra sign-in logs**, and **Entra directory
  audit logs**. Like Windows logs these carry no verdict, so severity is **derived from the operation** — BEC
  tradecraft (inbox/transport rules, mailbox delegation, OAuth/service-principal grants, role additions,
  password resets, failed sign-ins) maps to High/Medium with MITRE — while **Entra's own `riskLevel`**
  (Identity Protection) drives severity directly. Source IPs become IOCs; the UPN is surfaced so the asset↔IoC
  graph captures the account. Tagged **Microsoft 365** / **Entra ID**; aggregates + caps; optional `minSeverity`
  floor (drops routine Info activity).
- **AWS CloudTrail import** — cloud IR, **deterministic** (no AI call). Reads the native `{ "Records": [ … ] }`
  envelope, NDJSON (CloudTrail Lake / Athena), or a plain array. Severity is **derived from the API action** —
  IAM persistence/priv-esc (`CreateAccessKey`, `AttachUserPolicy`, `CreateLoginProfile`), logging/detection
  tampering (`StopLogging`, `DeleteTrail`, `DeleteFlowLogs`, GuardDuty `DeleteDetector`), S3 exposure
  (`PutBucketPolicy`/`PutBucketAcl`), AMI/snapshot sharing, secrets access (`GetSecretValue`) — each mapped to
  High/Medium + MITRE; a present **`errorCode`** (AccessDenied/UnauthorizedOperation = a probe) bumps severity,
  **root** usage is flagged, and a **failed ConsoleLogin** is a brute-force signal. The caller
  `sourceIPAddress` becomes an IOC (AWS-service callers are ignored); the principal (IAM user / assumed-role
  issuer) is in the description. Tagged **AWS CloudTrail**; aggregates + caps; optional `minSeverity` floor
  (drops routine Describe/List/Get reads).
- **GCP / Azure activity-log import** — the other two clouds, **deterministic** (no AI call), auto-detected
  per record. **GCP Cloud Audit Logs** (`gcloud logging read` JSON / log-sink NDJSON — the `protoPayload`
  AuditLog) and the **Azure Activity Log** (`az monitor activity-log list` JSON or the flat Log-Analytics
  `AzureActivity` shape). Severity is **derived from the action** — service-account keys & IAM/role grants
  (`CreateServiceAccountKey`, `SetIamPolicy`, `roleAssignments/write`), logging tampering (GCP sink delete,
  Azure `diagnosticSettings/delete`), firewall opens, storage exposure, key-vault/secret & storage-key access,
  snapshot/image sharing — each mapped to High/Medium + MITRE, with a bump when the call was **denied**
  (`status.code != 0` / `Failed`). The caller IP becomes an IOC; the principal email is surfaced for the
  asset↔IoC graph. Tagged **GCP Audit** / **Azure Activity**; aggregates + caps; optional `minSeverity` floor.
- **Plaso / log2timeline import** — a `psort` super-timeline CSV, **deterministic** (no AI call). Reads both
  the **dynamic** (psort default: `datetime,timestamp_desc,source,message,parser,display_name,…`) and legacy
  **l2tcsv** (`date,time,timezone,…,desc,…`) flavours, auto-detected from the header. Each row becomes an
  evidence event (Info) at its **own time** (l2tcsv `MM/DD/YYYY`+time+tz → UTC); **IOCs** (hashes, URLs, IPs)
  and the source file path are scraped from the message, and the l2tcsv `host` attributes the event. Tagged
  **Plaso**; repetitive rows aggregate; capped — *filter your psort output first* (date range / parsers).
- **Malware-sandbox report import** — detonation reports, **deterministic** (no AI call). Ingests **CAPEv2**
  (`report.json`) and **CrowdStrike Falcon Sandbox** (Hybrid Analysis summary JSON), auto-detected. The cleanest
  "ingest a verdict" case: the **sample verdict** (CAPE `malscore`/family, Falcon `verdict`/`threat_score`/
  `vx_family`) and **each behavioural signature** become timeline events carrying their **own severity** and
  **MITRE** (CAPE signature `ttp`, Falcon `mitre_attcks`/`attck_id`); every **dropped/extracted-file hash** and
  **network host/domain/URL** is harvested as an IOC. Tagged **CAPEv2** / **Falcon Sandbox**; aggregates + caps;
  optional `minSeverity` floor.

### AI analysis
- **Two-phase** — cheap per-window vision **extraction** → forensic timeline; strong text-only
  **synthesis** → findings, IOCs, MITRE ATT&CK, attacker path, key questions, next steps, threads.
- **Providers** — OpenAI, OpenRouter, Ollama, **local LiteLLM** (an OpenAI-compatible gateway over
  Ollama / vLLM / 100+ backends — keeps evidence fully on-box) or any OpenAI-compatible endpoint via
  `DFIR_AI_BASE_URL`, Gemini; optional **two-tier** (cheap extraction + strong synthesis); high-detail
  image tiling for small-text OCR; tunable timeout; **bounded `max_tokens`** + **truncation-tolerant
  JSON parsing** (no more spurious OpenRouter 402 / parse errors); **context-window budgeting**
  (`DFIR_AI_CONTEXT_TOKENS`, default 128k) — every prompt is trimmed/batched to fit, so a big case
  never 400s on *"maximum context length"*; an unfittable prompt fails with actionable guidance.
- **EDR/XDR + SIEM consoles are evidence** — CrowdStrike, Defender, SentinelOne, Splunk, Elastic,
  Sentinel, QRadar detections are extracted; analyst tool-operation / UI navigation is filtered out,
  with an **incident-signal allowlist** so a real detection is never dropped.
- **Severity-aware findings** — a Critical/High artifact row becomes a finding by default; a
  deterministic safety net auto-creates one (`AUTO` badge) for any high-severity event synthesis missed.
- **Live auto-synthesis** — debounced re-synthesis during capture so the dashboard stays current.
- **Efficient, grounded synthesis** — skips the AI call when nothing relevant changed (skip-if-unchanged);
  picks events *stratified* (all Critical/High + earliest initial-access + an even time-spread) for better
  kill-chain coverage than top-N-by-severity; and prepends a compact *compromised assets ← IoCs* +
  *threat-intel verdicts* digest so findings and the attacker path are grounded, not inferred.
- **AI-input anonymization** — reversibly tokenizes internal IPs/usernames/hostnames/domains/emails/
  user-paths and one-way-redacts secrets before the LLM sees them, restoring real values on display;
  adversary IOCs (public IPs, hashes, attacker domains) are preserved. Per-case toggle + a
  viewable/editable entity list (auto-derived + manual). Default on.

### Correlation & deduplication
- **Cross-source correlation** — the same artifact reported by different tools (e.g. Velociraptor +
  THOR on one file) collapses into **one corroborated event** (shared hash / same path within a time
  window / exact duplicate), tagged with the **real tool names** as sources. Runs on every merge;
  importing the same report twice never doubles the timeline.

### Investigation workflow
- **Case creation** — the dashboard's **+ New case** dialog auto-suggests the next
  `INC-YYYY-NNN` id (highest for the year + 1), pre-filled and editable, so cases stay
  consistently numbered without manual bookkeeping.
- **Scope** — set a from/to time window; everything re-projects to it deterministically.
- **Mark legitimate** — flag a finding / IOC / **forensic event** as benign (reversible); excluded
  from analysis and reports.
- **Per-case AI on/off** — **off by default** (capture-only); the dashboard's **AI: ON/OFF** button
  starts live analysis and backfills everything captured while it was off.
- **Threads, key questions, next steps** — open/closed leads and standard DFIR questions with pointers.
- **Ask the AI about the case** — free-form Q&A ("was data exfiltrated?", "was a USB connected?")
  grounded in everything known; when the answer is unknown it tells you **which artifact to collect
  and where**. One click pins the question to the case's open questions, and synthesis auto-answers
  it once the evidence arrives.
- **Investigator comments** — attach comments to any entity (event, finding, IOC, question, thread)
  via a 💬 chip; authored by name, stored per case, and synced live over the WS so investigators
  collaborate in real time.

### Threat-intel enrichment (OPSEC — **per-source, default local-only**)
- **Sources** — VirusTotal (hash/IP/domain/URL), MalwareBazaar (hash), AbuseIPDB (IP), **MISP** and
  **YETI** (your own instances), **RockyRaccoon** (Windows **process** intel — prevalence / LOLBIN /
  risk / expected parent / ATT&CK).
- **Per-source selection** — each source is **local** (your own MISP/YETI — queries stay on-box,
  OPSEC-safe) or **external** (third-party — sends indicators off-box). Pick which to use; the
  **default is local-only**, external is opt-in with a confirm. **Enabling a source re-checks every
  IOC on it** (per-source cache), so adding a site later backfills the whole case on it.
- **Process-chain validation** — RockyRaccoon parent→child check flags an anomalous chain
  (e.g. `excel.exe → powershell.exe`) on the timeline.
- **Reachability gate** — a self-hosted **MISP/YETI that's down** is **health-probed before any IOC is
  sent** (cached ~60s), so a dead instance isn't hit once per IOC. Down sources are **skipped and
  retried** (not marked "checked"), shown as **●up/down dots** in the Enrich picker, and a background
  poller **auto-resumes** enrichment when the server comes back (`DFIR_ENRICH_HEALTH_POLL_MS`).
- **Per-case toggle**, cached on the IOC, throttled, capped; verdict/score/tags/link badges; IOC CSV column.
- **Self-hosted TLS** — MISP / YETI on an internal-CA or self-signed cert: trust a PEM CA bundle
  (`DFIR_MISP_CA` / `DFIR_YETI_CA`, verification stays on) or skip verification for a lab
  (`DFIR_MISP_INSECURE` / `DFIR_YETI_INSECURE`). Scoped per provider — never relaxes the other lookups.

### Dashboard & reports
- **Live dashboard** over WebSocket — **collapsible, drag-to-reorder sections** (order + collapse state
  persist per browser), scope bar, clickable evidence links, and badges (`×N` aggregate, `⊕ N sources`,
  `AUTO`, enrichment verdicts, `⚠ unusual parent`).
- **Manual add** — a **+ Add event / + Add IOC manually** form on the timeline and IOC sections lets the
  analyst record something the AI didn't catch. Manual events (time, description, severity, optional
  asset/MITRE) are tagged `manual`, re-synthesized into findings, and survive re-analysis; manual IOCs are
  deduped and enriched.
- **MITRE techniques link to [attack.mitre.org](https://attack.mitre.org/)** everywhere they appear
  (findings, timeline, MITRE section, the report, and the IRIS push) — sub-techniques included.
- **Compromised assets + asset↔IoC graph** — events carry the affected **host** (from THOR / CSV /
  screenshots); the dashboard lists compromised hosts/users and draws an interactive **asset ↔ IoC graph**
  (which IoC touched each asset, and per asset all its IoCs) with Host/Account/Service toggles,
  **fullscreen**, **horizontal / vertical / radial** layouts, **zoom** (buttons + mouse-wheel), and
  click-a-node-to-focus. A *Compromised assets* section also appears in the report.
- **Reports** — Markdown **and HTML** report (standalone, print-friendly), plus a one-click **PDF**
  export that opens the print-styled HTML and triggers the browser's *Save as PDF* dialog (zero
  dependencies, fully offline) + CSVs (findings, IOCs incl. enrichment, capture timeline, forensic
  timeline incl. count/sources) + full JSON state export. All of these — generate report (MD+HTML),
  generate report (PDF), forensic-timeline CSV, Timesketch JSONL, full JSON state — are reachable from
  the dashboard's single **Export** menu.
- **Push to DFIR-IRIS** — push a case into a [DFIR-IRIS](https://dfir-iris.org/) instance with one
  click (dashboard **Push** menu → **DFIR-IRIS**, or `npm run iris:push -- <caseId>`). It **find-or-creates
  the IRIS case by name** (= the Companion case id) — re-exporting an existing case *updates* it — and
  maps **assets → assets**, **IOCs → IOCs** (type/TLP resolved at runtime, with threat-intel verdicts as
  description/tags), **forensic timeline → timeline** (events **auto-categorized** by MITRE tactic and
  linked to their assets/IOCs), the **executive summary → case summary**, **Recommended Next Steps →
  IRIS tasks**, and **every other section → notes** (attacker path, findings, MITRE, key questions, BIA,
  recommendations…). Idempotent: assets dedupe by name, IOCs by value, events by title+time, tasks by
  title; the summary and Companion notes are refreshed each run. Configure with `DFIR_IRIS_URL` +
  `DFIR_IRIS_KEY` (self-signed/internal-CA supported via `DFIR_IRIS_CA`/`_INSECURE`).
- **Timesketch timeline export & push** — turn the forensic timeline into a [Timesketch](https://timesketch.org/)
  timeline. The **Export** menu → **Timesketch JSONL** downloads the timeline as Timesketch import format
  (`message` / `datetime` / `timestamp_desc` + every structured field — severity, MITRE, asset, hashes, path,
  process chain — kept as **searchable columns**, plus a `tag` list) for manual upload; needs no config. **Push**
  menu → **Timesketch** (or `npm run timesketch:push -- <caseId>`) does it in one click: it logs in
  (Timesketch local auth), **find-or-creates the sketch by name** (= the Companion case id), and uploads the
  timeline. **Idempotent** — the managed timeline is **clean-replaced** on re-push, so events never duplicate.
  The pushed/exported timeline matches the report (same scope/legitimate filtering). Configure with
  `DFIR_TIMESKETCH_URL` + `DFIR_TIMESKETCH_USER` + `DFIR_TIMESKETCH_PASSWORD` (self-signed/internal-CA
  supported via `DFIR_TIMESKETCH_CA`/`_INSECURE`).
- **Full incident-report template** — `report.md` follows the [AnttiKurittu incident-report-template](https://github.com/AnttiKurittu/incident-report-template)
  (title page → executive summary → BIA, limitations, goals, glossary → incident/investigation
  timelines → investigation → conclusions/recommendations → attachments). Technical sections
  auto-fill from the case (incl. an **auto-calculated glossary** from a curated DFIR dictionary);
  human-authored sections (optional **company name + logo branding**, title page with **multiple
  investigators / reviewer / incident manager**, optional incident ID + distribution, BIA,
  recommendations…) are filled in the dashboard **Case Details** panel, persist per case, override
  the derived content, and show a "to be completed" placeholder until filled. The optional company
  logo (raster image, uploaded in the dashboard, stored inline so the report stays self-contained)
  and company name render at the top of the report title page.

### Ops
- **Portable Windows EXE (no install)** — every `vX.Y.Z` tag attaches a `dfir-companion-vX.Y.Z-win-x64.zip`
  to the GitHub Release. Unzip, drop your `.env` next to `dfir-companion.exe`, double-click,
  open `http://127.0.0.1:4773/dashboard`. The same zip ships the dashboard assets and the native
  `sharp` runtime — no Node install required. The browser add-on is a sibling
  `dfir-capture-extension-vX.Y.Z.zip` on the same release. Built with **Node SEA** + esbuild +
  `postject` (`companion/scripts/build-sea.mjs`, `npm run package:sea`).
- **Docker / Docker Compose** — one-command install of the whole stack (server + dashboard +
  browser add-on) with `docker compose up`; build-from-source or pull the multi-arch image from
  GHCR. Localhost-only is preserved, evidence persists on a volume, and **no Ollama/LiteLLM are
  bundled** (point `DFIR_AI_*` at any endpoint). See [Docker / Docker Compose](#docker--docker-compose).
- **Configurable** — port (`DFIR_PORT`), bind host (`DFIR_HOST`), cases root, all behavior via `DFIR_*` env vars.
- **Customizable AI prompts** — override any of the five prompts (extraction / CSV / log / synthesis /
  ask) via env (`DFIR_AI_*_PROMPT` or `*_PROMPT_FILE`); file edits apply with no restart.
  `npm run prompts:eject` dumps the defaults to start from.
- **CLI scripts** — `reanalyze`, `synthesize`, `coverage`, `verify:ai`, `clean-timeline` (see below).

## Repository layout

```
52.43-DFIR-Companion/
├── companion/         Node/TS localhost server (the core). See companion/README.md.
├── extension/         Chrome/Comet MV3 capture extension. See extension/README.md.
├── public/
│   └── dashboard.html Live dashboard, served by the companion at /dashboard.
├── docs/
│   └── superpowers/plans/   The original 4 implementation plans.
├── Dockerfile         Single-image build (server + dashboard + add-on); no Ollama/LiteLLM.
├── docker-compose.yml Localhost-only Compose: ./cases volume, add-on → ./addon.
└── cases/             Evidence + state output (gitignored). Location set by DFIR_CASES_ROOT.
```

## How the pieces fit

```
 Browser (Comet/Chrome)                Localhost companion (127.0.0.1:4773)
 ┌─────────────────────┐  POST         ┌───────────────────────────────────────┐
 │ DFIR Capture (MV3)  │ /captures ──▶ │ ingest → evidence (screenshots+jsonl)  │
 │  timer + events     │               │   │                                    │
 └─────────────────────┘               │   ▼ per-window AI extraction (cheap)   │
                                        │ forensic timeline ──▶ synthesis (strong)│
 Dashboard / Reports ◀── WS /ws,       │   findings, IOCs, MITRE, attacker path, │
   GET /cases/:id/state                │   key questions, threads                │
 └─────────────────────┘               └───────────────────────────────────────┘
```

**Two-phase analysis:** a cheap vision model reads each screenshot into the forensic
timeline; a stronger model does the single holistic synthesis call (findings, MITRE,
attacker path, questions). Configure both via `.env` — see `companion/README.md`.

## Quick start

> **Prerequisite:** [Node.js](https://nodejs.org/) **20 or later** (which ships with `npm`).
> Check with `node --version`. Everything below uses `npm`, so no other runtime is needed.

1. **Companion** (the server):

   ```
   git clone https://github.com/hasamba/DFIR-Companion.git
   cd DFIR-Companion/companion
   npm install
   cp .env.example .env      # set DFIR_AI_PROVIDER / MODEL / KEY (or leave AI off)
   npm run dev               # serves http://127.0.0.1:4773  (dashboard at /dashboard)
   ```

2. **Extension** (capture):

   ```
   cd DFIR-Companion/extension
   npm install
   npm run build             # then load extension/dist as an unpacked extension
   ```

   The popup only **attaches** to an existing case — you create cases in the dashboard.

3. Open `http://127.0.0.1:4773/dashboard`, click **+ New case** to create your case (it
   connects automatically). Then in the extension popup pick that case from the **Case**
   dropdown (**Refresh cases** if it isn't listed yet) and **Start**. Browse your evidence —
   the dashboard updates live.

Full configuration, HTTP endpoints, the case-folder layout, and the analysis model
are documented in **[companion/README.md](companion/README.md)**.

## Docker / Docker Compose

Run the whole thing — companion server + dashboard + the browser add-on — in one container.
**No Ollama or LiteLLM are bundled**; for AI you point `DFIR_AI_*` at any OpenAI-compatible
endpoint (a model you host, a remote provider, or an Ollama/LiteLLM you run separately). With AI
left unset the container still does full capture and all the deterministic importers.

> **Prerequisite:** [Docker](https://docs.docker.com/get-docker/) with the Compose plugin
> (`docker compose version`).

**Localhost-only by design:** the container binds `0.0.0.0` internally, but Compose publishes the
port to `127.0.0.1` on your host — so the dashboard is never exposed on your network.

1. **Start it** (build from source):

   ```
   git clone https://github.com/hasamba/DFIR-Companion.git
   cd DFIR-Companion
   docker compose up -d --build      # → http://127.0.0.1:4773/dashboard
   ```

   Or pull the prebuilt image from GHCR instead of building:

   ```
   docker compose pull && docker compose up -d
   # image: ghcr.io/hasamba/dfir-companion:latest
   ```

2. **Load the add-on** (capture). The container writes the pre-built, unpacked extension to
   `./addon` on first start. In Chrome/Comet open `chrome://extensions`, enable **Developer
   mode**, click **Load unpacked**, and select **`./addon/dist`** (a packaged
   `dfir-companion-extension.zip` is dropped there too).

3. Open `http://127.0.0.1:4773/dashboard`, click **+ New case**, then pick that case in the
   extension popup and **Start**.

**Data & config:**
- Evidence and case state persist in **`./cases`** on the host (mounted volume) — survives
  restarts and image rebuilds.
- Configure via the `environment:` block in [`docker-compose.yml`](docker-compose.yml), or
  uncomment `env_file: - .env` to use a `.env` file (copy `companion/.env.example`).
- To reach an AI endpoint running on the host, use `http://host.docker.internal:<port>/v1`
  (on Linux without Docker Desktop, also uncomment the `extra_hosts` line in the compose file).

## Environment variables (`companion/.env`)

All companion behavior is configured via env vars. Shell vars override `.env`.

| Variable | Required | Default | Meaning |
| --- | --- | --- | --- |
| `DFIR_CASES_ROOT` | no | `./cases` | Where case folders are written. Relative paths resolve against `companion/`. |
| `DFIR_PORT` | no | `4773` | Port the localhost server binds to (1–65535). Change to avoid `EADDRINUSE` or run multiple companions in parallel. The extension and dashboard must use the same port. |
| `DFIR_HOST` | no | `127.0.0.1` | Interface the server binds to. Localhost-only by default. The Docker image sets `0.0.0.0` (Compose maps the port back to `127.0.0.1` on the host). Only set `0.0.0.0` natively if you intentionally want LAN access — then put it behind your own auth/firewall. |
| `DFIR_AI_PROVIDER` | no (capture-only if unset) | — | `openai` \| `openrouter` \| `ollama` \| `litellm` \| `gemini`. |
| `DFIR_AI_MODEL` | when provider set | — | Model id understood by the provider (e.g. `gpt-4o`, `openai/gpt-4o-mini`, `ollama/llama3.1`, `google/gemini-2.0-flash-001`). |
| `DFIR_AI_KEY` | when provider set | — | Provider API key. Leave blank for an auth-less local LiteLLM proxy. |
| `DFIR_AI_BASE_URL` | no | provider default | Override the provider's API base URL — for a self-hosted **LiteLLM** proxy or any OpenAI-compatible local endpoint. `litellm` defaults to `http://localhost:4000/v1`. |
| `DFIR_AI_TIMEOUT_MS` | no | `180000` | Per-request timeout in ms. Raise for strong models on large timelines. |
| `DFIR_AI_IMAGE_DETAIL` | no | `high` | `high` \| `low` \| `auto`. OpenAI/OpenRouter only — tiles screenshots at full res for small-text OCR. |
| `DFIR_AI_SYNTH_PROVIDER` | no | = `DFIR_AI_PROVIDER` | Optional stronger model for the synthesis pass (findings / MITRE / attacker path). |
| `DFIR_AI_SYNTH_MODEL` | no | = `DFIR_AI_MODEL` | Synthesis model id. |
| `DFIR_AI_SYNTH_KEY` | no | = `DFIR_AI_KEY` | Synthesis provider API key. |
| `DFIR_AI_SYNTH_BASE_URL` | no | = `DFIR_AI_BASE_URL` | Synthesis base URL override (e.g. a separate local LiteLLM proxy for the synthesis model). |
| `DFIR_AI_AUTO_SYNTHESIZE` | no | `on` | Live synthesis during capture. `on` \| `off`. |
| `DFIR_AI_AUTO_SYNTHESIZE_MS` | no | `8000` | Debounce window in ms after the last screenshot before auto-synthesis fires. |

Example `.env` (two-tier):

```
DFIR_CASES_ROOT=./cases
DFIR_PORT=4773
DFIR_AI_PROVIDER=openrouter
DFIR_AI_MODEL=openai/gpt-4o-mini          # cheap extraction (per screenshot)
DFIR_AI_KEY=sk-or-...
DFIR_AI_SYNTH_MODEL=google/gemini-2.5-pro # strong synthesis (one call)
DFIR_AI_IMAGE_DETAIL=high
DFIR_AI_AUTO_SYNTHESIZE=on
DFIR_AI_AUTO_SYNTHESIZE_MS=8000
```

## npm scripts — full CLI reference

All run from `companion/`. Arguments after `--` are forwarded to the script.

### `npm run dev`

Start the server (reads `.env`). Binds `127.0.0.1:4773`. Dashboard at `/dashboard`.

```
npm run dev
```

### `npm run build`

Type-check / compile with `tsc`. No arguments.

```
npm run build
```

### `npm test`

Run the full vitest suite. No arguments.

```
npm test
```

### `npm run verify:ai -- [caseId] [flags]`

One-call smoke test: sends 3 screenshots from the middle of the case to the configured
model and confirms the response parses against the schema. Prints findings, forensic
events, and attacker-path preview.

| Arg / flag | Default | Effect |
| --- | --- | --- |
| `caseId` (positional) | `test1` | Case to sample screenshots from. |
| `--provider NAME` | from `.env` | Override `DFIR_AI_PROVIDER` for this run. |
| `--model ID` | from `.env` | Override `DFIR_AI_MODEL` for this run. |
| `--key KEY` | from `.env` | Override `DFIR_AI_KEY` for this run. |

```
npm run verify:ai
npm run verify:ai -- mycase
npm run verify:ai -- mycase --provider openrouter --model openai/gpt-4o --key sk-or-...
```

### `npm run coverage -- [caseId]`

Reports how many of a case's screenshots were analyzed vs. skipped (duplicates) vs.
never touched. Reads only `captures.jsonl` and `investigation.json` — no AI calls.

| Arg | Default | Effect |
| --- | --- | --- |
| `caseId` (positional) | `test1` | Case to inspect. |

```
npm run coverage -- test1
npm run coverage -- mycase
```

### `npm run reanalyze -- <caseId> [flags]`

Re-run AI analysis over a case's already-captured screenshots, rebuilding the
investigation state. Runs synthesis at the end unless `--no-synthesis` is passed.
Uses your API quota (~1 call per `--window` screenshots, plus 1 synthesis call).

| Arg / flag | Default | Effect |
| --- | --- | --- |
| `caseId` (positional) | `test1` | Case to process. |
| `--reset` | off | Empty the state before analyzing. Otherwise merges into existing. |
| `--all` | off | Include duplicate screenshots too (most thorough, more API calls). |
| `--window N` | `4` | Screenshots per AI extraction call. |
| `--provider NAME` | from `.env` | Override `DFIR_AI_PROVIDER` (extraction). |
| `--model ID` | from `.env` | Override `DFIR_AI_MODEL` (extraction). |
| `--key KEY` | from `.env` | Override `DFIR_AI_KEY` (extraction). |
| `--base-url URL` | from `.env` | Override `DFIR_AI_BASE_URL` (extraction) — e.g. a local LiteLLM proxy. |
| `--synth-provider NAME` | = extraction / `DFIR_AI_SYNTH_PROVIDER` | Provider for the synthesis pass. |
| `--synth-model ID` | = extraction / `DFIR_AI_SYNTH_MODEL` | Stronger model for synthesis (findings / MITRE / attacker path). |
| `--synth-key KEY` | = extraction / `DFIR_AI_SYNTH_KEY` | API key for the synthesis provider. |
| `--synth-base-url URL` | = extraction / `DFIR_AI_SYNTH_BASE_URL` | Base URL for the synthesis provider. |
| `--no-synthesis` | off | Skip the final synthesis pass (raw forensic timeline only). |

```
# Reanalyze unique screenshots, merge into existing state
npm run reanalyze -- test1

# Fresh rebuild from empty state
npm run reanalyze -- test1 --reset

# Include duplicates too (most thorough)
npm run reanalyze -- test1 --all --reset

# Different window size
npm run reanalyze -- test1 --reset --window 3

# Try a different model
npm run reanalyze -- test1 --reset --model openai/gpt-4o

# Switch provider + model + key for this run
npm run reanalyze -- test1 --reset --provider gemini --model gemini-1.5-pro --key AIza...

# Two-tier (recommended): cheap extraction, strong synthesis
npm run reanalyze -- test1 --reset \
  --model openai/gpt-4o-mini \
  --synth-model openai/gpt-4o

# Cross-provider two-tier
npm run reanalyze -- test1 --reset \
  --provider openrouter --model openai/gpt-4o-mini --key sk-or-... \
  --synth-provider openrouter --synth-model google/gemini-2.5-pro --synth-key sk-or-...

# Just rebuild the forensic timeline, skip conclusions
npm run reanalyze -- test1 --reset --no-synthesis
```

### `npm run synthesize -- <caseId> [flags]`

One text-only AI call over the full (in-scope) forensic timeline → findings, IOCs,
MITRE mapping, attacker path, key questions. Prefers `DFIR_AI_SYNTH_*` env vars; falls
back to the extraction model.

| Arg / flag | Default | Effect |
| --- | --- | --- |
| `caseId` (positional) | `test1` | Case to synthesize. |
| `--provider NAME` | `DFIR_AI_SYNTH_PROVIDER` ?? `DFIR_AI_PROVIDER` | Override the synthesis provider. |
| `--model ID` | `DFIR_AI_SYNTH_MODEL` ?? `DFIR_AI_MODEL` | Override the synthesis model. |
| `--key KEY` | `DFIR_AI_SYNTH_KEY` ?? `DFIR_AI_KEY` | Override the synthesis API key. |
| `--base-url URL` | `DFIR_AI_SYNTH_BASE_URL` ?? `DFIR_AI_BASE_URL` | Override the synthesis base URL (e.g. a local LiteLLM proxy). |

```
# Use whatever .env says
npm run synthesize -- test1

# Re-run conclusions with a stronger model (no re-capture needed)
npm run synthesize -- test1 --model openai/gpt-4o

# Switch provider for this run
npm run synthesize -- test1 --provider gemini --model gemini-1.5-pro --key AIza...
```

### `npm run clean-timeline -- <caseId> [--apply]`

Strip analyst/tool-usage rows (Velociraptor hunts, notebooks, searches, "Response and
Monitoring accessed", etc.) from the forensic timeline. No AI calls. Dry-run by default.

| Arg / flag | Default | Effect |
| --- | --- | --- |
| `caseId` (positional) | `test1` | Case to clean. |
| `--apply` | off | Actually save. Without it, just previews what would be removed. |

```
# Preview what would be removed
npm run clean-timeline -- test1

# Actually save the cleaned timeline
npm run clean-timeline -- test1 --apply
```

After cleaning, re-run `npm run synthesize -- <caseId>` to refresh conclusions.

## Recommended workflows

```
# Daily live capture (just start the server and browse)
npm run dev

# Verify a new model works against your case before committing to it
npm run verify:ai -- mycase --model openai/gpt-4o

# Check how complete the analysis is
npm run coverage -- mycase

# Recover a case with weak/empty findings: full rebuild
npm run reanalyze -- mycase --reset

# Timeline already good — only refresh conclusions
npm run synthesize -- mycase

# Strip noise from the timeline, then refresh conclusions
npm run clean-timeline -- mycase --apply
npm run synthesize -- mycase

# Two-tier cost-optimised rebuild
npm run reanalyze -- mycase --reset \
  --model openai/gpt-4o-mini \
  --synth-model google/gemini-2.5-pro
```

## Todo / Roadmap

Ideas and planned work, not yet committed. Add to this list as new ideas come up; move items
into the **Features** section (and `CHANGELOG.md`) once shipped.

- [ ] Per-provider enrichment throttle (so RockyRaccoon's tight rate limit doesn't slow VT/AbuseIPDB).
- [ ] Configurable companion host/port in the **extension** (currently `127.0.0.1:4773`).
- [ ] `_execute_action` hotkey to open the extension popup.
- [ ] Embed the interactive **asset ↔ IoC graph** in the HTML report export (currently dashboard-only).
- [ ] Manual editing of assets and asset↔IoC links (currently auto-derived).
- [ ] **Service**-type asset extraction, and asset↔asset (lateral-movement) edges in the graph.
- [ ] **Prompt caching** for the synthesis/extraction prompts (provider-layer change to `AIProvider`)
  to cut token cost on repeated calls — the static system prompt prefix is re-sent every synthesis.

## Tests

```
cd companion && npm test     # server unit tests
cd extension && npm test     # extension unit tests
```

## License

DFIR Companion is free software, licensed under the **GNU Affero General Public License v3.0**
(`AGPL-3.0-only`). See [`LICENSE`](LICENSE) for the full text.

Copyright © 2026 Yaniv Radunsky.

In short: you're free to use, study, modify, and share it — but if you distribute a modified
version **or run a modified version as a network service**, you must make your complete source
code available to its users under the same license. (This is the DFIR-tooling norm — Velociraptor,
MISP, and TheHive are AGPL too.)

