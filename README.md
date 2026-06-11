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
> **Hayabusa**, **THOR**, **Cyber Triage**, your EDR/SIEM. The Companion is the layer **after** detection — it
> ingests *their* verdicts and hits, correlates them across tools into one forensic timeline,
> and synthesizes the findings, attacker path, IOCs, and report. The value is the **"so what"**,
> not re-deriving alerts. New ingest connectors should consume a tool's output; they should not
> reimplement its detection.

## Screenshots

> **Demo case: GlobalTech Industries — BEC & Ransomware Precursor.**
> Seed it locally with `npm run seed-demo` then open `http://127.0.0.1:4773/dashboard`.

---

### Executive Summary & Recommended Next Steps

AI-generated case summary and AI-prioritized remediation actions (Critical → Medium), each with
rationale and a pointer to the finding or artifact it came from.

<img src="docs/screenshots/companion-demo-01.png" alt="DFIR Companion — AI executive summary and prioritized remediation next steps" width="900" />

---

### Forensic Timeline

31 corroborated events from Chainsaw · THOR · Suricata · CrowdStrike Falcon — severity filters, per-row
triage tags (`initial-access`, `c2-comms`, `key-evidence`, …), import change tracking
(+19 new events banner with expandable diff), and analyst star / bulk-action controls.

<img src="docs/screenshots/companion-demo-02.png" alt="DFIR Companion — forensic timeline with 31 events, severity filters, triage tags, and import tracking" width="900" />

---

### Attack Path Narrative · MITRE ATT&CK Kill Chain · Findings

Full attacker-path write-up from initial access to ransomware attempt, an interactive kill chain
(click a tactic to expand its events), and the top findings with confidence scores.

<img src="docs/screenshots/companion-demo-03.png" alt="DFIR Companion — attack path narrative, MITRE ATT&CK kill chain, and findings" width="900" />

---

### Findings

8 AI-generated findings (2 Critical · 2 High · 2 Medium · 1 Low) — each with a confidence %,
analyst triage tags, MITRE technique links, and a synthesis freshness diff (+8 new since last run).

<img src="docs/screenshots/companion-demo-04.png" alt="DFIR Companion — findings with confidence scores, analyst triage tags, and MITRE ATT&CK links" width="900" />

---

### Evidence Chain Graph

Process trees + lateral movement across DC01, FS01, and WKSTN-JSMITH stitched into one causal
attack graph. Derived deterministically from importer-populated fields — no AI, no cost, runs offline.

<img src="docs/screenshots/companion-demo-05.png" alt="DFIR Companion — evidence chain graph with process trees and lateral movement across hosts" width="900" />

---

### IOCs with Threat-Intel Enrichments

15 indicators (IPs · domains · hashes · files · processes · URL) enriched against VirusTotal,
AbuseIPDB, ThreatFox, URLhaus, and MalwareBazaar — verdict badges, detection scores, `NEW` import
highlights, and analyst `confirmed-malicious` / `pivot-point` triage labels.

<img src="docs/screenshots/companion-demo-06.png" alt="DFIR Companion — IOCs with VirusTotal, AbuseIPDB, ThreatFox, URLhaus, and MalwareBazaar enrichments" width="900" />

---

### Customer Exposure & Compromised Assets · IoC Graph

**Customer Exposure** (top): credential-leak check for the victim org's own domains and emails
against HIBP / DeHashed / Shodan — breach names, exposed services, no raw passwords stored.
**Compromised Assets & IoC graph** (bottom): interactive graph linking victim hosts and accounts
to the indicators that touched each — Host / Account toggles, fullscreen, drag-to-pin nodes.

<img src="docs/screenshots/companion-demo-07.png" alt="DFIR Companion — customer exposure panel and compromised assets IoC graph" width="900" />

---

### Key Investigative Questions

8 standard DFIR questions auto-answered from the synthesized case
(answered ✅ / partial 🟡 / unknown ❓), each with an evidence pointer or a "collect this next" directive.

<img src="docs/screenshots/companion-demo-08.png" alt="DFIR Companion — key investigative questions with answers and evidence pointers" width="900" />

---

## What it produces

For each case the AI builds and keeps up to date:

- **Forensic timeline** — real incident events with their *true* timestamps read from
  the artifacts (process create, logon, network connection, file MAC times…), sorted
  chronologically. Distinct from the capture/analysis log.
- **Findings** — granular, per-technique analytic conclusions, each with severity and
  MITRE ATT&CK mapping.
- **IOCs**, **MITRE ATT&CK** coverage, and an **attacker-path** narrative (kill chain).
- **Attack phases** — the timeline grouped into temporal **bursts** (activity clustered
  by time gap), each labelled with its dominant ATT&CK tactic — the *when did each stage
  happen* view, complementary to the categorical kill chain. Deterministic, no AI call.
- **Compromised assets** — the victim hosts and user accounts, with an interactive
  **asset ↔ IoC graph** showing which indicators touched each.
- **Key investigative questions** — initial access, lateral movement, compromised
  users/hosts, exfiltration, dwell time… each with an answer and a pointer to where to
  find/confirm it (or what to collect next).
- **Investigation threads** — open leads and resolved ones.
- **Reports** — a full incident-report in **Markdown, HTML, and PDF** (one-click print-to-PDF),
  plus CSV and JSON exports.

## Features

### Capture & ingest
- **MV3 browser extension** — timer + event-driven capture, `Ctrl+Shift+S` hotkey, offline queue, per-case start/stop
- **Import screenshots** — multi-select PNG/JPEG/WebP from any tool; same ingest path as the extension
- **One Import button** — drop any artifact file; server **auto-detects the format** and routes it automatically
- **Minimum-severity floor** — filter import noise at the gate; severity-less formats always pass through unchanged
- **Evidence-first** — files written to disk + append-only audit log before any analysis; perceptual-hash dedup

### Capture & evidence
- **MV3 browser extension** — timer + event-driven capture (navigation, tab switch, click);
  lossless full-resolution PNG; offline queue + auto-sync; per-case Start/Stop; **`Ctrl+Shift+S`
  hotkey** to toggle capture; captured tab title baked into the screenshot filename. It
  **attaches to an existing case** picked from a server-provided dropdown — case creation is a
  deliberate dashboard action, never an extension side effect.
- **Case management in the dashboard** — a **+ New case** form is the one place cases are born
  (id, name, investigator); the companion rejects captures to an unknown case so evidence never
  lands in a half-made one.
- **Case templates** — the New case modal offers five built-in templates (Ransomware, BEC/Email
  Compromise, Insider Threat, Web App Intrusion, General Malware) that pre-populate the Key
  Questions list with incident-type–specific investigation questions (pinned so synthesis can
  answer them). Each template also lists recommended import types and hunt platforms as hints.
  Custom templates can be saved from the Export menu (**Save as Template…**) and reused across
  cases; they're stored in a `templates/` directory alongside `cases/`.
- **Evidence-first ingest** — screenshot written to disk + append-only `captures.jsonl` audit
  line **before** any analysis; perceptual-hash duplicate detection.
- **Import external screenshots** — dashboard **Import Screenshots** button (multi-select PNG/JPEG/WebP)
  feeds images from any other tool through the same ingest path as the extension, so they're stored
  and analyzed identically.
- **Localhost only** — server binds `127.0.0.1`; CORS + Private-Network-Access so the
  `chrome-extension://` origin can reach it.

### Evidence importers

All importers are **deterministic (no AI call)**, read the artifact's own timestamps, and tag events with the real tool name for cross-source correlation. The same file can be re-imported without duplicating the timeline.

| Format | Key sources | Severity derived from |
|---|---|---|
| **SIEM / EDR JSON** | Elastic, Kibana, Splunk, QRadar, any JSON/NDJSON export | Windows/Sysmon per-EID table |
| **Chainsaw** | EVTX hunt JSON/JSONL (`chainsaw hunt --json`) | Matched Sigma rule level |
| **Hayabusa** | `json-timeline` or `csv-timeline` | Matched Sigma rule level |
| **Velociraptor** | JSON array, JSONL, or artifact map | Sigma/YARA verdict or per-EID |
| **THOR (Nextron)** | JSON-Lines scan output | THOR alert level |
| **Suricata / Zeek** | `eve.json`, Zeek JSON logs; telemetry → IOCs only | Alert priority / notice severity |
| **Cyber Triage** | JSONL / JSON / CSV timeline | Cyber Triage item score |
| **M365 / Entra ID** | UAL, Entra sign-in + audit logs | BEC tradecraft table / Entra riskLevel |
| **AWS CloudTrail** | Records JSON, NDJSON, Athena | API action table (IAM/logging/S3/secrets) |
| **GCP / Azure** | Cloud Audit Logs, Azure Activity Log | Action table (IAM/logging/secrets) |
| **Plaso** | `psort` CSV (dynamic + l2tcsv) | — (Info events) |
| **Sandbox reports** | CAPEv2 `report.json`, Falcon Sandbox summary | Sample verdict + behavioural signatures |
| **CSV** | Velociraptor / EDR exports | — |
| **Generic logs** | Firewall, syslog, VPN; repetitive lines → counted patterns | AI-triaged |

### AI analysis
- **Two-phase** — cheap per-window vision **extraction** → forensic timeline; strong text-only
  **synthesis** → findings, IOCs, MITRE ATT&CK, attacker path, **narrative timeline**, key questions, next steps, threads.
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
- **Ask the case** — free-form Q&A grounded in the full timeline; unknown answers direct you to what artifact to collect and where
- **Response Playbook** — the AI's recommended next steps + Critical/High findings become a trackable checklist (status, priority, assignee, due date, drag-and-drop reorder, custom tasks) with a completion badge; an opt-in **IR templates** toggle expands each Critical/High finding into severity-based response phases (Contain → Investigate → Eradicate → Recover, tailored to the ATT&CK tactic); auto-tasks re-derive on each synthesis but always preserve your progress; survives synthesis and renders into the report
- **Triage tags** — label any entity `confirmed-malicious`, `false-positive`, `key-evidence`, `pivot-point`, etc.; color-coded pills, survive synthesis
- **Analyst comments** — attach notes to any entity; synced live over WebSocket for multi-investigator collaboration
- **Timeline bulk actions** — star, multi-select, bulk-tag, or mark-legitimate in one batched write + re-synthesis
- **IOC bulk actions** — multi-select IOCs (checkbox column + select-all) and, from a bulk toolbar, **enrich** the selection against enabled threat-intel providers, **tag**, **mark legitimate**, or **copy** the values — each as one batched operation (enrichment touches only the selected indicators; mark-legitimate is one re-synthesis, not one per IOC)
- **IOC whitelist** (Settings → IOC Whitelist) — persistent, environment-level known-good patterns (CIDR ranges, exact hashes/values, regex) that **auto-mark matching IOCs legitimate on import** (and on demand); global across cases, import/exportable as CSV or JSON; opt-in by design (whitelisting internal ranges can hide lateral movement)
- **IOC corroboration badges** — each IOC shows a **⊕ N** badge for the number of distinct tools that observed it (the same hash/IP/domain seen by e.g. both THOR and Velociraptor); derived from the events' sources, surfaced in the IOC panel, the report's IOC table, and the IOC CSV export
- **Hunt-pivot generator** — one click from any event or IOC generates ready-to-run queries: Velociraptor VQL, KQL, ES|QL, SPL, Sigma, YARA, and Suricata rules; no AI, runs offline; configurable platform allowlist
- **Velociraptor live hunts** — run a pivot VQL as a fleet hunt across all enrolled endpoints from the dashboard (opt-in, requires API config)
- **Velociraptor triage bundles** (Settings → Velociraptor) — browse the server's collectable artifacts, save named bundles (a "Best Practice" quick-wins sweep ships by default, all editable), run one as a hunt scoped by label/OS + min-severity, then auto-collect (result rows **and** uploaded JSON reports like THOR/Hayabusa) → import → synthesize after a configurable delay; persisted per-case job with a live countdown + "Collect now". Per-artifact tuning: **parameters** (e.g. Hayabusa `RuleLevel`/`RuleStatus`) and **exclude filters** (VQL `WHERE` to drop noise at the source) (opt-in, requires API config)
- **IOC "flagged only" filter** — one click in the IOCs panel hides everything except indicators a threat-intel engine rated **malicious or suspicious**
- **Scope + legitimacy** — set a date/time window; mark findings/IOCs/events as legitimate (reversible); all views re-project deterministically
- **Synthesis & import freshness** — "last synthesized N ago" + what-changed diff; "last import N ago" + new-event/IOC highlights with `NEW` badges

### Threat-intel enrichment (off by default — opt-in per case)
- **Sources** — VirusTotal, Hunting.ch (MalwareBazaar · ThreatFox · URLhaus · YARAify), CrowdStrike Falcon TI, AbuseIPDB, MISP, YETI, RockyRaccoon (Windows process prevalence + anomalous parent/child detection)
- **Local vs external** — MISP/YETI queries stay on-box; third-party sources require an explicit per-case opt-in; enabling a source re-checks every existing IOC against it
- **Reachability gate** — self-hosted instances are health-probed before sending indicators; auto-resumes when back online

### Customer exposure (separate from IOC enrichment)
- **Checks the victim org's own assets** — HIBP, LeakCheck, DeHashed (email breaches), Shodan (exposed hosts/ports/CVEs); per-provider opt-in
- **OPSEC boundary** — only analyst-entered customer domains are queried; adversary/IOC domains are never sent; raw passwords never persisted

### Dashboard & reports
- **Live dashboard** over WebSocket — **collapsible, drag-to-reorder sections** (order + collapse state
  persist per browser), scope bar, clickable evidence links, and badges (`×N` aggregate, `⊕ N sources`,
  `AUTO`, enrichment verdicts, `⚠ unusual parent`).
- **Forensic timeline rows** show the affected **🖥 host** (the event's asset) for fast per-host scanning,
  and the row's **finding references are clickable** — they jump to and flash the finding in the Findings
  section. The report's incident timeline (§3.1) carries a matching **Host** column.
- **Manual add** — a **+ Add event / + Add IOC manually** form on the timeline and IOC sections lets the
  analyst record something the AI didn't catch. Manual events (time, description, severity, optional
  asset/MITRE) are tagged `manual`, re-synthesized into findings, and survive re-analysis; manual IOCs are
  deduped and enriched.
- **MITRE techniques link to [attack.mitre.org](https://attack.mitre.org/)** everywhere they appear
  (findings, timeline, MITRE section, the report, and the IRIS push) — sub-techniques included.
- **Compromised assets + asset↔IoC graph** — events carry the affected **host** (from THOR / CSV /
  screenshots); the dashboard lists compromised hosts/users and draws an interactive **asset ↔ IoC graph**
  (which IoC touched each asset, and per asset all its IoCs) with Host/Account/Service toggles,
  **fullscreen**, **horizontal / vertical / radial** layouts, **zoom** (buttons + mouse-wheel),
  click-a-node-to-focus, and **drag-to-reposition nodes** (manual positions persist per case as "pins"
  on top of the chosen layout; ↺ Reset layout clears them). A *Compromised assets* section also appears
  in the report.
- **Evidence Chain graph (causal: process trees + lateral movement)** — the *how it happened* view to
  complement the *what happened when* timeline. Derived deterministically (no AI) from fields the
  importers already populate: **process trees** (parent→child from `processName`/`parentName`, chained
  through shared `(asset, process)` nodes) and **lateral movement** (same binary **hash** across hosts →
  high confidence; same **account** across hosts → medium — Windows virtual principals like DWM/UMFD/MSI
  filtered out so they don't fake edges), and a **host→tree anchor** that hangs each process tree off its
  host so lateral movement **stitches them into one cross-host attack graph** (`evil.exe` runs on HOST-A →
  moves to HOST-B → spawns there) rather than disconnected islands. Every edge carries **confidence + the
  rule that derived it + its backing events**, so a causal claim is auditable. Dashboard **Evidence Chain** panel (process-tree /
  lateral toggles, confidence legend, layered SVG with arrowheads, zoom, fullscreen, click-to-focus, and
  **drag-to-reposition nodes** — positions persist per case, ↺ Reset layout restores the auto layout) and a
  report **§4.8 Chain of evidence** section. Derived on read (`GET /cases/:id/evidence-graph`).
- **Timeline Swimlane (visual chart)** — the *what happened when, across which assets* view: an
  interactive canvas chart with **assets / severity / tactic** on the Y-axis (Group-by selector; the
  panel subtitle tracks the choice), **time** on the X-axis, and events as **severity-colored dots**.
  Mouse-wheel **zoom** (pinned to the cursor) + **drag-to-pan** + Fit/zoom buttons, **click-a-dot** for a
  detail panel (severity, time, description, MITRE, sources, related findings) that also **jumps to and
  flashes the matching Forensic Timeline row**, and hover tooltips. **Select events** by **Shift-click** or
  **Shift-drag** a box → the selection is **bidirectional with the timeline table** (the same rings ⇄ row
  checkboxes ⇄ bulk-action bars) and feeds a one-click **⚑ Mark Legitimate** batch action; **⌖ Scope to
  view** sets the investigation scope window to the visible time range. **⤢ Fullscreen** (with a CSS
  fallback off secure-context) and **⤓ PNG** export (labels + chart composited) for ad-hoc screenshots; a
  static **Timeline Swimlane** SVG is embedded in the HTML report. Derived on read with the same
  scope/legitimate filtering as the report (`GET /cases/:id/swimlane?groupBy=asset|severity|tactic`).
- **Reports** — Markdown **and HTML** report (standalone, print-friendly), plus a one-click **PDF**
  export that opens the print-styled HTML and triggers the browser's *Save as PDF* dialog (zero
  dependencies, fully offline) + CSVs (findings, IOCs incl. enrichment, capture timeline, forensic
  timeline incl. count/sources) + full JSON state export. All of these — generate report (MD+HTML),
  generate report (PDF), forensic-timeline CSV, Timesketch JSONL, full JSON state — are reachable from
  the dashboard's single **Export** menu.
- **Word (.docx) report export** — download the incident report as a `.docx` for in-Word polish (one-way: edits don't round-trip).
- **AI executive summary** — one click (✨ Generate on the Executive Summary section) produces a
  management-facing, plain-language summary over the synthesized case (no ATT&CK ids / hashes / tool
  names); review it, then save it into the report's Executive Summary (it overrides the auto-derived
  summary). Prompt is customizable like the others (`DFIR_AI_EXEC_PROMPT` / `…_PROMPT_FILE`).
- **Narrative Timeline** — a flowing prose story of the incident generated for management and
  non-technical stakeholders ("At [time], the attacker gained initial access by…"). Generated as
  part of synthesis (stored in `state.narrativeTimeline`, always re-generated with the attacker path);
  a **✨ Generate** button on the dashboard also regenerates it standalone. **✏ Edit** opens an inline
  textarea for analyst refinement before export; edits persist via `PUT /cases/:id/narrative`. Included
  in the report as **§3.2 Narrative timeline** right after the incident-timeline table.
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
- **Export to Notion** — push a case into a [Notion](https://notion.so/) page so investigators can
  collaborate around it (dashboard **Push** menu → **Export to Notion**, or
  `npm run notion:push -- <caseId> --page <urlOrId>`). It asks **new page or existing page**: *new*
  creates the page as a row in a Notion **database** (`DFIR_NOTION_DATABASE_ID` — the ongoing
  investigation template) or under a parent page (`DFIR_NOTION_PARENT_PAGE_ID`); *existing* updates a
  page you paste. The Companion writes **all** its content — summary, findings, timeline, IOCs, MITRE,
  attacker path, key questions, next steps — **inside ONE managed toggle block it owns** on the page.
  A re-export refreshes only that block with the latest case data, so **anything you wrote outside it
  (your own notes, pasted finding screenshots) is never touched**. The target page + managed block are
  remembered per case (`state/notion-export.json`); delete the block and the next export recreates it.
  Configure with `DFIR_NOTION_TOKEN` (share the target page/database with the integration).
- **Push to ClickUp** — export the **Response Playbook** into a [ClickUp](https://clickup.com/) list as
  tasks (dashboard **Push** menu → **Push to ClickUp**). Each task carries its **status** (mapped onto the
  list's own statuses — To do / In progress / Complete; Skipped → Closed), **priority** (critical→Urgent …
  low→Low), **due date**, and assignee/notes. **Re-pushing the same case updates the tasks it created**
  (each playbook task's ClickUp id is remembered in `state/clickup-export.json`) rather than duplicating.
  The list id is asked for in a modal (pre-filled from the last push or `DFIR_CLICKUP_LIST_ID`). Configure
  with `DFIR_CLICKUP_TOKEN`.
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
- **Logging to file (session + per-case audit trail)** — every log line tees to the console **and** to files: a global session log (`logs/session-<time>.log`, beside the cases root, fresh per server start) plus a per-case log (`cases/<id>/logs/session-<time>.log`). `DFIR_LOG_LEVEL` (`debug|info|warn|error`) sets the default, and **Settings → Log verbosity** changes it **live with no restart**; at `debug` the log traces every AI call (which model/phase + token usage), each screenshot captured, the OCR redaction pass, prompt anonymization, and every enrichment lookup
- **Portable Windows EXE** — zip attached to every GitHub Release; unzip + double-click, no Node install required
- **Docker / Docker Compose** — `docker compose up`; evidence on a host volume, no bundled AI backend
- **Customizable AI prompts** — override any of the 6 prompts via env var or file; edits apply without restart (`npm run prompts:eject` to dump defaults)
- **Demo case** — `npm run seed-demo` seeds a fully-populated GlobalTech Industries scenario for local exploration
- **CLI scripts** — `reanalyze`, `synthesize`, `coverage`, `verify:ai`, `clean-timeline` (see below)

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

> **Updating an existing checkout?** After `git pull`, re-run `npm install` in **both**
> `companion/` and `extension/` — new features can add dependencies (e.g. the screenshot
> OCR redaction added `tesseract.js`). Then restart `npm run dev` (server code loads once
> at startup).

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

All companion behavior is configured via env vars (`companion/.env` or shell). Copy `companion/.env.example` to start — it has inline comments for every variable.

### Core

| Variable | Default | Meaning |
|---|---|---|
| `DFIR_CASES_ROOT` | `./cases` | Case folder location; relative paths resolve against `companion/` |
| `DFIR_PORT` | `4773` | Server port (must match the extension and dashboard) |
| `DFIR_HOST` | `127.0.0.1` | Bind interface; Docker image sets `0.0.0.0`, Compose re-maps to localhost on the host |
| `DFIR_MAX_BODY_MB` | `256` | Max upload size in MB; raise if large SIEM/EDR exports fail with HTTP 413 |
| `DFIR_LOG_LEVEL` | `info` | Log verbosity (`debug`/`info`/`warn`/`error`). Tees to console + `logs/session-<time>.log` (global) + `cases/<id>/logs/session-<time>.log` (per-case). `debug` traces AI calls, captures, OCR, anonymization, enrichment. Change live (no restart) via Settings → Log verbosity |
| `DFIR_LOG_DIR` | `logs/` beside cases root | Folder for the **global** session log. Relative paths anchor to `companion/`. Per-case logs always stay in the case folder |

### AI — extraction (required to enable analysis)

| Variable | Default | Meaning |
|---|---|---|
| `DFIR_AI_PROVIDER` | — | `openai` \| `openrouter` \| `ollama` \| `litellm` \| `gemini` \| `anthropic`; unset = capture-only |
| `DFIR_AI_MODEL` | — | Model id (e.g. `gpt-4o-mini`, `gemini-2.5-flash`); **must support vision** for screenshot extraction |
| `DFIR_AI_KEY` | — | Provider API key; leave blank for an auth-less local proxy |
| `DFIR_AI_BASE_URL` | provider default | Override base URL — for a local LiteLLM proxy or any OpenAI-compatible endpoint |
| `DFIR_AI_TIMEOUT_MS` | `180000` | Per-request timeout (ms); raise for strong models on large timelines |
| `DFIR_AI_MAX_TOKENS` | `16000` | Max completion tokens; too low truncates synthesis, prevents OpenRouter 402 on low balance |
| `DFIR_AI_SYNTH_MAX_EVENTS` | `300` | Cap on forensic events sent to synthesis; Critical/High always get a finding regardless |
| `DFIR_AI_CONTEXT_TOKENS` | `128000` | Model context window; raise for Claude/Gemini (200k/1M) to send more per call |
| `DFIR_AI_IMAGE_DETAIL` | `high` | `high` \| `low` \| `auto` (OpenAI/OpenRouter); `high` tiles at full res for small-text OCR |
| `DFIR_AI_AUTO_SYNTHESIZE` | `on` | Re-synthesize during capture: `on` \| `off` |
| `DFIR_AI_AUTO_SYNTHESIZE_MS` | `8000` | Debounce window before auto-synthesis fires (ms) |
| `DFIR_FLUSH_INTERVAL_MS` | `300000` | Safety-net flush of leftover capture buffers (ms); `0` disables |
| `DFIR_ANONYMIZE` | `on` | Tokenize victim IPs/hosts/users/paths before AI calls: `on` \| `off` |

### AI — synthesis (two-tier, optional)

If unset, synthesis reuses the extraction model. Recommended: cheap vision model for extraction, strong text model for synthesis.

| Variable | Default | Meaning |
|---|---|---|
| `DFIR_AI_SYNTH_PROVIDER` | = `DFIR_AI_PROVIDER` | Provider for the one-call synthesis pass |
| `DFIR_AI_SYNTH_MODEL` | = `DFIR_AI_MODEL` | Synthesis model id (e.g. `gpt-4o`, `gemini-2.5-pro`, `claude-sonnet-4-6`) |
| `DFIR_AI_SYNTH_KEY` | = `DFIR_AI_KEY` | Synthesis API key |
| `DFIR_AI_SYNTH_BASE_URL` | = `DFIR_AI_BASE_URL` | Synthesis base URL |

### AI — custom prompts (optional)

Each prompt has two override forms (priority order): `DFIR_AI_<NAME>_PROMPT` (inline text, read at startup) and `DFIR_AI_<NAME>_PROMPT_FILE` (path to file, re-read each call — edit and it applies immediately). `npm run prompts:eject` writes the built-in defaults as a starting point.

| Prompt name | `<NAME>` token |
|---|---|
| Per-screenshot extraction | `SYSTEM` |
| CSV import triage | `CSV` |
| Log import triage | `LOG` |
| Holistic synthesis | `SYNTH` |
| Case Q&A | `ASK` |
| Executive summary | `EXEC` |

### Threat-intel enrichment (optional — off by default)

Add a key to enable that provider. All external providers are opt-in per case from the dashboard.

| Variable | Default | Meaning |
|---|---|---|
| `DFIR_VT_KEY` | — | VirusTotal API key (hash / IP / domain / URL) |
| `DFIR_HUNTINGCH_KEY` | — | abuse.ch Auth-Key for Hunting.ch (MalwareBazaar · ThreatFox · URLhaus · YARAify); falls back to `DFIR_MB_KEY` |
| `DFIR_MB_KEY` | — | Legacy abuse.ch key — powers Hunting.ch; prefer `DFIR_HUNTINGCH_KEY` |
| `DFIR_ABUSEIPDB_KEY` | — | AbuseIPDB API key (IP reputation) |
| `DFIR_CROWDSTRIKE_CLIENT_ID` | — | CrowdStrike Falcon TI OAuth2 client ID |
| `DFIR_CROWDSTRIKE_CLIENT_SECRET` | — | CrowdStrike OAuth2 secret (needs *Indicators: Read* + *MalQuery: Read*) |
| `DFIR_CROWDSTRIKE_CLOUD` | `us-1` | Tenant cloud: `us-1` \| `us-2` \| `eu-1` \| `gov-us-1` \| `gov-us-2` |
| `DFIR_CROWDSTRIKE_BASE_URL` | from cloud | Explicit API base URL (overrides `DFIR_CROWDSTRIKE_CLOUD`) |
| `DFIR_ROCKYRACCOON_KEY` | — | RockyRaccoon key for Windows process prevalence / LOLBIN / ATT&CK |
| `DFIR_MISP_URL` | — | MISP instance URL — both URL + key required for enrichment and push |
| `DFIR_MISP_KEY` | — | MISP API auth key |
| `DFIR_MISP_CA` | — | PEM CA bundle for internal-CA MISP (verification stays on) |
| `DFIR_MISP_INSECURE` | — | `=1` to skip TLS verification (lab only) |
| `DFIR_MISP_DISTRIBUTION` | `0` | New event distribution: `0`=org, `1`=community, `2`=connected, `3`=all |
| `DFIR_MISP_ANALYSIS` | `1` | New event analysis state: `0`=initial, `1`=ongoing, `2`=complete |
| `DFIR_YETI_URL` | — | YETI instance URL — both URL + key required |
| `DFIR_YETI_KEY` | — | YETI API key |
| `DFIR_YETI_CA` | — | PEM CA bundle for internal-CA YETI |
| `DFIR_YETI_INSECURE` | — | `=1` to skip TLS verification (lab only) |
| `DFIR_ENRICH_DELAY_MS` | `1500` | Throttle between lookups (ms) |
| `DFIR_ENRICH_MAX` | `100` | Max IOCs per enrich run |
| `DFIR_ENRICH_HEALTH_TTL_MS` | `60000` | Cache up/down verdict for self-hosted providers (ms) |
| `DFIR_ENRICH_HEALTH_POLL_MS` | `60000` | Re-probe interval for down providers; `0` disables background poller |

### Customer exposure (optional)

Checks the **victim org's own** domains/emails against breach databases — never adversary/IOC domains.

| Variable | Default | Meaning |
|---|---|---|
| `DFIR_HIBP_KEY` | — | Have I Been Pwned API key |
| `DFIR_HIBP_USER_AGENT` | `DFIR Companion` | HIBP User-Agent header |
| `DFIR_LEAKCHECK_KEY` | — | LeakCheck Pro API key |
| `DFIR_LEAKCHECK_DOMAIN_LIMIT` | `1000` | Max records per domain search |
| `DFIR_DEHASHED_KEY` | — | DeHashed v2 API key |
| `DFIR_DEHASHED_BASE_URL` | DeHashed default | Override DeHashed API base URL |
| `DFIR_SHODAN_KEY` | — | Shodan key (domain → exposed hosts / ports / CVEs; no email lookup) |
| `DFIR_EXPOSURE_DELAY_MS` | `1500` | Throttle between provider lookups (ms) |

### DFIR-IRIS push (optional)

Both URL and key are required to enable.

| Variable | Default | Meaning |
|---|---|---|
| `DFIR_IRIS_URL` | — | IRIS instance URL |
| `DFIR_IRIS_KEY` | — | IRIS API key |
| `DFIR_IRIS_CA` | — | PEM CA bundle for internal-CA IRIS |
| `DFIR_IRIS_INSECURE` | — | `=1` to skip TLS verification (lab only) |
| `DFIR_IRIS_CUSTOMER_ID` | `1` | Customer id for new IRIS cases |
| `DFIR_IRIS_CLASSIFICATION_ID` | `1` | Classification id for new IRIS cases |

### Timesketch push (optional)

URL + user + password all required to enable push. Export to JSONL works without any config.

| Variable | Default | Meaning |
|---|---|---|
| `DFIR_TIMESKETCH_URL` | — | Timesketch instance URL |
| `DFIR_TIMESKETCH_USER` | — | Local-auth username |
| `DFIR_TIMESKETCH_PASSWORD` | — | Local-auth password |
| `DFIR_TIMESKETCH_TIMELINE` | `DFIR Companion timeline` | Managed timeline name |
| `DFIR_TIMESKETCH_CA` | — | PEM CA bundle for internal-CA Timesketch |
| `DFIR_TIMESKETCH_INSECURE` | — | `=1` to skip TLS verification (lab only) |

### Notion export (optional)

Token alone enables it. Share the target page/database with the integration. "New page" needs a
database or parent page (env default or entered per export); "existing page" updates a page you paste.

| Variable | Default | Meaning |
|---|---|---|
| `DFIR_NOTION_TOKEN` | — | Internal-integration secret (Notion: Settings → Connections → develop your own) |
| `DFIR_NOTION_DATABASE_ID` | — | Default database for "new page" exports (the investigation template) |
| `DFIR_NOTION_PARENT_PAGE_ID` | — | Alternative default: create the new page under this parent page |
| `DFIR_NOTION_CONTAINER_TITLE` | `🔍 DFIR Companion — Auto-generated` | Title of the managed block the Companion owns |
| `DFIR_NOTION_MAX_TIMELINE` | `500` | Max timeline rows written to Notion |
| `DFIR_NOTION_CA` | — | PEM CA bundle if a proxy uses an internal CA |
| `DFIR_NOTION_INSECURE` | — | `=1` to skip TLS verification (lab only) |

### Velociraptor live hunts + triage bundles (optional)

Set `DFIR_VELOCIRAPTOR_API_CONFIG` to enable. Generate the config once with:
```
velociraptor --config server.config.yaml config api_client --name dfir --role administrator,api api.config.yaml
```

| Variable | Default | Meaning |
|---|---|---|
| `DFIR_VELOCIRAPTOR_API_CONFIG` | — | Path to `api_client` config file |
| `DFIR_VELOCIRAPTOR_BINARY` | `velociraptor` | Executable path (full `.exe` path on Windows) |
| `DFIR_VELOCIRAPTOR_GUI_URL` | — | GUI base URL for deep-linking to launched hunts |
| `DFIR_VELOCIRAPTOR_ORG` | `root` | Org for the deep link's `?org_id=` (the GUI requires it, before the `#` fragment) |
| `DFIR_VELOCIRAPTOR_TIMEOUT_MS` | `60000` | Per-query timeout (ms) |
| `DFIR_VELOCIRAPTOR_MAX_ROWS` | `1000` | Max rows returned to the dashboard |
| `DFIR_VELOCIRAPTOR_MAX_OUTPUT` | `52428800` | Hard cap on interactive query output bytes (50 MB) |
| `DFIR_VELOCIRAPTOR_COLLECT_MAX_OUTPUT` | `268435456` | Larger cap for **bundle-hunt collection** (rows + uploaded JSON; THOR/Hayabusa are big). An artifact/upload over this is skipped (logged), not fatal — the rest still import. |
| `DFIR_VELO_HUNT_WAIT_MIN` | `10` | Default minutes before a **triage bundle** hunt auto-collects (per-run + per-bundle override; clamped 1–1440) |
| `DFIR_VELOCIRAPTOR_UPLOAD_VQL` | — | Advanced: override the VQL that reads a hunt's uploaded JSON reports (version-sensitive; keep the `__HUNT_ID__` placeholder) |

**Triage bundles** (**Settings → Velociraptor** tab): *Browse server artifacts* lists the server's collectable
`CLIENT` artifacts; assemble + save named **bundles** (a single **Best Practice** quick-wins sweep ships by
default, stored globally next to `cases/` in `bundles/`). **Every bundle, built-ins included, is editable in
place** — an edit saves an override; **Reset to default** discards it. **Run** one as a hunt (optionally scoped
by include/exclude labels + OS, and a **minimum-severity** import floor). The **collection timeout** is a bundle
setting (configured in the editor — bump it for slow artifacts like THOR; Velociraptor's default is 600 s) and is
applied automatically on every run. Bundles can also carry **per-artifact parameters** (passed to the hunt's
`spec`) so a heavy artifact emits less at the source — Best Practice ships **Hayabusa pinned to `RuleLevel`=Critical/High/Medium
+ `RuleStatus`=Stable+Experimental** so it doesn't flood the import; tune any artifact via the builder's optional *Advanced → parameters* JSON,
and drop noisy rows with per-artifact **exclude filters** (VQL `WHERE`, e.g. `NOT OSPath =~ 'pagefile'`). The hunt stays open until expiry, so
the Companion **auto-collects** after `DFIR_VELO_HUNT_WAIT_MIN` and ingests **both** the result rows **and any
uploaded JSON report** (e.g. THOR/Hayabusa via `Generic.Scanner.ThorZIP` — for those the rows don't matter, the
uploaded JSON does; it's auto-detected and routed to the right importer), then synthesizes — or click **Collect
now** on the live job card to pull early. The in-flight job persists per case (`state/velo-hunt.json`) and
survives a server restart; results appear on the dashboard timeline/IOCs.

### Analysis tuning

| Variable | Default | Meaning |
|---|---|---|
| `DFIR_HUNT_PLATFORMS` | all | Comma-separated platform allowlist for hunt-pivot cards: `velociraptor`, `defender`, `elastic`, `splunk`, `sigma`, `yara`, `suricata` |
| `DFIR_CORRELATE_WINDOW_S` | `2` | Time window (s) for same-path cross-source event merge |
| `DFIR_PHASE_GAP_S` | `300` | Gap between events (s) that starts a new attack phase |
| `DFIR_DEDUP` | `on` | Skip AI analysis of a screenshot that's the same frame as the previous one (still stored as evidence). Set `off` to analyze **every** screenshot |
| `DFIR_DEDUP_THRESHOLD` | `10` | Max perceptual-hash distance (512-bit dual dHash) for consecutive captures to count as the same frame; lower = stricter (fewer skipped as duplicates) |

Example `.env` (two-tier OpenRouter setup):

```
DFIR_AI_PROVIDER=openrouter
DFIR_AI_MODEL=openai/gpt-4o-mini          # cheap extraction (per screenshot)
DFIR_AI_KEY=sk-or-...
DFIR_AI_SYNTH_MODEL=google/gemini-2.5-pro # strong synthesis (one call)
DFIR_AI_IMAGE_DETAIL=high
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

## Roadmap

Planned work and ideas are tracked as **[GitHub Issues](https://github.com/hasamba/DFIR-Companion/issues?q=is%3Aissue%20state%3Aopen%20label%3Aenhancement)** under the `enhancement` label.

## Tests

```
cd companion && npm test     # server unit tests
cd extension && npm test     # extension unit tests
```

## Disclaimer

DFIR Companion is provided **"as is", without warranty of any kind**, whether express or
implied, including but not limited to the warranties of merchantability, fitness for a
particular purpose, accuracy, and non-infringement.

It is an **analysis aid, not an authority.** Its output — the forensic timeline, findings,
severities, IOCs, attacker-path narrative, reports, and any AI-generated conclusions — may be
**incomplete, inaccurate, or misleading.** In particular, it may **overstate results** (false
positives or inflated severity) or **miss incidents, events, or indicators entirely** (false
negatives). All output must be **independently reviewed and verified by a qualified investigator**
before it is relied upon, acted on, or included in any deliverable.

To the maximum extent permitted by applicable law, **the author and contributors accept no
liability** for any direct, indirect, incidental, consequential, or other damages, or for any
decision, action, or omission arising from the use of — or inability to use — this software or its
output, **including but not limited to overstated results or missed incidents.** You use the
software **at your own risk** and remain solely responsible for your investigation, your
conclusions, and your compliance with all applicable laws and authorizations.

## License

DFIR Companion is free software, licensed under the **GNU Affero General Public License v3.0**
(`AGPL-3.0-only`). See [`LICENSE`](LICENSE) for the full text.

Copyright © 2026 Yaniv Radunsky.

In short: you're free to use, study, modify, and share it — but if you distribute a modified
version **or run a modified version as a network service**, you must make your complete source
code available to its users under the same license. (This is the DFIR-tooling norm — Velociraptor,
MISP, and TheHive are AGPL too.)

