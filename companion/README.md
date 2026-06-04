# DFIR Companion

Localhost server that ingests browser screenshots as forensic evidence, runs
windowed AI analysis into an accumulating investigation state, reconstructs a
**forensic timeline** (real event timestamps) and **attacker path**, and serves a
live dashboard. Paired with the MV3 capture extension in `../extension`.

## Quick start

    cd companion
    npm install
    cp .env.example .env        # then edit .env (cases root, AI provider/model/key)
    npm run dev

Server listens on **http://127.0.0.1:4773** (localhost only). Dashboard at
http://127.0.0.1:4773/dashboard. On startup it logs the resolved cases root, e.g.
`[DFIR] cases root: ...\cases`.

> If you see `EADDRINUSE`, a companion is already running. Reuse it, or free the port:
> `Get-NetTCPConnection -LocalPort 4773 -State Listen | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force }`

## Configuration (`companion/.env`, gitignored)

| Variable | Meaning | Example |
| --- | --- | --- |
| `DFIR_CASES_ROOT` | Where case folders are written. Relative paths resolve against `companion/`, so the same folder is used no matter where you launch from. | `./cases` or `../cases` |
| `DFIR_PORT` | Port the localhost server binds to. Default `4773`. Must be 1–65535; invalid values fall back to the default with a warning. Change this if 4773 is taken, or to run multiple companions side-by-side. The extension and dashboard must use the same port. | `4773` or `4774` |
| `DFIR_AI_PROVIDER` | `openai` \| `openrouter` \| `ollama` \| `gemini`. Leave **unset** to run capture-only (no AI). | `openrouter` |
| `DFIR_AI_MODEL` | Model id understood by the provider. | `google/gemini-2.0-flash-001` |
| `DFIR_AI_KEY` | Provider API key. | `sk-...` |
| `DFIR_AI_IMAGE_DETAIL` | `high` \| `low` \| `auto` (default `high`). High tiles screenshots at full resolution for accurate small-text OCR (OpenAI/OpenRouter models). | `high` |
| `DFIR_AI_SYNTH_PROVIDER` / `DFIR_AI_SYNTH_MODEL` / `DFIR_AI_SYNTH_KEY` | Optional **synthesis** model (findings / MITRE / attacker path). The vars above are the cheap per-screenshot **extraction** model; point a stronger model here for the one text-only synthesis call. Unset → reuses the extraction model. | `google/gemini-2.5-pro` |

Other AI tunables: `DFIR_AI_TIMEOUT_MS` (per-request timeout, default 180000),
`DFIR_AI_MAX_TOKENS` (max completion tokens, default 8192 — also stops OpenRouter from
402-ing a large request by over-reserving credit), and `DFIR_AI_SYNTH_MAX_EVENTS`
(events fed to the synthesis prompt, default 300, most-severe first).

Shell environment variables override `.env`. `GET /health` returns `{ aiEnabled }`
so you can confirm whether an AI provider is configured.

## npm scripts

| Command | What it does |
| --- | --- |
| `npm run dev` | Start the server (reads `.env`). |
| `npm run build` | Type-check / compile with `tsc`. |
| `npm test` | Run the full vitest suite. |
| `npm run verify:ai -- [caseId]` | One-call smoke test: confirms the configured model returns schema-valid JSON and prints findings / forensic events / attacker path. Samples screenshots from the middle of the case (default `test1`). |
| `npm run coverage -- [caseId]` | Reports how many of a case's screenshots were actually analyzed vs. skipped (duplicates) vs. never analyzed. |
| `npm run reanalyze -- <caseId> [flags]` | Re-run AI analysis over already-captured screenshots, rebuilding the investigation state, then synthesize conclusions. See flags below. |
| `npm run synthesize -- <caseId>` | Holistic pass: read the full forensic timeline and derive findings, MITRE mapping, and the attacker-path narrative. One text-only AI call. Accepts `--provider`/`--model`/`--key` overrides. |
| `npm run clean-timeline -- <caseId> [--apply]` | Remove analyst/tool-usage entries (Velociraptor hunts, notebooks, searches, "Response and Monitoring accessed") that don't belong in the forensic timeline. No AI calls. Dry-run preview by default; `--apply` saves. |

### `reanalyze` flags

| Flag | Effect | Default |
| --- | --- | --- |
| `<caseId>` | Case to process (first positional arg). | `test1` |
| `--reset` | Start from an empty state before analyzing (otherwise merges into existing). | off |
| `--all` | Include duplicate screenshots too (most thorough; more API calls). Otherwise only non-duplicates. | off |
| `--window N` | Screenshots per AI call. | `4` |
| `--provider NAME` | Override `DFIR_AI_PROVIDER` (extraction model) for this run. | from `.env` |
| `--model ID` | Override `DFIR_AI_MODEL` (extraction model) for this run. | from `.env` |
| `--key KEY` | Override `DFIR_AI_KEY` for this run. | from `.env` |
| `--synth-model ID` | Use a **different (stronger) model for the synthesis pass** — findings / MITRE / attacker path. Per-screenshot extraction still uses `--model`. | = extraction model |
| `--synth-provider NAME` / `--synth-key KEY` | Provider/key for the synthesis model (if different). | = extraction provider/key |
| `--no-synthesis` | Skip the final synthesis pass (raw forensic timeline only, no findings/attacker path). | off |

Examples:

    npm run coverage -- test1
    npm run reanalyze -- test1 --reset                       # re-do all unique screenshots, fresh
    npm run reanalyze -- test1 --all --reset                 # include duplicates too
    npm run reanalyze -- test1 --reset --model openai/gpt-4o # try a different model
    # Two-tier (recommended): cheap model reads every screenshot, strong model writes conclusions
    npm run reanalyze -- test1 --reset --model openai/gpt-4o-mini --synth-model openai/gpt-4o

> `reanalyze` uses your API quota (~1 call per `--window` screenshots).

## HTTP endpoints

| Method & path | Purpose |
| --- | --- |
| `GET /health` | Reachability + `{ ok, aiEnabled }`. |
| `POST /cases` | Create a case: `{ caseId, name, investigator, aiProvider }`. |
| `POST /captures` | Ingest a screenshot: `{ caseId, timestamp, url, tabTitle, triggerType, imageBase64 }`. |
| `POST /cases/:id/import-csv` | Import a CSV result export (e.g. a Velociraptor artifact): `{ filename, csv }`. Persists the raw CSV as evidence, extracts dated forensic events + IOCs from the rows, then synthesizes. Returns `202 { accepted, file, rows }`; progress streams over the WS. The dashboard's **Import CSV** button calls this. |
| `POST /cases/:id/import-thor` | Import a **THOR (Nextron) scanner report** in JSON-Lines format (`thor --jsonfile`): `{ filename, json, minLevel? }`. Optional `minLevel` is a severity floor — `"alert"` (only Alerts), `"warning"` (Alerts+Warnings), or `"notice"` (all, default) — so you can cut volume (the dashboard prompts for it). Persists the raw report as evidence, then maps findings **deterministically** (no AI extraction) to the timeline + IOCs — `level` → severity (Alert→Critical, Warning→High, Notice→Medium), reading each finding's own artifact time, pulling hashes/files/processes/IPs as IOCs, and collapsing identical findings. **Scan noise is dropped by default**: `level:"Info"` rows and lifecycle modules (`Init`, `Startup`, `Control`, `ThorDB`, `Report`). Then synthesizes. Returns `202 { accepted, file, findings, dropped, total }`. The dashboard's **Import THOR** button calls this. |
| `POST /cases/:id/import-log` | Import a generic log file (firewall — Cisco ASA, pfSense, iptables, Palo Alto, Fortinet; syslog; sshd / auth.log; IIS / Apache / nginx access; Windows event-log text exports; VPN/IKE; application logs — anything line-oriented, typically `.log` or `.txt`): `{ filename, text }`. Persists the raw file as evidence, then **deduplicates** the lines into counted patterns and asks the AI to triage them, adding **only security-relevant** events to the timeline (routine noise like VPN rekeying/retransmissions is skipped). Repeated activity is **collapsed into one aggregated event** carrying an occurrence `count` and first→last time span (e.g. "20 failed logins…"). Any timestamp format is read (ISO-8601, RFC 3164 syslog, Apache, IIS, epoch…). Returns `202 { accepted, file, lines }`; progress streams over the WS. The dashboard's **Import Log** button calls this. |
| `GET /cases/:id/state` | Current investigation state (JSON). |
| `GET /cases/:id/evidence/:file` | Serve a piece of evidence (a screenshot or an imported CSV) by filename. Sandboxed to the case's `screenshots/` and `imports/` dirs (no path separators or `..`). The dashboard links findings/events to this so a click opens the artifact. |
| `GET /cases/:id/captures/count` | Number of captures recorded for the case. |
| `GET /cases/:id/scope` | Current investigation time-window: `{ start, end }` (ISO or null). |
| `POST /cases/:id/scope` | `{ start, end }` — set the window; re-synthesizes using only in-scope events. The dashboard's scope bar calls this. |
| `GET /cases/:id/legitimate` | List client-confirmed legitimate findings/IOCs/events (excluded from analysis). |
| `POST /cases/:id/legitimate` | `{ kind: "finding"\|"ioc"\|"event", ref, note, label? }` — mark a finding (ref = title), IOC (ref = value), or **forensic event** (ref = event id; `label` = its description for display) legitimate; re-runs synthesis without it. The dashboard's per-item **⚑ mark legitimate** button calls this. Legit **events** are hidden from the timeline and excluded from synthesis input but the raw event is preserved in state, so un-marking restores it. |
| `POST /cases/:id/legitimate/remove` | `{ id }` — un-mark; re-runs synthesis. |
| `GET /cases/:id/ai-control` | Current AI on/off state: `{ enabled, lastAnalyzedSeq }`. |
| `POST /cases/:id/ai-control` | `{ enabled }` — turn AI analysis on/off for the case. Evidence is always captured; when off, no AI runs. Turning it **on** backfills every screenshot captured while it was off. The dashboard's **AI: ON/OFF** button calls this. |
| `GET /cases/:id/enrich-control` | Threat-intel enrichment toggle state: `{ enabled, available, providers }`. |
| `POST /cases/:id/enrich-control` | `{ enabled }` — turn enrichment **on/off** for the case (default **off** for OPSEC). Turning it **on** enriches the IOCs already in the list AND auto-enriches IOCs added later (imports/synthesis). The dashboard's **Enrich: ON/OFF** toggle calls this. Stored in `state/enrich-control.json`. |
| `POST /cases/:id/enrich` | Manual one-shot IOC enrichment (does not change the toggle). Looks up the case's IOCs (hashes/IPs/domains/URLs) on the configured providers — **VirusTotal** (`DFIR_VT_KEY`), **MalwareBazaar** (`DFIR_MB_KEY`), **AbuseIPDB** (`DFIR_ABUSEIPDB_KEY`), **MISP** (`DFIR_MISP_URL` + `DFIR_MISP_KEY`), **RockyRaccoon** (`DFIR_ROCKYRACCOON_KEY`, **process** names — prevalence / LOLBIN / risk / expected parent / ATT&CK) — and annotates each with a verdict/score/link. Cached on the IOC (skips already-enriched unless `{ force: true }`); throttled (`DFIR_ENRICH_DELAY_MS`) and capped (`DFIR_ENRICH_MAX`, hashes/IPs first). `501` if no provider key is set. **⚠ OPSEC: sends indicators to third-party services.** |
| `POST /cases/:id/synthesize` | Run the synthesis pass (findings / MITRE / attacker path) from the forensic timeline; pushes the update to the dashboard. The dashboard's **Synthesize** button calls this. |
| `POST /cases/:id/report` | Write report files; returns their paths. |
| `GET /dashboard` | Live dashboard page. |
| `WS /ws?caseId=<id>` | Live state + AI-status push for the dashboard. |

CORS (incl. Private Network Access) is enabled so the browser extension can reach
the server from a `chrome-extension://` origin.

## Case folder layout

    cases/<caseId>/
      case.json
      screenshots/000001_<ts>_<tab-title>.webp   evidence (raw screenshots; title is slugified — OS-reserved chars stripped, capped at 60 chars; falls back to 000001_<ts>.webp when the title has no safe characters)
      imports/0001_<name>.csv             evidence (raw uploaded CSV / log / THOR JSON result exports)
      imports/0002_<name>.log             evidence (raw uploaded log files — firewall, syslog, sshd, IIS/Apache/nginx, app logs)
      metadata/captures.jsonl             append-only audit trail
      metadata/imports.jsonl              append-only import audit trail (CSV + log + THOR uploads share the same sequence)
      state/
        investigation.json                accumulating findings/timeline/forensic events
        pending_analysis.json             written if an analysis window fails (auto-cleared on success)
      reports/                            written by POST /cases/:id/report
        report.md                         Executive Summary, Attacker Path, Forensic Timeline,
                                          Findings, Investigation Log, MITRE ATT&CK
        findings.csv / iocs.csv
        timeline.csv                      capture/analysis order
        forensic-timeline.csv             real incident events, sorted by event time
        state-export.json

## How analysis works (two phases)

1. **Per-window extraction.** Non-duplicate captures are buffered per case and
   flushed to the AI when the window fills (default 4) or on a significant trigger
   (navigation / tab switch). Each window is merged into the persistent state by id
   (revisiting a topic updates, never duplicates). This phase is good at pulling
   **dated forensic events** out of the artifacts into the forensic timeline.
2. **Holistic synthesis.** Findings, MITRE mapping, and the attacker-path narrative
   need the *whole* timeline at once — a single window can't see it. So a synthesis
   pass reads the full forensic timeline and produces those conclusions. It runs
   automatically at the end of `reanalyze` (skip with `--no-synthesis`), and you can
   re-run it any time — including with a different model — via `npm run synthesize`.

**Investigation scope (time window).** The evidence often includes earlier, unrelated
activity. Set a **from/to** window in the dashboard's scope bar — synthesis then re-runs
using only in-scope forensic events, so findings, IOCs, attacker path, key questions, the
timeline view, and the report all reflect only that window. The raw events are preserved
(stored in `state/scope.json`), so widening or clearing the window restores them. Because
synthesis is an authoritative reassessment, it now **replaces** the analytic layer each run
rather than accumulating — so out-of-scope (or removed) conclusions drop cleanly.

**Confirmed-legitimate items (false positives).** When the client confirms an alert,
tool, IOC, or a specific forensic-timeline event was their own benign activity, click
**⚑ mark legitimate** on that finding / IOC / **event** in the dashboard (add a reason).
It's stored per case (`state/legitimate.json`), synthesis is re-run **excluding it**, and
it's listed in the "Confirmed Legitimate (excluded from analysis)" panel where you can
un-mark it. Findings/IOCs are dropped via both the prompt and a hard post-filter.
A legitimate **event** is hidden from the timeline view and excluded from the synthesis
input — but the raw event stays in state (it's evidence), so un-marking fully restores
it. Reports honor all of these exclusions too.

**Log import (firewall / syslog / VPN / access logs).** Log files are mostly
repetition, so importing one does **not** add a timeline row per line. The raw lines
are first **deduplicated deterministically** into distinct patterns (volatile tokens —
sequence numbers, IDs, ports, the trailing `_N` of identifiers — are masked; source IP
addresses are kept), each with an occurrence count and first/last time. The AI then
**triages the patterns** and adds timeline events only for the **security-relevant**
ones (auth failures / brute force, blocked traffic, scans, IDS/IPS hits, config/account
changes, beaconing/exfil, abnormal failure volume). Routine operational noise — VPN/IPsec
rekeying, IKE retransmissions, heartbeats, successful benign connections — is **skipped**,
even at high volume. Each emitted event is an **aggregate**: it carries a `count` and a
first→last span and reads like "20 failed SSH logins for root from 1.2.3.4 between …".
The dashboard shows a `×N` badge; reports include `count`/`endTimestamp` columns. A pure
operational log can legitimately yield **zero** timeline events — that's the correct,
signal-first outcome. (To re-process a log you imported before this behavior existed,
`npm run reanalyze -- <case> --reset` to clear the old per-line events, then re-upload the
log file from the dashboard.)

**High-severity rows become findings.** If an artifact row carries its own
Severity / Level / Criticality column reading **Critical**, **High**, or **Severe**
(e.g. a Microsoft Defender or EDR detection), it is treated as a finding by default —
the extraction and synthesis prompts are told a high-severity row is ~90% of the time a
finding. As a deterministic safety net, after each synthesis any in-scope, non-legitimate
**Critical/High** forensic event that synthesis left without a finding gets one
auto-created and linked (id prefix `f-auto-`, badged **AUTO** in the dashboard) so a
severe detection can never be silently missed. Refine or mark it legitimate as needed.

**Capture-only mode.** The dashboard's **AI: ON/OFF** button (per case) lets you
capture screenshots as evidence without running AI. When you switch it back on, the
server automatically analyzes everything captured while it was off (tracked by
`lastAnalyzedSeq` in `state/ai-control.json`), then synthesizes.

**Live capture and conclusions.** While you browse, the per-window extraction builds
the forensic timeline + investigation log. Findings, MITRE and the attacker path come
from the synthesis pass, which by default now runs **automatically and debounced**
during live capture (`DFIR_AI_AUTO_SYNTHESIZE=on`, ~8 s after the last screenshot in a
burst) and pushes updates to the dashboard. You can also trigger it manually with the
dashboard **Synthesize** button, `POST /cases/:id/synthesize`, or `npm run synthesize`.
Set `DFIR_AI_AUTO_SYNTHESIZE=off` (or raise `DFIR_AI_AUTO_SYNTHESIZE_MS`) to reduce
cost. After changing server code, **restart `npm run dev`** so the live pipeline picks
up the new prompts.

**Two-tier model strategy (cost-effective).** Per-screenshot extraction is the
high-volume part (one AI call per few screenshots) — use a cheap vision model there.
Synthesis is a single text-only call over the whole timeline — point a stronger model
at just that. Configure it once in `.env`:

    DFIR_AI_MODEL=openai/gpt-4o-mini          # extraction (cheap, reads every screenshot)
    DFIR_AI_SYNTH_MODEL=google/gemini-2.5-pro # synthesis (strong, one text-only call)

…then just `npm run reanalyze -- <caseId> --reset`. Or set it ad-hoc on the CLI
(overrides `.env`):

    npm run reanalyze -- <caseId> --reset --model openai/gpt-4o-mini --synth-model google/gemini-2.5-pro

Duplicates (by perceptual hash) are still stored as evidence but skipped by the AI —
use `reanalyze --all` to force them in.

The **forensic timeline** holds real incident events (host/attacker activity recorded
in the artifacts: executions, logons, file/registry/network changes) with their true
event timestamps. It is NOT the analyst's work log — the act of operating Velociraptor
(creating hunts, opening notebooks, running searches, "Response and Monitoring
accessed") belongs in the Investigation Log, not here. The prompts exclude tool-usage
events; for timelines built before that fix, `npm run clean-timeline` strips them.

### Text readability / OCR accuracy

Screenshots are captured **lossless** (PNG) at the browser's full viewport resolution
(typically ~2550px wide) — capture quality is not the bottleneck. Misread usernames,
hostnames and domains usually come from (1) the vision model downscaling large images,
and (2) model OCR strength. Mitigations:

- `DFIR_AI_IMAGE_DETAIL=high` (default) tiles images at full resolution for OpenAI/
  OpenRouter models instead of downscaling — the biggest single accuracy win.
- Use a stronger vision model for text-heavy forensic screenshots, e.g.
  `openai/gpt-4o` or `google/gemini-2.5-pro` rather than a fast/cheap flash model.
  Compare cheaply on the existing timeline without re-capturing:
  `npm run synthesize -- <caseId> --model openai/gpt-4o`
- Zoom the page in the browser (Ctrl +) before/while capturing so source text is larger.

Recommended recovery flow for a case that has screenshots but weak/empty analysis:

    npm run reanalyze -- <caseId> --reset      # rebuild timeline + synthesize conclusions
    # or, if the forensic timeline already looks good and you only want conclusions:
    npm run synthesize -- <caseId>             # one cheap call; try --model to compare
