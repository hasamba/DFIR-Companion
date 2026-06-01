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
| `DFIR_AI_PROVIDER` | `openai` \| `openrouter` \| `ollama` \| `gemini`. Leave **unset** to run capture-only (no AI). | `openrouter` |
| `DFIR_AI_MODEL` | Model id understood by the provider. | `google/gemini-2.0-flash-001` |
| `DFIR_AI_KEY` | Provider API key. | `sk-...` |

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
| `npm run reanalyze -- <caseId> [flags]` | Re-run AI analysis over already-captured screenshots, rebuilding the investigation state. See flags below. |

### `reanalyze` flags

| Flag | Effect | Default |
| --- | --- | --- |
| `<caseId>` | Case to process (first positional arg). | `test1` |
| `--reset` | Start from an empty state before analyzing (otherwise merges into existing). | off |
| `--all` | Include duplicate screenshots too (most thorough; more API calls). Otherwise only non-duplicates. | off |
| `--window N` | Screenshots per AI call. | `4` |
| `--provider NAME` | Override `DFIR_AI_PROVIDER` for this run. | from `.env` |
| `--model ID` | Override `DFIR_AI_MODEL` for this run. | from `.env` |
| `--key KEY` | Override `DFIR_AI_KEY` for this run. | from `.env` |

Examples:

    npm run coverage -- test1
    npm run reanalyze -- test1 --reset                       # re-do all unique screenshots, fresh
    npm run reanalyze -- test1 --all --reset                 # include duplicates too
    npm run reanalyze -- test1 --reset --model openai/gpt-4o # try a different model
    npm run reanalyze -- test1 --provider gemini --model gemini-1.5-pro --key <key>

> `reanalyze` uses your API quota (~1 call per `--window` screenshots).

## HTTP endpoints

| Method & path | Purpose |
| --- | --- |
| `GET /health` | Reachability + `{ ok, aiEnabled }`. |
| `POST /cases` | Create a case: `{ caseId, name, investigator, aiProvider }`. |
| `POST /captures` | Ingest a screenshot: `{ caseId, timestamp, url, tabTitle, triggerType, imageBase64 }`. |
| `GET /cases/:id/state` | Current investigation state (JSON). |
| `GET /cases/:id/captures/count` | Number of captures recorded for the case. |
| `POST /cases/:id/report` | Write report files; returns their paths. |
| `GET /dashboard` | Live dashboard page. |
| `WS /ws?caseId=<id>` | Live state + AI-status push for the dashboard. |

CORS (incl. Private Network Access) is enabled so the browser extension can reach
the server from a `chrome-extension://` origin.

## Case folder layout

    cases/<caseId>/
      case.json
      screenshots/000001_<ts>.webp        evidence (raw screenshots)
      metadata/captures.jsonl             append-only audit trail
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

## How analysis works

Non-duplicate captures are buffered per case and flushed to the AI when the window
fills (default 4) or on a significant trigger (navigation / tab switch). Each window
is merged into the persistent state by id (revisiting a topic updates, never
duplicates). Duplicates (by perceptual hash) are still stored as evidence but skipped
by the AI — use `reanalyze --all` to force them in. The model is asked to extract
real artifact timestamps into the forensic timeline and to narrate the attacker path.
