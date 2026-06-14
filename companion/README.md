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

> **Updating an existing checkout?** After `git pull`, re-run `npm install` — new features
> can add dependencies (e.g. the screenshot OCR redaction added `tesseract.js`). Then restart
> `npm run dev`; server code loads once at startup, so changes need a restart.

> If you see `EADDRINUSE`, a companion is already running. Reuse it, or free the port:
> `Get-NetTCPConnection -LocalPort 4773 -State Listen | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force }`

## Configuration (`companion/.env`, gitignored)

| Variable | Meaning | Example |
| --- | --- | --- |
| `DFIR_CASES_ROOT` | Where case folders are written. Relative paths resolve against `companion/`, so the same folder is used no matter where you launch from. | `./cases` or `../cases` |
| `DFIR_PORT` | Port the localhost server binds to. Default `4773`. Must be 1–65535; invalid values fall back to the default with a warning. Change this if 4773 is taken, or to run multiple companions side-by-side. The extension and dashboard must use the same port. | `4773` or `4774` |
| `DFIR_LOG_LEVEL` | Log verbosity: `debug` \| `info` \| `warn` \| `error` (default `info`). Logs tee to the console **and** to files — a global `logs/session-<time>.log` (beside the cases root) + a per-case `cases/<id>/logs/session-<time>.log` (new file per server start). `debug` traces every AI call (model/phase + token usage), screenshot capture, OCR redaction, anonymization, and enrichment lookups. Change live (no restart) from **Settings → Log verbosity**. | `info` or `debug` |
| `DFIR_LOG_DIR` | Folder for the **global** session log. Default: a `logs/` folder beside the cases root. Relative paths anchor to `companion/`; absolute paths used as-is. Per-case logs always stay in the case folder (`cases/<id>/logs/`). | `./logs` or `D:\DFIR\logs` |
| `DFIR_AI_PROVIDER` | `openai` \| `openrouter` \| `ollama` \| `litellm` \| `gemini`. Leave **unset** to run capture-only (no AI). | `litellm` |
| `DFIR_AI_MODEL` | Model id understood by the provider. | `ollama/llama3.1` |
| `DFIR_AI_KEY` | Provider API key (blank for an auth-less local LiteLLM proxy). | `sk-...` |
| `DFIR_AI_BASE_URL` | Override the provider's API base URL. Needed for a self-hosted **LiteLLM** proxy or any OpenAI-compatible local endpoint. `litellm` defaults to `http://localhost:4000/v1`. | `http://localhost:4000/v1` |
| `DFIR_AI_IMAGE_DETAIL` | `high` \| `low` \| `auto` (default `high`). High tiles screenshots at full resolution for accurate small-text OCR (OpenAI/OpenRouter models). | `high` |
| `DFIR_AI_SYNTH_PROVIDER` / `DFIR_AI_SYNTH_MODEL` / `DFIR_AI_SYNTH_KEY` | Optional **synthesis** model (findings / MITRE / attacker path). The vars above are the cheap per-screenshot **extraction** model; point a stronger model here for the one text-only synthesis call. Unset → reuses the extraction model. | `google/gemini-2.5-pro` |
| `DFIR_AI_VELO_PROVIDER` / `DFIR_AI_VELO_MODEL` / `DFIR_AI_VELO_KEY` / `DFIR_AI_VELO_BASE_URL` | Dedicated model for **Velociraptor VQL hunt generation** (`✨ Suggest Velociraptor hunts` + Fleet Hunts) — separate from extraction/synthesis/OCR, since many models botch VQL (#70). Key/base-URL fall back to the main `DFIR_AI_KEY`/`DFIR_AI_BASE_URL`. Also editable in **Settings → AI**. | `openrouter` / `anthropic/claude-haiku-4.5` |

Other AI tunables: `DFIR_AI_TIMEOUT_MS` (per-request timeout, default 180000),
`DFIR_AI_MAX_TOKENS` (max completion tokens, default 16000 — also stops OpenRouter from
402-ing a large request by over-reserving credit), `DFIR_AI_SYNTH_MAX_EVENTS`
(events fed to the synthesis prompt, default 300, most-severe first), and
`DFIR_AI_CONTEXT_TOKENS` (the model's context window, default **128000**). Every prompt is
budgeted to fit `DFIR_AI_CONTEXT_TOKENS`: the synthesis/ask timelines are trimmed, CSV/log
imports are batched by token budget (not just row count), and the state-summary echo is
bounded — so a big case no longer fails with *"maximum context length is 128000 tokens"*.
Raise it for a bigger-context model (Claude 200k, Gemini 1M); the default only trims
genuinely huge prompts. A prompt that still can't fit fails fast with an actionable message
instead of a cryptic upstream 400.

Local models via **LiteLLM**: run [LiteLLM](https://docs.litellm.ai/) as a local gateway
in front of Ollama / vLLM / any of its 100+ backends — it speaks the OpenAI chat-completions
API, so the companion talks to it natively. Start the proxy (`litellm --model ollama/llama3.1`,
default port `4000`), then set `DFIR_AI_PROVIDER=litellm` and `DFIR_AI_MODEL=<your proxy model>`.
The `litellm` provider defaults `DFIR_AI_BASE_URL` to `http://localhost:4000/v1`; set that var
only to change the host/port (e.g. a proxy on another box). Leave `DFIR_AI_KEY` blank for an
auth-less proxy, or set it to the proxy's master/virtual key. Screenshot extraction needs a
**multimodal** model; text-only models still drive CSV/log/synthesis (pair them via the two-tier
`DFIR_AI_SYNTH_*` vars). Keeping everything on-box means evidence never leaves your network.

Direct local **Ollama** (no proxy): Ollama already serves a native OpenAI-compatible API, so you
can skip LiteLLM entirely — set `DFIR_AI_PROVIDER=ollama`, `DFIR_AI_BASE_URL=http://localhost:11434/v1`,
and `DFIR_AI_MODEL` to a pulled model (a **vision** model such as `llama3.2-vision` for screenshot
extraction). Leave `DFIR_AI_KEY` blank — Ollama ignores it. *Without* `DFIR_AI_BASE_URL` the `ollama`
provider targets hosted Ollama Cloud (`https://ollama.com/v1`), which does need a key.

Self-hosted enrichment TLS: if your **MISP** or **YETI** instance presents an internal-CA
or self-signed cert, set `DFIR_MISP_CA` / `DFIR_YETI_CA` to a PEM CA-bundle path to trust a
private CA (verification stays on), or `DFIR_MISP_INSECURE` / `DFIR_YETI_INSECURE` (`=1`) to
skip verification for a lab (insecure — logs a warning). Each is scoped to that one provider
via an injected undici dispatcher; VirusTotal/AbuseIPDB and the AI calls keep the verified store.

Custom AI prompts: override any of the five built-in prompts — `SYSTEM` (per-screenshot
extraction), `CSV`, `LOG`, `SYNTH` (holistic synthesis), `ASK` (case Q&A) — via env. Set `DFIR_AI_<NAME>_PROMPT`
for inline text, or `DFIR_AI_<NAME>_PROMPT_FILE` to point at a file. The **file** is re-read on
each AI call, so editing it applies on the next analysis with **no restart**; an unreadable/empty
file falls back to the built-in prompt with a warning. `npm run prompts:eject` writes the four
defaults to `./prompts` so you can start from them.

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
| `npm run prompts:eject -- [dir]` | Write the four built-in AI prompts (`system`/`csv`/`log`/`synthesis`) to files (default `./prompts`) so you can customize them, then point the `DFIR_AI_*_PROMPT_FILE` env vars at them. |
| `npm run data:update-attack` | Re-fetch the MITRE ATT&CK STIX bundle and re-slim it into `data/attack-groups.json` (the offline dataset behind the Adversary Hints panel). One network call, offline-prep only — never at request time. |

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
| `--base-url URL` | Override `DFIR_AI_BASE_URL` (e.g. a local LiteLLM proxy) for this run. | from `.env` |
| `--synth-model ID` | Use a **different (stronger) model for the synthesis pass** — findings / MITRE / attacker path. Per-screenshot extraction still uses `--model`. | = extraction model |
| `--synth-provider NAME` / `--synth-key KEY` / `--synth-base-url URL` | Provider/key/base-URL for the synthesis model (if different). | = extraction provider/key/base-URL |
| `--no-synthesis` | Skip the final synthesis pass (raw forensic timeline only, no findings/attacker path). | off |

Examples:

    npm run coverage -- test1
    npm run reanalyze -- test1 --reset                       # re-do all unique screenshots, fresh
    npm run reanalyze -- test1 --all --reset                 # include duplicates too
    npm run reanalyze -- test1 --reset --model openai/gpt-4o # try a different model
    # Two-tier (recommended): cheap model reads every screenshot, strong model writes conclusions
    npm run reanalyze -- test1 --reset --model openai/gpt-4o-mini --synth-model openai/gpt-4o

> `reanalyze` uses your API quota (~1 call per `--window` screenshots).

> **`npm audit` advisories:** the 5 advisories `npm audit` reports are all in the `vitest`
> **dev** toolchain (test-only, not shipped) and are tracked + deferred deliberately — the only
> fix is a breaking major `vitest` upgrade and the exploit preconditions don't occur in this
> project's workflow. See [`../SECURITY.md`](../SECURITY.md) before "fixing" them.

## HTTP endpoints

| Method & path | Purpose |
| --- | --- |
| `GET /health` | Reachability + `{ ok, aiEnabled }`. |
| `GET /cases` | List existing cases (newest first), each `{ caseId, name, createdAt, investigator, aiProvider }`. The extension's case dropdown uses this. |
| `POST /cases` | Create a case: `{ caseId, name, investigator, aiProvider }`. **The one place a case is born** (the dashboard's **+ New case** form and CLI tooling); returns **409** if the id already exists. The extension no longer creates cases. |
| `POST /captures` | Ingest a screenshot: `{ caseId, timestamp, url, tabTitle, triggerType, imageBase64 }`. Returns **404** if the case doesn't exist — captures never auto-create a case (create it in the dashboard first). |
| `POST /cases/:id/import` | **Unified import** — the dashboard's single **Import** button posts any data file here: `{ filename, text, minSeverity? }`. The server **auto-detects** the type (`importDetect.ts`: JSON/NDJSON vs CSV vs log, then per-format signatures) and dispatches to the matching importer below (or the AI CSV/log path). Optional **`minSeverity`** (`critical`/`high`/`medium`/`low`/`info`; blank/`info` = everything) is a **gate-aware** floor (`analysis/severityFloor.ts`) applied to **every** import kind: an import that grades severity keeps only events at/above the floor, but an import that carries **no** severity (all-Info host triage like KAPE/Plaso, plain telemetry) is **kept in full** — "if there are no severities, import everything". Evidence-first; returns `202 { accepted, kind, file, minSeverity }` with the detected `kind` (so a mis-route is visible) and the normalized floor. (Images go to `POST /captures`, not here.) |
| `POST /cases/:id/import-csv` | Import a CSV result export (e.g. a Velociraptor artifact): `{ filename, csv }`. Persists the raw CSV as evidence, extracts dated forensic events + IOCs from the rows, then synthesizes. Returns `202 { accepted, file, rows }`; progress streams over the WS. (The per-format routes back the unified `/import` above.) |
| `POST /cases/:id/import-thor` | Import a **THOR (Nextron) scanner report** in JSON-Lines format (`thor --jsonfile`): `{ filename, json, minLevel? }`. Optional `minLevel` is a severity floor — `"alert"` (only Alerts), `"warning"` (Alerts+Warnings), or `"notice"` (all, default) — so you can cut volume (the dashboard prompts for it). Persists the raw report as evidence, then maps findings **deterministically** (no AI extraction) to the timeline + IOCs — `level` → severity (Alert→Critical, Warning→High, Notice→Medium), reading each finding's own artifact time, pulling hashes/files/processes/IPs as IOCs, and collapsing identical findings. **Scan noise is dropped by default**: `level:"Info"` rows and lifecycle modules (`Init`, `Startup`, `Control`, `ThorDB`, `Report`). Then synthesizes. Returns `202 { accepted, file, findings, dropped, total }`. The dashboard's **Import THOR** button calls this. |
| `POST /cases/:id/import-siem` | Import a **SIEM / EDR JSON export** — the second JSON ingest path besides THOR, for Elastic/Kibana, Splunk, an EDR console, or a raw winlogbeat dump: `{ filename, json, minSeverity? }`. Optional `minSeverity` is a severity floor (`"low"` drops Info noise like logoffs/process-terminated; `"medium"`/`"high"`/`"critical"` keep only that level and above; blank keeps everything). Persists the raw export as evidence, then maps it **deterministically** (no AI extraction): the container is unwrapped (`{ data: [{ _source }] }`, `{ hits: { hits } }`, a plain array, NDJSON, or `{ events\|records\|results }`); **Windows Event Log + Sysmon** records get a per-EID mapping (label, derived severity — failed-logon→Medium, service-install/explicit-cred→High, LSASS access / suspicious LOLBin command-line bumped, benign csrss CreateRemoteThread downgraded — plus MITRE, IOC + asset/account extraction with `::ffff:` IPs unwrapped and Sysmon hashes parsed); any **other** SIEM/EDR record falls back to field auto-detection (timestamp / host / message / severity). Repetitive identical events are **aggregated** into one counted row and the total is capped, so an 11k-event export doesn't flood the timeline. Then synthesizes. Returns `202 { accepted, file, events, records, groups, format, iocs }`. The dashboard's **Import SIEM/EDR** button calls this. |
| `POST /cases/:id/import-chainsaw` | Import **Chainsaw hunt output** or a **raw EVTX dump** — the third JSON ingest path, and the richest for Windows IR: `{ filename, json, minSeverity? }`. Accepts [Chainsaw](https://github.com/WithSecureLabs/chainsaw) `hunt --json`/`--jsonl` (a JSON array or NDJSON of detections) **or** `evtx_dump -o json`/`jsonl` (bare `{ Event: { System, EventData } }` records), auto-detected per record. Persists the raw file as evidence, then maps it **deterministically** (no AI extraction). For a Chainsaw detection the matched **Sigma/built-in rule** leads the description, its **level drives severity**, and its `attack.tXXXX` **tags become MITRE techniques** — on top of the same per-EID Windows/Sysmon mapping + IOC/asset/hash/process-chain extraction as `import-siem`, run against the **embedded EVTX event** (`document.data.Event` / aggregate `documents[]`). A raw `evtx_dump` record (named EventData **or** the `Data[{@Name,#text}]` form) has no verdict → **per-EID severity/MITRE fallback**. Two different rules on the same event stay separate; the same rule firing repeatedly aggregates into a counted row; events are tagged **Chainsaw / EVTX** as `sources`; the artifact's own time is used. Optional `minSeverity` floor (blank keeps everything). Then synthesizes. Returns `202 { accepted, file, events, records, detections, groups, format, iocs }`. The dashboard's **Import Chainsaw/EVTX** button calls this. |
| `POST /cases/:id/import-hayabusa` | Import a **Hayabusa** (Yamato Security) detection timeline — JSON/JSONL (`hayabusa json-timeline`) **or** CSV (`hayabusa csv-timeline`, the default): `{ filename, text, minSeverity? }`. Sister of `import-chainsaw`; persists the file as evidence then maps it **deterministically** (no AI extraction), **verdict-first** — the matched Sigma rule's **`Level` → severity**, **`RuleTitle`** leads the description, `MitreTactics`/`MitreTags` (`Txxxx`) → MITRE. IOCs/host/process-chain come from the rendered detail fields (the CSV `Details`/`ExtraFieldInfo` cells' `Key: value ¦ …` form is parsed back into fields). Both `crit`/`critical` & `med`/`medium` levels accepted; the timestamp offset is honored to UTC; events tagged **Hayabusa**; repetitive events aggregate + cap; optional `minSeverity` floor (blank keeps everything). Then synthesizes. Returns `202 { accepted, file, events, records, groups, format, iocs }`. The dashboard's **Import Hayabusa** button calls this. |
| `POST /cases/:id/import-log` | Import a generic log file (firewall — Cisco ASA, pfSense, iptables, Palo Alto, Fortinet; syslog; sshd / auth.log; IIS / Apache / nginx access; Windows event-log text exports; VPN/IKE; application logs — anything line-oriented, typically `.log` or `.txt`): `{ filename, text }`. Persists the raw file as evidence, then **deduplicates** the lines into counted patterns and asks the AI to triage them, adding **only security-relevant** events to the timeline (routine noise like VPN rekeying/retransmissions is skipped). Repeated activity is **collapsed into one aggregated event** carrying an occurrence `count` and first→last time span (e.g. "20 failed logins…"). Any timestamp format is read (ISO-8601, RFC 3164 syslog, Apache, IIS, epoch…). Returns `202 { accepted, file, lines }`; progress streams over the WS. The dashboard's **Import Log** button calls this. |
| `POST /cases/:id/import-velociraptor` | Import **Velociraptor native JSON** — collection results / hunt exports: `{ filename, text, minSeverity? }`. Reads a JSON array, **JSONL** (the native form), a single object, an Elastic-style wrapper, or a Velociraptor **multi-artifact map** (`{ "Artifact.Name": [rows] }`). Persists the file as evidence then maps it **deterministically** (no AI extraction): each row is **classified** — **Sigma** detections map verdict-first (rule level→severity, title→description, tags→MITRE) over the parsed event; **YARA** hits → High detections with rule + scanned file/process + hash; parsed **EVTX** rows (`System`+`EventData`, EventID number or `{Value}`) reuse the per-EID mapping; other artifacts (pslist/netstat/file listing…) auto-detect time/host/IOCs. Reads the **artifact's own time** (not the `_ts` collection time unless nothing better); IOCs pulled from every column; events tagged **Velociraptor**; aggregates + caps; optional `minSeverity` floor (`low` drops the Info raw-collection rows). Then synthesizes. Returns `202 { accepted, file, events, rows, detections, groups, format, iocs }`. The dashboard's **Import Velociraptor** button calls this. |
| `POST /cases/:id/import-network` | Import **Suricata `eve.json`** + **Zeek JSON** network logs (Security Onion's network side): `{ filename, text, minSeverity? }`. Reads NDJSON (native), an array, or an Elastic wrapper; routes per record (Suricata `event_type`, Zeek `_path`). Persists the file as evidence then maps it **deterministically** (no AI extraction): the **timeline is built from the detections** — Suricata **`alert`** (signature→description, `alert.severity`→severity, `alert.metadata`→MITRE, flow 5-tuple) and Zeek **`notice`** — while **telemetry** (`dns`/`http`/`tls`/`fileinfo`/`files`/`ssl`/`x509`) contributes **IOCs only** (domains, URLs, file hashes, alert/notice IPs), keeping the timeline signal-rich. The artifact's own time is used (Suricata offset ts, Zeek epoch `ts`); events tagged **Suricata**/**Zeek**; alerts aggregate + cap; optional `minSeverity` floor on alert events (telemetry IOCs kept regardless). Then synthesizes. Returns `202 { accepted, file, events, records, alerts, groups, format, iocs }`. The dashboard's **Import Suricata/Zeek** button calls this. |
| `POST /cases/:id/import-kape` | Import a **KAPE / Eric Zimmerman Tools CSV** (host-forensics triage): `{ filename, text, minSeverity? }`. The producing EZ tool is **auto-detected from the CSV header**, then each row maps **deterministically** (no AI extraction) to a forensic event reading the **artifact's own time** + file/hash/process IOCs. Supports **Prefetch** (PECmd), **Amcache** (AmcacheParser, incl. SHA1), **ShimCache/AppCompatCache** (AppCompatCacheParser), **LNK** (LECmd), **JumpLists** (JLECmd), **UsnJrnl $J** & **$MFT** (MFTECmd, files only), **SRUM** (SrumECmd), **Recycle Bin** (RBCmd), **Shellbags** (SBECmd). Evidence rows (Info severity); the .NET min-date sentinel is dropped; events tagged by artifact name for cross-source correlation; aggregates + caps; optional `minSeverity` floor. Then synthesizes. Returns `202 { accepted, file, artifact, events, rows, groups, iocs }`. The dashboard's **Import KAPE/EZ** button calls this. |
| `POST /cases/:id/import-cybertriage` | Import a **Cyber Triage** (Sleuth Kit Labs) timeline export (host triage): `{ filename, text, minSeverity?, fileTelemetry? }`. Reads the **JSONL** (richest), **JSON array**, or **CSV** timeline form. **Deterministic** (no AI extraction), **verdict-first** like Hayabusa/Velociraptor: Cyber Triage already scores items, so **scored rows** (`score` `Notable_Normal`=Bad / `LikelyNotable_Normal`=Suspicious, or the CSV `threat_level`) map to events with severity **derived from the verdict** + a keyword bump on the reason text (lsass dump/mimikatz/ransomware→Critical; RAS/AnyDesk/PsExec/YARA→High), the **`scoreDescription`** leads the description, MITRE from the reason (lsass→T1003.001, RAS→T1219, scheduled task→T1053.005, UAC-bypass→T1548.002), and the process chain / path / host / args are carried through. The export is mostly raw filesystem telemetry, so to stay signal-rich the importer **splits the feed**: unscored **Process + Scheduled-Task** rows → **Info** evidence (a bounded execution/persistence timeline); the unscored **File** MFT super-timeline is **dropped by default** (`fileTelemetry:true` opts it back in); **network** rows contribute the **remote IP as an IOC** only. Events tagged **Cyber Triage**; aggregates + caps; optional `minSeverity` floor. Then synthesizes. Returns `202 { accepted, file, format, events, rows, notable, groups, iocs }`. (The CSV form is **lossy** — no host, no process chain; prefer the JSONL export.) The dashboard's single **Import** button auto-detects and routes here. |
| `POST /cases/:id/import-m365` | Import **Microsoft 365 / Entra ID** audit data (cloud/identity IR): `{ filename, text, minSeverity? }`. Auto-detects and maps the **M365 Unified Audit Log** (`Search-UnifiedAuditLog` CSV/JSON or Management Activity API — the `AuditData` JSON blob is parsed/merged), **Entra sign-in logs**, and **Entra directory audit logs**. **Deterministic** (no AI extraction): severity is **derived from the operation** (BEC tradecraft — inbox/transport rules, mailbox delegation, OAuth/service-principal grants, role additions, password resets, failed sign-ins → High/Medium + MITRE), while **Entra `riskLevel`** (Identity Protection) drives severity directly. Source IPs (de-bracketed from `[ip]:port`) become IOCs; the UPN is surfaced for the asset graph. Events tagged **Microsoft 365**/**Entra ID**; aggregates + caps; optional `minSeverity` floor. Then synthesizes. Returns `202 { accepted, file, events, records, groups, format, iocs }`. The dashboard's **Import M365/Entra** button calls this. |
| `POST /cases/:id/import-aws` | Import **AWS CloudTrail** logs (cloud IR): `{ filename, text, minSeverity? }`. Reads the `{ Records: [...] }` envelope, NDJSON (CloudTrail Lake/Athena), or an array. **Deterministic** (no AI extraction): severity is **derived from the API action** (IAM persistence/priv-esc, CloudTrail/GuardDuty/flow-log tampering, S3 exposure, AMI/snapshot sharing, secrets access → High/Medium + MITRE), with bumps for a present `errorCode` (denied probe), `userIdentity.type == Root`, and failed/root ConsoleLogin. The caller `sourceIPAddress` becomes an IOC (AWS-service callers ignored); the principal (IAM user / assumed-role issuer) is in the description. Events tagged **AWS CloudTrail**; aggregates + caps; optional `minSeverity` floor (drops routine reads). Then synthesizes. Returns `202 { accepted, file, events, records, groups, format, iocs }`. The dashboard's **Import AWS CloudTrail** button calls this. |
| `POST /cases/:id/import-cloud-activity` | Import **GCP Cloud Audit Logs** + **Azure Activity Log** (cloud IR): `{ filename, text, minSeverity? }`. Auto-detects per record — GCP (`protoPayload` AuditLog / `cloudaudit` logName) and Azure (`operationName` + `caller`, native camelCase **or** flat Log-Analytics PascalCase). **Deterministic** (no AI extraction): severity is **derived from the action** via per-cloud rule tables (service-account keys/IAM role grants, logging-sink/diagnostic deletion, firewall opens, storage exposure, secret/key-vault & storage-key access, snapshot/image sharing, VM run-command → High/Medium + MITRE), bumped when the call was denied (`status.code != 0` / `Failed`). The caller IP becomes an IOC; the principal email is surfaced for the asset graph. Events tagged **GCP Audit**/**Azure Activity**; aggregates + caps; optional `minSeverity` floor. Then synthesizes. Returns `202 { accepted, file, events, records, groups, format, iocs }`. The dashboard's **Import GCP/Azure** button calls this. |
| `POST /cases/:id/import-plaso` | Import a **Plaso / log2timeline** super-timeline (`psort` CSV): `{ filename, text, minSeverity? }`. Header-detects the **dynamic** (`datetime,message,…`) and legacy **l2tcsv** (`date,time,timezone,…,desc,…`) flavours. **Deterministic** (no AI extraction): each row → an **Info** evidence event at its own time (l2tcsv MM/DD/YYYY+time+tz → UTC); IOCs (hashes/URLs/IPs, octet-bounded so version strings aren't mistaken for IPs) + the source file path are scraped from the message; the l2tcsv `host` attributes the event. Tagged **Plaso**; repetitive rows aggregate + cap (*filter your psort output first*). Then synthesizes. Returns `202 { accepted, file, format, events, rows, groups, iocs }`. The dashboard's **Import Plaso** button calls this. |
| `POST /cases/:id/import-sandbox` | Import a **malware-sandbox** detonation report — **CAPEv2** (`report.json`) or **CrowdStrike Falcon Sandbox** (Hybrid Analysis summary JSON), auto-detected: `{ filename, text, minSeverity? }`. **Deterministic** (no AI extraction): the **sample verdict** (CAPE `malscore`/family, Falcon `verdict`/`threat_score`/`vx_family`) + **each behavioural signature** become events with their own severity + MITRE (CAPE `ttp`, Falcon `mitre_attcks`/`attck_id`); dropped/extracted-file hashes and network hosts/domains/URLs are harvested as IOCs. Accepts an array of reports. Events tagged **CAPEv2**/**Falcon Sandbox**; aggregates + caps; optional `minSeverity` floor. Then synthesizes. Returns `202 { accepted, file, format, events, signatures, iocs }`. The dashboard's **Import Sandbox** button calls this. |
| `POST /cases/:id/import-memory` | Import **memory-forensics** output — **Volatility 3** (`vol -r json …`: a JSON array of row objects, the `pstree` tree nested under `__children`; also JSONL and a combined `{ "<plugin>": [rows] }` map) or **Rekall** (`--format json`: a `[directive, payload]` statement list): `{ filename, text, minSeverity?, dllTelemetry? }`. **Deterministic** (no AI extraction): each plugin table is identified by its **columns** and mapped — `pslist`/`psscan`/`pstree` → process-tree events (parent→child links, started-at from `CreateTime`), `netscan`/`netstat` → connection events (+ foreign IP/port IOCs; external ESTABLISHED → Low), `malfind` → **High** injected/executable-private-memory events (**ATT&CK T1055**), `cmdline` → command-line events (bumped on LOLBin / encoded-PowerShell tradecraft), `svcscan`/`modules`/`driverscan` → service/driver evidence; process names / file paths / foreign IPs are harvested as IOCs. `dlllist`/`ldrmodules` contribute file IOCs only (`dllTelemetry` opts the per-DLL events back in). Events tagged **Volatility** / **Rekall**; aggregates + caps; optional `minSeverity` floor. Then synthesizes. Returns `202 { accepted, file, format, tool, events, injected, connections, iocs }`. The dashboard's single **Import** button auto-detects and routes here. |
| `POST /cases/:id/import-thehive` | Import a **TheHive 5** case/alert/observable export: `{ filename, text }`. **Deterministic** (no AI): accepts a single case/alert object, an array, or a `{ data: [...] }` search-result container → one forensic event per record. Severity from TheHive's **1–4 scale** (1→Info, 2→Medium, 3→High, 4→Critical); MITRE from ATT&CK-tagged `tags` (e.g. `"T1059.001"`); TLP/PAP labels prepended; `customFields` appended. Observable records with `ioc: true` → IOCs by `dataType` (`ip`, `domain`/`fqdn`, `url`, `hash`, `filename`→file, `mail`→other). **Elasticsearch guard**: records with `_source` are skipped. Events tagged **TheHive**. Then synthesizes. Returns `202 { accepted, file, format, events, total, observables, iocs }`. The dashboard's single **Import** button auto-detects and routes here. |
| `POST /cases/:id/import-email` | Import an **email artifact** — `.eml` (RFC 2822/MIME) or best-effort `.msg` (Outlook OLE): `{ filename, text, minSeverity? }`. **Deterministic** (no AI extraction, dependency-free `parseMimeEmail`): one forensic event dated at the message's own **`Date:`** header, with sender / reply-to / originating IP / authentication results in the description. Severity is **derived from the email's own signals** — SPF/DKIM/DMARC **fail** → High; a suspicious sender (From vs different-org Reply-To/Return-Path, or a display-name that spoofs another domain) → Medium; clean → Info. **URLs** (links + defanged `hxxp` re-fanged), **sender/reply-to domains**, the **originating IP**, and **attachment filenames + hashes** become IOCs. Covers **ATT&CK T1566** (Phishing; +`.001` for attachments, +`.002` for links). `.msg` is BEST-EFFORT — the binary OLE container is recovered for its embedded RFC 822 transport-headers stream (the import pipeline is text-only); export as `.eml` for full fidelity. Events tagged **Email**. Then synthesizes. Returns `202 { accepted, file, format, events, subject, sender, iocs }`. The dashboard's single **Import** button auto-detects and routes here. |
| `POST /cases/:id/import-auditd` | Import a **Linux auditd** log — the raw `/var/log/audit/audit.log` / **`ausearch`** record format (raw or `-i`), or an **`aureport`** numbered table: `{ filename, text, minSeverity? }`. **Deterministic** (no AI extraction): the several `type=… msg=audit(TS:SERIAL): …` lines that share a SERIAL collapse into **one logical event** (a `key=value` tokenizer handles quoted values, the nested `msg='…'` USER_* blob, and hex-encoded PROCTITLE/EXECVE-args/SOCKADDR); severity + MITRE come from a **record-type table** (logins, account/group mgmt → T1136, sudo → T1548.003, SELinux/AppArmor denials → T1562.001, `CONFIG_CHANGE` audit tampering → T1562.006, anomaly records), **bumped** on a failed auth (→ T1110) or a suspicious command line. IOCs: `exe`/`comm`/argv[0] → process+file, watched `name=` → file, login `addr`/`hostname` + decoded SOCKADDR → ip/domain. Read at the **audit() epoch**. Events tagged **auditd**; aggregates + caps; optional `minSeverity`. Then synthesizes. Returns `202 { accepted, file, format, events, records, groups, iocs }`. The dashboard's single **Import** button auto-detects and routes here. |
| `POST /cases/:id/import-journald` | Import a **systemd-journald** structured log — **`journalctl -o json`** / **`-o json-pretty`**: `{ filename, text, minSeverity? }`. **Deterministic** (no AI extraction): each entry is read at its **own time** (`_SOURCE_REALTIME_TIMESTAMP` in preference to `__REALTIME_TIMESTAMP`, both µs epoch); severity is **derived from `PRIORITY`** (syslog 0–7) then **bumped** from the message + identifier with a Linux tradecraft table (sshd `Failed password` → T1110, `Accepted` root login → T1078, `useradd` → T1136.001, `sudo` → T1548.003, promiscuous-mode → T1040, AVC/AppArmor denials → T1562.001). IOCs: `_EXE`/`_COMM` → process+file, IPs/domains/URLs scraped from `MESSAGE`. Events tagged **journald**; aggregates + caps; optional `minSeverity`. Then synthesizes. Returns `202 { accepted, file, format, events, entries, groups, iocs }`. The dashboard's single **Import** button auto-detects and routes here. |
| `POST /cases/:id/import-sysdig` | Import a **sysdig / Falco** export: `{ filename, text, minSeverity? }`. **Deterministic** (no AI extraction). A binary `.scap` must be exported to text first; the importer eats both forms, routed per-record: **Falco** alert JSON (`rule`/`priority`/`output`/`output_fields`/`tags`) are the **detections** → timeline events mapped **verdict-first** (priority → severity, ATT&CK `tags` → MITRE, proc/file/IP/hash from `output_fields`); **sysdig** `-j` event JSON (`evt.type`/`evt.num`/`proc.name`/`evt.info`, read at `evt.datetime`/`evt.rawtime`) is high-volume telemetry → **Info** evidence with proc/file/network IOCs. Events tagged **Falco** / **sysdig**; aggregates + caps; optional `minSeverity`. Then synthesizes. Returns `202 { accepted, file, format, events, records, alerts, groups, iocs }`. The dashboard's single **Import** button auto-detects and routes here. |
| `POST /cases/:id/import-wazuh` | Import **Wazuh SIEM/EDR** alert exports: `{ filename, text, minSeverity? }`. Accepts a JSON array or NDJSON of alert objects, **or** a Wazuh API export (`GET /security/events` → `{ data: { affected_items: [...] } }`). **Deterministic** (no AI extraction): **`rule.level`** drives severity (≥13 Critical, ≥10 High, ≥7 Medium, else Info); `rule.level < 3` noise is dropped by default; `rule.mitre.technique` → MITRE; `agent.name` → asset; `data.srcip`/`dstip` → IP IOCs; `data.md5`/`sha256` → hash IOCs; `data.url` → URL IOCs; `data.win.eventdata.commandLine` → process IOC. Events tagged **Wazuh**; aggregates + caps; optional `minSeverity`. Then synthesizes. Returns `202 { accepted, file, format, events, records, groups, iocs }`. The dashboard's single **Import** button auto-detects and routes here. |
| `GET /cases/:id/state` | Current investigation state (JSON). |
| `GET /cases/:id/evidence/:file` | Serve a piece of evidence (a screenshot or an imported CSV) by filename. Sandboxed to the case's `screenshots/` and `imports/` dirs (no path separators or `..`). The dashboard links findings/events to this so a click opens the artifact. |
| `GET /cases/:id/captures/count` | Number of captures recorded for the case. |
| `GET /cases/:id/scope` | Current investigation time-window: `{ start, end }` (ISO or null). |
| `POST /cases/:id/scope` | `{ start, end }` — set the window; re-synthesizes using only in-scope events. The dashboard's scope bar calls this. |
| `GET /cases/:id/legitimate` | List client-confirmed legitimate findings/IOCs/events (excluded from analysis). |
| `POST /cases/:id/legitimate` | `{ kind: "finding"\|"ioc"\|"event", ref, note, label? }` — mark a finding (ref = title), IOC (ref = value), or **forensic event** (ref = event id; `label` = its description for display) legitimate; re-runs synthesis without it. The dashboard's per-item **⚑ mark legitimate** button calls this. Legit **events** are hidden from the timeline and excluded from synthesis input but the raw event is preserved in state, so un-marking restores it. |
| `POST /cases/:id/legitimate/remove` | `{ id }` — un-mark; re-runs synthesis. |
| `GET /ioc-whitelist` | List the **global IOC whitelist** rules (known-good CIDR/exact/regex patterns). |
| `POST /ioc-whitelist` | `{ match: "cidr"\|"regex"\|"exact", pattern, iocType?, note? }` — add a rule (validated; idempotent). Matching IOCs are auto-marked legitimate on import. |
| `DELETE /ioc-whitelist/:ruleId` | Remove a whitelist rule. |
| `POST /ioc-whitelist/import` | `{ text }` — bulk-import rules from pasted **CSV** (header `match,pattern,type,note`) or **JSON**; skips duplicates. |
| `GET /ioc-whitelist/export?format=csv\|json` | Download the whitelist as CSV or JSON. |
| `POST /cases/:id/ioc-whitelist/apply` | Apply the whitelist to this case's current IOCs now — marks matches legitimate, re-synthesizes; returns `{ matched, added, legitimate }`. |
| `GET /nsrl` | **NSRL known-good hash set** stats: `{ count, enabled }` (count of loaded NIST NSRL / RDS hashes). |
| `POST /nsrl/import` | `{ text }` — import known-good hashes from a pasted **NSRLFile.txt** (RDS CSV), a **hashdeep CSV**, or a **hash-per-line / comma list** (MD5/SHA-1/SHA-256); dedups, returns `{ added, parsed, total }`. |
| `POST /nsrl/import-file` | `{ path }` — load hashes from file(s) on the **server's filesystem** (`;`-separated for multiple) — the in-UI equivalent of `DFIR_NSRL_FILE`, for big RDS sets you don't want to paste. Best-effort per file; returns `{ added, total, files[] }`. |
| `POST /nsrl/db` | `{ path }` — connect (or swap) the **NSRL RDS SQLite database** at runtime — the full ~160 GB set, queried on demand (not loaded into memory). Opens read-only, auto-detects the `METADATA` table + sha256/md5 columns, persists the path. Rejected (400) when `DFIR_NSRL_DB` env-manages the path. Returns the connection status. |
| `DELETE /nsrl/db` | Disconnect the RDS database (the flat set is unaffected). |
| `POST /nsrl/clear` | Wipe the global NSRL set (e.g. to swap RDS releases). |
| `GET /nsrl/export` | Download the set as a newline-delimited hash list. |
| `POST /cases/:id/nsrl/apply` | Apply the NSRL set to this case now — marks events/IOCs with a known-good file hash legitimate, re-synthesizes; returns `{ matchedIocs, matchedEvents, added, legitimate }`. Auto-runs on every import; also pre-load big sets at startup via `DFIR_NSRL_FILE`. |
| `GET /kev` | **CISA KEV catalog** stats: `{ count, enabled, catalogVersion?, dateReleased? }`. |
| `POST /kev/import-url` | `{ url? }` — fetch the CISA KEV JSON from a URL (defaults to the official CISA feed); stores the catalog and invalidates the synthesis cache. Returns `{ total }`. Requires server outbound internet access. |
| `POST /kev/import-file` | `{ path }` — load the KEV JSON from a server-local file path (for air-gapped deployments). Returns `{ total }`. |
| `DELETE /kev` | Clear the KEV catalog from disk. |
| `GET /cases/:id/ai-control` | Current AI on/off state: `{ enabled, lastAnalyzedSeq }`. |
| `POST /cases/:id/ai-control` | `{ enabled }` — turn AI analysis on/off for the case. **Defaults off** (a fresh case captures evidence without running AI). Evidence is always captured; when off, no AI runs. Turning it **on** backfills every screenshot captured while it was off. The dashboard's **AI: ON/OFF** button calls this. |
| `GET /cases/:id/enrich-control` | Per-source enrichment state: `{ anyConfigured, providers: [{ name, scope, enabled }] }`. `scope` is `local` (your own MISP/YETI — OPSEC-safe) or `external` (third-party SaaS). |
| `POST /cases/:id/enrich-control` | `{ providers: [names] }` (or legacy `{ enabled }`) — set which sources are enabled for the case. **Default is local-only** (OPSEC-safe). Saving enriches the current IOCs and auto-enriches IOCs added later; **enabling a source re-checks every IOC on it** (per-source cache via `enrichedBy`). The dashboard's **Enrich** picker calls this. Stored in `state/enrich-control.json`. |
| `POST /cases/:id/enrich` | Manual one-shot IOC enrichment (does not change the toggle). Looks up the case's IOCs (hashes/IPs/domains/URLs) on the configured providers — **VirusTotal** (`DFIR_VT_KEY`), **Hunting.ch** (`DFIR_HUNTINGCH_KEY`, or the legacy `DFIR_MB_KEY` — abuse.ch unified hunt fanning one indicator across MalwareBazaar + ThreatFox + URLhaus + YARAify, each a separate clickable result), **CrowdStrike Falcon** (`DFIR_CROWDSTRIKE_CLIENT_ID` + `_SECRET`, optional `_CLOUD` — Threat-Intel-only: Falcon Intelligence Indicators for hash/IP/domain/URL + MalQuery sample metadata for hashes; OAuth2, no endpoint/SIEM scopes), **AbuseIPDB** (`DFIR_ABUSEIPDB_KEY`), **MISP** (`DFIR_MISP_URL` + `DFIR_MISP_KEY`), **RockyRaccoon** (`DFIR_ROCKYRACCOON_KEY`, **process** names — prevalence / LOLBIN / risk / expected parent / ATT&CK), **YETI** (`DFIR_YETI_URL` + `DFIR_YETI_KEY`, your own instance) — and annotates each with a verdict/score/link. Cached on the IOC (skips already-enriched unless `{ force: true }`); throttled (`DFIR_ENRICH_DELAY_MS`) and capped (`DFIR_ENRICH_MAX`, hashes/IPs first). **Reachability-gated**: a self-hosted MISP/YETI that's down is health-probed (cached ~60s) before sending, then skipped + retried rather than blasted one request per IOC. `501` if no provider key is set. **⚠ OPSEC: sends indicators to third-party services.** |
| `GET /enrich-health` | Reachability of the configured providers (for the dashboard's ●up/down dots): `{ providers: [{ name, scope, probed, ok, detail? }] }`. Probes each self-hosted source (MISP `GET /servers/getVersion`; YETI API-token exchange), cached ~60s (`DFIR_ENRICH_HEALTH_TTL_MS`). Providers without a health endpoint (external SaaS) report `probed:false, ok:true`. A background poller (`DFIR_ENRICH_HEALTH_POLL_MS`, default 60s, `=0` off) re-probes down servers and auto-resumes enrichment for cases it had to skip. |
| `GET /cases/:id/customer-exposure` | Customer-exposure status: `{ anyConfigured, providers: [names], targets: { domains, emails }, effectiveTargets, exposure }`. `effectiveTargets` adds case emails **under a customer domain**; `exposure` is the last saved result. **Separate from IOC enrichment** — about the victim org's own assets. |
| `PUT /cases/:id/customer-exposure/targets` | Save the customer's own `{ domains, emails }` (comma/space/newline lists accepted; normalized + de-duped) plus an optional `providers` list — which exposure sources to run (omitted/empty = all). Stored in `state/customer.json`. |
| `POST /cases/:id/customer-exposure/check` | Run the breach/leak/exposure check across the configured providers — **LeakCheck** (`DFIR_LEAKCHECK_KEY`), **Have I Been Pwned** (`DFIR_HIBP_KEY`), **DeHashed** (`DFIR_DEHASHED_KEY`), **Shodan** (`DFIR_SHODAN_KEY` — domain attack-surface: exposed hosts/ports/services/CVEs). An optional body `{ providers: [names] }` restricts the run to those sources (else the per-case saved selection, else all). Domain searches use ONLY customer domains (never IOC domains); auto-discovered case emails are checked only under those domains. Throttled (`DFIR_EXPOSURE_DELAY_MS`). Persists a summary to `state/customer-exposure.json` **without raw passwords** (only a credential-present flag). `501` if no provider key is set. **⚠ OPSEC: sends the customer's own domains/emails to third-party services.** |
| `POST /cases/:id/synthesize` | Run the synthesis pass (findings / MITRE / attacker path) from the forensic timeline; pushes the update to the dashboard. The dashboard's **Synthesize** button calls this. |
| `GET /cases/:id/import-meta` | Last-import record for the dashboard's **📥 Last import N ago — +N new events / +N new IOCs** banners above the Forensic Timeline and IOCs: `{ lastImportedAt, lastImportKind, lastImportFile, addedCount, removedCount, lastDiff: { added, removed }, iocsAddedCount, iocsRemovedCount, iocsDiff: { added, removed } }`. Written by the unified `/import` route after each import completes (diffs the timeline before/after by normalized time+description, and the IOCs by exact value); drives the per-row `NEW` highlights. Stored in `state/import-meta.json`; pushed live over the WS (`import_meta_changed`). |
| `GET /cases/:id/import/undo-stack` · `POST …/import/undo` · `POST …/import/redo` | **Import undo/redo** (#76). An import can flood the dashboard with hundreds of events (and the synthesis that follows rewrites the findings/MITRE/attacker-path); before each import the **full pre-import `InvestigationState`** is snapshotted onto a per-case stack (`state/import-undo-stack.json`, `ImportUndoStore`; depth `DFIR_IMPORT_UNDO_DEPTH`, default 10). `undo` restores that snapshot **verbatim** — findings, IOCs, timeline, MITRE, attacker path, the lot — and pushes the current state to a redo stack; `redo` re-applies it. **No AI re-synthesis** — the snapshot already holds the exact prior conclusions. `GET …/undo-stack` returns a lightweight `{ canUndo, canRedo, maxDepth, nextUndo, nextRedo, undo:[], redo:[] }` summary (labels/times + event/IOC/finding counts, not the raw snapshots) for the Undo/Redo buttons next to the Import button; both POSTs return the updated summary, broadcast the restored state over the WS, and push `import_undo_changed`. A no-op re-import adds no checkpoint; an undo also clears the "📥 last import" banner. Machine-local — **not** part of the portable case snapshot. 501 when no state store is wired. |
| `POST /cases/:id/ask` | `{ question }` → ask the LLM a free-form question about the case ("was data exfiltrated?", "was a USB connected?"). Single-shot, no state change; returns `{ answer, status (answered/partial/unknown), pointer (which artifact to collect/where), relatedEventIds }`. |
| `POST /cases/:id/questions` | `{ question, answer?, status?, pointer? }` → add an analyst question to the case's key questions, **pinned** (preserved across synthesis, which answers it once the evidence supports it). The dashboard's **Add to open questions** button calls this. |
| `GET /cases/:id/comments` · `POST` · `DELETE …/:commentId` | **Investigator comments** on any entity. POST `{ targetType, targetId, author, text }` adds one; DELETE removes by id. Stored in `state/comments.json` (never wiped by synthesis); add/remove ping dashboard clients over the WS for live collaboration. The 💬 chips on events/findings/IOCs/questions/threads call these. |
| `GET /cases/:id/playbook` · `POST` · `POST …/sync` · `PATCH …/order` · `PATCH …/:taskId` · `DELETE …/:taskId` · `GET/PUT …/control` | **Response Playbook** (issue #36): a trackable checklist auto-derived from the case's recommended **next steps** + **Critical/High findings**, plus analyst **custom** tasks. `GET` re-syncs idempotently against the latest state (write-if-changed) and returns `{ tasks, stats, control }` (completion %); `POST` adds a custom task `{ title, priority?, … }`; `POST …/sync` forces a re-derive; `PATCH …/order` `{ ids }` reorders; `PATCH …/:taskId` edits `{ status, priority, assignee, dueDate, notes, … }`; `DELETE …/:taskId` removes. `GET/PUT …/control` reads/sets `{ useTemplates }` — the **IR-template** toggle (Phase 2, default off): when on, each Critical/High finding expands into severity-based response phases (Critical → Contain/Investigate/Eradicate/Recover, High → Investigate/Contain) with the Investigate step tailored to the finding's ATT&CK tactic. A re-derive **preserves analyst status/edits** and prunes only *pristine* (untouched) auto-tasks whose source vanished. Stored in `state/playbook.json` (`PlaybookStore`) + `state/playbook-control.json` (`PlaybookControlStore`), never wiped by synthesis; changes ping dashboard clients over the WS. Rendered into the report as a **Response Playbook** section. |
| `POST /cases/:id/report` | Write report files; returns their paths. `report.md` **and** `report.html` follow the [AnttiKurittu incident-report-template](https://github.com/AnttiKurittu/incident-report-template): technical sections auto-fill from the case, human-authored sections come from report metadata (below). |
| `GET /cases/:id/report/report.md` · `…/report.html` | Serve a generated report for export (view or download). `?download=1` forces a save dialog; on the HTML, `?print=1` injects a print trigger so the browser opens its **Save as PDF** dialog on load (the PDF export — the on-disk file is never modified); `404` until the report has been generated. The HTML export is standalone and print-friendly; raw HTML in untrusted data is escaped. |
| `GET /cases/:id/report.docx` | Download the incident report as a **Word `.docx`** — generated on demand from the current case state (same scope/legitimate filtering as the Markdown and HTML exports). Headings, GFM tables, lists, blockquotes, code blocks, and inline emphasis all map across. The `.docx` is not persisted to disk; each request regenerates it. Always returns an attachment download. The dashboard's **Export** menu → **Generate report (Word .docx)** calls this. |
| `GET /cases/:id/incident-timeline.csv` | Export **just the incident (forensic) timeline** as CSV, generated on demand (same scope/legitimate filtering as the report) — no full report needed. The dashboard's **Export Timeline CSV** button calls this. |
| `GET /cases/:id/attack-layer.json` | Export a **MITRE ATT&CK Navigator layer** (JSON) for the case — techniques from the findings + forensic timeline, colored/scored by worst observed severity, with each finding's title in the cell comment (same scope/legitimate filtering as the report). Sub-techniques get an expanded parent so they're visible. Drops into the [Navigator](https://mitre-attack.github.io/attack-navigator/)'s *Open Existing Layer → Upload from local*. The layer is stamped with the current ATT&CK version (override via `DFIR_ATTACK_VERSION` so the Navigator doesn't prompt to upgrade on import). The dashboard's **Export → ATT&CK Navigator layer (JSON)** calls this. Pure (`buildAttackLayer`), no AI. |
| `GET /cases/:id/timeline.jsonl` | Export the incident (forensic) timeline as **Timesketch-compatible JSONL** (`message`/`datetime`/`timestamp_desc` + searchable fields, one event per line; same scope/legitimate filtering). Upload it into a Timesketch sketch manually, or use the dashboard's **Push to Timesketch** button. The **Export Timesketch JSONL** button calls this. |
| `GET /cases/:id/export/stix` | Export a **STIX 2.1 bundle** (JSON) for the case — a `report`, one `indicator` per IOC (as a STIX `pattern`, carrying the threat-intel verdict in `indicator_types` + description), one `attack-pattern` per MITRE technique (ATT&CK external reference), `malware` SDOs from enrichment family tags, `identity` for the producing firm + victim org (from report metadata), and `indicator →indicates→ attack-pattern`/`malware` `relationship`s (same scope/legitimate filtering as the report). Every id is a deterministic UUIDv5, so re-exporting an unchanged case yields a byte-identical bundle. Drops into any TIP (OpenCTI, MISP, Anomali, ThreatConnect). The dashboard's **Export → STIX 2.1 bundle (JSON)** calls this. Pure (`buildStixBundle`), no AI, no STIX library. |
| `GET /cases/:id/export/snapshot` · `POST /snapshots/import` | **Investigation snapshot** (issue #56) — a single portable JSON bundling the case for cross-machine sharing: `case` meta, the **allowlisted** `state/*.json` files (`investigation.json` — forensic timeline, findings, IOCs, MITRE, attacker path — plus `scope`/`legitimate`/`comments`/`tags`/`notebook`/`report-meta`/`playbook`/`playbook-control`/`asset-overrides`/`customer`/`customer-exposure`/`synth-meta`/`import-meta`), evidence **references** (`captures`/`imports` audit rows, no bytes), and headline `counts`. Carries **no AI API keys** (they live in `.env`, never in case state) and **no machine-specific config** — `ai-control`, `enrich-control` (external-enrichment opt-in stays off so the recipient re-opts-in), `notion`/`clickup-export` target ids, `velo-hunt` jobs, the anonymization maps and the transient analysis queue are all excluded by the allowlist. Import validates the envelope (format/version, allowlist re-applied so a hand-edited snapshot can only write allowlisted files), then restores into a **new** case — `POST` body `{ snapshot, targetCaseId? }` (or a bare snapshot); 409 when the id exists (re-import under a new id), 400 on a non-snapshot. The dashboard's **Export → Investigation snapshot** + **Import snapshot…** call these. Pure rules in `analysis/snapshot.ts` (`buildSnapshot`/`parseSnapshot`/`prepareImport`), I/O in `analysis/snapshotIo.ts`; no AI. |
| `GET /cases/:id/export/redacted` | Download a **redacted case package** (ZIP) for sharing with external parties (#54). The anonymized report (`report.md`/`report.html`), CSVs, and full state JSON have internal IPs / hosts / usernames / emails / paths replaced with **consistent tokens** (`ANON_HOST_1`…) and secrets one-way-redacted (`[REDACTED_SECRET]`); adversary indicators (public IPs, hashes, attacker domains) are preserved. Screenshots are **EXIF-stripped** and their detectable PII text is **blurred** (best-effort OCR — the same anonymizer + Tesseract path as the live vision redaction). AI provider keys + per-case config (`ai-control`, `enrich-control`, `anon-*`, capture logs, `case.json`) are **never included** — the package is built from a curated allowlist, and a `REDACTION-NOTES.txt` documents what was redacted/excluded plus the residual-risk caveats (faces and other non-text PII are not auto-detected). Query flags opt parts out: `?screenshots=0` `&blur=0` `&csvs=0` `&state=0` `&report=0`. Built fresh per request; the canonical on-disk report (real values) is untouched. The dashboard's **Export → Redacted case package (ZIP)** calls this. Pure ZIP writer (`zipArchive`, node:zlib), no archiver dependency. |
| `GET /timesketch/status` · `POST /cases/:id/push/timesketch` | Whether a Timesketch target is configured, and push the case's forensic timeline into a sketch (logs in, find-or-creates the sketch by name = case id, clean-replaces the managed timeline, uploads). Enabled by `DFIR_TIMESKETCH_URL` + `_USER` + `_PASSWORD`. |
| `GET /clickup/status` · `GET /cases/:id/clickup-export` · `POST /cases/:id/push/clickup` | Whether a ClickUp target is configured, the last export pointer (saved list id), and push the **Response Playbook** into a ClickUp list as tasks. Body `{ listId? }` falls back to the saved list, then `DFIR_CLICKUP_LIST_ID`. Each task carries status (mapped onto the list's real statuses), priority (critical→Urgent…low→Low), due date, and assignee/notes; **re-push UPDATES** the tasks it created (per-task ClickUp ids remembered in `state/clickup-export.json`, `ClickUpExportStore`) instead of duplicating. Enabled by `DFIR_CLICKUP_TOKEN` (501 otherwise). Hand-rolled `ClickUpClient` over an injectable `fetchFn`; pure `clickupMap` + `pushPlaybookToClickUp` orchestrator are unit-tested. |
| `GET /notifications/status` · `GET/POST/PUT/DELETE /notifications` · `POST /notifications/test` | **Notifications** (Settings → Notifications). Global CRUD over notification channels — **Slack** / **MS Teams** incoming webhooks, **SMTP email**, and **Telegram bot** — each with a severity threshold (`minSeverity`) and per-event toggles (`critical_finding` / `playbook_update` / `milestone`). Channels fire on **new/escalated findings** (after a real synthesis run), **playbook task add / status change**, and **investigation milestones** (case opened, report generated). Opt-in: the store starts empty; secrets (webhook URLs, SMTP passwords, bot tokens) are **redacted** in every response and preserved on a blank-field edit. `POST /notifications/test` sends a test to one channel (`{ channelId }`) or all, bypassing the filters. Pure core (`analysis/notifications.ts` filtering + builders, `notificationStore`) + per-type formatters/senders (`integrations/notify/*`, hand-rolled SMTP over an injectable connect, no `nodemailer`) are unit-tested with no network. Best-effort — a send failure never breaks the triggering request. `DFIR_PUBLIC_URL` deep-links the message back to the case; `DFIR_NOTIFY_CA`/`_INSECURE` for a self-hosted webhook host (e.g. Mattermost). |
| `GET /notion/status` · `POST /cases/:id/push/notion` | Whether a Notion target is configured, and export the case into a Notion page for collaboration. Body `{ mode: "new"\|"existing", page?, parent?, database? }`: *new* creates the page (a row in `DFIR_NOTION_DATABASE_ID`, else under `DFIR_NOTION_PARENT_PAGE_ID`); *existing* updates a page (URL/ID). All Companion content lives inside ONE managed toggle block it owns on the page; a re-export refreshes only that block — investigator notes/screenshots outside it are never touched. The target page + container id are remembered in `state/notion-export.json`. Enabled by `DFIR_NOTION_TOKEN` (share the page/database with the integration). |
| `GET /velociraptor/artifacts` · `GET/POST/DELETE /bundles` | **Triage bundles** (dashboard *Settings → Integrations*). `GET /velociraptor/artifacts` lists the configured server's collectable **CLIENT** artifacts (`artifact_definitions()` filtered to `type = CLIENT`) for the bundle builder. `/bundles` is global CRUD over named artifact bundles (built-in *Best Practice* + custom; bodies accept `{ name, artifacts, description?, defaultWaitMinutes?, timeoutSeconds?, params?, filters? }`). `params` is a per-artifact override map (`{ "Windows.Hayabusa.Rules": { "RuleLevel": "Critical, High, and Medium" } }`) passed to the hunt's `spec` so a heavy artifact emits less at the source; `filters` is a per-artifact VQL `WHERE` map (`{ "DetectRaptor.Generic.Detection.YaraFile": "NOT OSPath =~ 'pagefile'" }`) applied to `hunt_results` **before** the row cap to drop noise at the source. Bundles persist next to `cases/` in a `bundles/` dir. **Built-ins are editable in place**: `POST /bundles` with a built-in id writes an override; `DELETE /bundles/:id` removes a custom bundle **or resets an edited built-in** to its shipped default (404 only for an unknown non-built-in id). |
| `POST /cases/:id/velociraptor/run-bundle` · `GET …/hunt-jobs` · `POST …/collect` | Run a bundle as a **hunt** (`{ bundleId, waitMinutes?, minSeverity?, timeoutSeconds?, includeLabels?, excludeLabels?, os? }` → 202 `{ huntId, guiUrl, collectAt }`; `timeoutSeconds` overrides the per-collection timeout — Velociraptor default 600 s — for slow artifacts like THOR), then **auto-collect** after `waitMinutes` (default `DFIR_VELO_HUNT_WAIT_MIN` / per-bundle default; clamped 1–1440). **Multiple hunts run concurrently** — each is tracked separately by hunt id with its own auto-collect timer (a second run no longer drops the first). Collection ingests **both** the per-artifact result rows (the `{ "Artifact.Name": [rows] }` artifact-map fed to the deterministic **Velociraptor importer**) **and** any uploaded JSON reports (`huntUploads` reads `.json` uploads server-side — e.g. THOR/Hayabusa via `Generic.Scanner.ThorZIP` — each `detectImportKind`-routed to the right importer; HTML ignored). An optional `minSeverity` floor applies to the import. Records one combined import-meta diff + triggers synthesis. `hunt-jobs` returns the per-case job list (newest first; `state/velo-hunt.json`, survives restart) for the status cards + countdowns; `collect` (body `{ huntId }`, defaults to the latest) pulls a specific hunt **now** (early, or to re-pull stragglers). All 501 when `DFIR_VELOCIRAPTOR_API_CONFIG` is unset; the upload VQL is overridable via `DFIR_VELOCIRAPTOR_UPLOAD_VQL`. |
| `POST /cases/:id/velociraptor/suggest-hunts` | **AI-suggested fleet hunts** (issue #57). One text-only AI call over the synthesized findings / ATT&CK techniques / pivotable IOCs → `{ suggestions: [{ title, rationale, vql, severity, mitreTechniques, relatedFindingIds }] }`: proactive **Velociraptor VQL** hunts that run across **all** enrolled endpoints to find this case's tradecraft elsewhere. **Ephemeral** (no state change), returns `[]` without an AI call on an empty case (no findings/events). Needs an AI provider (501 otherwise) — does **not** need the Velociraptor API; the dashboard shows each hunt's VQL + rationale for review, then deploys the chosen one through `POST /velociraptor/hunt` (`launchHunt`). Pure pieces (`huntSuggest.ts`: schema, digest renderers, sanitizer) are unit-tested; cap via `DFIR_HUNT_SUGGEST_MAX` (default 8), prompt overridable via `DFIR_AI_HUNTS_PROMPT[_FILE]`. |
| `POST /cases/:id/playbook/suggest-hunts` | **AI-suggested playbook hunts** (issue #70). One text-only AI call over the **Response Playbook** + the case's known endpoints/findings/timeline → `{ suggestions: [{ taskId, title, rationale, vql, severity, mitreTechniques, mode, targetHost? }] }`: one **Velociraptor VQL** hunt per **endpoint-related** task. The **deploy mode is decided deterministically** from the case's *observed* endpoints (`playbookHunt.ts`): a task tied to exactly one host → `mode:"collection"` on that `targetHost`; otherwise → `mode:"hunt"` (fleet). A hallucinated/unobserved host is clamped to a fleet hunt. Returns `[]` without an AI call on an empty/closed playbook. Needs an AI provider + the playbook store (501 otherwise). Also **refreshes the Velociraptor client inventory in parallel** (best-effort) so a host enrolled mid-investigation is resolvable by deploy time, and grounds the model in the server's **real CLIENT artifacts** + the **dedicated Velociraptor hunt model** (`DFIR_AI_VELO_*`) when configured. **Persisted + incremental** (`state/playbook-hunts.json`, `PlaybookHuntStore`): suggestions survive a page refresh — `GET /cases/:id/playbook` returns the stored `huntSuggestions`, dropping any whose task was reworded/deleted (each task is fingerprinted at generation; `selectFreshHunts`). Re-pressing Generate only sends **new or changed** tasks to the model (`pendingHuntTasks`/`mergePersistedHunts`) and keeps the rest — never regenerating existing VQL; `{ force:true }` regenerates everything. Returns `{ suggestions, generated }`. The dashboard's Playbook panel shows each task's VQL + a mode badge (inline under each task, collapsible), then deploys via `POST /velociraptor/hunt` (fleet) or `POST /velociraptor/collect-host` (collection). Pure pieces unit-tested; cap via `DFIR_PBHUNT_SUGGEST_MAX` (default 30; press Generate again if the cap is hit), prompt overridable via `DFIR_AI_PBHUNTS_PROMPT[_FILE]`. |
| `POST /velociraptor/collect-host` · `POST /velociraptor/collect-results` | Launch the VQL as a **single-endpoint collection** (issue #70 — the playbook-hunt deploy path for a one-host task). `collect-host` `{ hostname, vql, description }`: resolves the host → `client_id` from the persisted **client inventory** (`matchClient`, short-name⇄FQDN tolerant; refreshes the inventory once on a miss), then runs `collect_client` on just that client → `{ clientId, flowId, hostname, artifact, sources, guiUrl }`. `collect-results` `{ clientId, flowId, artifact, sources }` reads that flow's rows (`source(client_id, flow_id, artifact/source)`) so the dashboard shows them **inline + auto-polls** (the per-flow analog of `/velociraptor/hunt-results`), not just a GUI deep link. 501 when the API is off; 502 when no enrolled client matches the host. |
| `GET /velociraptor/clients` · `POST /velociraptor/clients/refresh` | The persisted **client inventory** (issue #70) — host/FQDN ↔ `client_id` for every enrolled endpoint, in `velociraptor/clients.json` (`VelociraptorClientStore`, global, beside `cases/`). `GET` reads `{ updatedAt, clients }`; `POST …/refresh` snapshots the fleet now (`SELECT client_id, os_info FROM clients()` → `listClients`). Refreshed at startup (**retry-with-backoff** so a Velociraptor that's down at boot self-heals when it comes up), on a collect miss (self-healing), and from **Settings → Velociraptor → Refresh client list**. Resolving from this file avoids the brittle live `clients(search='host:<fqdn>')` lookup (the search index tokenizes the hostname on dots, so an FQDN search misses a short-name-enrolled client). |
| `GET /velociraptor/status` · `POST /velociraptor/reconnect` | **Reconnect** (Settings → Velociraptor, issue #84). `status` reports `{ configured, updatedAt, clients }` from the LIVE client + inventory. `reconnect` re-reads `DFIR_VELOCIRAPTOR_*` from `.env` (Settings only writes the file), **rebuilds the client**, and refreshes the inventory — which doubles as a reachability probe (`clients()` round-trips to the server). Mirrors the DFIR-IRIS reconnect (#88): lets the analyst connect after configuring Velociraptor, or after the server comes back online, **without the #1-gotcha restart** (the client is stateless — it spawns the binary per query — but a rebuild applies newly-saved config and flips it on if the config path wasn't set at boot). Also re-arms any persisted live monitors that couldn't start while the client was absent. Always 200; the body says `{ configured, ok, clients?, error? }`. `rebuildVelociraptorClient` is injectable (tests use a stub, no spawn). |
| `GET /velociraptor/event-artifacts` · `GET/POST/DELETE /cases/:id/velociraptor/monitors[/:mid][/stop\|start\|poll]` · `POST …/monitors/auto` | **Live CLIENT_EVENT monitoring** (issue #84). `event-artifacts` lists the server's continuous-monitoring artifacts (`type = CLIENT_EVENT`) for the picker. A monitor watches one such artifact (e.g. `Windows.Events.ProcessCreation`) on **one client OR all enrolled clients**: `POST /…/monitors` `{ clientId, artifact, pollSeconds?, hostname?, minSeverity? }` — or `{ allClients: true, artifact, … }` for the whole fleet (the all-clients read iterates `clients()` + `source()`, so no endpoint is picked) — starts it (202; idempotent per client+artifact, cursor starts at *now* so no history backfill). The server polls the monitoring result set every `pollSeconds` (`DFIR_VELO_MONITOR_POLL_S`, default 30, clamped 5–3600), wraps new rows as a Velociraptor artifact-map, and runs the **streamed import** path (persist → `importVelociraptor` → import-meta diff → whitelist/NSRL → re-synthesize). `POST …/monitors/auto` discovers every artifact already enabled in Velociraptor's **Client Monitoring** table (`get_client_monitoring()`) and starts an all-clients monitor for each (422 with guidance when none configured). The last-seen cursor + stats persist per monitor in `state/velo-monitor.json` (`VeloMonitorStore`) so a restart **resumes without re-ingesting**; a poll error is captured (`status:"error"`, `lastError`) **without** advancing the cursor (retried next tick). `…/:mid/stop` clears the timer + marks stopped (keeps the cursor); `…/start` resumes; `…/poll` polls now; `DELETE …/:mid` removes it. All 501 when `DFIR_VELOCIRAPTOR_API_CONFIG` is unset; the per-client / all-clients / discovery VQL are overridable via `DFIR_VELOCIRAPTOR_MONITOR_VQL` / `_MONITOR_ALL_VQL` / `_MONITORED_VQL`. The Companion only **reads** the stream — the artifact must already be enabled in Velociraptor's Client Monitoring for the target client(s). Pure poll loop in `integrations/velociraptor/monitorPoller.ts`. |
| `POST /cases/:id/push` · `GET/POST/DELETE /cases/:id/push-token[/generate]` | **Generic push ingest** (issue #84). An external tool POSTs an alert payload — any shape `importDetect` routes (a Velociraptor artifact-map, a SIEM alert, a Hayabusa line, `{ source, events:[…] }`, or raw text/NDJSON) — with an `X-DFIR-Key` header (or `Authorization: Bearer`); the server detects the kind and runs the **same** import → diff → re-synthesize pipeline as the Import button, responding **202** immediately. **Auth** (`analysis/pushAuth.ts`, constant-time compare): a **global** token (`DFIR_PUSH_TOKEN`) and/or a **per-case** token (`state/push-token.json`, `PushTokenStore`) — push is **403 (disabled)** until one is set, **401** on a missing/wrong key. Token routes manage the per-case secret: `GET …/push-token` returns `{ configured, token, globalConfigured, pushUrl }`, `POST …/push-token/generate` mints a 128-bit token, `DELETE` clears it (Settings → Integrations → Push ingest). The payload normalizer is pure (`analysis/pushPayload.ts`). |
| `GET /cases/:id/asset-graph` | The **asset ↔ IoC graph**: `{ assets, iocs, edges }` — compromised assets (hosts from each event's `asset`, accounts parsed from event text) and the IoCs that touched each. Derived on demand with the report's scope/legitimate filtering. Powers the dashboard's *Compromised Assets* section and graph. |
| `GET /cases/:id/evidence-graph` | The **evidence chain graph** (causal): `{ nodes, edges }` — `spawned` (process trees, parent→child keyed by `(asset, process)`) and `lateral_move` (same **hash** across hosts, high confidence; same **account** across hosts, medium) edges. Each edge carries `confidence` + the `rule` that derived it + `basis` + backing `eventIds`. Pure (`buildEvidenceGraph`), no AI, derived on demand with the report's scope/legitimate filtering. Powers the dashboard's *Evidence Chain* panel and report §4.8. |
| `GET /cases/:id/ioc-sources` | **Per-IOC corroboration**: `{ iocId: [tools that observed it] }` — derived on demand by matching each IOC value against the forensic events' `sources` (indexed exact-token match; same scope/legitimate filtering as the report). Powers the dashboard's **⊕ N sources** badge; also feeds the report IOC table + CSV `sources`/`sourceCount` columns. Pure (`deriveIocSources`), no AI. |
| `GET /cases/:id/phases` | The **temporal attack phases**: `AttackPhase[]` — the forensic timeline grouped into bursts of activity by the time gap between consecutive events (threshold `DFIR_PHASE_GAP_S`, default 5 min). Each phase carries `{ id, label (dominant ATT&CK tactic), startTimestamp, endTimestamp, eventIds, inferredTechniques, eventCount, maxSeverity }`. Pure (`buildAttackPhases`), no AI, derived on demand with the report's scope/legitimate filtering. Powers the dashboard's *Attack Phases* panel and report §3.2. |
| `GET /cases/:id/beacon-candidates` | **Beacon / C2 candidates**: `BeaconCandidate[]` — outbound connection channels (source host → destination IP:port) whose inter-arrival intervals are too regular to be human traffic, the classic C2 callback signature. Each carries `{ id, source, destIp, destPort?, eventCount, intervalSeconds, jitterSeconds, jitterPct, firstSeen, lastSeen, severity, external, eventIds }`. Derived from the forensic timeline's network events (`srcIp`/`dstIp`/`port`/`asset`); a tuple needs ≥ `DFIR_BEACON_MIN_COUNT` events (default 5) and jitter ≤ `DFIR_BEACON_MAX_JITTER_PCT` (default 20%). Severity High when the destination is a public IP (likely external C2), else Medium. Pure (`detectBeacons`), no AI, derived on demand with the report's scope/legitimate filtering. A hunting lead, **not a verdict**. Powers the dashboard's *Beacon Candidates* panel and report §4.9. |
| `GET /cases/:id/timeline-gaps` | **Log gap analysis**: `TimelineGap[]` — suspiciously long silent periods in the forensic timeline. Each carries `{ id, startTimestamp, endTimestamp, durationSeconds, durationLabel, severity, complete, silentSources, activeSources, beforeEventId, afterEventId }`. A **complete** gap (every source dark) is High and earns a finding (the cleared-logs/stopped-collector signature, MITRE T1070); a **partial** gap (one tool quiet while others log) is Medium. A gap must clear the floor `DFIR_GAP_MIN_MINUTES` (default 30) AND either overlap `DFIR_GAP_ACTIVE_HOURS` (when set) or be ≥ `DFIR_GAP_DENSITY_FACTOR` × the timeline's median cadence (default 4) — so naturally-sparse timelines aren't noisy. Pure (`detectTimelineGaps`), no AI, derived on demand with the report's scope/legitimate filtering. A lead, **not proof** of tampering. Powers the dashboard's *Timeline Gaps* panel and report §3.3. |
| `POST /cases/:id/timeline-gaps/hypothesize` | **Gap hypothesis generation + shadow-artifact hunting** (issue #96). One text-only AI call over the **flagged gaps** (worst-first, capped `DFIR_GAP_HYPOTHESIS_MAX`, default 5) and each gap's **surrounding events** (the events just before/after the silence, `DFIR_GAP_HYPOTHESIS_CONTEXT` per side, default 8) → `{ caveat, hypotheses: [{ gapId, gap, hypothesis, attackerActions, confidence, severity, mitreTechniques, recommendedArtifactIds, targetHosts, shadowArtifacts }] }`: the AI hypothesises what the attacker did during each silent window, grounded in the context. Each gap is also paired with a **deterministic** catalog of *shadow artifacts* — USN Journal, SRUM, Prefetch, Amcache, ShimCache, BAM, MFT, UserAssist, LNK — that the OS keeps independently of the tampered log, each with a deployable **Velociraptor VQL** collection to reconstruct the missing time frame (so a gap the AI skips still carries collections). **Ephemeral** (no state change), returns `{ hypotheses: [] }` without an AI call when no gap is flagged. Needs an AI provider (501 otherwise) — does **not** need the Velociraptor API; the dashboard shows each hypothesis + its collections for review, then deploys a chosen one through `POST /velociraptor/hunt`. Pure pieces (`shadowArtifacts.ts` catalog; `gapHypothesis.ts` schema/renderers/combiner) are unit-tested; prompt overridable via `DFIR_AI_GAPHYP_PROMPT[_FILE]`. |
| `GET /cases/:id/adversary-hints` | **Adversary group hints**: `{ attackVersion, groupCount, caseTechniqueCount, minOverlap, caveat, hints[] }` — known MITRE ATT&CK groups ranked by how many of the case's identified techniques they also use (each hint: `{ id, name, aliases, description, url, overlapCount, exactCount, overlapTechniques, exactTechniques, groupTechniqueCount, score }`). **Hybrid, sub-technique-aware**: an exact sub-technique match (T1059.001 ↔ T1059.001) scores full, a base-only match (T1059.001 vs T1059.003, or a case tagged at bare T1059) scores half — so `score = exactCount + 0.5·(overlapCount − exactCount)` ranks focused actors above ones that merely share the broad technique, while breadth (`overlapCount`, base-or-better) still drives the `minOverlap` threshold. Scored offline from the bundled `data/attack-groups.json` (no AI, no network) with the report's scope/legitimate filtering; thresholds `DFIR_ADVERSARY_MIN_OVERLAP` (default 3) / `DFIR_ADVERSARY_TOP_N` (default 5). Hypothesis fuel, **not attribution**. Pure (`rankAdversaryGroups`). Powers the dashboard's *Adversary Hints* panel and report §4.6.1. |
| `GET /cases/:id/report-meta` | Human-authored report metadata (optional company name + logo branding, title page, distribution, BIA, limitations, glossary, recommendations…) for the case, or defaults. Stored in `state/report-meta.json` (the logo inline as a base64 data URI). |
| `PUT /cases/:id/report-meta` | Replace the report metadata with a normalized payload (unknown keys dropped, wrong-typed fields defaulted). The dashboard's **Case Details** panel calls this; values merge into `report.md` on generation. |
| `GET /report-templates` · `GET /report-templates/:id` · `POST /report-templates` · `DELETE /report-templates/:id` | **Custom report templates** (#60) — GLOBAL branded layouts: accent colour, cover title/subtitle, running header/footer (with `{{organization}}`/`{{incidentId}}`-style placeholders + `{{#if}}` blocks), and per-section enable/reorder. Built-ins (`standard`, `executive-brief`, `technical-detailed`) are editable in place (saving under a built-in id writes an override; `DELETE` resets it). Stored in `report-templates/` beside `cases/`. Managed in **Settings → Report Templates**. |
| `GET /cases/:id/report-template` · `PUT /cases/:id/report-template` | The per-case selection (`{ templateId }`, default `standard`) of which report template renders the case's report. Stored in `state/report-template.json`; chosen from the **Case Details** picker. The chosen template flows to the Markdown, HTML, and Word exports. A deleted/dangling selection falls back to the default. |
| `GET /cases/:id/mobile-summary` | **Mobile companion summary**: a compact, READ-ONLY projection for the phone PWA — `{ caseId, caseName, updatedAt, summary, severityCounts, counts: { findings, events, iocs, openThreads, flaggedIocs, techniques }, findings, events, iocs }`. Findings are worst-first; events are most-severe-then-most-recent; IOCs are flagged-first (each with its worst threat-intel `verdict`) — every heavy list capped (`DFIR_MOBILE_MAX_FINDINGS`/`_EVENTS`/`_IOCS`) with a pre-cap `total` so the UI shows "N of M". Same scope/legitimate filtering as the report. Pure (`buildMobileSummary`), no AI. Powers `/mobile`. |
| `GET /dashboard` | Live dashboard page. |
| `GET /mobile` | **Mobile companion** — installable, read-only PWA (case status, findings, timeline, IOCs) for quick glances during IR. Navigate directly to `http://127.0.0.1:4773/mobile` from your phone/tablet (requires `DFIR_HOST=0.0.0.0` or a tunnel since the server binds localhost by default). Backed by `/cases/:id/mobile-summary`; `/manifest.webmanifest` + `/sw.js` make it installable with an offline app-shell. |
| `WS /ws?caseId=<id>` | Live state + AI-status push for the dashboard. |

CORS (incl. Private Network Access) is enabled so the browser extension can reach
the server from a `chrome-extension://` origin.

## Setting up Telegram notifications

Telegram channels use a **Bot API** bot token + a chat/channel/group ID. No env vars
are needed — everything is stored in `notifications/config.json` alongside `cases/`.

**1. Create a bot and get its token**

Open a chat with [@BotFather](https://t.me/BotFather) in Telegram, run `/newbot`, and
follow the prompts. BotFather returns a token in the form `123456789:AAF...`. Copy it.

**2. Get the chat ID**

| Destination | How to get the chat ID |
| --- | --- |
| Private chat with yourself | Search for your bot, send `/start`, then open `https://api.telegram.org/bot<TOKEN>/getUpdates` in a browser — the `chat.id` in the first result is your user ID (a positive integer). |
| Group | Add the bot to the group, send any message, open `getUpdates` — the `chat.id` is a negative integer. |
| Public channel | The username works directly as the chat ID: `@mychannel`. |
| Private channel | Add the bot as an **administrator**, forward any channel post to `@userinfobot` or `@getidsbot`, which reports the channel's numeric ID (usually `-100…`). |

**3. Add the channel in the dashboard**

Go to **Settings → Notifications**, choose **Telegram bot**, paste the bot token and chat
ID, set your severity threshold and event toggles, then click **Add**. Hit **Test** to
confirm a message arrives.

The bot token is stored in `notifications/config.json` (beside `cases/`) and is **never
echoed back to the browser** — the dashboard only sees whether a token is set.

## NSRL known-good hashes (#63)

A known-software hash matches a benign OS/application file, so flagging it lets the Companion
**auto-mark the matching forensic event / IOC legitimate** (reversibly) and drop it from findings —
cutting false positives. Two backends, used together (a hash is known-good if **either** has it):

**1. Flat hash set** — for a small, curated list. Manage it in **Settings → NSRL**: paste an
`NSRLFile.txt` (RDS CSV), a hashdeep CSV, or a hash-per-line list; load a file off the server by path;
or pre-load at startup with `DFIR_NSRL_FILE` (`;`-separated paths). Stored normalized in
`nsrl/known-hashes.txt`, held in memory.

**2. The full NSRL RDS SQLite database** — for the real ~160 GB Reference Data Set, which is far too
large to load into memory. The Companion **queries it on demand** (one indexed point-lookup per hash),
read-only, via Node's built-in SQLite. Point at it with `DFIR_NSRL_DB=<path-to.db>` or connect it in
**Settings → NSRL**.

Matching keys on **sha256 + md5** (what forensic events/IOCs carry), *not* sha1 — so index the column(s)
you query. One-time setup (significantly speeds up every lookup):

```powershell
# Download the "Modern RDS minimal" SQLite set (RDS_*.db) from the NSRL site, then:
sqlite3 "D:\NSRL\RDS_2026.03.1_modern.db" "CREATE INDEX IF NOT EXISTS idx_metadata_sha256 ON METADATA(sha256);"
# (optional, if you also want md5 matches)
sqlite3 "D:\NSRL\RDS_2026.03.1_modern.db" "CREATE INDEX IF NOT EXISTS idx_metadata_md5 ON METADATA(md5);"
sqlite3 "D:\NSRL\RDS_2026.03.1_modern.db" "ANALYZE;"
```

The hash column lives on the `METADATA` base table (`FILE` is a view), which the Companion auto-detects.

> **"database or disk is full" while building the index?** The sort spills tens of GB to `%TEMP%` on
> C:. Redirect it to the DB's drive first: `mkdir D:\NSRL\sqlite_tmp` then
> `set SQLITE_TMPDIR=D:\NSRL\sqlite_tmp` before launching `sqlite3` (or `PRAGMA temp_store_directory='D:\NSRL\sqlite_tmp';`).

**Opt-in by design:** both backends start empty/disconnected. NSRL is *known*, not strictly
*known-good* — some RDS sets include hacktools, and a known hash can still be malicious in context
(DLL side-loading, a renamed LOLBin) — and every match is reversible from *Confirmed Legitimate*.

## CISA KEV integration (#99)

The [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
lists CVEs that are **actively exploited in the wild** — not just theoretical risks. When the catalog is loaded,
the Companion scans your forensic timeline event descriptions and IOC values for CVE IDs and cross-references
them against the catalog. Matches are surfaced in two places:

- **Synthesis context** — KEV-matched CVEs are prepended to every synthesis and `ask` prompt so the AI can flag them
  as high-probability initial access vectors with exact product + patch information.
- **Report §4.5.1** — a dedicated CISA KEV correlation table in the Investigation section lists each matched CVE,
  the vendor/product, CISA's required action, and whether it was used in a ransomware campaign.

**Loading the catalog:** go to **Settings → KEV** and click **Load from CISA feed** (requires server outbound internet),
or point to a locally-saved copy with **Load from file** (for air-gapped deployments). The catalog is stored in
`kev/catalog.json` (beside `cases/`); it is global and shared across all cases. Reload it periodically as CISA
updates the catalog.

**Opt-in by design:** the catalog starts empty. A KEV match is a strong hypothesis (the CVE is actively
exploited), not proof of exploitation in this specific case — the AI is told this explicitly.

## Case folder layout

    cases/<caseId>/
      case.json
      screenshots/000001_<ts>_<tab-title>.webp   evidence (raw screenshots; title is slugified — OS-reserved chars stripped, capped at 60 chars; falls back to 000001_<ts>.webp when the title has no safe characters)
      imports/0001_<name>.csv             evidence (raw uploaded CSV / log / THOR / SIEM-EDR JSON result exports)
      imports/0002_<name>.log             evidence (raw uploaded log files — firewall, syslog, sshd, IIS/Apache/nginx, app logs)
      metadata/captures.jsonl             append-only audit trail
      metadata/imports.jsonl              append-only import audit trail (CSV + log + THOR + SIEM/EDR + Chainsaw/EVTX + Hayabusa + Velociraptor + Suricata/Zeek + KAPE/EZ + Cyber Triage + M365/Entra + AWS CloudTrail + GCP/Azure + Plaso + Sandbox + Memory + Email + auditd + journald + sysdig/Falco + Wazuh uploads share the same sequence)
      logs/session-<time>.log             per-case audit trail (AI calls / captures / OCR / anonymization / enrichment for this case; one file per server session, DFIR_LOG_LEVEL)
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

**Capture-only mode (the default).** AI analysis is **off by default** per case, so a
fresh app start or a new case captures screenshots as evidence without running any AI
until you opt in — the same OPSEC/cost-first stance as threat-intel enrichment. The
dashboard's **AI: ON/OFF** button (per case) turns live analysis on; when you switch it
on, the server automatically analyzes everything captured while it was off (tracked by
`lastAnalyzedSeq` in `state/ai-control.json`), then synthesizes. Explicit imports
(CSV / log / THOR / SIEM-EDR JSON) always analyze regardless of this toggle.

**Anonymization (default on).** Before any text is sent to the LLM (screenshot-window
context, CSV, log, Ask, synthesis), sensitive *victim* data is replaced with reversible
typed tokens (`ANON_HOST_1`, `ANON_USER_2`, …) and secrets are one-way-redacted to
`[REDACTED_SECRET]`. The model's response is restored to real values before it reaches
the timeline, IOCs, findings, or the dashboard — so `InvestigationState` and all exports
always contain the real data ("tokenize-in-transit").

- **Tokenized (victim / internal):** RFC 1918 / loopback / CGNAT internal IPs, known
  hostnames / FQDNs, `DOMAIN\user` / internal-UPN accounts, internal / AD domains,
  emails, and the username segment of user-profile paths (`C:\Users\<name>\…`).
- **Preserved (adversary / IOC):** public IPs, malware hashes, attacker domains — so
  threat signal and threat-intel enrichment survive with real indicators.
- **Secrets** (AWS keys, JWTs, GitHub/Slack tokens, `password=` / `Authorization: Bearer …`,
  URL credentials) are **one-way redacted** (`[REDACTED_SECRET]`), never restored.
  Hashes are deliberately NOT treated as secrets.
- **Per-case control** via the dashboard **Anon** button: enable/disable, choose which
  of the six categories to tokenize, toggle secret redaction. Persisted in
  `state/anon-control.json`. Toggling forces a re-synthesis so conclusions reflect the new
  wire policy.
- **Entity list (transparency + manual additions).** The Anon modal shows the
  *auto-derived* entities (hosts / accounts / internal domains derived from the case
  timeline — read-only, grows as the investigation does) and lets the analyst
  **add/remove custom entities** (value + category, including a free-form **"Other"**
  for codenames). Custom entities are tokenized by exact match even if that category's
  detector is off. Persisted in `state/anon-entities.json`.
- **Screenshots are OCR-redacted (best-effort).** With an external vision model, each
  screenshot is run through local OCR (Tesseract.js, on-box — no cloud OCR API) **before**
  it is sent: words matching the case entity set are covered with opaque black rectangles in
  an **in-memory** copy. The original screenshot files on disk are never modified. OCR is
  best-effort, so the dashboard still warns when anon is on and the vision model is external.
  Pointing `DFIR_AI_MODEL` at a local Ollama vision model keeps screenshots on-box and skips
  OCR entirely.
  - **Visibility:** a one-line `[OCR] case=… redaction ran on N screenshot(s) — scrubbed M
    word(s)…` is logged whenever the pre-pass runs (so you can tell the redacted path ran vs.
    images going to the model un-redacted). `DFIR_OCR_DEBUG=1` adds a per-screenshot line —
    words OCR read and **which** were blacked out (local log only). `DFIR_OCR_DEBUG_DIR=<path>`
    also writes each redacted copy sent to the model to `<path>/<caseId>/` so you can eyeball
    the boxes; the original evidence is never touched.
- `DFIR_ANONYMIZE=off` flips the default for **new** cases (existing cases keep their
  saved setting).

**Live capture and conclusions.** While you browse, the per-window extraction builds
the forensic timeline + investigation log. Screenshots are analyzed in **windows** (a
window of `--window` captures, default 4); a `timer`/`click` capture buffers until the
window fills, while a page **navigation** or **tab switch** flushes the buffer early. So
the AI doesn't always wait for four — a navigation flushes a lone screenshot immediately — but a
single hotkey snap (trigger `timer`) followed by idle would otherwise sit unanalyzed. A
**safety-net sweep** (`DFIR_FLUSH_INTERVAL_MS`, default 5 min; `0` disables) drains any
leftover buffer on its interval so even one screenshot is eventually analyzed. Findings,
MITRE and the attacker path come from the synthesis pass, which by default now runs
**automatically and debounced** during live capture (`DFIR_AI_AUTO_SYNTHESIZE=on`, ~8 s
after the last screenshot in a burst) and pushes updates to the dashboard. You can also trigger it manually with the
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
