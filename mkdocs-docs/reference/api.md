# Scripting & API

Every button in the dashboard calls an HTTP endpoint on the Companion. A script can call the same
endpoints. Use this page to automate the common jobs: create a case, send evidence in, wait for the
analysis, and pull the results out.

This page covers the stable, script-friendly endpoints only. The dashboard uses several hundred more.
Those change between releases, so do not build on them.

!!! info "Base URL"
    All examples use `http://127.0.0.1:4773`, the default. Change the port with `DFIR_PORT`.
    The examples use `curl` and `jq`. A Python version of the full workflow is at the
    [end of the page](#full-example-in-python).

---

## Before you start

### Authentication

How a script authenticates depends on the authentication mode (`DFIR_AUTH_MODE`).

**Single-user mode (the default).** No credential is necessary. The server listens on `127.0.0.1`
only, and the listen address is the protection. There are two exceptions:

- **Push ingest** (`POST /cases/<id>/push`) always needs a push token. See
  [Push ingest](#push-ingest-webhook).
- **A password-protected case** needs an unlock cookie. See [Locked cases](#locked-cases).

**Team mode** (`DFIR_AUTH_MODE=team`). Every request needs a credential. For scripts, use a
**service token**:

1. Sign in to the dashboard as a case administrator.
2. Create a service token for the case, with the scopes the script needs (see
   [Team Accounts & Case Roles](team-authentication.md)).
3. Copy the token. It starts with `dfirsvc_`. The Companion shows the token one time only.
4. Send it on every request:

```bash
curl -H "Authorization: Bearer $DFIR_TOKEN" http://127.0.0.1:4773/cases
```

| Token scope | Lets the script |
|---|---|
| `read` | Read case state, the timeline, jobs for the case |
| `write` | Everything `read` does, plus import, push, synthesize, change the case |
| `export` | Download reports, CSV/JSONL timelines, the custody manifest |
| `review` | Accept or reject second-opinion changes |
| `capture` | Send screenshots to `POST /captures` (use with `write`) |

Service-token limits:

- A service token belongs to **one case**. It cannot see or change other cases.
- A service token **cannot create cases**, cannot read the jobs list (`/api/jobs`), and cannot call
  any administrator endpoint. For those, sign in with a user account instead:
  `POST /auth/local/login` with `{"username": "...", "password": "..."}`. Keep the `dfir_session`
  cookie, and send the `csrfToken` from the response as the `X-DFIR-CSRF` header on every
  non-GET request.
- A service token gets no live WebSocket updates. Poll instead.

### Request rules

- **Send JSON.** Set `Content-Type: application/json` on every request with a body. The push
  endpoint also accepts `text/plain` and `application/x-ndjson`.
- **No file uploads (multipart).** To send a file, put its content in a JSON string field. The
  import examples below show how with `jq`.
- **Size limit.** A request body can be up to 256 MB (`DFIR_MAX_BODY_MB`). Over the limit, the
  server returns `413`. For a larger file on the server's own disk, use
  [Import a file from the server's disk](#import-a-file-from-the-servers-disk).
- **Do not send an `Origin` header.** The server blocks browser origins it does not know. `curl`
  and Python `requests` do not send one, so this rule only matters for custom HTTP clients.
- **Case ids** are 1–80 characters: letters, digits, `.`, `_`, `-`. The first character is a
  letter or digit.

### Status codes you will see

| Code | Meaning |
|---|---|
| `200` / `201` | Done |
| `202` | Accepted. The work continues in the background |
| `400` | The request is wrong. The `error` field says why |
| `401` | No credential, a wrong credential, or a locked case |
| `403` | Your role does not allow it, or the server runs in demo mode |
| `404` | The case does not exist, or you have no access to it |
| `409` | The case waits for an analyst decision, or the item already exists |
| `413` | The body is too large |
| `423` | The case is closed or archived. Reopen it first |
| `429` | Rate limit. Wait and try again |
| `501` | The feature is not configured (for example, no AI provider) |

Every error body is JSON: `{"error": "<reason>"}`.

**Rate limits:** imports are limited to 300 per minute per case (`DFIR_IMPORT_RATE_MAX`). AI
calls, and CSV or log imports that need AI, are limited to 20 per minute per case.

---

## Cases

### Create a case

```bash
curl -s -X POST http://127.0.0.1:4773/cases \
  -H 'Content-Type: application/json' \
  -d '{"caseId": "IR-2026-001", "name": "Finance ransomware", "investigator": "analyst1"}'
```

| Field | Required | Notes |
|---|---|---|
| `caseId` | yes | See the case-id rule above |
| `name` | yes | Display name |
| `investigator` | no | In team mode, the server uses the signed-in user's name |
| `incidentTypeId` | no | Applies that incident type's playbook. List the ids with `GET /incident-types` |
| `templateId` | no | Seeds key questions and next steps from a case template |

Returns `201` with the case. Returns `409` if the id exists.

`GET /api/next-case-id` gives a suggested id if you do not have your own numbering.

### List cases

```bash
curl -s http://127.0.0.1:4773/cases | jq '.[] | {caseId, name, status}'
```

There is no endpoint for one case. To read one case, use
[`GET /cases/<id>/state`](#read-the-case-state).

### Close, reopen, set the incident type

```bash
# Close (closed cases refuse new evidence with 423)
curl -s -X PATCH http://127.0.0.1:4773/cases/IR-2026-001/status \
  -H 'Content-Type: application/json' -d '{"status": "closed"}'

# Reopen
curl -s -X PATCH http://127.0.0.1:4773/cases/IR-2026-001/status \
  -H 'Content-Type: application/json' -d '{"status": "open"}'

# Set the incident type (merges its questions; add "replace": true to replace them)
curl -s -X POST http://127.0.0.1:4773/cases/IR-2026-001/incident-type \
  -H 'Content-Type: application/json' -d '{"typeId": "ransomware"}'
```

Archive, restore and delete are case-administrator actions. They are in the
[Case Management](cases.md) page and are not repeated here.

### Locked cases

A case with a password refuses most requests with `401 {"error": "locked"}`. `/import` and `/push`
work without an unlock. For everything else, unlock first and keep the cookie:

```bash
curl -s -c jar.txt -X POST http://127.0.0.1:4773/cases/IR-2026-001/unlock \
  -H 'Content-Type: application/json' -d '{"password": "case-password"}'

curl -s -b jar.txt http://127.0.0.1:4773/cases/IR-2026-001/state
```

Five wrong passwords start a lockout (`429` with a `Retry-After` header).

---

## Getting evidence in

There are three ways in. All three run the same pipeline as the dashboard's **Import** button:
format detection, the content tagger, severity grading, and (if AI is on for the case) a
background synthesis.

| Way | Use it when |
|---|---|
| [`POST /cases/<id>/import`](#import-a-file) | A script has a file and sends its content |
| [`POST /cases/<id>/import-file`](#import-a-file-from-the-servers-disk) | The file is already on the Companion machine, or it is larger than the body limit |
| [`POST /cases/<id>/push`](#push-ingest-webhook) | Another tool sends events as they happen (SIEM, SOAR, webhook) |

### Import a file

The server detects the format from the content and the file name, the same as a drag-and-drop.

```bash
jq -Rs '{text: ., filename: "hayabusa.csv", minSeverity: "medium", assetHost: "WS-042"}' hayabusa.csv \
  | curl -s -X POST http://127.0.0.1:4773/cases/IR-2026-001/import \
      -H 'Content-Type: application/json' --data-binary @-
```

| Field | Required | Notes |
|---|---|---|
| `text` | yes | The file content as a string. `json` or `csv` also work as the field name |
| `filename` | no | Helps format detection, and names the stored evidence file. Always send it |
| `minSeverity` | no | `critical`, `high`, `medium`, `low` or `info`. Events below it are not imported |
| `assetHost` | no | The host these records belong to, when the file does not say |

Returns `202`:

```json
{ "accepted": true, "kind": "hayabusa", "file": "0007_hayabusa.csv", "minSeverity": "Medium" }
```

The Companion saves the evidence and records it in chain of custody **before** it answers. The
parsing runs in the background. To know when it ends, see
[Wait for background work](#wait-for-background-work).

If AI is off for the case and the format needs AI (a generic CSV or log), the response adds
`"analyzed": false, "reason": "ai-off"`. The file is kept as evidence but not parsed.

If the file is JSON that no importer recognises, it is imported as generic SIEM events
(`"kind": "siem"`, default severity Low) and the response adds a `"warning"` sentence that says so.

!!! note "Binary files"
    `text` is a string, so this endpoint takes text formats: CSV, JSON, JSONL, logs. A binary file,
    such as an executable or a raw `.evtx`, is refused with `400` and `"refused": true`, here and
    in `import-file` below. Convert it first (for example, a raw `.evtx` with Hayabusa or
    EvtxECmd) and import the output. UTF-16 exports with a byte-order mark import normally.

### Import a file from the server's disk

```bash
curl -s -X POST http://127.0.0.1:4773/cases/IR-2026-001/import-file \
  -H 'Content-Type: application/json' \
  -d '{"path": "/evidence/plaso_supertimeline.csv", "minSeverity": "low"}'
```

- `path` is an absolute path **on the Companion machine**, not on the machine that runs the script.
  A relative path is refused with `400`.
- The Companion's own configuration file (`.env`) and the cases root are refused with `403`. The
  one exception is this case's `drop/` folder, so a file the drop folder refused as too large can
  still be imported from there.
- A Plaso CSV streams from disk with no size limit. Other formats have a limit of 256 MB
  (`DFIR_MAX_IMPORT_FILE_MB`).
- In team mode, this endpoint needs a **global administrator**, because it reads the server's disk.
  A service token cannot call it.
- Returns `202`, the same as `/import`.

### Push ingest (webhook)

Push ingest is for tools that send events, not files. It needs a push token, in both modes.

**Get a token:** either set `DFIR_PUSH_TOKEN` (one token for every case), or make a token for one
case in **Settings → Integrations**, or with the API:

```bash
PUSH=$(curl -s -X POST http://127.0.0.1:4773/cases/IR-2026-001/push-token/generate | jq -r .token)
```

The token is shown one time only. Generating again replaces it.

**Send events:**

```bash
curl -s -X POST http://127.0.0.1:4773/cases/IR-2026-001/push \
  -H "X-DFIR-Key: $PUSH" -H 'Content-Type: application/json' \
  -d '{"source": "wazuh-webhook", "events": [
        {"timestamp": "2026-09-28T10:14:03Z",
         "rule": {"level": 12, "description": "Mimikatz detected"},
         "agent": {"name": "WS-042"}}
      ]}'

# Or raw NDJSON, one event per line
curl -s -X POST http://127.0.0.1:4773/cases/IR-2026-001/push \
  -H "X-DFIR-Key: $PUSH" -H 'Content-Type: application/x-ndjson' \
  --data-binary @alerts.ndjson
```

- The body can be `{"source": ..., "events": [...]}`. The array can also be called `rows`,
  `records`, `data` or `results`.
- `source` names the stored evidence file (`push_<source>.json`). Add `filename` to help format
  detection.
- `Authorization: Bearer <push token>` also works in place of `X-DFIR-Key`.
- Returns `202 {"accepted": true, "kind": ..., "source": ...}`. The import runs in the background.
- If the payload is JSON that no importer recognises, the `202` adds the same `"warning"` sentence
  as `/import`, and the case log gets a WARN line.
- No token configured → `403`. Missing or wrong key → `401`.
- **Team mode:** send a service token with `write` scope as `Authorization: Bearer dfirsvc_...`.
  A push key alone gets `401`.

---

## Wait for background work

Imports and push ingest answer `202` at once and run in the background. Poll the jobs list:

```bash
curl -s 'http://127.0.0.1:4773/api/jobs?caseId=IR-2026-001' \
  | jq '.jobs[] | {id, kind, label, status, detail}'
```

- `kind` is `import`, `synthesis`, `enrichment`, `deep-pass`, `mcp` or `second-opinion`.
- `status` is `queued`, `running`, `succeeded`, `failed`, `cancelled` or `interrupted`.
- An import job's `label` is `<kind>: <file>`, where `<file>` is the `file` value from the
  import response. Match on it to find your import.
- `GET /api/jobs/<jobId>` returns one job. `POST /api/jobs/<jobId>/cancel` stops it.

To wait for the AI side, poll `GET /cases/<id>/ai-state` until `state` is not `analyzing`:

```bash
until [ "$(curl -s http://127.0.0.1:4773/cases/IR-2026-001/ai-state | jq -r .state)" != "analyzing" ]; do
  sleep 10
done
```

`state` is `off`, `idle`, `analyzing`, `blocked` or `error`. `blocked` means the case waits for an
analyst decision (for example, a duplicate-host merge). A script cannot make that decision.

!!! warning "Team mode"
    A service token cannot read `/api/jobs`. Poll `/cases/<id>/ai-state` instead, which a
    `read` token can call.

---

## Running the analysis

### Turn AI on for a case

```bash
curl -s -X POST http://127.0.0.1:4773/cases/IR-2026-001/ai-control \
  -H 'Content-Type: application/json' -d '{"enabled": true}'
```

Turning AI on analyzes the evidence already in the case, in the background. After that, every
import that finishes starts a new synthesis by itself.

### Re-synthesize

```bash
curl -s -m 1800 -X POST http://127.0.0.1:4773/cases/IR-2026-001/synthesize \
  -H 'Content-Type: application/json' -d '{}'
```

This call **waits** until the synthesis ends, which can take many minutes. Give the client a long
timeout (`-m 1800` is 30 minutes). The response has counts:
`{"findings": 12, "mitreTechniques": 9, "forensicEvents": 340, ...}`.

- `409` with `"error": "host_merge_decision_required"` or `"presidio_approval_required"`: an analyst
  must decide in the dashboard first.
- `423`: the case is closed.
- `501`: no AI provider is configured.

### Deep pass

The deep pass reads every forensic-timeline event at or above a severity floor in batches.

```bash
# See the cost first
curl -s http://127.0.0.1:4773/cases/IR-2026-001/deep-pass/preview

# Run it (waits until done)
curl -s -m 3600 -X POST http://127.0.0.1:4773/cases/IR-2026-001/deep-pass \
  -H 'Content-Type: application/json' -d '{"minSeverity": "High"}'
```

`minSeverity` is `Critical`, `High`, `Medium` or `Low`. `Info` is refused.

### Second opinion

Needs `DFIR_AI_SECOND_OPINION_MODEL`. The call waits until the second model finishes.

```bash
curl -s -m 1800 -X POST http://127.0.0.1:4773/cases/IR-2026-001/second-opinion \
  -H 'Content-Type: application/json' -d '{}'

curl -s http://127.0.0.1:4773/cases/IR-2026-001/second-opinion   # read the result
```

---

## Getting results out

### Read the case state

One call returns the whole investigation: findings, IOCs, MITRE techniques, attacker path, and the
forensic timeline.

```bash
curl -s 'http://127.0.0.1:4773/cases/IR-2026-001/state?timelineLimit=500' \
  | jq '{findings: (.findings | length), iocs: (.iocs | length), events: .forensicTimelineTotal}'
```

| Query | Notes |
|---|---|
| `timelineLimit` | Forensic-timeline rows per page. Default and maximum 10000 |
| `timelineCursor` | Start row. Use `forensicTimelineNextCursor` from the last page |
| `q` | Text search over the whole forensic timeline |

This is the only JSON source for findings and IOCs. Page through a large timeline:

```bash
CUR=0
while [ "$CUR" != "null" ]; do
  curl -s "http://127.0.0.1:4773/cases/IR-2026-001/state?timelineLimit=5000&timelineCursor=$CUR" > page_$CUR.json
  CUR=$(jq -r '.forensicTimelineNextCursor // "null"' page_$CUR.json)
done
```

### Reports

Generate the report first. The downloads return `404` until you do.

```bash
curl -s -X POST http://127.0.0.1:4773/cases/IR-2026-001/report
```

| Download | Endpoint | Type |
|---|---|---|
| Markdown report | `GET /cases/<id>/report/report.md` | `text/markdown` |
| HTML report | `GET /cases/<id>/report/report.html` | `text/html` |
| Word report | `GET /cases/<id>/report.docx` | `.docx`, built on each request |
| Interactive HTML | `GET /cases/<id>/report/interactive` | one self-contained file |
| STIX 2.1 bundle | `GET /cases/<id>/export/stix` | JSON |

```bash
curl -s -o report.md   http://127.0.0.1:4773/cases/IR-2026-001/report/report.md
curl -s -o report.docx http://127.0.0.1:4773/cases/IR-2026-001/report.docx
```

The report template is a case setting, not a query parameter:
`PUT /cases/<id>/report-template` with `{"templateId": "standard"}`.

!!! note "CSV files"
    `POST /report` also writes `findings.csv` and `iocs.csv` into the case folder. No endpoint
    serves them. Build the same data from `/state`, or use the timeline and blocklist exports below.

### Timelines

| Export | Endpoint | Format |
|---|---|---|
| Forensic timeline, for a spreadsheet | `GET /cases/<id>/incident-timeline.csv` | CSV |
| Forensic timeline, for Timesketch | `GET /cases/<id>/timeline.jsonl` | NDJSON |
| Super-timeline, every imported row | `GET /cases/<id>/super-timeline.jsonl` | NDJSON, streamed |

Search the super-timeline without downloading all of it:

```bash
curl -s 'http://127.0.0.1:4773/cases/IR-2026-001/super-timeline?q=powershell&from=2026-09-01T00:00:00Z&limit=500' \
  | jq '.total, (.events[] | {timestamp, asset, description})'
```

Filters: `from`, `to`, `q`, `origins`, `exclude`, `excludeHosts`, `labels`, `excludeText`
(comma-separated), `tagged=1`, `starred=1`, and `offset` / `limit` (default 500, maximum 10000).

### IOC blocklist

A ready-to-load list for a firewall, proxy or EDR:

```bash
curl -s -o block.csv \
  'http://127.0.0.1:4773/cases/IR-2026-001/export/ioc-blocklist?format=csv&minSeverity=High&types=ip,domain'
```

| Query | Values |
|---|---|
| `format` | `txt` (default), `csv`, `stix` |
| `minSeverity` | `Critical`, `High`, `Medium`, `Low`, `Info` |
| `types` | any of `ip,domain,url,hash,email` |
| `verdictOnly` | `true` to keep only IOCs with an enrichment verdict |

### Search an IOC across every case

Needs `DFIR_CROSS_CASE=on`. Otherwise it returns `404`.

```bash
curl -s 'http://127.0.0.1:4773/global/iocs?q=evil.example&type=domain,url&minCases=2'
```

The results include only the cases the caller can read.

### Chain of custody

```bash
# Re-hash every artifact and check the chain. Waits until done.
curl -s http://127.0.0.1:4773/cases/IR-2026-001/custody/verify | jq '{ok, mismatches, chainBreaks}'

# The signed manifest (verifies only on this installation)
curl -s -o manifest.json http://127.0.0.1:4773/cases/IR-2026-001/custody/manifest
```

The full custody API is in [Chain of Custody](chain-of-custody.md#api-summary).

### Health check

```bash
curl -s http://127.0.0.1:4773/health | jq '{ok, aiEnabled, aiProvider}'
```

`/health` needs no credential in either mode. It does not report the version. The version is in
`GET /update-check` (field `current`), which is an administrator endpoint in team mode.

---

## Full example in Python

Create a case, import a Hayabusa CSV, wait, and download the report. Single-user mode. For team
mode, set `TOKEN`, and create the case in the dashboard first (a service token cannot create cases).

```python
import time
import requests

BASE = "http://127.0.0.1:4773"
CASE = "IR-2026-001"
TOKEN = None  # team mode: "dfirsvc_..."

s = requests.Session()
if TOKEN:
    s.headers["Authorization"] = f"Bearer {TOKEN}"

# 1. Create the case (409 = it exists already, which is fine)
r = s.post(f"{BASE}/cases", json={"caseId": CASE, "name": "Finance ransomware"})
if r.status_code not in (201, 409):
    r.raise_for_status()

# 2. Import a file
with open("hayabusa.csv", encoding="utf-8") as f:
    r = s.post(f"{BASE}/cases/{CASE}/import",
               json={"text": f.read(), "filename": "hayabusa.csv", "minSeverity": "medium"})
r.raise_for_status()
stored = r.json()["file"]
print("accepted:", r.json())

# 3. Wait for the import job
while True:
    jobs = s.get(f"{BASE}/api/jobs", params={"caseId": CASE}).json()["jobs"]
    mine = [j for j in jobs if j["kind"] == "import" and j["label"].endswith(stored)]
    if mine and mine[0]["status"] not in ("queued", "running"):
        print("import:", mine[0]["status"], mine[0].get("error") or "")
        break
    time.sleep(3)

# 4. Wait for the AI (no-op when AI is off for the case)
while s.get(f"{BASE}/cases/{CASE}/ai-state").json()["state"] == "analyzing":
    time.sleep(10)

# 5. Read the results and download the report
state = s.get(f"{BASE}/cases/{CASE}/state", params={"timelineLimit": 1}).json()
print(len(state["findings"]), "findings,", state["forensicTimelineTotal"], "timeline events")

s.post(f"{BASE}/cases/{CASE}/report").raise_for_status()
with open("report.md", "wb") as f:
    f.write(s.get(f"{BASE}/cases/{CASE}/report/report.md").content)
```
