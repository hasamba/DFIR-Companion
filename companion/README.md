# DFIR Companion (Core)

Localhost server that ingests browser screenshots and stores them as forensic evidence.

## Run

    cd companion
    npm install
    DFIR_CASES_ROOT=./cases npm run dev

Server listens on http://127.0.0.1:4773 (localhost only).

## Endpoints

- `POST /cases` — `{ caseId, name, investigator, aiProvider }`
- `POST /captures` — `{ caseId, timestamp, url, tabTitle, triggerType, imageBase64 }`

## Case folder layout

    cases/<caseId>/
      case.json
      screenshots/000001_<ts>.webp
      metadata/captures.jsonl   (append-only audit trail)
      state/                    (populated in Plan 2)
      reports/                  (populated in Plan 3)

## Test

    npm test
