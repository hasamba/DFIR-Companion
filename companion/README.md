# DFIR Companion (Core)

Localhost server that ingests browser screenshots and stores them as forensic evidence.

## Run

    cd companion
    npm install
    cp .env.example .env    # then edit .env to set your AI key, etc.
    npm run dev

Server listens on http://127.0.0.1:4773 (localhost only).

Configuration lives in `companion/.env` (gitignored). See `.env.example` for the
supported variables: `DFIR_CASES_ROOT`, `DFIR_AI_PROVIDER`, `DFIR_AI_MODEL`,
`DFIR_AI_KEY`. Environment variables set in your shell still override `.env`.

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
