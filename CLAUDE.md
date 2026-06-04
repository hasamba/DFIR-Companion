# CLAUDE.md — working on DFIR Companion

Guidance for AI agents (and humans) modifying this codebase. Read this before changing
the server or the analysis pipeline.

## What this is

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
   finding), and the scope/legitimate filters.

**Evidence import (deterministic + AI).** Besides screenshots, the pipeline ingests:
CSV (`analyzeCsv`), generic logs (`analyzeLog` — `logAggregate.ts` collapses repetitive
lines into counted patterns first, then AI triages only suspicious ones), and **THOR**
Nextron JSON (`importThor` → `thorImport.ts`, fully deterministic, no AI call; drops
info/lifecycle noise, maps level→severity, reads the artifact's own time). All feed the
same forensic timeline via `mergeDelta`.

**Cross-source correlation runs in `mergeDelta`** (`correlate.ts`): events describing the
same artifact collapse into one — by exact dup (time+description, so re-imports don't
double), shared hash, or same path within a time window. The merged event unions `sources`
(real tool names via `toolDetect.ts`); 2+ distinct tools = corroboration. Idempotent.

**State** = `InvestigationState` (`analysis/stateTypes.ts`), persisted per case in
`cases/<id>/state/investigation.json`. `ForensicEvent` carries optional structured fields
(`count`, `endTimestamp`, `sha256`/`md5`/`path`, `asset` (the affected host), `sources`,
`processName`/`parentName`, `chainCheck`); `IOC` carries optional `enrichments[]`. The
**asset ↔ IoC graph** (`analysis/assetGraph.ts`, pure) derives compromised assets (hosts from
`event.asset`; accounts from `DOMAIN\user`/UPN in event text) and the IoCs that touched each. Side files in `state/`:
`ai-control.json`, `legitimate.json`, `scope.json`, `enrich-control.json` (enrichment
on/off, **default off**), `pending_analysis.json`, `report-meta.json` (human-authored report
sections — title page, distribution, BIA, glossary, recommendations…).

**Per-case stores** follow the same pattern (atomic temp-file rename): `AiControlStore`,
`LegitimateStore`, `ScopeStore`, `EnrichControlStore`, `ReportMetaStore`. Pure filters/transforms live next to
them (`applyLegitimate`, `filterEventsByScope`, `isAnalystWorkLog`, `correlateEvents`,
`backfillHighSeverityFindings`) and are unit-tested independently of I/O.

**Threat-intel enrichment** (`enrichment/`): `EnrichmentProvider`s (VirusTotal, MalwareBazaar,
AbuseIPDB, MISP, YETI, RockyRaccoon) look up IOCs by kind; `enrichService.ts` routes/throttles/
caps/caches; `chainValidate.ts` checks RockyRaccoon parent→child chains. **OPSEC: off by default**,
opt-in per case (`enrich-control`), sends indicators to third parties. Providers use injectable
`fetchFn` (no network in tests), enabled only when their `DFIR_*` key(s) are set.

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
   list in the root `README.md`** (and remove the item from its **Todo / Roadmap** if it was
   listed there), then run both test suites. Keeping the root README Features section current is a
   standing instruction — it's the living catalogue of what the tool does.

## Git

- Conventional commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`). One focused commit
  per change. Work on `master` is current; create a branch for larger work.
- Commit only when asked, or per the user's standing workflow.

## Versioning & CHANGELOG (do this on every tag)

- **Always keep `CHANGELOG.md` updated.** Add notable changes under `[Unreleased]`
  (Added / Changed / Fixed) as you make them — this is a standing instruction.
- **On every version tag:** move `[Unreleased]` → `[X.Y.Z] - YYYY-MM-DD`, bump the
  version in **all three** of `companion/package.json`, `extension/package.json`, and
  `extension/manifest.json` (keep them in sync), update the changelog compare links,
  then create an annotated `vX.Y.Z` tag on that commit and push `master` + the tag.
- SemVer: pre-1.0 (`0.x`) — new features bump the minor (`0.1 → 0.2`); fixes-only bump
  the patch. The project is not yet stable.

## Useful scripts (in `companion/`)

`npm run dev` · `npm test` · `npm run verify:ai -- <case>` (one-call model smoke test) ·
`npm run coverage -- <case>` (how many screenshots were analyzed) ·
`npm run reanalyze -- <case> [--reset --all --model … --synth-model …]` ·
`npm run synthesize -- <case> [--model …]` · `npm run clean-timeline -- <case> [--apply]`.
