# CLAUDE.md — working on DFIR Companion

Guidance for AI agents (and humans) modifying this codebase. Read this before changing
the server or the analysis pipeline.

## What this is

A localhost DFIR tool in two projects:
- **`companion/`** — Node 20+/TypeScript, Express server on `127.0.0.1:4773`. The core.
  Captures screenshots → evidence; AI analyzes them into a per-case `InvestigationState`;
  serves the dashboard + reports. Vitest tests.
- **`extension/`** — Chrome/Comet **MV3** extension (TypeScript + Vite). Captures the
  active tab and POSTs to the companion. Vitest + fake-indexeddb tests.
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
   time.
2. **Holistic synthesis** (`SYNTHESIS_PROMPT`, `AnalysisPipeline.synthesize`): one
   text-only call over the whole (in-scope) forensic timeline. Produces findings, IOCs,
   MITRE, attacker path, key questions, and back-links events→findings via
   `relatedEventIds`. **Synthesis replaces the analytic layer** (findings/IOCs/MITRE) so
   out-of-scope or stale conclusions drop; it preserves the forensic timeline and threads.

**State** = `InvestigationState` (`analysis/stateTypes.ts`), persisted per case in
`cases/<id>/state/investigation.json`. Side files in `state/`: `ai-control.json`
(AI on/off + lastAnalyzedSeq), `legitimate.json` (false positives), `scope.json`
(time window), `pending_analysis.json` (failed window marker).

**Per-case stores** follow the same pattern (atomic temp-file rename): `AiControlStore`,
`LegitimateStore`, `ScopeStore`. Pure filters live next to them (`applyLegitimate`,
`filterEventsByScope`, `isAnalystWorkLog`) and are unit-tested independently of I/O.

## Conventions / invariants — don't break these

- **Evidence-first:** the ingest path writes the screenshot to disk and appends the
  append-only `captures.jsonl` audit line **before** any analysis. Analysis never gates
  evidence persistence.
- **Localhost only:** the server binds `127.0.0.1`. CORS + Private-Network-Access headers
  are required so the `chrome-extension://` origin can reach it — don't remove them.
- **Graceful AI parsing:** model output may be wrapped in markdown fences → use
  `extractJsonText` before `JSON.parse`. Schema enums use **`.catch(fallback)`** so one
  unexpected value (e.g. an IOC type the model invented) does not reject the whole
  response. Keep enums lenient.
- **Provider abstraction:** all AI calls go through `AIProvider` (`providers/`). Requests
  have an injectable `fetchFn` (tests pass a mock — no real network in tests) and a
  configurable `timeoutMs` (`DFIR_AI_TIMEOUT_MS`, default 180s; strong models are slow).
- **Two-tier + cost:** extraction is high-volume (one call per few screenshots) → cheap
  model; synthesis is one text-only call → can use a strong model. Configure via
  `DFIR_AI_MODEL` / `DFIR_AI_SYNTH_MODEL`. Be mindful of API cost when running
  `reanalyze`/`synthesize` against real cases.
- **Secrets:** `.env` is gitignored (so are `cases/`). Never commit keys or evidence.
  Config is via `DFIR_*` env vars — see `companion/.env.example`.
- **Immutability:** the merge (`stateMerge.ts`) returns new objects, never mutates input
  state. Keep it pure.

## Adding a feature — the usual shape

1. Pure logic + its own unit test in `analysis/` (e.g. a filter or store).
2. Wire it into `AnalysisPipeline` and/or `createApp` routes in `server.ts`; pass any
   new store into the pipeline in `startServer` **and** in `scripts/synthesize.ts` /
   `scripts/reanalyze.ts` (they build their own pipelines).
3. Surface it in `public/dashboard.html` (the dashboard is plain JS; use `esc()` for any
   AI/user text in `innerHTML`, and fail loudly with a "restart the server" message if an
   endpoint 404s).
4. Reflect it in the Markdown report (`reports/markdown.ts`) when relevant.
5. Update `companion/README.md` (endpoints/env/scripts) and run both test suites.

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
