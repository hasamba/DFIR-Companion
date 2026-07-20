# Prompt regression / evaluation harness (issue #64)

Automated way to tell whether a prompt change improves or regresses extraction/synthesis quality.

## Status: Phase 1 + Phase 2

The original issue asked for a single harness with "CI-friendly exit codes" that runs real extraction/synthesis and computes precision/recall. That can't be one thing: meaningful precision/recall needs **real** model calls, which cost tokens and are flaky/slow — they can't gate every PR. So the harness runs in two modes off the *same* runners, scorer, and fixtures:

- **Phase 1 — mock (CI-gating):** every fixture is driven by a `MockProvider` built from its canned response. Deterministic, zero-cost, runs in normal CI. Gates the *plumbing and the scoring math*.
- **Phase 2 — `--real` (non-blocking):** the env-configured provider (`realProviderOrNull()` → `buildProvider()`) scores the **current prompt's actual output** against the golden expectations — the real regression signal. Gated on `DFIR_AI_*`: if no provider is configured it **skips (exit 0)**, so it never breaks CI. Uses `REAL_THRESHOLDS` (recall-gated — see *Why `--real` gates on recall* below) because a real model won't reproduce a golden set exactly. Run it manually or on a nightly/labeled workflow; it is **not** in `npm test`.

Screenshots (`analyzeWindow`, the vision path) are covered two ways:
- **Mock (CI-gating):** `SCREENSHOT_FIXTURES` in `fixtures.ts` — a synthetic capture + canned delta drives the plumbing through a stub image, gating the analyzeWindow→scorer path without committing any evidence.
- **Real (non-blocking, opt-in):** `npm run eval:real:screenshots` (or `eval:real`, which includes it) points `analyzeWindow` at actual screenshots in a **local, uncommitted** directory (`DFIR_EVAL_SCREENSHOT_DIR`) and grades them against the **vision** provider (`DFIR_VISION_*`) — see *Real screenshot grading* below. It skips cleanly (exit 0) whenever the directory, the vision provider, or any images are absent, so CI never depends on it.

The committed golden set (CSV, log, screenshot, synthesis) is entirely synthetic.

## Files

| File | Role |
|------|------|
| `scorer.ts` | Pure scoring core — no I/O, no clock, no AI. Fuzzy extraction match → precision/recall; synthesis coverage/hallucination/rubric checks. |
| `scorer.test.ts` | Unit tests for every scorer path. |
| `harness.ts` | Drives the real pipeline (`analyzeCsv` / `analyzeLog` / `analyzeWindow` / `synthesize`) via a MockProvider, maps output to the scorer's shapes. |
| `fixtures.ts` | Golden dataset: input + canned model response + expected `GoldenEvent[]` / synthesis seed. |
| `harness.test.ts` | Integration: fixtures through the pipeline → scorer, asserting thresholds + a deliberate regression. |
| `run.ts` | CLI runner with a summary report + CI exit codes. |

## Run

```bash
# Phase 1 — deterministic (MockProvider), safe to gate PRs
npm run eval             # extraction + screenshots(mock) + synthesis
npm run eval:extraction  # precision/recall per fixture
npm run eval:screenshots # mock-only analyzeWindow plumbing check
npm run eval:synthesis   # coverage / hallucination per fixture

# Phase 2 — real provider (needs DFIR_VISION_PROVIDER / DFIR_VISION_KEY in env or .env); non-blocking
npm run eval:real
npm run eval:real:extraction
npm run eval:real:screenshots  # needs DFIR_EVAL_SCREENSHOT_DIR too — see below; skips cleanly without it
npm run eval:real:synthesis
```

Exit code `0` = all pass (or `--real` skipped for no provider), `1` = a gate failed, `2` = a runner error.

### Real screenshot grading (issue #135)

`eval:real:screenshots` (and `eval:real`, which includes it) runs `analyzeWindow` against ACTUAL screenshots and the REAL, vision-scoped provider (`buildProvider()` / `DFIR_VISION_*`) — deliberately **not** the text provider `realProviderOrNull()` resolves for the other `--real` fixtures, since that's a different model in production.

Real case screenshots are sensitive and must never be committed to this repo, so the images and their goldens live entirely **outside** the repo, in a local directory you point at via:

```bash
export DFIR_EVAL_SCREENSHOT_DIR=/path/to/local/screenshot-set
```

Layout: each screenshot image (`.png`, `.jpg`, `.jpeg`, or `.webp`) is paired with a same-basename `.json` sidecar:

```
screenshot-set/
  scheduled-task.webp
  scheduled-task.json
```

```json
{
  "tabTitle": "Velociraptor — Windows.System.TaskScheduler on WS02",
  "url": "https://velociraptor.local/app/index.html#/collected/C.case1/WS02",
  "golden": [
    { "timestamp": "2026-06-01T02:13:00Z", "keywords": ["powershell"], "mitreTechniques": ["T1053.005"], "asset": "WS02" }
  ]
}
```

`tabTitle` / `url` default to a generic placeholder if omitted; `golden` uses the same `GoldenEvent[]` shape as every other fixture (see *Scoring model* below). An optional per-image `"thresholds": { "minPrecision": 0, "minRecall": 0.7 }` overrides the default `REAL_THRESHOLDS`. An image without a valid sidecar is skipped with a warning, not a hard failure, so you can build the set up incrementally.

If `DFIR_EVAL_SCREENSHOT_DIR` is unset, no vision provider is configured, or the directory has no valid image+sidecar pairs, the run prints a message and exits `0` — CI never depends on a local screenshot set existing.

> `DFIR_VISION_PROVIDER` / `DFIR_VISION_MODEL` / `DFIR_VISION_KEY` were formerly `DFIR_AI_PROVIDER` / `DFIR_AI_MODEL` / `DFIR_AI_KEY`; the legacy names still work as a deprecated fallback.

## Scoring model

**Extraction — fuzzy precision/recall.** LLM output never equals a golden string, so a produced event *matches* a golden expectation when every constraint the golden **specifies** holds (constraints it omits aren't checked): timestamp within `toleranceMinutes`, all `keywords` present (case-insensitive), ATT&CK technique overlap (a produced **sub**-technique satisfies a golden parent — `T1110.001` answers `T1110` — but not the reverse), asset equality. Greedy 1:1 matching → TP/FP/FN → precision/recall/F1. Mock mode gates on both at 0.8; `--real` gates on **recall only**.

A **false positive** is a produced event matching *no* golden — not merely one the 1:1 matching left over. A model asked about a 10-row brute-force burst may emit one event per row rather than one aggregate; those rows all satisfy the same golden, so they're the same fact at finer granularity, not invention.

### Why `--real` gates on recall, not precision

A golden is a **must-find list, not an exhaustive enumeration** of the input. This pipeline is built to extract everything and grade severity afterwards (that *is* the super-timeline), so a thorough model correctly emits the benign rows each fixture seeds as noise — none of which are in the golden, all of which count against precision. Measured on this fixture set: `gemini-2.5-pro` reaches **100% recall on all four extraction fixtures across repeated runs** while sitting at 25–50% precision purely by extracting real, unlisted, benign events. A precision gate fails the *better* model for doing its job.

Recall is what actually regresses — "the prompt stopped finding the brute force" is a bug; "the prompt also mentioned a notepad launch" is not. Precision is still computed and printed, just non-gating.

### Choosing a model for `--real`

Extraction quality varies enormously by model, and the harness is only a usable regression signal when the model is **stable run-to-run** — otherwise pass/fail is a coin flip and no change can be attributed. Measured here:

| model | extraction result |
|---|---|
| `google/gemini-2.5-pro` | 4/4 pass, 100% recall, stable across runs |
| `openai/gpt-4o-mini` | flaps run-to-run (same fixture scored 0% and 100% on identical input); consistently misses the proxy-exfil case entirely |

Point `--real` at a strong model via `DFIR_VISION_MODEL` (it need not be the model used for day-to-day extraction). A red `--real` on a weak model is telling you about the *model*, not a prompt regression.

**Synthesis — deterministic quality checks (no golden needed):**
- **Coverage** — every Critical/High event is cited by ≥1 finding (else a regression).
- **Hallucination** — a finding citing an event id absent from the timeline *invented* that reference; a finding citing no real event and no IOC is *ungrounded*.
- **Rubric** — a numeric `confidence` must carry a `confidenceReason` (advisory; doesn't fail the gate).

## Adding a golden case

Append to `EXTRACTION_FIXTURES` (input + canned delta + `golden`), `SCREENSHOT_FIXTURES` (synthetic captures + canned delta + `golden`, mock-only), or `SYNTHESIS_FIXTURES` (seed timeline + canned synthesis delta) in `fixtures.ts`. Keep golden data **synthetic or sanitized** — never snapshot real case evidence. To add a *real* screenshot case, drop an image + sidecar `.json` into your local `DFIR_EVAL_SCREENSHOT_DIR` — see *Real screenshot grading* above; nothing is added to the repo.
