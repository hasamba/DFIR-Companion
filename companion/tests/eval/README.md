# Prompt regression / evaluation harness (issue #64)

Automated way to tell whether a prompt change improves or regresses extraction/synthesis quality.

## Status: Phase 1 + Phase 2

The original issue asked for a single harness with "CI-friendly exit codes" that runs real extraction/synthesis and computes precision/recall. That can't be one thing: meaningful precision/recall needs **real** model calls, which cost tokens and are flaky/slow — they can't gate every PR. So the harness runs in two modes off the *same* runners, scorer, and fixtures:

- **Phase 1 — mock (CI-gating):** every fixture is driven by a `MockProvider` built from its canned response. Deterministic, zero-cost, runs in normal CI. Gates the *plumbing and the scoring math*.
- **Phase 2 — `--real` (non-blocking):** the env-configured provider (`realProviderOrNull()` → `buildProvider()`) scores the **current prompt's actual output** against the golden expectations — the real regression signal. Gated on `DFIR_AI_*`: if no provider is configured it **skips (exit 0)**, so it never breaks CI. Uses relaxed `REAL_THRESHOLDS` (recall-weighted) because a real model won't reproduce a golden set exactly. Run it manually or on a nightly/labeled workflow; it is **not** in `npm test`.

Screenshot goldens (`analyzeWindow`) are deliberately not committed — real case screenshots are sensitive. The committed golden set is synthetic CSV/log/synthesis, which exercises prompt quality without shipping evidence. A future step can point `--real` at a local screenshot directory via env.

## Files

| File | Role |
|------|------|
| `scorer.ts` | Pure scoring core — no I/O, no clock, no AI. Fuzzy extraction match → precision/recall; synthesis coverage/hallucination/rubric checks. |
| `scorer.test.ts` | Unit tests for every scorer path. |
| `harness.ts` | Drives the real pipeline (`analyzeCsv` / `analyzeLog` / `synthesize`) via a MockProvider, maps output to the scorer's shapes. |
| `fixtures.ts` | Golden dataset: input + canned model response + expected `GoldenEvent[]` / synthesis seed. |
| `harness.test.ts` | Integration: fixtures through the pipeline → scorer, asserting thresholds + a deliberate regression. |
| `run.ts` | CLI runner with a summary report + CI exit codes. |

## Run

```bash
# Phase 1 — deterministic (MockProvider), safe to gate PRs
npm run eval             # both extraction + synthesis
npm run eval:extraction  # precision/recall per fixture
npm run eval:synthesis   # coverage / hallucination per fixture

# Phase 2 — real provider (needs DFIR_AI_PROVIDER / DFIR_AI_KEY in env or .env); non-blocking
npm run eval:real
npm run eval:real:extraction
npm run eval:real:synthesis
```

Exit code `0` = all pass (or `--real` skipped for no provider), `1` = a gate failed, `2` = a runner error.

## Scoring model

**Extraction — fuzzy precision/recall.** LLM output never equals a golden string, so a produced event *matches* a golden expectation when every constraint the golden **specifies** holds (constraints it omits aren't checked): timestamp within `toleranceMinutes`, all `keywords` present (case-insensitive), ATT&CK technique overlap, asset equality. Greedy 1:1 matching → TP/FP/FN → precision/recall/F1, gated against `minPrecision`/`minRecall` (default 0.8).

**Synthesis — deterministic quality checks (no golden needed):**
- **Coverage** — every Critical/High event is cited by ≥1 finding (else a regression).
- **Hallucination** — a finding citing an event id absent from the timeline *invented* that reference; a finding citing no real event and no IOC is *ungrounded*.
- **Rubric** — a numeric `confidence` must carry a `confidenceReason` (advisory; doesn't fail the gate).

## Adding a golden case

Append to `EXTRACTION_FIXTURES` (input + canned delta + `golden`) or `SYNTHESIS_FIXTURES` (seed timeline + canned synthesis delta) in `fixtures.ts`. Keep golden data **synthetic or sanitized** — never snapshot real case evidence.
