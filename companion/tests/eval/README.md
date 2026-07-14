# Prompt regression / evaluation harness (issue #64)

Automated way to tell whether a prompt change improves or regresses extraction/synthesis quality.

## Status: Phase 1 (CI-safe foundation)

The original issue asked for a single harness with "CI-friendly exit codes" that runs real extraction/synthesis and computes precision/recall. That can't be one thing: meaningful precision/recall needs **real** model calls, which cost tokens and are flaky/slow — they can't gate every PR. So the harness is split:

- **Phase 1 (this):** the pure **scorer** + a **MockProvider** harness + golden fixtures + a CLI runner. Deterministic, zero-cost, runs in normal CI. Gates the *plumbing and the scoring math*.
- **Phase 2 (planned):** a `--real` mode that swaps `makeEvalPipeline`'s MockProvider for the env-configured `buildProvider()` (gated on `DFIR_AI_KEY`) and points the same runners at a ≥5-case golden screenshot/CSV/log set. Runs manually or nightly, **non-blocking**, with tolerance thresholds. The scorer and fixture shapes below are the stable contract Phase 2 builds on.

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
npm run eval             # both extraction + synthesis
npm run eval:extraction  # precision/recall per fixture
npm run eval:synthesis   # coverage / hallucination per fixture
```

Exit code `0` = all pass, `1` = a gate failed, `2` = a runner error.

## Scoring model

**Extraction — fuzzy precision/recall.** LLM output never equals a golden string, so a produced event *matches* a golden expectation when every constraint the golden **specifies** holds (constraints it omits aren't checked): timestamp within `toleranceMinutes`, all `keywords` present (case-insensitive), ATT&CK technique overlap, asset equality. Greedy 1:1 matching → TP/FP/FN → precision/recall/F1, gated against `minPrecision`/`minRecall` (default 0.8).

**Synthesis — deterministic quality checks (no golden needed):**
- **Coverage** — every Critical/High event is cited by ≥1 finding (else a regression).
- **Hallucination** — a finding citing an event id absent from the timeline *invented* that reference; a finding citing no real event and no IOC is *ungrounded*.
- **Rubric** — a numeric `confidence` must carry a `confidenceReason` (advisory; doesn't fail the gate).

## Adding a golden case

Append to `EXTRACTION_FIXTURES` (input + canned delta + `golden`) or `SYNTHESIS_FIXTURES` (seed timeline + canned synthesis delta) in `fixtures.ts`. Keep golden data **synthetic or sanitized** — never snapshot real case evidence.
