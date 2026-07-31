# No-regression reports

When a built-in evaluated prompt or active default model changes, normal CI requires:

- `no-regression-report.json`: the privacy-safe real-model report compared with an accepted baseline;
- `no-regression.json`: a small attestation that pins that report's SHA-256, source fingerprint and
  baseline key.

Generate both from the new defaults:

```bash
npm run eval:real -- --require-provider \
  --baseline tests/eval/baselines/<accepted-baseline>.json --require-baseline \
  --output tests/eval/reports/no-regression-report.json \
  --attestation tests/eval/reports/no-regression.json
```

CI reads the report itself, verifies its hash, requires `outcome: passed`, confirms the baseline
comparison passed, and checks that its source fingerprint matches the changed defaults. Reports
contain metrics and hashes only—never evidence, prompts, raw model output, or credentials.
