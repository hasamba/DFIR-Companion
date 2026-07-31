# Production evaluation corpus

## License, privacy and provenance

Corpus version `1.0.0` is distributed under the repository's `AGPL-3.0-only` license. Every case was
written from scratch as fictional evaluation data. No client case, production export, public breach
dataset, credential, or real person's identity was used.

Hostnames and account labels are generic. Domains use the reserved `.example` suffix. Public IP
addresses use the documentation ranges `192.0.2.0/24`, `198.51.100.0/24`, and `203.0.113.0/24`.
Each manifest and case records:

- `origin: synthetic`;
- how it was authored;
- `containsClientData: false`;
- the date of its privacy review.

The loader rejects any other provenance class, credential-shaped values, a manifest/case ID mismatch,
or a golden claim that cites an event absent from that case. Evaluation reports contain only scores,
outcomes, hashes and resource totals; they deliberately omit corpus inputs, prompts and model output.

## Coverage

Version 1 contains one case for each required family: ransomware, BEC, insider threat, lateral
movement, Linux, cloud identity, email, memory, network, and clean activity. Across those cases it
also includes incomplete evidence, contradictory sources, and an instruction embedded in untrusted
evidence. The clean maintenance case requires zero findings: producing one fails the suite.

## Versioning

- Patch: wording or metadata correction that does not change a golden expectation.
- Minor: additive case, event, claim or scoring expectation.
- Major: incompatible schema or scoring interpretation.

Baselines pin the corpus hash, not only the semantic version. Any data or golden change therefore
requires a new baseline before it can be compared as the same evaluation.

## Contribution review

Before adding a case:

1. Write fictional evidence; never sanitize a real case and call it synthetic.
2. Use reserved domains/IP ranges and generic identities.
3. Make the golden exhaustive enough that every additional finding is genuinely a false conclusion.
4. Tie each expected claim to the exact supporting evidence IDs.
5. Add an explicit forbidden conclusion where the scenario tempts causal overreach.
6. Add uncertainty and a concrete next step when evidence is incomplete or contradictory.
7. Run the deterministic corpus tests and the repository's full seven-gate suite.
