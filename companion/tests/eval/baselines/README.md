# Evaluation baselines

A baseline is an immutable privacy-safe scorecard for one pinned provider, model, prompt hash and
corpus hash. Its filename is:

`<provider>--<model>--<first-12-prompt-hash>.json`

The protected workflow always uploads a candidate baseline with its report. A human reviews the run
and may add the candidate here in a later, explicitly authorized commit. Never invent scores or copy
one model's baseline under another model/prompt identity.

Comparisons require the same provider, exact model and exact corpus hash. The candidate prompt may
differ—that is how a proposed prompt is compared with the prior pinned prompt. Quality drops beyond
the configured tolerance fail; latency, token and monetary-cost increases above 25% are reported as
resource regressions rather than being hidden inside a single pass/fail number.
