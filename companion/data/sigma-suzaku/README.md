# Bundled Suzaku CloudTrail rules (#2499)

These Sigma rules grade imported AWS CloudTrail logs at import time, beside the SigmaHQ rules in
`../sigma`. They are copied verbatim from Yamato Security's
[suzaku-rules](https://github.com/Yamato-Security/suzaku-rules); nothing in `rules/` is edited by hand.

- Source: `Yamato-Security/suzaku-rules`, folder `suzaku/aws/cloudtrail`, commit
  `56c5275e99fce54b40c75e586d670ce771fe0fd8` (2026-11-01) — `release.json`, and `UPSTREAM` for the
  weekly upstream check (#2343). 741 files; each file's path under `rules/` is its upstream path
  without the leading `suzaku/`.
- License: Detection Rule License (DRL) 1.1 — `LICENSE.DRL-1.1.md`. Every match the Companion records
  names the rule's author and links the rule at the commit above.
- What loads (default settings): 736 rules. The other 5 files are multi-document correlation rules
  (`aws_cloudtrail_iam_persistence_chain.yml`, `aws_cloudtrail_many_access_denied.yml`,
  `aws_cloudtrail_many_failed_logins.yml`, `aws_cloudtrail_many_recon_events.yml`,
  `aws_cloudtrail_s3_enum_after_getcalleridentity.yml`), which the engine does not run; they are
  listed as refused with that reason.
- Not included: `suzaku/m365` and `suzaku/azure/activity_logs` (the engine cannot read those log
  sources yet — #2500), `suzaku/gws` (Google Workspace logs are not imported), and
  `suzaku/temp_sigma_rules` (stand-ins for SigmaHQ rules already bundled in `../sigma`, written for
  the Event Hub field layout).
- Settings: `DFIR_SIGMA_SUZAKU_RULES` (on), `DFIR_SIGMA_SUZAKU_STATUSES` (stable, test,
  experimental — 711 of the files are experimental) and `DFIR_SIGMA_SUZAKU_MIN_LEVEL` (critical).
  Most of these rules are one rule per API call with no context, so below the floor they only label.
- Updating: copy the upstream folder over `rules/aws/cloudtrail`, move the commit in `release.json`
  and `UPSTREAM` forward in the same PR, and run the detection-overlap check
  (`tests/analysis/detectionOverlap.test.ts`) and `tests/analysis/sigmaBundledRules.test.ts`.
