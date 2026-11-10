# Bundled Suzaku rules (#2499, #2500, #2522)

These Sigma rules grade imported AWS CloudTrail logs (#2499), Microsoft 365 unified audit logs and Azure
Activity Logs (#2500) and Google Workspace audit activity (#2522) at import time, beside the SigmaHQ rules in
`../sigma`. They are copied verbatim from Yamato Security's
[suzaku-rules](https://github.com/Yamato-Security/suzaku-rules); nothing in `rules/` is edited by hand.

- Source: `Yamato-Security/suzaku-rules`, folders `suzaku/aws/cloudtrail` (741 files), `suzaku/m365`
  (21), `suzaku/azure/activity_logs` (4) and `suzaku/gws/{admin,calendar,drive,login}` (20), commit `56c5275e99fce54b40c75e586d670ce771fe0fd8`
  (2026-11-01) — `release.json` (with each folder's git tree SHA, the identity the updater compares),
  and `UPSTREAM` for the weekly upstream check (#2343, CloudTrail folder). Each file's path under
  `rules/` is its upstream path without the leading `suzaku/`.
- License: Detection Rule License (DRL) 1.1 — `LICENSE.DRL-1.1.md`. Every match the Companion records
  names the rule's author and links the rule at the commit above.
- What loads (default settings): 779 rules — 736 CloudTrail, 21 Microsoft 365, 4 Azure Activity, 18
  Google Workspace (admin 8, login 8, Drive 2). The other 7 files are multi-document correlation rules
  (`aws_cloudtrail_iam_persistence_chain.yml`, `aws_cloudtrail_many_access_denied.yml`,
  `aws_cloudtrail_many_failed_logins.yml`, `aws_cloudtrail_many_recon_events.yml`,
  `aws_cloudtrail_s3_enum_after_getcalleridentity.yml`, `gws_calendar_mass_invite.yml`,
  `gws_login_many_source_ips.yml`), which the engine does not run; they are listed as refused with that
  reason. So no calendar rule loads, although calendar records are imported.
- Google Workspace rules name the Reports API event (`eventName`) and its parameters directly
  (`NEW_VALUE`, `is_suspicious`, `visibility`); the resolver reads the one event a row came from and the
  parameter of that name, by its typed value (`src/analysis/sigmaLogSources.ts`, `GWS_SOURCES`). A rule
  for one application (`google_workspace.login`) runs only on that application's events.
- Microsoft 365 rules name members of the unified audit log's Name/Value lists directly
  (`Parameters.ForwardingSmtpAddress`, `ExtendedProperties.UserAgent`); the field resolver reads the
  `Value` of the element with that `Name` (`src/analysis/sigmaLogSources.ts`, `AZURE_M365`).
- Not included: `suzaku/temp_sigma_rules` (stand-ins for SigmaHQ rules already bundled in `../sigma`, written for
  the Event Hub field layout).
- Settings: `DFIR_SIGMA_SUZAKU_RULES` (on), `DFIR_SIGMA_SUZAKU_STATUSES` (stable, test,
  experimental — 711 of the files are experimental) and `DFIR_SIGMA_SUZAKU_MIN_LEVEL` (critical).
  Most of these rules are one rule per API call with no context, so below the floor they only label.
- Analysts can install a newer Suzaku commit at runtime (Settings → Sigma rules, #2508); it lives
  in the server data folder and never changes this bundled copy.
- The updater watches each Google Workspace application folder (`suzaku/gws/admin`, `calendar`,
  `drive`, `login`), one level deep like the others: a new upstream `suzaku/gws/<app>` folder is not
  picked up until it is added to `SUZAKU_WATCH_PATHS` (`src/analysis/suzakuReleaseClient.ts`).
- Updating this bundled copy: copy the upstream folders over `rules/aws/cloudtrail`, `rules/m365`,
  `rules/azure/activity_logs` and `rules/gws`, move the commit and the seven folder tree SHAs in `release.json` and the
  commit in `UPSTREAM` forward in the same PR, and run the detection-overlap check
  (`tests/analysis/detectionOverlap.test.ts`) and `tests/analysis/sigmaBundledRules.test.ts`.
