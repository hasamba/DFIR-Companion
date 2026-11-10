# Bundled Sigma rules

These rules grade imported cloud logs (#2202) and web server / proxy access logs (#2203) at import time. They are copied verbatim from the
SigmaHQ release named in `version.txt`; nothing in `rules/` is edited by hand.

- Source: https://github.com/SigmaHQ/sigma, release `r2026-07-01`, asset `sigma_all_rules.zip`
  (sha256 `5725c91b5813587ad6a4b0b8e0233fa44348b1595f818d8b7fd39d6033385085`, matching the digest
  GitHub publishes for the asset).
- Included: `rules/cloud/aws/cloudtrail`, `rules/cloud/azure/signin_logs`,
  `rules/cloud/azure/audit_logs` (#2202), every rule whose logsource is the generic `webserver`
  or `proxy` category — `rules/web/webserver_generic`, `rules/web/proxy_generic` and the matching
  files under `rules-emerging-threats/` (#2203) — and `rules/cloud/gcp/audit` (15 rules, product
  `gcp`, service `gcp.audit`; #2346), extracted from the same release asset after checking its
  sha256, and `rules/cloud/azure/activity_logs` (33 rules in the release asset, product `azure`,
  service `activitylogs`; #2500), extracted the same way, and `rules/cloud/gcp/gworkspace` (10 rules,
  product `gcp`, service `google_workspace.admin` / `.login`; #2522), extracted the same way. They read
  the Google Workspace Reports API import; `eventService` / `protoPayload.serviceName` is the
  application's Cloud Logging service (`admin.googleapis.com`, `login.googleapis.com`). The three login
  rules are `experimental`, so they load only when that status is switched on.
- License: the rules are released under the Detection Rule License (DRL) 1.1 —
  `LICENSE.DRL-1.1.md`, and SigmaHQ's own `LICENSE`. Every match the Companion records names the
  rule's author and links the rule, as the DRL requires.
- GCP method names: several GCP rules spell the method the way another log pipeline does
  (`.serviceAccounts.disable`, `projects.content.reidentify`, `compute.vpnTunnels.insert`) where a
  real Cloud Audit Log writes `google.iam.admin.v1.DisableServiceAccount`,
  `google.privacy.dlp.v2.DlpService.ReidentifyContent` or `v1.compute.vpnTunnels.insert`. The rules
  stay verbatim; the field resolver also offers the rule's spelling for that exact service + method
  (`src/analysis/sigmaGcpMethodAliases.ts`, which holds the 15-rule audit). Every bundled GCP rule
  is reached by at least one real method name, and `tests/analysis/sigmaGcpImport.test.ts` pins the
  list of rules that match none (currently empty).
- `disabled.yml` is the Companion's own list of rules shipped switched off, each with its reason.

Which rules actually load (by status, by whether the Companion can read every field they use) is
decided when the server starts and is listed in the server log.
