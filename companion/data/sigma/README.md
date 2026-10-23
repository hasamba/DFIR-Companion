# Bundled Sigma rules

These rules grade imported cloud logs (#2202) and web server / proxy access logs (#2203) at import time. They are copied verbatim from the
SigmaHQ release named in `version.txt`; nothing in `rules/` is edited by hand.

- Source: https://github.com/SigmaHQ/sigma, release `r2026-07-01`, asset `sigma_all_rules.zip`
  (sha256 `5725c91b5813587ad6a4b0b8e0233fa44348b1595f818d8b7fd39d6033385085`, matching the digest
  GitHub publishes for the asset).
- Included: `rules/cloud/aws/cloudtrail`, `rules/cloud/azure/signin_logs`,
  `rules/cloud/azure/audit_logs` (#2202), and every rule whose logsource is the generic `webserver`
  or `proxy` category — `rules/web/webserver_generic`, `rules/web/proxy_generic` and the matching
  files under `rules-emerging-threats/` (#2203).
- License: the rules are released under the Detection Rule License (DRL) 1.1 —
  `LICENSE.DRL-1.1.md`, and SigmaHQ's own `LICENSE`. Every match the Companion records names the
  rule's author and links the rule, as the DRL requires.
- `disabled.yml` is the Companion's own list of rules shipped switched off, each with its reason.

Which rules actually load (by status, by whether the Companion can read every field they use) is
decided when the server starts and is listed in the server log.
