# Why some user stories have no browser test

`feature-user-stories.csv` has a `browser_test` column, kept in sync with the specs by
`npm run check:us-map`. An empty cell there means "not covered by **this** suite" — it does not
mean untested. This file records why, so the same gaps are not re-investigated every few months.

Everything below was checked against the code, not assumed.

## 1. Extension code — covered by the extension's own suite

These live in the browser add-on, not the dashboard. A Playwright run against the companion cannot
reach them; covering them would need a second harness that launches Chromium with the unpacked
extension loaded. They run in the `extension` CI job today.

| Story                              | Covered by                                                                     |
| ---------------------------------- | ------------------------------------------------------------------------------ |
| US-010 capture toggle              | `extension/tests/captureController.test.ts`                                    |
| US-162 adapter auto-detection      | `extension/tests/adapters.test.ts`                                             |
| US-163 manual adapter override     | `extension/tests/override.test.ts`                                             |
| US-164 right-click send            | `extension/src/contextMenuCapture.ts` (no dedicated spec)                      |
| US-165 offline capture queue       | `extension/tests/captureQueue.test.ts`, `captureQueuePermanentFailure.test.ts` |
| US-166 draggable button position   | `extension/tests/buttonPosition.test.ts`                                       |
| US-167 case attach/detach          | `extension/tests/companionClient.test.ts`                                      |
| US-168 companion URL normalisation | `extension/tests/settings.test.ts`                                             |
| US-169 toolbar badge and hotkey    | `extension/tests/manifest.test.ts`, `settings.test.ts`                         |
| US-248 team service-token field    | `extension/tests/companionClient.test.ts`, `popupValidation.test.ts`           |
| US-249 site-access panel           | `extension/tests/siteAccess.test.ts`, `popupRender.test.ts`                    |
| US-250 permissions/audit link      | `extension/tests/options.test.ts`, `popupRender.test.ts`                       |
| US-251 activity capture triggers   | `extension/tests/contentCapture.test.ts`, `serviceWorker.test.ts`              |

## 2. Derivation algorithms — unit-level by nature

These describe how a value is computed, not an interface. Driving them through a browser would mean
constructing evidence precise enough to force one scoring path, which asserts the fixture rather
than the product; and several depend on a real model, which this suite must not call.

US-039 (per-window extraction), US-171 (grounded synthesis safeguards), US-174 (coverage audit),
US-176 (second-look loop), US-178 (rabbit-hole verdict), US-179 (hypothesis projections),
US-180 (prevalence bias), US-185 (MACB inconsistencies), US-186 (failure-burst correlation),
US-187 (4624 logon typing), US-188 (lookalike domains), US-189 (finding confidence),
US-190 (learned dismissal patterns), US-198 (uncertainty ledger), US-206 (enrichment backoff),
US-207 (per-model telemetry), US-209 (hunt snapshot diff), US-210 (relevance scoring),
US-211 (Codex provider), US-212 (Claude Code provider), US-217 (command-line normalisation),
US-218 (semantic second-opinion keys), US-351 (near-duplicate host detection and synthesis gate),
US-355 (per-case Presidio layer and last-decision resume), US-360 (PowerShell 4104 fragment
reassembly).

Spot-checked as genuinely covered elsewhere: `tests/analysis/lookalikeDomains.test.ts` (US-188),
`tests/enrichment/provider.test.ts` (US-206), `tests/providers/codex.test.ts` (US-211).

## 3. Blocked by the fixed-reply AI stub

`tests/e2e/aiStub.ts` answers with fixed prose. Endpoints that require the model to return
**structured JSON** cannot be exercised through it — teaching the stub each caller's schema would
be mocking the product rather than standing in for a provider.

- **US-196** view-summary — retries four times against its schema, then answers 500.
- **US-069** suggest hunts — the envelope is covered in `velociraptor.spec.ts`; the VQL it would
  propose is not, for the same reason.

## 4. Needs a live third-party system

Covering these means letting the suite reach a real service, which it must never do — a run that
pushed case data to a live MISP because someone's environment happened to be configured would be a
genuinely bad outcome. The refusal paths _are_ covered.

- **US-219** MISP forensic-timeline payload — needs a MISP to send to.
- **US-204** comment mention notifications — dispatching one sends a real message.
- **US-235 / US-273** Presidio approval panel and optional detection layer — the harness deliberately
  has no live analyzer; proposal, decision, masking, timeout and resume behavior are exercised with
  a local Presidio stub in the server and analysis suites.
- **US-356** Telegram notification channel — the shared war-room credential fallback and explicit
  channel override are covered with isolated environment and fetch mocks; a browser test would send
  case content to a real bot.

## 5. Client-side only

- **US-203** Sigma draft — built and downloaded in the browser from a finding's evidence. No server
  route exists, so a test could only reimplement the generator.

## 6. Not reachable from a test harness

- **US-170** cancelable case-loading overlay — the Dismiss handler is attached only during a real
  in-flight load, which this harness cannot provoke. Noted while writing `caseLifecycle.spec.ts`:
  the affordance is also click-only, with no keyboard path.

## 7. Superseded

- **US-088** JSON snapshot — its own `expected_behaviour` says it was replaced by the
  password-encrypted `.dfircase` in #56. There is no endpoint. **This row should probably leave the
  inventory.**

## 8. Purely visual

- **US-221** forensic timeline card layout. The story is about appearance — "bordered cards
  consistent with Findings/IOCs", controls "on stable readable lines". The only way to assert that
  from a test is to pin CSS classes or measure boxes, which fixes the styling in place and breaks on
  every redesign, including the one #384 will bring. Worth revisiting after that lands.

US-053 (source filter), US-055 (kill-chain expansion) and US-183 (IOC pagination) were in this
section and should not have been. A filter that filters, a disclosure that discloses and a pager
that pages are behaviour, whatever the panel looks like — they are covered in
`workflows/panelBrowsing.spec.ts`, with no appearance assertions.

## 9. Analyst-triggered external download

- **US-359** Download latest Velociraptor — the browser suite verifies that the explicitly manual
  action is visible and disclosed, but does not click it because that would reach GitHub and write
  an executable. Release selection, download, extraction, executable mode and error handling are
covered with mock assets in `tests/analysis/velociraptorDownload.test.ts` and
`tests/analysis/velociraptorRelease.test.ts`.

## 10. Known browser-coverage debt — automated below the browser

These stories are exercised by the companion unit/integration suite, dashboard feature-manifest
tests, or static accessibility checks, but have no dedicated Playwright journey yet. This is an
honest coverage disposition, not a claim that browser coverage would be impossible. Keeping the
IDs here makes `check:us-map` report the gap deliberately instead of rediscovering it as an
unexplained warning.

- Dashboard interactions and views: **US-222, US-223, US-224, US-225, US-226, US-227, US-228,
  US-229, US-230, US-231, US-232, US-233, US-234, US-236, US-237, US-238, US-239, US-240**.
- Offline/PWA and administration pages: **US-243, US-244, US-245, US-246, US-247**.
- Analysis, enrichment, provider and integration behavior: **US-252, US-253, US-254, US-255,
  US-256, US-257, US-258, US-259, US-260, US-261, US-262, US-263, US-264, US-265, US-266,
  US-267, US-268, US-269, US-270, US-271, US-272, US-274, US-275, US-276, US-277, US-278,
  US-279, US-280, US-281, US-282, US-283, US-284, US-285, US-286, US-287, US-288, US-289,
  US-290, US-291, US-292, US-293, US-294, US-295, US-296, US-297, US-298, US-299, US-300,
  US-301, US-302, US-303, US-304, US-305, US-306, US-307, US-308, US-309, US-310, US-311,
  US-312, US-313, US-314**.
- Team-auth policies and endpoints: **US-315, US-316, US-317, US-318, US-319, US-320, US-321,
  US-322, US-323, US-324, US-325, US-326, US-327, US-328, US-329, US-330, US-331, US-332,
  US-333, US-334, US-335, US-336**. The Playwright server intentionally runs with team auth off;
  Supertest suites exercise bootstrap, login, sessions, roles, tokens, policy classification and
  remote-binding refusal in isolation.
- Narrow route/static-asset contracts: **US-337, US-338, US-339, US-340, US-341, US-342, US-343,
  US-344, US-345, US-346, US-347, US-348, US-349, US-350**.
