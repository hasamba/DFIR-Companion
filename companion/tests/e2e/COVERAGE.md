# Why some user stories have no browser test

`feature-user-stories.csv` has a `browser_test` column, kept in sync with the specs by
`npm run check:us-map`. An empty cell there means "not covered by **this** suite" — it does not
mean untested. This file records why, so the same gaps are not re-investigated every few months.

Everything below was checked against the code, not assumed.

## 1. Extension code — covered by the extension's own suite

These live in the browser add-on, not the dashboard. A Playwright run against the companion cannot
reach them; covering them would need a second harness that launches Chromium with the unpacked
extension loaded. They run in the `extension` CI job today.

| Story | Covered by |
| --- | --- |
| US-010 capture toggle | `extension/tests/captureController.test.ts` |
| US-162 adapter auto-detection | `extension/tests/adapters.test.ts` |
| US-163 manual adapter override | `extension/tests/override.test.ts` |
| US-164 right-click send | `extension/src/contextMenuCapture.ts` (no dedicated spec) |
| US-165 offline capture queue | `extension/tests/captureQueue.test.ts`, `captureQueuePermanentFailure.test.ts` |
| US-166 draggable button position | `extension/tests/buttonPosition.test.ts` |
| US-167 case attach/detach | `extension/tests/companionClient.test.ts` |
| US-168 companion URL normalisation | `extension/tests/settings.test.ts` |
| US-169 toolbar badge and hotkey | `extension/tests/manifest.test.ts`, `settings.test.ts` |

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
US-218 (semantic second-opinion keys).

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
genuinely bad outcome. The refusal paths *are* covered.

- **US-219** MISP forensic-timeline payload — needs a MISP to send to.
- **US-204** comment mention notifications — dispatching one sends a real message.

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

- **US-053** timeline source filter, **US-055** kill-chain expansion, **US-183** IOC pagination,
  **US-221** timeline card layout. These are DOM interactions whose stories describe appearance
  ("bordered cards consistent with Findings/IOCs"). They are testable in principle, but asserting
  CSS classes pins styling rather than behaviour and breaks on every redesign — including the one
  #384 will bring. Worth revisiting after that lands.
