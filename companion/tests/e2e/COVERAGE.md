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

The 2026-08 coverage expansion moved 53 stories out of this section into real browser specs
(`staticContracts`, `opsSurfaces`, `integrationRefusals`, `importersDeterministic`,
`dashboardControls`, `findingsAndIocActions`, `timelineLenses`, `caseControls`,
`announcerEvents`, `anonymization`, plus claims added to `custody`, `threatData`, `importers`,
`synthesis` and `analystJourney`). What remains, and why, per story:

- **US-232** merge-target case picker — the modal is a generic candidates-list component reached
  only from the asset-override and exposure-FP merge flows; driving it means building one of
  those flows end to end first.
- **US-243** mobile PWA offline shell — needs a service-worker registration + offline-reload
  journey; not attempted yet.
- **US-244, US-245, US-246, US-247** admin/login pages — same class as the team-auth block
  below: the pages' real behaviors (roles, tokens, audit log, bootstrap) exist only with team
  auth on, which this harness deliberately never enables. Supertest covers the endpoints.
- **US-252** deep-reasoning toggle — the option only affects Anthropic/OpenRouter providers, and
  the harness's stub is OpenAI-shaped; the toggle's own label says as much.
- **US-253, US-267** AI-generated hunt VQL / multi-platform query translation — blocked by the
  fixed-reply stub (§3); the envelopes are covered in `velociraptor.spec.ts`.
- **US-255, US-256, US-257, US-258, US-260, US-269, US-270, US-271** — derivation and job
  machinery below the UI: prompt drift, token batching, phishing correlation, clock-skew
  DETECTION (the recompute route IS covered in `opsSurfaces`), IOC-repair of provoked
  corruption, admission ordering, resume-after-restart (needs a server restart mid-run, which
  the webServer harness cannot do), and cancel (the stub answers too fast to catch a running
  job). Unit suites cover each.
- **US-265** confidence badges, **US-278** cockpit phase view — renderable from the seeded case
  and honestly still debt: no spec asserts the badge or the card list yet (the card ACTION route
  is covered in `opsSurfaces`).
- **US-275** KEV matching — needs the live CISA catalogue; the empty-catalogue contract is
  pinned in `threatData.spec.ts`.
- **US-300, US-301** Jira / ServiceNow push — the push and its idempotent re-push send case
  data to a real tracker; the unconfigured-boundary contracts (501 naming the env vars, status
  reporting unconfigured) are pinned unclaimed in `integrationRefusals.spec.ts`, and the push
  logic runs against mocked transports in `tests/integrations/`.
- **US-302** SO-CRATES submission & polling — needs a live sandbox; the job-list surface the
  dashboard polls is pinned unclaimed in `integrationRefusals.spec.ts`.
- **US-339** hunt-execution cancel — cancelling needs an execution IN PROGRESS, and the harness
  has no hunt backend to keep one running; the cancel-after-end refusal is pinned unclaimed in
  `opsSurfaces.spec.ts`.
- **US-289** generic AI-assisted log import — the extraction is the story and the fixed-reply
  stub cannot prove it (§3); the acceptance boundary rides the US-015 test unclaimed.
- **US-280, US-281, US-304, US-305** war-room bots and notification dispatch — sending anything
  reaches a real chat/webhook. A loopback webhook sink is a plausible future harness extension;
  nothing is claimed today.
- **US-290** log dedup before AI — the aggregation is asserted at unit level
  (`logAggregate`); the browser surface shows only its side effect.
- **US-292…US-299** CIRCL / hunting.ch / RDAP / RockyRaccoon / Shodan / orchestration / custom
  TLS / MCP agentic — live third-party systems (§4) or infra with no honest offline seam.
- **US-303** LeakCheck — configured-only surface; no reachable route to assert without a key.
- **US-307, US-308, US-309** Gemini/Ollama/LiteLLM providers — wiring alternatives to the one
  provider path the whole suite already drives (US-306, claimed in `synthesis.spec.ts`); unit
  suites cover their request shaping.
- **US-310** base-URL safety validation — `validateBaseUrl` has no route-level caller to
  exercise; unit-covered.
- **US-311** atomic writes — storage infrastructure (`atomicWrite`), unit-covered.
- **US-314** update-available notice — the check is a GitHub round-trip this suite must never
  make; the opt-in default and "never checked" disclosure ARE pinned (unclaimed) in
  `opsSurfaces.spec.ts`.
- **US-340** signed-release pack download — the release workflow starts behind team auth
  (workflow/submit answers 409 without it); the reachable refusals are pinned (unclaimed) in
  `opsSurfaces.spec.ts`, the full chain lives in the Supertest suites.
Claims that are deliberately PARTIAL, and say so where they are claimed: **US-224** drives
open ↔ closed through the lifecycle menu (archive/restore transitions are route-covered by
US-005 in `caseLifecycle.spec.ts`); **US-225** covers collapse + persistence, not drag-reorder;
**US-237** covers the Essential/All toggle and tab activation, not the in-app deep-link callers;
**US-240** captures the import and synthesis announcements — import FAILURE is not provokable
through this harness's UI, because every text file falls back to the log importer and is
accepted; **US-268** covers the queue surface (list + trackable job), with progress/cancel/resume
noted above.

- Team-auth policies and endpoints: **US-315 … US-336**. The Playwright server intentionally
  runs with team auth off; Supertest suites exercise bootstrap, login, sessions, roles, tokens,
  policy classification and remote-binding refusal in isolation.
