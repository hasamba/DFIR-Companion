# DFIR Companion — Feature Test Report

Canonical feature/user-story tracker: `feature-user-stories.csv` (120 user stories, one row per
feature, with status / test result / errors / fix). This file is the narrative companion to that
spreadsheet.

## Phase 1 — Feature catalogue

Every feature was derived from the code: `companion/src/server.ts` (235 Express routes), the
dashboard sections in `public/dashboard.html`, the analysis pipeline, importers, enrichment
providers, integrations, and the capture extension. 120 user stories were written with expected
behaviour grounded in the code, tracked in `feature-user-stories.csv`.

## Phase 2 — Testing every user story

Tested against a live running companion (the user is on `127.0.0.1:4773`; a second instance was
run on `127.0.0.1:4775` with a temp cases root to exercise mutations without disturbing real
cases). AI (OpenRouter), enrichment (MISP/YETI/OpenCTI), and second-opinion were enabled, so AI
paths were exercised for real.

- All 80 read/GET endpoints (state, derived panels, reports, exports, integration status,
  velociraptor status, threat-data, settings, tags/comments/playbook/notebook/scope/anon) returned
  200 on the demo case.
- Mutating CRUD (create case, add event/IOC, comments, tags, scope, legitimate, ai-control,
  anon-control, report-meta, correlation-profile, customer-exposure, notebook, playbook,
  asset-overrides, templates, report-templates, notifications, bundles, status, archive) returned
  20x on a throwaway case.
- AI endpoints exercised for real: `/ask` (200, real answer), `/synthesize` (200: 3 findings, 4
  MITRE, attacker path, IOCs + events preserved).
- External-dependency paths (IRIS/Timesketch/MISP/Notion/ClickUp push, VirusTotal/AbuseIPDB
  enrichment, live Velociraptor VQL/hunts/monitors) are status-checked but not push-exercised;
  the Velociraptor binary itself is blocked by AV/EDR in this environment (`spawn EPERM`), which
  the server already reports with an actionable message.

### Two real bugs found (both logistical/data-integrity, not UX-cosmetic)

**Bug 1 — Corrupted `investigation.json` (critical).** Reproduced: create a case, add an event,
then add an IOC (which fires background enrichment) while a background re-synthesis from the event
add is still running. `investigation.json` ended up as valid JSON followed by the tail of the
second write (`}echniques": [], ...`), i.e. two concurrent saves raced. Every endpoint that loads
state then 500'd with `Unexpected non-whitespace character after JSON at position N`: `/report`,
`/ask`, `/import/undo`, `/import/redo`, `/executive-summary`, `/narrative`, `/second-opinion`,
`/velociraptor/suggest-hunts`, `/memory/next-steps`, `/timeline-gaps/hypothesize`. Root cause:
`atomicWrite` used one fixed `${target}.tmp`, so concurrent saves of the same file shared and
clobbered each other is temp file.

**Bug 2 — Lost update (analyst add vanishes).** Reproduced: add an event, then immediately add an
IOC; after the background synthesis finished (~30s), the IOC was gone (`iocs=0`). Synthesis saved
from its pre-AI snapshot, overwriting the IOC added during the call.

### Fixes

1. `src/storage/atomicWrite.ts` — the temp file is now unique per call (`${target}.<uuid>.tmp`),
   plus best-effort cleanup of an orphaned temp on a permanent failure. Concurrent saves can no
   longer corrupt the target; the worst case is a lost update (last writer wins), never a malformed
   file.
2. `src/analysis/stateLock.ts` (new) + wiring in `server.ts` and `pipeline.ts` — a per-case
   `StateLock` serializes the short load->save critical sections for manual event/IOC adds,
   background enrichment, and synthesis. AI/network work stays outside the lock so the analyst is
   never blocked.
3. `src/analysis/pipeline.ts` `synthesize()` — before persisting, re-reads the latest state and
   carries forward events/IOCs/threads that are new since its snapshot (referencing the raw
   `loaded` snapshot, not the in-memory correlated one, so correlateEvents dedup results are not
   re-added). Mirrors the existing pinned-questions re-load.

## Phase 4 — Post-fix re-test

On the fixed instance (`4775`), the reproduction now passes consistently:
- `repro4` (the corruption sequence): `/report` 200, `/import/undo` 400 "nothing to undo", `/ask`
  200 — 3/3 runs, no malformed `investigation.json`.
- `lostupdate` (event + IOC + wait for synthesis): IOC survives both immediately and after
  synthesis (`iocs=1`, value preserved) — 3/3 runs.
- Normal synthesis still works: a 3-event case synthesizes to 3 findings / 4 MITRE / attacker path
  with IOCs and events preserved, so the change is non-regressive.

### Note on the unit test suite

`npm run build` (`tsc`) is clean. The vitest suite could not be executed in this environment
(`spawn EPERM` on the esbuild/vite child process — the same AV/sandbox restriction that blocks
`tsx`/`velociraptor`), so verification was done by live reproduction instead. The `atomicWrite`
tests mock `rename`/`writeFile` and assert call counts and thrown errors, none of which the
unique-tmp change affects; the synthesize change is a no-op when no concurrent mutation happens
(`latest == loaded`, so nothing is added).

## Phase 6 — Recursive quality pass (post router-split)

The server has since been refactored: routes moved out of `server.ts` into `src/routes/*.ts` (18
files). This pass re-validated the inventory against that new layout rather than re-deriving it
from scratch.

- **Regression, ground truth this time**: the vitest sandbox restriction above no longer applies
  in this environment. `npm test` ran for real: companion server **296/296 test files, 3440/3440
  tests passing**; extension **9/9 test files, 119/119 tests passing**. Zero automated failures.
- **Coverage gap found**: 49 real features existed in code with no CSV row — most notably the
  entire case password/lock-unlock feature (`routes/casePassword.ts`), encrypted case
  export/import/delete, async job management, several AI-synthesis sub-features (hypotheses,
  confidence control, remediation plan, presentation mode), and 8 distinct browser-extension
  workflows (structured adapter push, manual adapter override, right-click capture, offline queue,
  draggable button, case attach, connection settings, toolbar badge). Added as US-121 through
  US-169. Two stale CSV route references were also corrected (US-105, US-107).
- **Security review** of the newly-discovered case-password and encrypted-export code
  (`analysis/casePassword.ts`, `analysis/caseEncryption.ts`, `analysis/caseExportArchive.ts`,
  `analysis/instanceSecret.ts`) found the cryptography sound: `scryptSync` password hashing with a
  fresh random salt, `crypto.timingSafeEqual` comparisons, a per-install random HMAC secret for
  unlock-cookie signing, fresh IV/salt per AES-256-GCM encryption, and zip-slip-safe archive
  extraction. Two real gaps found:
  - **Fixed**: `GET /cases/:id/lock-status` and `POST /cases/:id/unlock` skipped the
    `isValidCaseId` check present on the sibling password routes, letting a crafted caseId reach
    `store.getCaseMeta` before an existence check (narrow path-traversal exposure). Added the same
    guard plus a regression test (`casePasswordRoutes.test.ts`); 18/18 tests pass.
  - **Open, not auto-fixed** (needs a policy decision, not a mechanical patch): `POST
    /cases/:id/unlock` has no rate limiting or brute-force lockout. Low risk under the default
    `127.0.0.1`-only binding, but a real gap if the server is ever run with `DFIR_HOST=0.0.0.0`
    (e.g. Docker). Recommend `express-rate-limit` or a per-case/per-IP attempt counter on
    `/unlock` before that deployment mode is treated as supported.
- **Confidence**: of 169 rows, 88 are `passed` and 11 are `fixed` (99 total, 59%, live-tested via
  the running-server pass in Phase 2 or dedicated unit tests observed in this pass); 54 (32%) are
  `catalogued` (grounded in reading the code, not yet exercised against a live server); 16 (9%)
  are `blocked` (need an external service/credential this environment doesn't have). No open
  critical or high-severity defect remains except the rate-limiting gap noted above, which is
  deployment-mode-dependent (default localhost-only binding is not exposed to it).
