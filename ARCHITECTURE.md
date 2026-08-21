# Architecture — the module map

The target structure for `companion/src`, and the dependency rules that hold it in place.

This exists because of [#384](https://github.com/hasamba/DFIR-Companion/issues/384): `analysis/pipeline.ts`
was 6,136 lines and `server.ts` 4,275, and they got that way because there was never a written answer
to "where does this code go?" Decomposing them without that answer just produces smaller files in
arbitrary places, and the tangle regrows. So the map came first, the extractions follow it, and
`npm run check:boundaries` stops the next tangle forming.

#384 is closed. See [Who owns what](#who-owns-what) for where the remaining size targets live.

**How to use it:** before adding a module, find its domain below. Before adding an import, check the
edge is allowed. If the code you want to write does not fit any domain, that is worth a conversation
in the PR — not a new top-level directory.

**Status:** every file in `companion/src` is assigned to a domain **today**, in
`scripts/module-map.json`. The rules are enforced from day one; they do not wait for files to move.
The domain *directories* are the target — `src/analysis/` is 296 files in one flat directory right
now, and files move into their directory as extraction PRs touch them (see [Migration](#migration)).

**Moving a file is not free for the gate**, and it is worth knowing why before you try it. The map
classifies by domain, but the violation ledger keys on the *physical path*. So relocating a file
that appears in the ledger retires its old entries and creates new ones at the new path — the gate
reports both, fails, and `--update` refuses to add the replacements because it only ever shrinks.
That is deliberate rather than an oversight: a move is exactly when a boundary violation should be
re-examined rather than carried along. Land the move with `--init` and say in the PR which entries
are the same debt at a new address and which are genuinely new.

---

## The five layers

Every module belongs to exactly one layer. **An import may go down a layer or sideways within one;
it may never go up.**

**Type-only imports count.** `import type` is exempt from `check:imports`, because an erased import
cannot form a runtime initialisation cycle — that reasoning is correct there and does not carry over
here. A type import still means one domain knows another's shape, which is the coupling this map
exists to control. It is not a rounding error either: **15 of the 39 recorded violations are
type-only**, so exempting them would have hidden a third of the problem on day one.

| Layer | Contents | May import |
|---|---|---|
| **Composition** | `server.ts` and `src/composition/` | everything |
| **Delivery** | `routes/`, `reports/`, `integrations/`, `enrichment/`, `live/` | Domain, Platform, Shared |
| **Domain** | `analysis/*` (11 domains, below) | Domain (per the tier order), Platform, Shared |
| **Platform** | `storage/`, `providers/`, `auth/`, `http/`, `settings/`, `logging/`, `config/`, `ingest/`, `dedup/` | Platform, Shared |
| **Shared** | `types.ts`, `version.ts`, `serverAssets.ts` | Shared only |

Two placements that look surprising and are deliberate:

- **`integrations/` is Delivery, not Platform.** It contains outbound push clients (IRIS, MISP,
  Timesketch, Notion, Jira, ServiceNow) that take domain objects and send them somewhere. Anything
  that consumes a `Finding` is downstream of the domain that defines one. The inbound half —
  `integrations/velociraptor/velociraptorApi.ts` — is a raw API client with no domain knowledge and
  reads as Platform; it is Delivery here only because splitting the directory is a separate change.
  See [Known structural debt](#known-structural-debt).
- **`serverAssets.ts` is Shared, not Composition.** `readPublicAsset` is a file reader that four
  route families and `reports/` use. Grouping it with `server.ts` would make every one of those a
  layer violation for no reason.

## The `analysis/` domains

Eleven domains, ordered into tiers. Within `analysis/`, the same rule applies: **a domain may import
a lower tier or its own, never a higher one.** The tiers are read off what the code actually does
today, not invented — `ai` importing `ingest` 39 times is why `ai` is at the top.

| Tier | Domain | Owns | Files | Lines |
|---|---|---|---|---|
| **5** | `ai/` | `pipeline`, the ~25 prompt constants, `synth*`, `deepPass*`, `hypothesis*`, `secondOpinion`, `secondLook`, `uncertainty`, `queryTranslate`, `aiCost` | 47 | 11,081 |
| **4** | `workflow/` | `cockpit*`, `dashboardViews`, `collectionPlan*`, `scope*`, `presentation`, `notebook`, `activityLog`, `priorWork`, `summary` | 23 | 4,483 |
| **3** | `ingest/` | the ~40 `*Import.ts` modules, `importDetect`, `importerSpec`, `importResume`, `importUndo`, `declarativeImporter`, `zip*` | 48 | 15,768 |
| **2** | `findings/` | `ioc*`, `finding*`, `falsePositive*`, `fp*`, `tagger*`, `tags`, `confidence*`, `severityFloor` | 36 | 4,116 |
| **2** | `detect/` | deterministic detectors: `beaconDetect`, `burstDetect`, `exfilCorrelate`, `sshBruteForce`, `timestompDetect`, `tradecraftRules`, `sessionSegmentation`, `assetGraph`, `evidenceGraph` | 26 | 4,663 |
| **2** | `hunt/` | `huntQuery*`, `huntSuggest`, `huntOutcomes`, `savedHunt*`, `playbookHunt*` | 16 | 3,355 |
| **2** | `notify/` | `notifications`, `push*`, `slackSocketMode`, `telegramPoller`, `slashCommand*` | 10 | 1,684 |
| **1** | `case/` | `case*`, `custody*`, `analysisRun*`, `job*`, `updateCheck*`, `preflight`, `diagnostics` | 34 | 5,837 |
| **1** | `privacy/` | `anonymize`, `anon*`, `presidio*`, `ocrRedact`, `redact*`, `imageRedact`, `secretSpillRules`, `deobfuscate` | 18 | 2,697 |
| **1** | `intel/` | reference data and mapping: `attack*`, `d3fend*`, `kev*`, `nsrl*`, `adversary*`, `playbook*`, `compliance*`, `geoMap`, `incidentType*` | 33 | 5,261 |
| **0** | `timeline/` | the event record itself: `superTimeline*`, `forensicGate`, `forensicSort`, `correlate`, `stateMerge`, `searchFilter`, `time*`, `clockSkew` | 16 | 2,773 |

Five placements worth stating outright, because each one is a decision someone will otherwise
relitigate:

- **`detect/` is separate from `ai/`.** The deterministic detectors are the thing that must keep
  working when no AI provider is configured. Folding them into `ai/` would make that guarantee
  invisible, and it is the difference between a tool that degrades and a tool that stops.
- **`ai/` sits above `workflow/`, not beside it.** They started on the same tier, which would have
  permitted imports in both directions — and both directions already exist: 5 runtime imports
  `ai → workflow`, 3 type imports `workflow → ai`. A same-tier rule would have blessed a cycle. AI
  orchestration consumes workflow state, not the reverse; the 3 back-references are ledgered.
- **`timeline/` is tier 0 and owns `correlate.ts`.** Correlation and de-duplication of events are
  properties of the record, not detections over it. Filing it with the detectors made three
  `superTimeline`/`clockSkew`/`stateMerge` imports look like violations when the misfiling was the
  problem; the map assigns it to `timeline/` and those entries are gone.
- **`responseSchema.ts` is Shared too.** It defines `deltaSchema` — the shape of a *change* to
  investigation state — and it was filed under `ai/` because the AI extraction path parses model
  responses with it. That was wrong: it imports only `zod` and `canonicalEvent`, `stateMerge.ts` at
  tier 0 already imported it as a recorded violation, and every deterministic importer validates its
  constructed delta with it. A delta is vocabulary, not an AI concept. Moving it cleared six
  violations the ingest extraction would otherwise have created, and retired the `stateMerge` one.
- **`stateTypes.ts` and `canonicalEvent.ts` are Shared, not `timeline/`.** `stateTypes.ts` is
  imported by 189 files in every area of the tree — it is the application's event vocabulary in the
  same sense `types.ts` is, and their mutual type reference makes them one unit. Filing them in a
  domain would make every Platform module that touches a `ForensicEvent` a layer violation. Their
  target home is `src/eventTypes/`, alongside `types.ts`.
- **`stateStore`, `stateLock`, `investigationStateFiles`, `caseSqliteWorker` and `sqliteRuntime`
  leave `analysis/` for `storage/`.** They are persistence, and `storage/backupManager.ts` already
  reaches up into `analysis/` for all five. The map files them under `storage` today, which is why
  `storage → analysis` is nearly absent from the ledger despite those imports existing.

## The forensic / super-timeline boundary

This is the one rule here about forensic correctness rather than tidiness. It is **decided,
enforced and tested**.

### The rule

`forensicGate.ts` partitions imported events by severity — `Low` and above into the **forensic
timeline**, `Info` telemetry into the **super-timeline** only. Then:

> **The model reads the forensic timeline. Nothing automatic reads the raw record.**

The reason is not tidiness. A real case carries tens of thousands of prefetch, amcache and shellbag
rows. Feeding them to a model exhausts the token budget and drowns the signal that earned the
forensic cut in the first place.

### Three analyst-initiated paths touch the raw record

None of them run on their own — each is a button the analyst presses. Two now satisfy the rule
**literally**, by promoting before asking:

| Path | How it obeys |
|---|---|
| `explainEvent` | promotes the one event, then explains it from the forensic timeline |
| `starredReport` | promotes the starred raw events, then reports from the forensic timeline |

Promotion is not a workaround, it is the honest record of what happened: clicking "explain this" or
starring an event **is** the analyst declaring it interesting, and the forensic timeline is where
interesting events live. Each promotion carries a note saying which action caused it, so it can be
told apart from an import six months later. This is the seam `runSecondLook` already used —
deterministic search, promote with provenance, then re-synthesize.

### `viewSummary` is the one sanctioned exception

It summarizes whatever the analyst has filtered the raw view down to, which can be thousands of
rows. Promotion is not available to it: writing thousands of Info events into the forensic timeline
would permanently drown the record — **obeying the rule that way would cause exactly the harm the
rule prevents.**

So it reads the raw record directly, under three constraints that keep it safe:

1. **Analyst-initiated only.** Nothing automatic reaches it.
2. **Ephemeral.** No promotion, no state change; nothing it reads enters the case.
3. **Capped** at `VIEW_SUMMARY_MAX_ROWS` (500, was 10,000), and it *tells the analyst* when the cap
   truncated their view rather than silently summarizing a slice.

The old 10,000 was more than a model summarizes usefully and more than an analyst can check, which
made the single exception the widest path into the raw record in the codebase.

### How it is enforced

`tests/analysis/forensicBoundary.test.ts` asserts each half: that `starredReport` promotes exactly
the starred events and records why, that `viewSummary` promotes **nothing**, that the cap holds, and
that truncation is disclosed. Each was mutation-tested — removing the promotion or restoring the
10,000 cap fails.

Fixing `explainEvent` also closed [#406](https://github.com/hasamba/DFIR-Companion/issues/406): its
old paged lookup searched only the first 500 rows, so explaining an event past that threw
`event not found` for an event that plainly existed, and the failure scaled with case size.
`starredReport` likewise stopped calling `.all(caseId)`, which materialized the entire
super-timeline to resolve a handful of ids.

## Enforcement

`npm run check:boundaries` — the third gate in the family `check:size` and `check:imports` already
established, and it works the same way.

- `scripts/module-map.json` assigns **every file** in `companion/src` to a domain, and declares the
  allowed edges. Files are listed by exact path, not by count, so deleting one file never creates
  room for a different one.
- `scripts/boundary-violations.json` records the **39 violations** that break the map today, as
  concrete `source-file → target-file [kind]` entries spanning 27 domain edges — an edge being one
  ordered `source-domain → target-domain` pair, resolved through this map, so the number is
  reproducible rather than remembered. Not domain pairs,
  and not counts: an already-recorded edge must not become a licence to add more imports along it.
  The `[kind]` suffix is `runtime` or `type`, and it is part of the key so that a grandfathered
  type-only edge turning into a runtime one reads as a **new** violation rather than passing
  silently — the coupling got strictly worse without either file changing name.
- The scanner sees `import … from`, bare `import "x"`, **`await import("x")`** and the
  **`import("x").Type`** type query. The last two matter: a dynamic import is precisely how someone
  routes around a boundary error, since the static form fails the gate and `await import()` did not.
- The list only shrinks. `--update` refuses to add an entry, so removing a violation is a visible
  deletion in review and adding one requires an argument rather than a silent edit.
- A test asserts the tables in this document match `module-map.json`. The JSON is what CI enforces,
  but a document that is allowed to drift from it is worse than no document — people read this file,
  not the JSON.

The graph is built the same way `check-imports.mjs` builds it: a regex over relative `.js`
specifiers, because the companion imports its own modules exclusively that way. No resolver needed.

For context: **1,839 of the 1,878 cross-domain file dependencies already comply.** The map is mostly
a description of how this codebase is already written, which is the only kind of rule people follow.
Both figures come from `npm run check:boundaries -- --json`, which counts them in the same pass that
finds the violations, and a test asserts this sentence against it. The pair read 1,275 of 1,323 long
enough to imply a ledger nine entries longer than the one on disk — nothing derived it and nothing
checked it, which is the only reason it could drift.

### The initial ledger

Every entry is small. Grouped by domain edge, with the shape of the problem:

| Files | Edge | What it is |
|---|---|---|
| ~~4~~ 0 | `detect -> integrations` | **CLEARED.** Five detectors importing `integrations/iris/mitreTactics.ts` for ATT&CK tactic names — reference data filed under a push client. The predicted fix was the one that worked: the file moved to `analysis/` (intel), and IRIS now imports it downward like any other consumer. |
| ~~3~~ 0 | `intel -> integrations` | **CLEARED** by the same move — it was the same `mitreTactics.ts` import. |
| 3 | `timeline -> detect` | `correlate.ts` and `stateMerge.ts` reaching for `chainSignature`, `exfilCorrelate`, `initialAccess` |
| 3 | `case -> integrations` | Velociraptor stores importing the API client's types |
| 3 | `intel -> workflow` | `playbook.ts` and `incidentTypes.ts` importing collection directives and templates |
| 3 | `workflow -> ai` | type-only back-references from `cockpit.ts` and `priorWork.ts`; see the tier note above |
| 2 each | `case -> ingest`, `intel -> detect`, `timeline -> findings`, `timeline -> ai`, `routes -> composition` | `routes -> composition` is the two `AppOptions` type imports |
| 1 each | `privacy -> detect`, `privacy -> findings`, `privacy -> ingest`, `case -> detect`, `case -> ai`, `case -> workflow`, `case -> enrichment`, `timeline -> intel`, `timeline -> workflow`, `findings -> ingest`, `detect -> ingest`, `intel -> ingest`, `intel -> findings`, `workflow -> reports`, ~~`workflow -> integrations`~~ (cleared — the third `mitreTactics.ts` importer), `shared -> findings`, `storage -> privacy`, `auth -> case`, `providers -> ai` | `shared -> findings` is `stateTypes.ts` importing an `IocExcludeRule` type — the event vocabulary should not know about IOC exclusion rules, and it is the one entry that is a genuine modelling wart rather than a misfiling |

### Known structural debt

Two tangles the map records rather than hides, because both need a design decision and neither
belongs in a boundary ledger pretending to be a small fix:

1. **`integrations/` mixes two layers.** The outbound push clients consume domain objects (Delivery);
   `velociraptorApi.ts` is a raw HTTP client with no domain knowledge (Platform). Until it is split
   into `integrations/push/` and `integrations/clients/`, one direction of every
   `analysis ↔ integrations` edge has to be ledgered whichever layer the directory is assigned.
2. **`public/dashboard.html` is decomposed, and all three of its targets are met.** Its inline
   JavaScript is 1,964 lines against the 2,000-line target, down from 19,203 when #384 wired the
   gates in. **That is all five `<script>` blocks without a `src`, which is what `check:size`
   ratchets** — 1,776 in the main block plus 82, 45, 43 and 18 in the four small ones. The main
   block alone is the flattering number and has never been the measure; #490 caught it circulating
   as if it were, at a point when choosing it would have closed #415 with 170 extractable lines
   still inline. The CSS half finished first: 3,234 lines of `<style>` became `public/css/dashboard-*.css`
   — since split by concern into seven files, the largest 488 lines — leaving 4 lines that are a DOM
   node the runtime writes into rather than a stylesheet. #415 is closed.

   What remains inline is the part that was never the target: the page's own wiring, `esc`/`escAttr`
   (pinned, at 694 and 263 call sites), and the shared keys like `targetKey` and `investigatorName`
   that belong to no single feature. 137 feature modules under `public/js/` hold the rest.

   `check:size` holds `public/js/**.js` to the same 800-line limit and freezes `dashboard.html`'s
   inline JS and CSS as separate shrink-only budgets — shrink-only, so meeting the target locks it
   in rather than reopening it as headroom. The markup itself is deliberately not measured — ~3,000
   lines of HTML is fine; a 16,000-line program inside a markup file was not.

   **`check:imports` does not cover the extracted modules, and no longer claims to.** It includes
   `public/js/**` so that "the first cycle between extracted feature modules fails a PR", but all
   138 modules #415 has produced are classic scripts publishing onto `window` — none uses
   `import`/`export`, so the regex-based graph sees 138 nodes and 0 edges. That pattern is
   deliberate (a feature must survive a sibling 404; see `public/js/dashboard-facade.js`), and it
   routes every inter-module dependency around that gate. The root stays for the pre-#415 ES modules
   under `public/js`, which do import.

   The ~463-edge global graph is governed instead by
   `companion/tests/dashboard/dashboardLoadOrder.test.ts`. **It does not look for cycles**, because
   that question is borrowed from ES-module semantics and does not transfer: here every cross-module
   name resolves through `window` at call time, so two features whose handlers call each other are
   fine, and 32 such cycles exist today, harmlessly. It asks about ORDER instead — whether a module
   calls a sibling's published name *during load*, before that sibling's `<script>` tag has run.
   Unguarded that throws inside the load-time IIFE and takes the rest of the module with it; guarded
   with `typeof` it is skipped in silence and the feature is simply never there. That is the blank
   page `check:imports` was reaching for.

   Standing it up found one: `dashboard-ioc-provenance.js` probed `window.DfirFacade` at its own
   load, ten module tags before the facade publishes it, so the guard was always false and its
   "feature unavailable" notice could never appear. That probe now sits with its siblings in the
   inline script, which runs after every module. With it fixed the count is zero, so the gate is
   hard and unbaselined. Closed by #482.

   It is **not** in the domain map above, and that is the remaining gap: the layer/tier rules cover
   `companion/src` only. Two extraction patterns now exist and they are not interchangeable:
   `public/js/hunt-workbench.js` and five siblings are ES modules with direct vitest coverage —
   those six predate #415 and are **not** what the extraction produces — while the 138
   `dashboard-*.js` feature modules are classic scripts whose contract is enforced by the manifest
   gate in `companion/tests/dashboard/dashboardFeatureModules.test.ts` and whose load order is
   enforced by `dashboardLoadOrder.test.ts`. Most have no behavioural test of their own; the
   swimlane's execution fixture (`dashboardSwimlaneWiring.test.ts`, #479) is the pattern for one.

## Migration

Nothing is sorted in a big bang. The map classifies every file now, so the gate is live from day one;
what happens incrementally is the *physical* move into domain directories.

Each extraction PR: moves one cohesive group into its domain directory, re-records the smaller number
with `npm run check:size -- --update` (shrink-only, so the new size becomes a permanent floor), and
deletes any ledger entries it resolves.

The order, by ascending risk:

1. **Resolve the forensic / super-timeline rule** (above). It gates only the `analysis/ai/` boundary
   rule, not the rest of the map — the other ten domains carry no forensic semantics and should not
   wait on a product decision.
2. Land the map, `module-map.json`, the exact violation ledger, `check:boundaries`, and CI wiring.
3. ~~Extend the size **and cycle** ratchets to `public/js/**`; add inline JS/CSS budgets for
   `dashboard.html`.~~ **Done** — `check:size` covers `public/js/**.js` plus `#inline-js` and
   `#inline-css` budgets for every `public/*.html`; `check:imports` covers `public/js/**`.
4. Characterization tests before anything moves: route/middleware inventory, environment-factory
   behaviour, persisted-state and report-format compatibility, per-dashboard-feature regression.
5. `server.ts` integration factories → `src/composition/` (~500 lines, pure env reads, no domain logic).
6. `pipeline.ts` prompts → `analysis/ai/prompts/`. **Four consumers read `pipeline.ts` for prompts and
   must move atomically with it, or `pipeline.ts` stays as a compatibility facade:**
   `tests/eval/changeGate.ts` (string-searches for the constants and *throws* if absent),
   `tests/eval/checkChange.ts:36`, `tests/eval/identity.ts:21` (both read the file path directly), and
   `scripts/eject-prompts.ts:11` (imports the constants).
7. The 35 `importX` methods → `analysis/ingest/` per-format modules.
   **Done, and #418 finished the rest of `pipeline.ts` on the same pattern:** the AI-backed families
   (the analyst reports, hunt generation, extraction, the provider-call gate, synthesis, Deep Pass,
   second opinion) are free functions in `analysis/ai/` taking a narrow context interface, and the
   class holds one-line delegations. `AnalysisPipeline` is now a facade — 591 lines, of which the 36
   import delegations are the largest single block. What made this harder than the ingest extraction
   is written up in the module headers: synthesis's context is deliberately wide because synthesis
   genuinely touches most of `PipelineOptions`, and `tests/analysis/synthesizeCharacterisation.test.ts`
   is the substitute for the machine attestation the prompt move could rely on.
8. `mitreTactics.ts` → `intel/`; `correlate.ts` → `timeline/`; the five persistence modules →
   `storage/`; `stateTypes.ts` + `canonicalEvent.ts` → `src/eventTypes/`. Together these clear
   roughly a third of the ledger, because the map already files them where they belong and only the
   files themselves have yet to move.
9. ~~`createApp`'s middleware (~2,350 lines in one function)~~ — done in #416: it is now 19 factories
   under `src/composition/`, each taking its dependencies by name. Then dashboard features as small
   vertical slices.

### Who owns what

#384 established the map and the gates, and took the two extractions that could be made provably
safe. It is closed. The size targets it defined did not disappear with it — each one now sits with
the issue that owns the work, so no number is a blocker without an assignee:

| Target | ≤ | Today | Owner |
|---|---|---|---|
| `analysis/pipeline.ts` | 800 | **591 — met** | [#418](https://github.com/hasamba/DFIR-Companion/issues/418) |
| `server.ts` | 800 | **623 — met** | [#416](https://github.com/hasamba/DFIR-Companion/issues/416) |
| `public/dashboard.html` inline JS | 2,000 | 1,964 — met | [#415](https://github.com/hasamba/DFIR-Companion/issues/415) |
| `public/dashboard.html` inline CSS | 800 | **4 — met** | [#415](https://github.com/hasamba/DFIR-Companion/issues/415) |
| `public/css/dashboard-*.css` (8 parts) | 800 | **489 max — met** | [#415](https://github.com/hasamba/DFIR-Companion/issues/415) |
| Files in `src/` over 800 lines | 0 | 10 | the ledger below |
| Flat files in `src/analysis/` | 0 | 296 | whichever extraction touches them |
| Boundary ledger | 10 | 39 | shrinks as the above land |

**The ratchets hold every one of these flat in the meantime.** `check:size` freezes each file at its
recorded length, `check:imports` at one known cycle, `check:boundaries` at the recorded violations.
Nothing on this list can get worse while nobody is working on it — which is the whole reason the
gates were built before the extractions rather than after.

Two of these numbers moved the *wrong* way during #384, from ordinary parallel work: the dashboard's
inline script grew by 110 lines and `src/analysis/` gained six files. That is not a failure of the
gates — they froze the new numbers as soon as they landed — but it is the argument for #415 and #416
having owners rather than waiting.

**`public/css/dashboard-*.css` was a new row, not a new problem.** #415 moved the CSS out of the
`<style>` blocks, which would otherwise have retired the `inline CSS` budget by making the gate stop
looking: `check-file-size.mjs` walks `public/js` and now `public/css` too, so the 3,224 lines are
still ledgered and still shrink-only, at their new address. A budget a file can escape by changing
extension is not a budget.

---

## The dashboard client

The five layers above describe `companion/src`. The browser half has its own shape, and since #415
it has a written answer to the question that governs it.

- **`public/css/dashboard-*.css`** — the stylesheet, in eight cascade-ordered parts. Was fourteen
  inline `<style>` blocks, then one 3,261-line file. The parts are a pure byte split: concatenating
  them in link order reproduces that file exactly, which is what keeps the cascade unchanged.
- **`public/js/dashboard-*.js`** — pure helpers extracted from the inline script: escaping, time
  formatting, text and prevalence shapes, glyphs, filters, IOC verdicts, value derivations and HTML
  fragment builders. Classic scripts rather than ES modules, deliberately;
  [`dashboard-escape.js`](public/js/dashboard-escape.js) carries the argument.
- **`public/js/<feature>.js`** — feature modules with their own DOM: the graph views, the command
  palette, settings search, the hunt workbench, the diagnostics panel, the case-load progress bar.
- **`public/js/dashboard-state.js`** — **who owns dashboard state.** Read this before moving
  anything else out of the inline script.

The last one is the one that matters, because it is what the remaining ~18,000 lines are blocked on.
Move a function that reads `lastState` and you have to decide who owns `lastState` first. The file
answers that from measurement rather than taste — of 422 top-level bindings, 145 are never written,
231 more are read by five functions or fewer, and the two hottest have **one writer each** — and
draws three tiers from it: the case snapshot and the cross-cutting selection are owned centrally,
and the other 231 bindings move into their feature's module and stay private. It also records what
was rejected (one store for all 408; a reactive layer; per-feature objects with no centre) and why.

Every module under `public/js/` and `public/css/` must be listed in `STATIC_ASSETS`
(`src/http/staticAssets.ts`) or it 404s in production with no other symptom.
`tests/settings/settingsSearch.test.ts` pins that, walking the import graph so a transitive import
cannot be missed either.

