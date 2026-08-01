# Architecture — the module map

The target structure for `companion/src`, and the dependency rules that hold it in place.

This exists because of [#384](https://github.com/hasamba/DFIR-Companion/issues/384): `analysis/pipeline.ts`
is 6,136 lines and `server.ts` is 4,275, and they got that way because there was never a written answer
to "where does this code go?" Decomposing them without that answer just produces smaller files in
arbitrary places, and the tangle regrows. So the map comes first, the extractions follow it, and
`npm run check:boundaries` stops the next tangle forming.

**How to use it:** before adding a module, find its domain below. Before adding an import, check the
edge is allowed. If the code you want to write does not fit any domain, that is worth a conversation
in the PR — not a new top-level directory.

**Status:** every file in `companion/src` is assigned to a domain **today**, in
`scripts/module-map.json`. The rules are enforced from day one; they do not wait for files to move.
The domain *directories* are the target — `src/analysis/` is 290 files in one flat directory right
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
exists to control. It is not a rounding error either: **16 of the 48 recorded violations are
type-only**, so exempting them would have hidden a third of the problem on day one.

| Layer | Contents | May import |
|---|---|---|
| **Composition** | `server.ts`, and `src/composition/` once the integration factories land | everything |
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
| **5** | `ai/` | `pipeline`, the ~25 prompt constants, `synth*`, `deepPass*`, `hypothesis*`, `secondOpinion`, `secondLook`, `uncertainty`, `queryTranslate`, `aiCost` | 25 | 10,861 |
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

Four placements worth stating outright, because each one is a decision someone will otherwise
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

This is the one rule here about forensic correctness rather than tidiness, and it is **unresolved**.
What follows states the invariant, records the paths that break it, and hands the decision back to
#384. It is deliberately not settled in this document — the resolution changes product behaviour,
and that is not a call an architecture refactor gets to make quietly.

### The invariant, as the code states it

`forensicGate.ts:7` partitions imported events by severity — `Low` and above to the **forensic
timeline**, `Info` telemetry to the **super-timeline** only — and states the consequence directly:

> anything graded Info never reaches the forensic timeline, so the AI cannot see it

`superTimeline.ts:1` says the same from the other side: the super-timeline is *"never synthesized by
AI"*. Read together: **AI reasons over the forensic timeline; Info-graded telemetry is not AI input.**

The reason is not tidiness. The super-timeline is unbounded in a way the forensic timeline is not —
a real case carries tens of thousands of prefetch, amcache and shellbag rows. Feeding them to a model
exhausts the token budget and drowns the signal that earned the forensic cut in the first place.

### Three paths currently break it

| Path | What reaches the model |
|---|---|
| `explainEvent` (`pipeline.ts:4340`) | a raw super-timeline event plus its raw neighbours |
| `starredReport` (`pipeline.ts:4892`) | super-timeline-only events the analyst starred |
| `viewSummary` (`pipeline.ts:4985`) | up to 10,000 raw rows from the analyst's current filter |

These are debt, not policy. This document records them; it does not sanction them.

Their bounds are also weaker than they look. `starredReport` calls `.all(caseId)` and materializes
the entire super-timeline to resolve a handful of ids. `viewSummary` reads 10,000 rows.
`explainEvent`'s paged lookup is outright broken — it searches only the first 500 rows and throws
`event not found` for anything past them, filed as
[#406](https://github.com/hasamba/DFIR-Companion/issues/406). Whatever the boundary decision, these
need targeted store operations and hard volume caps.

### `runSecondLook` is the compliant pattern

`runSecondLook` (`pipeline.ts:5932`) also touches the super-timeline and does **not** break the
invariant, because it never hands the model a raw record:

1. deterministic search over the raw record, bounded by the incident window;
2. matches promoted into the forensic timeline, tagged with provenance;
3. re-synthesis reads the forensic timeline, as always.

Promotion is the seam. Anything that needs raw rows to influence AI output should converge on this
shape, and the promotion step belongs **outside** `analysis/ai/` — it is a timeline operation, not an
AI one.

### What #384 has to decide

For `explainEvent` and `starredReport`, promotion-first is plausible: both operate on analyst-chosen
ids, and the promoted set is small.

For `viewSummary` it is not. Promoting up to 10,000 Info events to make the summary "legal" would
write that telemetry into the forensic timeline permanently, polluting the exact record the invariant
protects and degrading every later automatic synthesis. `viewSummary` is inherently *"tell me about
the raw telemetry I am looking at"*. The honest options are to keep it as a named exception with a
hard row cap, or to drop the feature — not to launder it through promotion.

So: **decide the rule first, then enforce it.** If the outcome is strict, the enforcement is that
nothing under `analysis/ai/` may import `analysis/timeline/superTimelineStore.js` at all, and the
promotion helper lives in `analysis/timeline/`. If the outcome carries exceptions, they are named
modules on an explicit allowlist with their caps stated. Either way the rule is mechanical once
`analysis/ai/` exists as a directory; it cannot be scoped before then.

## Enforcement

`npm run check:boundaries` — the third gate in the family `check:size` and `check:imports` already
established, and it works the same way.

- `scripts/module-map.json` assigns **every file** in `companion/src` to a domain, and declares the
  allowed edges. Files are listed by exact path, not by count, so deleting one file never creates
  room for a different one.
- `scripts/boundary-violations.json` records the **48 violations** that break the map today, as
  concrete `source-file → target-file [kind]` entries spanning 30 domain edges. Not domain pairs,
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

For context: **1,275 of the 1,323 cross-domain file dependencies already comply.** The map is mostly
a description of how this codebase is already written, which is the only kind of rule people follow.

### The initial ledger

Every entry is small. Grouped by domain edge, with the shape of the problem:

| Files | Edge | What it is |
|---|---|---|
| 4 | `detect -> integrations` | five detectors importing `integrations/iris/mitreTactics.ts` for ATT&CK tactic names — reference data filed under a push client. Moving it to `intel/` clears this edge and most of the next two. |
| 3 | `intel -> integrations` | same `mitreTactics.ts` import |
| 3 | `timeline -> detect` | `correlate.ts` and `stateMerge.ts` reaching for `chainSignature`, `exfilCorrelate`, `initialAccess` |
| 3 | `case -> integrations` | Velociraptor stores importing the API client's types |
| 3 | `intel -> workflow` | `playbook.ts` and `incidentTypes.ts` importing collection directives and templates |
| 3 | `workflow -> ai` | type-only back-references from `cockpit.ts` and `priorWork.ts`; see the tier note above |
| 2 each | `case -> ingest`, `intel -> detect`, `timeline -> findings`, `timeline -> ai`, `routes -> composition` | `routes -> composition` is the two `AppOptions` type imports |
| 1 each | `privacy -> detect`, `privacy -> findings`, `privacy -> ingest`, `case -> detect`, `case -> ai`, `case -> workflow`, `case -> enrichment`, `timeline -> intel`, `timeline -> workflow`, `findings -> ingest`, `detect -> ingest`, `intel -> ingest`, `intel -> findings`, `workflow -> reports`, `workflow -> integrations`, `shared -> findings`, `storage -> privacy`, `auth -> case`, `providers -> ai` | `shared -> findings` is `stateTypes.ts` importing an `IocExcludeRule` type — the event vocabulary should not know about IOC exclusion rules, and it is the one entry that is a genuine modelling wart rather than a misfiling |

### Known structural debt

Two tangles the map records rather than hides, because both need a design decision and neither
belongs in a boundary ledger pretending to be a small fix:

1. **`integrations/` mixes two layers.** The outbound push clients consume domain objects (Delivery);
   `velociraptorApi.ts` is a raw HTTP client with no domain knowledge (Platform). Until it is split
   into `integrations/push/` and `integrations/clients/`, one direction of every
   `analysis ↔ integrations` edge has to be ledgered whichever layer the directory is assigned.
2. **`public/dashboard.html` is gated but not yet decomposed.** It is 25,571 lines, of which 19,256
   are JavaScript inside `<script>` tags and 3,231 are CSS inside `<style>` tags — larger than
   `pipeline.ts` and `server.ts` combined. It sits outside `companion/src/`, so until #384 wired it
   in, neither ratchet had ever seen it, and it grew by 165 lines of script during the branch that
   added the gates.

   Both ratchets now cover it: `check:size` holds `public/js/**.js` to the same 800-line limit and
   freezes `dashboard.html`'s inline JS and CSS as separate shrink-only budgets, and `check:imports`
   includes `public/js/**` so the first cycle between extracted feature modules fails a PR. The
   markup itself is deliberately not measured — ~3,000 lines of HTML is fine; a 19,000-line program
   inside a markup file is not.

   It is **not** in the domain map above, and that is the remaining gap: the layer/tier rules cover
   `companion/src` only. The extraction pattern is proven (`public/js/hunt-workbench.js` and five
   siblings are ES modules with direct vitest coverage), so the next step is moving features out,
   not designing a second map.

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
8. `mitreTactics.ts` → `intel/`; `correlate.ts` → `timeline/`; the five persistence modules →
   `storage/`; `stateTypes.ts` + `canonicalEvent.ts` → `src/eventTypes/`. Together these clear
   roughly a third of the ledger, because the map already files them where they belong and only the
   files themselves have yet to move.
9. `createApp`'s middleware (~2,350 lines in one function), then dashboard features as small vertical
   slices.

### What closes #384

Progress needs a finish line, not just a direction. #384 is an umbrella; each slice above is a child
issue, and the umbrella closes when all of these hold:

| Condition | Today | Target |
|---|---|---|
| `analysis/pipeline.ts` | 6,136 lines | ≤ 800 |
| `server.ts` | 4,275 lines | ≤ 800 |
| `public/dashboard.html` inline JS | 19,256 lines | ≤ 2,000 |
| `public/dashboard.html` inline CSS | 3,231 lines | ≤ 800 |
| Files in `src/` over 800 lines | 13 | 0 |
| Flat files in `src/analysis/` | 290 | 0 |
| Boundary ledger | 48 violations | ≤ 10 |
| Forensic / super-timeline rule | unresolved | decided, enforced, tested |
