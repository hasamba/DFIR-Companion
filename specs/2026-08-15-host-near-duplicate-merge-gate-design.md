# Host near-duplicate merge gate

- **Date:** 2026-08-15
- **Status:** Approved, not yet implemented
- **Branch:** `claude/merge-duplicate-win11-hosts-7f5fc5`

## Problem

One machine that appears under two spellings — a short name (`WIN11`) and an FQDN
(`WIN11.windomain.local`) — is treated as two separate hosts throughout the case. The analyst
discovers this only after AI synthesis has already run, by which point the narrative, the findings,
and the playbook have all been built on a split host.

`findNearDuplicates()` in `companion/src/analysis/hostAlias.ts:113` already detects exactly this
shape. Today its result is surfaced in one place — a passive warning inside the Host Scope panel
(`public/js/dashboard-host-scope.js:89-100`) — that nothing forces the analyst to read, and that
appears long after the damage is done.

## Why this is not cosmetic

A split host corrupts one analytical decision outright. `Finding.corroboration.distinctHosts`
(`companion/src/analysis/findingGrounding.ts:198`) counts distinct `event.asset` values, so one host
spelled two ways reads as "seen on 2 hosts". That trips the `distinctHosts <= 1` guard at
`findingGrounding.ts:239` and lets an **uncorroborated finding skip its confidence downgrade** — the
finding is scored as better-evidenced than the evidence supports.

Other host-keyed state that synthesis writes back, all wrong when a host is split:

- `state.attackerPath` — a one-machine intrusion narrated as two (`stateMerge.ts:377-378`)
- AI-created events echo back whichever spelling the model saw, permanently seeding a **third**
  spelling into `forensicTimeline` (`responseSchema.ts:85`)
- `CollectDirective.host` on next steps and key questions recommends collecting from a host already
  collected under its other spelling

## Decisions

| # | Decision |
|---|---|
| 1 | An unresolved near-duplicate pair **hard-blocks** synthesis until the analyst resolves it. |
| 2 | Unattended imports block too, and fire a **milestone notification** so the case does not stall silently. |
| 3 | Resolving the **last** pending pair **auto-runs** the blocked synthesis. |
| 4 | A merge **resolves host names at prompt-render time**, everywhere synthesis reads or ranks them. Stored evidence is never rewritten. |

## Architecture

### Source of truth: `forensicTimeline` only

Detection reads host names from `InvestigationState.forensicTimeline` plus the fleet roster.

This is sufficient and correct: the super timeline is touched exactly once during synthesis, and
only *after* the model call, in the second-look sweep (`synthesis.ts:547`). It never feeds the
prompt, so it cannot contribute a host that poisons the output.

It is also the only affordable option. `aggregateHostEvidence`
(`companion/src/analysis/hostScopeAggregate.ts:133-141`) streams every super-timeline event with no
time filter, and there is no `DISTINCT`-asset fast path in `caseSqliteWorker.ts`. On a 5M-event case
that is roughly 5,000 worker round-trips and 5M `JSON.parse` calls — tens of seconds to minutes, on
every synthesis run. The Host Scope panel keeps its broader super-timeline view as advisory; the
gate deliberately covers the narrower set that actually reaches the model.

### Where the gate lives

A single chokepoint inside `synthesize()`, at `companion/src/analysis/ai/synthesis.ts:450`:

```ts
448:  const loaded = await ctx.opts.stateStore.load(caseId);
449:  if (loaded.forensicTimeline.length === 0) return loaded;
450:  // ← gate here: state loaded, no prompt built, no provider call, nothing written
451:  const run = await prepareSynthesisRun(ctx, caseId, loaded, observationsBlock);
```

Every path that runs the AI funnels through `synthesize()` — all ~30 import routes via
`resynthesizeInBackground` (`composition/captureAnalysis.ts:260-324`) and the manual Synthesize
button. Guarding at the ~30 import call sites instead would offer ~30 chances to miss one, and a
missed one is a silent hole in the safety property being built.

Detection additionally runs at **import completion**, where it raises the badge and fires the
notification. That second placement is what makes the feature work when AI is disabled for a case:
`resynthesizeInBackground` bails early when there is no provider or the per-case AI toggle is off,
so the gate would never fire, but the analyst is still told.

### Notification

Reuse the existing notifier — `createCaseNotifier` (`composition/caseNotifier.ts:25`) — with
`kind: "milestone"`. Milestones **bypass the per-channel severity threshold**
(`analysis/notifications.ts:77-78`, `shouldNotify`), so a blocked case cannot be filtered into
silence by a channel configured for Critical-only. No new notification kind is needed.

### What gets stored: dismissals only

The pending list is **derived, not stored**. A merged pair stops being flagged on its own, because
`findNearDuplicates` resolves names through the alias index *before* looking for short/FQDN pairs
(`hostAlias.ts:114`), and a merge makes both spellings resolve to one canonical name. Merges already
persist in `AssetOverridesStore`.

The only new persisted state is dismissals — "these really are two different machines":

```
state/host-duplicate-dismissals.json  →  [{ canonical, other, dismissedAt, dismissedBy }]
```

Pending = `findNearDuplicates(...)` minus dismissals, computed on read. There is no second copy of
the truth to drift out of sync, and no "already checked this case" flag to go stale — which is what
makes a duplicate arriving on import 47 behave identically to one arriving on import 1.

Store shape follows `PresidioPendingStore` (`companion/src/analysis/presidioPending.ts:11-38`):
per-case JSON under `store.stateDir(caseId)`, written with `atomicWrite`.

### Making the merge reach the AI

Wiring `assetOverridesStore` and the fleet client store into `SynthesisContext.opts`
(`synthesis.ts:75-90`, `ai/pipelineOptions.ts`) is **required, not optional** — without a real
`HostAliasIndex` the gate cannot distinguish an already-merged pair from an unresolved one and would
re-prompt forever on hosts the analyst already merged.

Once the index is available there, it must resolve host names at every point synthesis renders or
ranks them. All of these are called **without** an alias index today:

| Location | What it produces |
|---|---|
| `synthesisPromptEvents.ts:157-158`, `synthEvidence.ts:31` | per-event `<host:{e.asset}>` tags |
| `synthGroup.ts:78`, `:242-251` | `on N hosts (a, b, +k more)` |
| `synthSelect.ts:351` | `COMPROMISED ASSETS` block via `buildAssetGraph` |
| `synthSelect.ts:413-417` | `SIGNAL CONCENTRATION` via `buildSignalConcentrationDigest` → `rankHosts` |
| `knownUnknowns.ts:282` | uncovered-phase collect targets via `rankHosts` |
| `synthesisMerge.ts:288-290` | `hostNames` set gating corroboration steps |

The per-event tags matter most: without resolving those, the model reads both spellings in the raw
event stream and will narrate two machines no matter what the derived blocks say.

Resolution happens **at render time only**. Stored events keep their original `asset` string, the
same way `AssetOverrides` is an overlay rather than a mutation. Raw evidence is never rewritten.

`rankHosts` and `buildAssetGraph` already accept an optional `aliasIndex` parameter — that plumbing
landed earlier on this branch for the playbook path (see *Prior work* below); this design extends
the same parameter to the synthesis call sites.

## Data flow

```
import lands evidence
  └─ detect near-dups (forensicTimeline assets + fleet roster, minus dismissals)
       └─ any unresolved? → milestone notification + raise the dashboard badge

resynthesizeInBackground → synthesize()
  └─ line 450: unresolved pairs?
       ├─ yes → throw HostMergeDecisionRequired (before any prompt build or token spend)
       │         → 409 + ai_status:"error" → badge + panel
       └─ no  → proceed, resolving every host name through the alias index

analyst resolves a pair
  ├─ Merge         → existing POST /cases/:id/asset-overrides/assets/:assetId/merge (FQDN canonical)
  └─ Keep separate → append to host-duplicate-dismissals.json

  └─ pending list now empty? → auto-kick synthesis
```

Merge direction defaults to the **FQDN as canonical**, matching what `buildHostAliasIndex` already
treats as canonical (`fqdn || hostname`, `hostAlias.ts:54`).

## Components

**New**

- `companion/src/analysis/hostDuplicateDismissals.ts` — the dismissals store
- `companion/src/analysis/hostDuplicateGate.ts` — derives the pending list; owns
  `HostMergeDecisionRequired`
- `companion/src/routes/hostDuplicates.ts` — `GET /cases/:id/host-duplicates`,
  `POST …/merge`, `POST …/dismiss`
- `public/js/dashboard-host-duplicates.js` — badge + panel, modeled on `dashboard-presidio.js`

**Modified**

- `ai/synthesis.ts` — the guard at line 450
- `ai/pipelineOptions.ts`, `analysis/pipeline.ts`, `composition/aiProviders.ts` — thread
  `assetOverridesStore` + fleet store into the synthesis context
- `synthSelect.ts`, `knownUnknowns.ts`, `synthGroup.ts`, `synthesisPromptEvents.ts`,
  `synthesisMerge.ts` — resolve host names through the alias index
- `ai/retry.ts:20` — add `HostMergeDecisionRequired` to the non-retryable list, beside
  `PresidioApprovalRequired`; otherwise the gate burns three retries per run
- `routes/presidioApproval.ts:31-37` — one more branch in `sendPipelineError` →
  `409 { error: "host_merge_decision_required", pairs: [...] }`
- `composition/captureAnalysis.ts` — import-time detection + notification

## Error handling

The gate throws before any provider call, so a blocked run spends no tokens and writes no state.

The panel loads on **case-connect and on `ai_status:"error"`**, not only on the 409. This is not
belt-and-braces; it is required. Imports respond `202` and kick synthesis fire-and-forget, so there
is no open request to carry a 409 when the gate fires mid-import. `dashboard-presidio.js:181-186`
documents this exact constraint for the PII gate.

Two known, accepted limitations:

- `synthesize()` recurses at `synthesis.ts:566` inside a `try` whose `catch` at `:573` swallows and
  logs. A gate throw on that second-look re-synthesis will not surface as a badge; the first-pass
  result stands. Acceptable — the first pass is the one that builds the panels, and it was already
  gated.
- The second-opinion `dryRun` path also routes through `synthesize()`, so the gate blocks it too.
  This is correct: a second opinion on a split host is as wrong as a first one.

## Edge cases

- **Duplicate appears on a later import.** Caught. The pending list is re-derived from full current
  state on every check, so import 47 behaves like import 1.
- **Fleet roster already links the pair.** No prompt. `buildHostAliasIndex` pairs hostname↔fqdn from
  the snapshot, so both spellings resolve to one canonical name and `findNearDuplicates` — which
  runs over resolved names — never flags them.
- **Analyst dismissed the pair earlier.** Never asked again; dismissals are permanent per pair.
- **Three spellings** (`win11`, `win11.example.com`, `win11.corp.local`). `findNearDuplicates`
  yields one pair per short/FQDN combination, so two pairs surface and both must be resolved. The
  block lifts only when the list is empty.
- **Case already synthesized before this ships.** The next synthesis blocks, the analyst merges, and
  the auto-run repairs the panels.
- **AI disabled for the case.** The gate never fires, but import-time detection still raises the
  badge and notification.

## Testing

- Pending derivation: dismissals filter out; a merged pair stops being flagged; a fleet-linked pair
  is never flagged; three spellings yield two pairs.
- Gate: throws at `synthesis.ts:450` before any provider call (assert the provider mock is never
  invoked); `retry.ts` does not retry it; `sendPipelineError` maps it to the 409 shape.
- Auto-kick fires only when the **last** pair clears, not on the first of two.
- Merge reach: with an alias index, the rendered prompt contains exactly one spelling — assert on
  the per-event `<host:>` tags specifically, since those are the ones that would otherwise leak
  both.
- Corroboration: a finding supported by events on one host spelled two ways reports
  `distinctHosts === 1` and does **not** escape the confidence cap.
- Regression: a case with no near-duplicates synthesizes byte-identically to today. This gate must
  be invisible when it has nothing to say.

## Prior work on this branch

Uncommitted changes already thread an optional `aliasIndex` through the playbook path:
`assetGraph.ts`, `hostRanking.ts`, `hostScopeLoad.ts` (adds `loadHostAliasIndex`), `playbook.ts`,
`caseAppliers.ts`, `routes/aiSynthesis.ts`, plus a regression test in
`tests/analysis/hostRanking.test.ts`. That work is consistent with this design and is its
foundation — this spec extends the same parameter into the synthesis path and adds the gate in
front of it.

## Out of scope

- Widening detection beyond the short-name/FQDN rule (e.g. Velociraptor client-id pairing). The
  current rule is high-precision; loosening it risks prompting on genuinely distinct machines.
- Merging account entities. `hostMergesFromAssetIds` (`hostAlias.ts:97`) deliberately ignores
  non-host merges: folding a host into an account states something about ownership, not identity.
- Backfilling the corrected host into already-written `attackerPath` prose. The auto-run
  re-synthesis regenerates it.
