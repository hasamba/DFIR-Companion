# Making DFIR-Companion Lead the Investigation

> **Implementation status: ALL 15 proposals shipped and merged to master — the roadmap is COMPLETE.**
> #1–#15 are implemented, unit-tested, and merged (PRs #96–#99, #102, #103 for #1–#10; #11 = second-look
> loop; #12 = immediate FP cascade; #13 = rabbit-hole detection; #14 = ACH-style hypotheses; #15 =
> per-case prevalence/baseline + proactive FP-pattern propagation, landed as #15a + #15b). Full suite
> green (3638 tests), clean `tsc`. Deferred within those items (documented
> in each commit): the `~` context-prefix prompt notation and per-class counts into synthMeta (#4); the
> anchor-scoring bump retune and the auto-generated "corroborate `<ioc>`" nextStep (#7); #10 trigger (b)
> cap-hit truncation; #11 report-side surfacing of collection leads (kept on the live dashboard only);
> #14 threading an explicit `relatedHypothesisId` through the hunt-DEPLOY route/UI (exhaustion works
> today via technique-overlap matching; the explicit link field exists but isn't set from the UI yet).
> **One operational step remains for #1:** the live `companion/prompts/*.txt` override files are
> gitignored deployment artifacts — regenerate them with `npm run prompts:eject` so the deployment picks
> up the built-in prompt (hypotheses / confidenceReason / structured-tag & attack-graph / #8 collect /
> #11 evidenceRequests instructions). Until then the drift-detection check warns on every preflight and
> synthesis run. **The roadmap is fully delivered; no items remain.**

**Goal.** Make the Companion genuinely lead an investigation — better decisions, higher recall of
what actually happened, better dot-connecting, a working FP / rabbit-hole / real-lead triage, the
right questions at the right time, and concrete "collect X from host Y, here's why" direction —
by improving the intelligence and wiring of the loop that already exists, not by bolting on new
features.

**How this was produced.** A multi-agent audit: six readers mapped the synthesis pipeline, the
existing guidance surfaces, the FP/triage machinery, the correlation layer, the investigator UX
flow, and the full ground-truth benchmark history (fairhaven, halcyon, veridia, northpeak,
branch-office, spillage, llm-injection). Four expert lenses (IR lead, detection engineering,
LLM-pipeline engineering, intelligence-analysis methodology) proposed improvements; overlapping
proposals were merged (convergence across independent lenses is noted — it is a strong quality
signal); each merged proposal was then adversarially judged by skeptics instructed to refute it
against the real code. Line references are to the state of the code at the time of the audit.

---

## The diagnosis: five structural reasons the guidance doesn't lead

The individual guidance surfaces already exist and are individually well built — synthesis emits
prioritized `nextSteps` with collection pointers and 12 standard `keyQuestions` with
answered/partial/unknown status; there are status-tracked hypotheses with expected outcomes, gap
hypotheses paired with deployable shadow-artifact collections, AI fleet-hunt suggestions with a
real hit/miss feedback loop, and a memory next-step agent that emits exact Volatility commands.
The problem is structural, not missing surfaces:

1. **The AI sees a crippled view of the evidence.** Synthesis is one shot over ≤300 events chosen
   by severity + earliest-15 + even time-spread (`synthSelect.ts`). The true attack chain in four
   consecutive benchmarks was graded Low/Info and never won a context seat, while mis-graded noise
   filled the cap — so the model narrated the noise (halcyon fabricated an APT story; fairhaven
   invented 5 findings; northpeak's whole recon/exfil front half never surfaced). Each selected
   event is rendered as one 240-char prose line: asset, process lineage, src/dst IP, and
   corroborating-source count are all dropped. The deterministic causal attack graph
   (`evidenceGraph.ts`/`graphContext.ts`) is fed to `ask()` and `suggestHunts()` but **not** to the
   one call that writes findings and the attacker path. Beacon and burst detections never reach any
   prompt.

2. **The loop never closes.** The super-timeline (the complete raw record) is unreachable by
   synthesis except via manual promotion; hypotheses name their own confirming evidence
   (`expectedOutcome`) and unknown questions name hosts — and nothing searches the raw store for
   those terms. Hunt hit/miss outcomes, playbook task completion, and refuted hypotheses are never
   fed back into synthesis, so the tool re-recommends work the analyst already did and re-asserts
   theories the analyst already killed.

3. **Collection directives are free prose, so nothing can act on them.** `NextStep.pointer` and
   `InvestigationQuestion.pointer` carry "pull Security.evtx 4624 on HOST07" as text. The rich
   Velociraptor plumbing that already exists (collect-host, shadow-artifact deploys, hunt outcome
   tracking) can't attach a Deploy button; nothing detects that a later import satisfied the
   request, so stale "collect X" recommendations keep rendering after X was collected — the single
   fastest way to teach analysts to ignore the guidance.

4. **Nothing separates FP from rabbit hole from lead.** The taxonomy is binary live/FP. A
   real-but-irrelevant artifact (veridia's rclone red herring, halcyon's benign USB copy) has no
   representation. Finding confidence is an unverifiable model-emitted number; findings routinely
   ship with zero `relatedEventIds` (unfalsifiable from the UI); corroboration is computed for IOCs
   and merged events but never rolled up to findings; and one stale CTI verdict can still mint a
   Critical finding against the org's own server (northpeak).

5. **The deployed system silently disables its own intelligence.** The live prompt files in
   `companion/prompts/` (which `.env` points at, overriding built-ins) are stale: `synthesis.txt`
   contains no `hypotheses` section, no `confidenceReason`, no `keyQuestions.relatedFindingIds` —
   so in the actual deployment, synthesis-driven hypothesis auto-generation never fires and
   confidence ships unexplained. Separately, a 27K-line proxy log that yields **zero** events shows
   up as a quiet "+0 events" — the tool cannot see, or warn about, its own blind spots.

---

## Recommendations, in build order

Effort: S = hours-to-a-day, M = days, L = a week-plus. "Confirmed" = survived both adversarial
judges; "verified" = premise checked directly against the code.

### Tier 0 — Prerequisites and same-day wins

#### 1. Re-eject the live prompt files + prompt-capability drift detection (S) — confirmed, prerequisite for everything prompt-touching
- Regenerate `companion/prompts/synthesis.txt`, `system.txt`, `log.txt`, `csv.txt` from the current
  built-ins (`npm run prompts:eject` to a temp dir, diff, port deliberate local edits forward).
  This alone revives hypothesis auto-generation (#140), `confidenceReason`, and
  `keyQuestions.relatedFindingIds` in the live deployment.
- Add per-prompt `REQUIRED_MARKERS` lists (literal JSON field names, e.g. SYNTH →
  `hypotheses`, `confidenceReason`, `relatedFindingIds`) next to the built-in constants. At startup
  (server.ts preflight route feeding `preflight.ts`): (a) assert each marker appears in its own
  built-in (so the marker list can't rot), (b) substring-check each configured override file and
  emit one warning per drifted prompt: *"prompt override synthesis.txt is missing capabilities:
  hypotheses, confidenceReason — model output will silently lack them."* Also log once per
  synthesis run, since `_PROMPT_FILE` is re-read per call.
- Files: `companion/prompts/*.txt`, `src/analysis/pipeline.ts`, `src/analysis/preflight.ts`.
- Note: gap-driven hypotheses (GAPHYP path) still work today; it is the synthesis-driven
  auto-generation that is dead live.

#### 2. Condition synthesis on what the investigator already did (S) — confirmed
Three cheap deterministic context blocks wired into `synthesize()`'s prompt **and** its
skip-if-unchanged hash (so completing work triggers fresh advice):
- `renderPriorHuntsBlock(outcomes)` — already imported in pipeline.ts, currently reaching only the
  three hunt prompts. "A hunt that found nothing is negative evidence; a hit is a pivot point."
- A capped playbook digest: DONE tasks → "do NOT re-recommend; build on results"; SKIPPED tasks →
  "not investigated — re-raise only if evidence warrants" (skipped ≠ done).
- A NEGATIVE KNOWLEDGE block of analyst-refuted hypotheses (cap ~15, analyst-touched only so
  model-generated refutations don't self-reinforce): "REFUTED: <title> — do not re-assert or derive
  findings/nextSteps from it." Today only *open* hypotheses are injected.
- Post-parse safety net: a returned nextStep that overlaps a DONE task is demoted-and-annotated
  ("similar to completed task <id>") — never silently dropped, and only when the host/artifact
  entity tokens match (so "pull evtx on HOST09" survives when "…on HOST07" was done).
- Files: `pipeline.ts`, `huntOutcomes.ts`, `playbook.ts`, `hypothesis.ts`, `hypothesisStore.ts`,
  `falsePositiveSimilarity.ts`.
- Directly attacks "never waste the investigator's time": the #157 hunt-outcome loop already proved
  this feedback pattern works — hunts stopped re-proposing dead VQL; findings/nextSteps never got
  the same treatment.

#### 3. Answer-contradiction validator: keyQuestion answers may not contradict the deterministic timeline (S) — verified (halcyon)
- Halcyon answered `q_exfiltration` "No data exfiltration confirmed" while xcopy-to-E: and 7z
  staging commands sat verbatim, correctly technique-tagged, in the timeline. The most dangerous
  single output an IR tool can produce is a flatly wrong negative conclusion delivered with
  authority.
- Deterministic post-parse pass beside the existing FP safety net: map standard question ids to
  technique families (q_exfiltration → T1041/T1048/T1052/T1567; q_lateral_movement → T1021.*;
  q_persistence → T1053/T1546/T1547; q_log_tampering → T1070.*). When an answer matches a negation
  pattern ("no … confirmed/observed") but in-scope non-FP events carry those techniques, force
  status to `partial` and rewrite the pointer to cite the contradicting event ids. Pure function
  over tags that already exist (`tradecraftRules.ts`, `reconTechniques.ts`, `exfilCorrelate.ts`).
- Surface as a visible "answer contradicted by timeline evidence" badge on the question card and in
  reports.
- Files: `pipeline.ts`, `stateTypes.ts`, dashboard, reports.

### Tier 1 — Fix what the AI sees (the root cause of every fabricated narrative)

#### 4. Chain-aware, corroboration-weighted synthesis event selection (M) — confirmed, impact 9, all four lenses converged
Replace the pure severity+spread sampler in `selectSynthesisEvents()` with **reserved per-class
budgets** (not just priority order, so classes survive even when Critical/High alone exceed the
cap):
- **Anchor context (~40%)**: for each Critical/High event, same-asset events within ±15 min (hard
  cap ~6 per anchor, command-line/process events preferred) — so the Low-graded "what happened
  right before/after on this host" chain rides in with its anchor.
- **Corroborated (~25%)**: events with `sources.length ≥ 2` (already merged by `correlate.ts`),
  ranked to prefer cross-source-*type* corroboration (endpoint+network) over same-family
  duplicates.
- **Technique-tagged (~15%)**: non-empty `mitreTechniques` regardless of severity — behavioral
  signal the deterministic layer already computed.
- **Remainder**: filled burst-by-burst via `burstDetect.ts` phases (keep whole bursts, drop whole
  bursts) instead of an even spread that shreds clusters.
- Return an annotated selection so `renderEvent` can prefix sampled context lines with `~` and emit
  per-cluster omission markers ("~40 similar Medium events on HOST-X omitted, 3 shown") instead of
  silent thinning; teach the `~` notation to the synthesis prompt (built-in **and** ejected file).
  Degrade gracefully under the two-pass budget refit (trim per-anchor context before dropping
  anchors). Record per-class counts in `synthMeta.ts` and show them on the "last synthesized" card
  so the investigator knows what classes of evidence the AI actually saw.
- Files: `synthSelect.ts`, `pipeline.ts`, `burstDetect.ts`, `synthMeta.ts`, prompts, dashboard.
- Why: all four incident-story benchmarks failed at this layer, not at grading; the branch-office
  corroboration lens (4,546 → 71 events, storyline surfaced) proved the missing signal already
  works. Acceptance: re-run fairhaven/halcyon/veridia ground truth — the previously-excluded true
  chains (sqlcmd/tar/curl PUT; robocopy/7z/xcopy; mysqldump) must appear in the selected set.

#### 5. Give synthesize() the structured evidence it already owns (M) — confirmed, all four lenses converged
Three prompt-side wirings, in priority order:
1. Extend synthesize's `renderEvent` with compact structured tags after the prose, only when set
   (the `<asset>` pattern from `suggestPlaybookHunts` already exists):
   `<host:WS07> <proc:cmd.exe←powershell.exe> <net:10.1.2.3→52.1.1.1:443> <sources:3>`.
   Apply the same to `ask()`'s identical renderEvent as a near-free follow-on.
2. Feed `buildGraphContext(state)` — the deterministic causal attack graph of spawn chains, file
   lineage, lateral movement — into `synthesize()` (today it reaches only `ask()`/`suggestHunts()`),
   computed **after** the skip-if-unchanged hash, counted in `synthOverhead` so the existing budget
   machinery pays for it. Fix `graphContext.ts` to render each edge's confidence + rule
   (`[high, shared-hash]`) so hard lineage edges outweigh regex-scraped shared-account hints.
3. Add two one-line digests to the synthesis context: statistically-confirmed beacon candidates
   ("PERIODIC BEACON: WS04 → 203.0.113.7:443 every ~62s, 214 events") carrying `BEACON_CAVEAT`
   verbatim and phrased as *candidate — verify*, cross-referenced against IOC enrichment verdicts;
   and burst attack phases ("09:02–09:15 Discovery (41 ev), 11:30–11:38 Collection (12 ev)").
   Beacon/burst digests are the lowest-priority piece — ship wirings 1+2 first if trimming.
- Files: `pipeline.ts`, `graphContext.ts`, `synthSelect.ts`, `beaconDetect.ts`, `burstDetect.ts`.
- Why: fairhaven's wrong-anchor credential finding and halcyon's cross-host fabrication are exactly
  cross-host dot-connecting failures where the deterministic graph knew better than the prose the
  model was given.

#### 6. Deterministic per-finding grounding + corroboration rollup with confidence caps (M) — confirmed, all four lenses converged
A deterministic pass right after `backfillHighSeverityFindings`:
1. **Grounding**: filter each finding's `relatedEventIds` to ids present in scope. Findings left
   empty get `ungrounded=true`, a "no cited evidence — hypothesis, not fact" badge (card +
   reports), and a hard confidence cap (~45, named constant). Backfill only via **exact**
   IOC-value/host token matches (reusing `iocCorroboration.ts`'s index) — never fuzzy
   title/description matching, which fabricates grounding.
2. **Rollup**: from the surviving related events compute
   `{distinctTools, distinctHosts, maxSeverity, intelAgreement, graphLinked}` and persist as
   structured `Finding.corroboration`.
3. **Caps**: deterministically enforce what the prompt already asks but can't enforce —
   single-tool + single-host + no corroborated IOC ⇒ confidence ≤ 65 with reason appended;
   CTI-verdict-only findings can't stay Critical/High ⇒ floor to Medium and auto-append a nextStep
   "corroborate <ioc> — pull <logSource> on <host>".
4. **Surface**: "2 tools / 3 hosts / intel ✓" vs "uncorroborated" badges; rollup line echoed into
   the next synthesis prompt so the model sees which of its own claims are weak. Keep hunt prompts
   consuming ungrounded findings (annotated) — hunts exist to corroborate weak leads; don't exclude.
- Files: `pipeline.ts`, `confidence.ts`, `stateTypes.ts`, `responseSchema.ts`,
  `iocCorroboration.ts`, `evidenceGraph.ts`, dashboard, reports.
- Why: halcyon shipped 0/7 findings with any cited events; northpeak's stale-CTI Critical was
  patched with prompt warnings that the model ignored. This is the structural version of those
  point fixes, and it changes real decisions: triage order, whether a Critical is trusted, and the
  derived next collection step.

#### 7. Deterministic intel-verdict corroboration gate (M) — confirmed
- `verdictCorroboration(ioc, events, hostNames)` in `iocAnchors.ts` →
  `corroborated` (2+ distinct providers agree — scan ALL enrichments, not just the first — or 1
  provider + a linked ≥Medium behavioral event) | `lone-intel` | `conflicted` (matches the case's
  own host assets or RFC1918/internal).
- Consume in three places: the THREAT-INTEL VERDICTS prompt block annotates each line and moves
  `conflicted` to an "INTEL CONFLICTS — do not treat as confirmed" sub-block; anchor scoring gives
  conflicted 0 bump and lone-intel a reduced bump (but both **stay in the digest** — hiding fresh
  single-provider C2 hits would hurt recall); a standalone post-synthesis pass caps intel-only
  findings at Medium/60 with an explanatory `confidenceReason`.
- Providers sharing feeds (OpenCTI ingesting MISP) are pseudo-independent: label "corroborated",
  never "confirmed".
- Files: `iocAnchors.ts`, `synthSelect.ts`, `pipeline.ts`, `enrichService.ts`, dashboard.
- Why: northpeak's stale OpenCTI verdict on the org's own DB server produced a Critical "C2"
  finding — the single most decision-distorting output the tool has generated in any benchmark, and
  its current guard is advisory prose.

### Tier 2 — Make the program direct collection (the "what/where/how to proceed" core)

#### 8. Structured collection directives, wired to deploy, with import-satisfaction detection (L) — confirmed by both judges ("the difference between a report generator and a tool that leads collection")
- Add optional `collect?: { host?, artifact?, logSource?, expectedOutcome? }` +
  `relatedFindingIds` to `NextStep` and `InvestigationQuestion`; demand it in the synthesis prompt
  (built-in **and** ejected file) for every `unknown` question and collection-type nextStep,
  prioritizing questions that discriminate between open hypotheses; lenient `.catch` validation.
- Three consumers:
  1. `derivePlaybookTasks` consumes `collect.host/artifact` directly (replacing the bare-`f<n>`
     prose scraping) and seeds tasks from unknown questions (sourceKey `question:<id>`).
  2. Next-steps/key-questions panels render a **Deploy/Collect** button when Velociraptor is
     configured — mapping artifact/logSource onto the `shadowArtifacts.ts` catalog or generic
     file-collection VQL via the existing `/velociraptor/collect-host` route — and a copyable
     manual-collection checklist when it is not. Guard: `collect.host` must validate against
     `knownEndpoints(state)` (reuse playbookHunt's validator); unvalidated hosts render as text,
     never as a button (hallucinated hostnames must not trigger dead collections).
  3. On import, match new events against open collect targets requiring **both** host and
     logSource/artifact-family. A match marks the step/question "evidence received — re-evaluating"
     (never auto-answers or hides), injects the question into the existing `questionsToReanswer`
     block, and adds a "SATISFIED COLLECTIONS — do not re-recommend" block to the next synthesis
     prompt. Keyed by collect target in a per-case side store (nextStep ids don't survive
     re-synthesis).
- Phasing: schema+prompt+playbook first, satisfaction detection second, Deploy UI last.
- Files: `stateTypes.ts`, `responseSchema.ts`, `pipeline.ts`, `playbook.ts`, `playbookHunt.ts`,
  `importMeta.ts`, `stateMerge.ts`, `shadowArtifacts.ts`, `routes/velociraptor.ts`, prompts,
  dashboard.
- Why: the model already produces this information as prose — it is being thrown away as
  unparseable text. The gap-hypothesis panel proves the full recommend→deploy→ingest pattern works
  end-to-end today; this generalizes it to the two primary guidance surfaces. The
  import-satisfaction piece is the single best anti-fatigue change available.

#### 9. Kill-chain gap analysis that directs collection (M) — confirmed
- `buildKnownUnknowns` — the system's only kill-chain-stage gap enumerator — is prompt-only: no
  route, no panel; the investigator never sees the single best deterministic what-to-collect-next
  signal the system derives. Its uncovered-tactic line also names no artifact or host.
- Refactor to `buildKnownUnknownItems()` returning structured items
  (`{kind, tactic?, window?, targetHosts[], artifacts[]}`) with the prompt string as a renderer
  over it; extract the opts assembly shared with the synthesis path so panel and prompt provably
  show the identical list.
- Add a deterministic `TACTIC_EVIDENCE` table (mirroring `TACTIC_FOCUS` in playbook.ts):
  Initial Access → mail/proxy/VPN logs + browser history on earliest-active assets and top-ranked
  hosts; Lateral Movement → Security.evtx 4624 type-3/RDP on evidenceGraph lateral-edge host pairs;
  C2 → DNS/proxy for connective IOCs; Exfiltration → SRUM/USN on staging hosts — reusing
  `SHADOW_ARTIFACTS` where they map.
- Expose `GET /cases/:id/known-unknowns`; render an "Evidence gaps — what this case is missing"
  panel near the top of the dashboard (wired into section-visibility settings AND view profiles),
  each item carrying its collection directive with one-click collect via the existing
  shadow-artifact deploy plumbing; silence-gap items link to the existing Timeline Gaps panel
  rather than duplicating its UI. Uncovered tactics also become playbook task seeds
  (`ku:<tactic>`) so gap-driven collection is status-tracked. Add a report section.
- Files: `knownUnknowns.ts`, `playbook.ts`, `shadowArtifacts.ts`, `routes/timeline.ts`,
  `hostRanking.ts`, `iocAnchors.ts`, dashboard, reports.
- Why: "no initial-access evidence" should generate "pull mail-gateway logs / browser history from
  patient-zero candidate HOST-X" — nothing does that today, and no lead can point at evidence that
  never entered the case.

#### 10. Source-yield instrumentation: surface zero-yield imports and cap truncation (M) — confirmed
- Extend `ImportRecord` with per-import `linesIn`, `eventsOut`, `iocsOut`, `capHit`,
  `path (deterministic|ai)`; have `logAggregate` return a truncated flag.
- v1 uses only three high-precision triggers (no generic yield-ratio floor — that's the one leg
  with real fatigue risk): (a) `eventsOut==0` with `linesIn > ~1000` via the AI-triage path,
  (b) `capHit=true`, (c) network telemetry imported with no detector feed in the case.
- Consume in three existing surfaces: the import banner shows a persistent warning chip with a
  directive next action ("proxy_access.log: 27,290 lines → 0 events via AI triage — re-run triage
  or grep the raw file for the case's IOCs/hosts") instead of "+0 events"; `buildKnownUnknowns`
  emits a fourth bullet class (source type → inferred missing phases, e.g. proxy →
  Discovery/C2/Exfiltration) flowing into synthesis and hunt prompts; triggers (a)/(b) raise a
  Medium coverage finding via the idempotent gap-finding path, while (c) stays a hint.
- Files: `importMeta.ts`, `routes/import.ts`, `pipeline.ts`, `knownUnknowns.ts`, dashboard.
- Why: northpeak's defining failure — 27K lines silently contributing nothing, read as "source
  clean". The tool must be able to lead collection around its own blind spots.

#### 11. Second-look loop: targeted re-query of raw evidence + one bounded re-synthesis (L) — three lenses converged
- Post-synthesis executor with two input paths: (a) **deterministic harvest** — search terms from
  open hypotheses (`relatedIocs`, host/process tokens in `expectedOutcome`), unknown questions'
  collect targets, and top connective IOCs; (b) **model-issued** — an optional `evidenceRequests`
  array (max 5: `{host?, timeWindow?, keywords[], reason}`) in the delta schema, with a prompt
  section instructing the model to request evidence it wasn't shown.
- Resolve terms against the scoped events the sampler omitted AND the super-timeline via the
  existing `querySuper` filters, restricted to the case's active window. Auto-promote matches via
  the existing `promoteSuperTimeline` path, capped (~50/term, ~200/sweep), each tagged
  `[second-look: h2]` so the existing Promoted badge shows provenance.
- If anything was promoted, queue exactly **one** background re-synthesis — bounded by the existing
  input-hash plus a one-iteration flag. A request that matched nothing is itself surfaced as a
  collection lead. Surface on the synth-meta card: "second look: 42 raw events matching hypothesis
  h2 (rsync, nfs-01) promoted — conclusions updated."
- Files: `pipeline.ts`, `superTimeline.ts`, `responseSchema.ts`, `hypothesis*.ts`, `iocAnchors.ts`,
  `synthMeta.ts`, dashboard.
- Why: the complete raw record is unreachable by the AI today no matter what hypotheses it forms;
  northpeak's recon/clone/exfil story sat in raw rows synthesis never saw. This closes the
  hypothesize → re-query → verify loop with existing plumbing and strict bounds.

### Tier 3 — Triage intelligence: FP, rabbit holes, and learned baselines

#### 12. Immediate deterministic FP cascade (M) — three lenses converged
- Today FP feedback only takes effect at the *next* synthesis; between mark and re-run the
  dashboard keeps showing answers/next-steps that rested on the FP'd finding.
- Extract the question-invalidation logic out of `synthesize()` into a shared
  `reconsiderKeyQuestions(state, markers)` called synchronously by the FP-mark route: affected
  questions flip to "unknown — supporting finding rejected" with a "stale, re-synthesis queued"
  badge immediately.
- Same handler: recompute host ranking / connective-IOC ranking over FP-filtered events (a host
  whose entire signal was FP'd must stop topping the ranking); flag hypotheses whose supporting
  evidence intersects new FP markers (`needsReview`, pristine ones flip to `unknown`, respecting
  the analyst-touched freeze contract).
- Anomaly triage: one-click "mark this spike as FP" feeding `TimelineAnomaly.eventIds` (already
  carried) into the existing batch-mark endpoint; annotate each anomaly with how many of its events
  are already FP'd so dismissed spikes visibly deflate.
- Files: `routes/findings.ts`, `falsePositive.ts`, `pipeline.ts`, `hostRanking.ts`, `iocAnchors.ts`,
  `timelineAnomalies.ts`, `hypothesis*.ts`, dashboard.

#### 13. Rabbit-hole detection: connectedness + "real-but-unrelated" relevance verdict (M) — three lenses converged
- Deterministic half: `mainComponent()` on the evidence graph (the connected component holding the
  corroborated Critical/High severity mass); per-finding connectedness = fraction of its related
  events/IOCs touching that component via existing edges or shared connective IOCs; zero linkage ⇒
  `relevance='disconnected'`.
- AI half: per-finding `relevance` enum (`connected | unrelated-but-real | undetermined`) in the
  delta schema + a prompt section asking the model to flag genuine-but-likely-unrelated activity
  with a one-line reason.
- FP-context retention: `authorized-test` / `known-good-tool` markers become a retained one-line
  CONTEXT block ("sanctioned test activity during window X") instead of pure erasure — a pentest
  running during the window is investigation-shaping context.
- Surface: findings grouped **Leads / Possible rabbit holes — verify before chasing / Parked**,
  with a "no causal link to main attack path — to link it, look for: <missing-edge discriminator>"
  chip; disconnected findings down-weighted in playbook/hunt/nextStep seats so guidance stops
  spending budget on them.
- Files: `evidenceGraph.ts`, `pipeline.ts`, `responseSchema.ts`, `stateTypes.ts`,
  `falsePositive.ts`, `playbook.ts`, prompts, dashboard.
- Why: this is the direct answer to "which events are rabbit holes" — the taxonomy for it simply
  doesn't exist today (veridia's red herring became a High finding; halcyon's benign USB copy was
  indistinguishable from the real exfil).

#### 14. ACH-style hypotheses: contradicting evidence, discriminators, hunt-miss exhaustion (M)
- Extend the (revived, see #1) hypotheses output spec: per-hypothesis `supportingEventIds`,
  `contradictingEventIds` ("events INCONSISTENT with this explanation"), and a `discriminator`
  ("the single artifact that would best separate this hypothesis from the leading alternative —
  name host + artifact").
- Link hunts to hypotheses (`relatedHypothesisId` on suggestions/outcomes): a hunt that comes back
  empty weakens the hypothesis it tested; after N misses against its `expectedOutcome`, mark it
  `exhausted` → flows into the NEGATIVE KNOWLEDGE synthesis block (#2).
- Rank the hypothesis panel ACH-style by *fewest contradictions*, not most support; discriminators
  double as concrete collection directives and feed question prioritization in #8.
- Files: `pipeline.ts`, `responseSchema.ts`, `hypothesis*.ts`, `huntSuggest.ts`, `huntOutcomes.ts`,
  prompts, dashboard.
- Why: red herrings become findings unopposed when nothing tracks what contradicts a theory; this
  is the classic intelligence-analysis fix, attached to machinery that already exists.

#### 15. Per-case prevalence/baseline index + proactive FP pattern propagation (L)
- Prevalence: at import, compute per-case occurrence counts of normalized pattern keys
  (process+command-shape, sha256, asset+pattern) across forensic + super timelines; stamp events
  ("seen 214× on 12 hosts over 9 days"), feed rarity into the #4 selection fill, and render
  common/rare tags in `renderEvent` so the model gets explicit baseline context instead of
  guessing.
- FP propagation: extend markers with an optional `patternFingerprint` derived from the anchor
  event; after every import, run the existing `findSimilarEvents` scorer against the import diff
  and, above a threshold, surface an import-banner suggestion "214 new events match FP pattern
  nightly-robocopy — review and bulk-mark" (one-click via the existing batch endpoint; never
  auto-applied).
- Files: `falsePositiveSimilarity.ts`, `falsePositive.ts`, `stateMerge.ts`, `routes/import.ts`,
  `importMeta.ts`, `synthSelect.ts`, dashboard.
- Why: marking an FP currently teaches the system nothing lasting — the same nightly-robocopy
  pattern re-arrives High after every import; `tradecraftRules.ts`'s unconditional-High
  robocopy/xcopy grade explicitly depends on an FP-suppression loop that doesn't exist proactively.

---

## Measuring it

Every Tier 1 change is directly measurable against the existing ground-truth benchmark corpus —
that is the acceptance test, not unit tests alone:

- **fairhaven**: the sqlcmd/tar/curl-PUT chain must reach the model's context (#4); the
  Explicit-Credential-Use finding must anchor to the real 4648 pivot event (#5); zero findings with
  empty `relatedEventIds` (#6).
- **halcyon**: no cross-host APT narrative (#4/#5); `q_exfiltration` cannot answer "none confirmed"
  while T1052/T1074 events exist (#3).
- **northpeak**: the zero-yield proxy import must raise a visible coverage warning and a
  known-unknown (#10); the stale-CTI finding on the org's own server must be capped by the intel
  gate (#7).
- **veridia**: the rclone red herring should land in "possible rabbit holes", not as a High lead
  (#13).

## Suggested sequencing

1. **Week 1**: #1 (prompt re-eject + drift check) → #2 → #3. Small, independent, immediately
   user-visible, and #1 unblocks everything else.
2. **Weeks 2–3**: #4 + #5 together (they share the renderEvent/prompt work), then #6 + #7 (they
   share the post-synthesis validator pattern). Re-run the benchmark corpus after each.
3. **Weeks 4–6**: #8 phased (schema+prompt+playbook → satisfaction detection → Deploy UI), #9, #10.
4. **Then**: #11–#15 in whatever order case experience prioritizes; #12 before #13 (the rabbit-hole
   grouping builds on immediate FP recomputation), #14 after #8 (discriminators feed question
   prioritization), #15 last (largest and most independent).

## Verification status

Proposals #1, #4, #5, #6, #8 were each confirmed by two independent adversarial judges (one
attacking investigator value, one verifying every code citation against the repo); #2, #7, #9, #10
by one judge each; #3, #11–#15 are supported by multi-lens convergence and direct code verification
of their premises (stale live prompts, prose-only pointers, prompt-only knownUnknowns, support-only
hypothesis links, exact-ref FP markers, binary FP taxonomy) but did not complete a full
adversarial pass. No judged proposal was rejected; judge corrections (conservative grounding
backfill only, host validation before Deploy buttons, no generic yield-ratio floor, skipped ≠ done,
beacon caveats) are folded into the text above.
