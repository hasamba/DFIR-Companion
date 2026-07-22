# Changelog

All notable changes to DFIR Companion are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Maintainer note:** keep entries concise (one line each). Add changes under `[Unreleased]`
> as you go; on release, rename it to the version + date, bump `companion/package.json`,
> `extension/package.json`, `extension/manifest.json` (+ both `package-lock.json`), and tag `vX.Y.Z`.

## [Unreleased]

### Added
- **Help icon in the toolbar** — a `?` button immediately left of the settings gear opens the online user manual (<https://hasamba.github.io/DFIR-Companion/manual/>) in a new tab, so the docs are reachable from the dashboard instead of only from the repo.
- **Deep pass now has a dashboard surface** (#204) — a *Deep Pass* section (and toolbar button) between Findings and the Forensic Timeline. Opening it runs the AI-free pre-flight and shows one row per severity floor with the events, prompt rows, batches and estimated input tokens that floor would cost on THIS case, because prompt rows scale with hosts and no default floor is right everywhere: on a 14-host case a hardcoded High+ would read nine rows and report success. Nothing is spent until *Run deep pass*; while it runs, the batch it is on is shown beside a *Cancel* button (both fed by the existing background-job registry), and the Re-synthesize / 2nd-opinion buttons are locked because a deep pass ends in a synthesis of its own that they would overwrite. The result card names the floor, events, rows, batches and observations — and, when batches failed, says so in red as **partial coverage**, since such a run read less of the case than its event count implies; the card survives a page reload. Refusals render as guidance rather than errors: over the batch ceiling repeats the server's message naming a floor that would fit, and a closed/archived case says to reopen it. The Run button is gated on the SYNTHESIS provider (new `/health.synthesisEnabled`), not the vision one, so a vision-only config no longer offers a button that can only fail.
- **Batched deep pass — full AI coverage of large, multi-host cases** — an analyst-triggered run (`POST /cases/:id/deep-pass`) that reads EVERY graded forensic event at or above a chosen severity floor, in as many batches as it takes, instead of the single prompt's worth normal synthesis can show. Prompt-row count scales with hosts, so grouping and a bigger cap are not enough on a real engagement: measured after grouping, a 12-host case needs 5 prompts' worth of rows and a 14-host case 13. `GET /cases/:id/deep-pass/preview` reports, for the actual case, how many events / rows / batches and roughly how many tokens each floor would cost, so the floor is chosen against real numbers — no fixed default is correct, since a detection-heavy import is well served by a High+ floor while a telemetry-heavy case may hold only a handful of High events in total. Batches return structured OBSERVATIONS only — what happened, which hosts, when, and the event ids it rests on — with no severity, finding or narrative field in the schema, so a batch cannot render a verdict on the slice it sees; exactly one final synthesis call draws every conclusion, and observations citing event ids the case does not contain are discarded before it runs. Oversized observation digests are condensed in bounded rounds rather than silently truncated, the run is cancellable between batches, and nothing is persisted until the final synthesis succeeds — so an aborted run leaves the case exactly as it was. A run needing more batches than `DFIR_DEEP_PASS_MAX_BATCHES` (default 30) is refused before spending anything, with a message naming a floor that would fit. The batch prompt is ejectable via `DFIR_AI_OBSERVE_PROMPT_FILE`.

### Changed
- **User manual now documents every AI run separately** — "The AI runs, one by one" (USER_MANUAL.md §8 and the AI Analysis reference page) replaces the old two-phase description with an at-a-glance table plus a plain-English page for screenshot OCR, extraction, synthesis, the second-look sweep, deep reasoning, the second opinion and the batched deep pass: why each exists, what it is good for, when to reach for it, and which environment variables control it.
- **Synthesis groups repeated detections, so a detection-heavy import gets FULL AI coverage instead of its first 300 rows** — repeated hits of the same detection (same rule, same severity, within an hour) now collapse into a single prompt entry carrying the hit count, host spread and time span, instead of consuming one event seat each. Detections are fingerprinted on their RULE IDENTITY (`Tool [Artifact] Detector: RuleName`) rather than the whole description, so one rule firing across many hosts no longer fragments into one pattern per host; a file hash still wins when present, so two distinct samples caught by one YARA rule stay separate rows, and any description not in that format keeps its previous fingerprint unchanged. Measured on a real Velociraptor + Sigma/YARA case: 1,089 events render as 546 entries, and with the raised event cap every one of those 1,089 events reaches the model (was 300). Grouping affects the AI prompt only — the case, the timeline, event ids, severities and findings are untouched. Tunable via `DFIR_SYNTH_GROUP`, `DFIR_SYNTH_GROUP_GAP_SECONDS`, `DFIR_SYNTH_GROUP_MIN_REPEATS`.
- **Default synthesis event cap raised from 300 to 600** (`DFIR_AI_SYNTH_MAX_EVENTS`) — grouping roughly halves the row count on a detection-heavy import, so 600 rows cost about what 300 used to (~49k timeline tokens against a ~105k input budget at the default 128k context) while being enough to cover an entire typical case. The synthesis coverage card now also reports how many events arrived as grouped entries, so "did the AI read everything?" is answerable at a glance.
- **Info-severity events no longer take synthesis prompt seats** (`DFIR_SYNTH_INCLUDE_INFO=1` restores them) — a real case carried 213 Info rows that pushed the prompt from 546 to 759 entries, past the cap, costing 26 GRADED detections their place in the prompt. Info events remain in the case, the timeline and the coverage report exactly as before; they simply no longer compete for budget with the graded detections, and anything genuinely important is promoted out of Info by the deterministic content tagger before synthesis runs. The coverage card attributes these to their own bucket ("213 Info") instead of blaming the size limit. Net effect on that case: every one of its 1,089 non-Info events now reaches the model, up from 1,063.
- **Velociraptor artifact catalog is cached for 45 s instead of spawning the binary on every call** — the collectable-artifact list (`artifact_definitions()`) backs the bundle picker, the live-event picker, the bundle time-scope preview, the run-bundle pre-flight, and playbook hunt suggestions, and each call previously spawned the `velociraptor` binary. It is now cached per artifact type inside the client, with concurrent callers sharing one query, so an interactive control that re-reads it (e.g. changing a dropdown) no longer costs a subprocess each time. Deliberate refreshes still see the server immediately: the pickers' *Browse server artifacts* buttons bypass the cache (`?refresh=1`), as does the run-bundle pre-flight that decides which artifacts to drop from a hunt, and **Reconnect** builds a fresh client with a cold cache.
- **Assets & IoC Graph and Evidence Chain now share the Login Graph's interactive Cytoscape view** — both moved off static SVG onto a shared graph-view module, so all three graphs offer the same five layouts (spread/dagre/circle/concentric/breadthfirst), bezier/taxi edges, selection transparency, live filter, fit, fullscreen, and PNG export. Custom node glyphs (host/account/service/process/file/network) are preserved, and the Evidence Chain keeps its typed, colored, directional edges. The old bespoke asset layouts (horizontal/vertical/radial) and manual node-position saving were replaced by the shared generic layouts.
- **Screenshot/vision AI vars renamed `DFIR_AI_*` → `DFIR_VISION_*`** — the vision-model config (`DFIR_VISION_PROVIDER` / `_MODEL` / `_KEY` / `_BASE_URL` / `_IMAGE_DETAIL`) now has a name that reflects its screenshots-only role, distinct from the text-work family (`DFIR_AI_SYNTH_*`). The legacy `DFIR_AI_*` names still work as a deprecated fallback (the new name wins when both are set), so existing `.env` files keep working with no change required.

### Fixed
- **The AI status pill now says a deep pass is running** — it read "AI: ready (waiting for activity)" for the entire run, which on a large case is tens of minutes of the model working while the only always-visible AI indicator says it is idle. It now reads e.g. "AI: deep pass (Medium+) — reading batch 2 of 5", following the run's own progress (reading / condensing / synthesizing) and returning to idle at the end. The new `deep-pass` phase is checked before the ingest fallback, so a run started while live analysis is paused is no longer mislabelled "deterministic import — not AI"; a run refused by the batch ceiling returns the pill to idle rather than reporting an AI error.
- **A claude-code answer that RESTARTS after hitting max output tokens no longer poisons the parse** — when a response is cut at the output cap, the CLI continues the turn in a second assistant message, and the Companion splices the two back together. But the model does not always continue: on a large case it may abandon the truncated attempt and rewrite the whole answer from the top, fence and all. Splicing then glues a truncated document onto a complete one, and the half-open string literal swallows the next line, so the parse dies with `Bad control character in string literal in JSON` — costing a full retry (measured: ~9 minutes and ~50k output tokens per wasted attempt, twice in one deep-pass run). The two cases are now told apart by result rather than by guesswork: the splice is kept whenever it parses, and only when it does not — and the final message parses cleanly on its own — is the earlier text treated as an abandoned draft and dropped. If neither parses, the splice is returned unchanged so the existing truncation repair still applies. Verified against four captured live responses: the two that failed this way now parse (17 and 16 findings recovered), and the others are unchanged.- **A deep pass on a closed or archived case is refused instead of rewriting it** (#204) — the run ends in a forced synthesis that replaces the case conclusions, but only `/synthesize` carried the lifecycle guard; `POST /cases/:id/deep-pass` now returns the same 423. The activity-log entry for a run also names failed batches (and a cancelled run) so partial coverage stays visible in the durable record, not just in the HTTP response the dashboard throws away.
- **A MISP connectivity failure now names the likely cause instead of the symptom** — the `/servers/getVersion` check that opens every push (and gates enrichment) reported only `MISP HTTP 400 on /servers/getVersion`, naming neither the URL tried nor the setting at fault, while every transport failure collapsed into undici's opaque `fetch failed`. Failures now quote the full URL and, where the evidence supports it, the fix: a `400`/`404`/`405` points at `DFIR_MISP_URL` having the wrong scheme (an https-only instance reached over `http://`), a stray path suffix, or not being a MISP at all; connection-refused, DNS and timeout failures are named as such; a certificate rejection points at `DFIR_MISP_CA` / `DFIR_MISP_INSECURE`, and a TLS handshake failure at `https://` against a plain-http port; a `2xx` that isn't MISP JSON says the URL probably points at another service. A `5xx` still reports the URL but does NOT blame the setting — the instance answered, so the URL reached MISP. Auth failures keep pointing at `DFIR_MISP_KEY`, and non-ping failures are untouched. The same diagnosis now backs the enrichment health card's MISP detail.
- **"Collect now" on a hunt that is already collecting is no longer silently discarded** — a second collect for the same hunt arriving while the first was still finishing was dropped outright, behind a `202 {accepted:true}`: the hunt's result count froze at the previous collect's value and the stragglers that checked in during the first collect were lost, with nothing logged. The window is the tail of a collect (persisting the job, broadcasting the change), which is milliseconds on an idle machine but seconds under disk load — so it presented as intermittent "flakiness" rather than a lost request. Concurrent collects are now COALESCED into one follow-up pass that runs when the current one finishes, and the response says which happened (`queued: true`), so the button can show "queued…" instead of implying the click did nothing. Also fixes a hunt left with a persisted status of `collecting` by a server that died mid-collect: that status was treated as "a collect is in flight" forever, permanently bricking every later collect for that hunt, and is now correctly ignored (only in-process state decides what is actually running).
- **Saving an integration setting now actually takes effect without a restart** — `POST /settings/reload` (the "Applying…" step behind the Setup wizard's *Save & test*) applied the just-saved `DFIR_<PREFIX>_*` group into the process environment and stopped there, but every integration client is built once at startup, so the running server kept its boot-time config: a corrected MISP URL sat in the environment while pushes still went to the old address, and a freshly-saved enrichment key never reached the provider set. Worse, the wizard reported "✓ Saved & configured" because that check reads the environment, not the live client. The route now rebuilds whatever the prefix feeds — MISP push, the enrichment and customer-exposure provider sets, IRIS, Timesketch, Velociraptor, Notion, ClickUp — and returns a `rebuilt` list naming what took effect. Rebuilds are construction only (no network), so the call stays fast and cannot fail on an unreachable server; the per-integration **Reconnect** routes remain the way to verify connectivity. AI (`DFIR_AI_*` / `DFIR_VISION_*`) is unchanged: connectivity probes already read the environment per call, and the running analysis pipeline still needs a restart. **Settings → Save** now applies the groups it changed the same way, replacing the blanket "restart the server to apply server-side changes" with what actually took effect (e.g. *"✓ Saved and applied live: enrichment, misp"*), and still says restart when the change was one only a restart can apply. Found while diagnosing a MISP push that kept failing against a stale `http://` URL after `.env` had been corrected to `https://` (#178).
- **Synthesis no longer sends an anchors-only prompt when Critical/High events exceed the event budget** — a detection-heavy import (hundreds of Sigma/YARA hits graded High) used to fill the entire budget with the most severe events and discard everything else, including the earliest activity that anchors initial access, leaving the model a list of alerts with no beginning to the story. Part of the budget is now reserved for the earliest events regardless of how many anchors exist, and when anchors must still be dropped the most-repeated patterns go first (they are already represented by their grouped entry) instead of dropping strictly by severity.
- **Claude Code provider: a long answer that hit the model's output cap failed with `Unexpected token 'p', "provider, "... is not valid JSON`** — when a response exceeds the max output tokens the CLI continues the turn in a second assistant message, but its terminal `result` field carries only that LAST message, so the pipeline was parsing the tail half of the JSON. Both halves are now stitched back together from the stream (dropping the markdown fence the continuation re-opens mid-value), so a big second-opinion/synthesis run completes instead of erroring out after two full attempts. `parseJsonLoose` also now prefers an already-valid JSON response over fence extraction, so a finding that quotes a ```fenced``` command no longer slices its own response apart.
- **`POST /bundles` was silently dropping `timeoutSeconds`, `expirySeconds`, `params`, `filters`, and `superTimelineOnly` on save** — editing a bundle in the dashboard (including the built-in Super-Timeline Triage bundle) cleared its super-timeline-only routing along with the other fields, so the next run sent raw MFT/USN rows into the forensic timeline instead of the super-timeline.
- **Very large cases no longer fail with an opaque error, and save ~26% smaller state** — `investigation.json` is now written as compact JSON instead of pretty-printed (it is machine-read, never hand-edited): at 250K events that is 2.1x faster to serialize (1210ms → 563ms) and 112.5 MB → 83.4 MB, which also shortens the atomic-rename window `DFIR_ATOMIC_WRITE_RETRIES` guards. Loading a state file past V8's ~512 MB max string length now raises an explicit "state file is too large to load" error naming the case, the limit, and the recovery path (restore a smaller snapshot from `state/backups/`, or split across cases) instead of an opaque `RangeError`, mirroring the 413 the import route already returns. Backup restore and `.dfircase` import also write it compact, so recovering or re-importing a near-ceiling case no longer re-inflates it back over the limit (`case.json` stays pretty-printed).
- **Text AI features no longer require the screenshot/vision provider** — synthesis, ask, event explain, executive summary/remediation/narrative, hunt suggestions, CSV/log import triage, query translation, tagger-rule drafting, gap hypotheses, and auto/re-synthesis now run whenever a synthesis provider is configured (`DFIR_AI_SYNTH_PROVIDER`), instead of returning 501 in OCR-less installs where the vision provider (`DFIR_VISION_PROVIDER`) is unset.

### Added
- **Time scope for Velociraptor triage bundles** — the bundle run form now offers a time-scope control (All time, last 24h/7d/30d/90d, or a custom UTC range) that bounds collection AT THE SOURCE by mapping the window onto each artifact's own date parameters (auto-detected from the server, correctable inline and saved on the bundle), instead of importing everything and filtering afterward; relative presets set a lower bound only (a hunt keeps scheduling on clients that check in later, so an upper bound pinned at launch would silently drop their activity); artifacts with no date parameter still collect in full and are called out in the preview; the resolved window (and whether coverage could be verified) is recorded on the hunt job and shown on its card.
- **Assignment & workflow status for findings** — each finding can now be assigned to an analyst and given an editable triage status (New / In progress / In review / Resolved), set inline on the finding card. It's separate from the AI-set finding status and is stored in a per-case side file (`state/finding-workflow.json`), so it survives re-synthesis. New `GET /cases/:id/finding-workflow` and `PATCH /cases/:id/findings/:findingId/workflow` routes; changes broadcast to other open dashboards live (closes #87).
- **Hashed manifest in redacted report exports** — every redacted report ZIP now includes a machine-readable `export-manifest.json` listing each file's `path`, `sha256`, and `bytes` plus `caseId`, `exportedAt`, and `generatedBy` (app version) — mirroring the whole-case `.dfircase` archive manifest. A recipient can now verify artifact integrity and enumerate the package's contents programmatically, not just read the human-readable notes (closes #79).
- **Time-bound graph filtering** — the Assets & IoC Graph and Evidence Chain graph now honour the active timeline time filter: brushing a range on the swimlane (or setting the search-bar from/to dates, or applying a saved timeframe) re-renders both graphs to only the nodes/edges whose events fall in that window, and clearing the filter restores the full graph. Derived on read via optional `?from`/`?until` params on the graph routes; undated events are kept, matching the timeline filter (closes #83).
- **Kill-chain overlay on the Evidence Chain graph** — a new "Node colour" option recolours the evidence graph by each node's dominant ATT&CK tactic (derived from its backing events' techniques, reusing the canonical tactic mapping) instead of by severity, laid out along the kill chain from Initial Access → Impact with a matching phase legend. Nodes with no mapped tactic degrade cleanly to a neutral grey; the tactic is also shown in the node side panel. No AI, derived on read (closes #93).
- **Structured uncertainty ledger** — synthesis now emits a structured `uncertainties[]` separating what the analysis KNOWS from what it INFERRED from what it SPECULATED (status: confirmed/inferred/speculated/unknown, each with its basis and the gap to resolve it). Surfaced as a new "Uncertainty Ledger" dashboard section (weakest status first, color-coded) and an "Analytical confidence" table in the report, so an inferred conclusion is never read as a confirmed fact (closes #73).
- **Login Graph** — new dashboard section: an interactive, Timesketch-style directed graph of Windows logon activity (accounts → hosts from super-timeline 4624/4625 rows). Draggable nodes, five layouts (spread/dagre/circle/concentric/breadthfirst), bezier/taxi edges, selection transparency, live filter, PNG export, fullscreen. Failed logons render as dashed red edges, risky logon shapes (external RDP, cleartext, `runas /netonly`) as orange, and a one-click filter hides machine/system-session account noise. Click an edge for the underlying events; click a node to pivot into the super-timeline. Fully offline (vendored cytoscape.js).
- **Entity merging for duplicate assets/IOCs** — fold a duplicate asset or IOC onto a canonical node/indicator; reversible, and IOC merges preserve the alias across re-synthesis (closes #82).
- **Starred-events review workflow (TimeSketch-style)** — event stars now live in the case (shared, tag-backed) with automatic migration of existing browser-local stars; "☆ Starred only" filters the whole super-timeline server-side; new "✨ Starred report" (savable AI forensic report over only the starred events) and "✨ Summarize view" (AI overview of the current filtered view) buttons.

## [0.32.0] - 2026-07-16

### Added
- **Cross-tool command-line correlation** — merges same process-creation events reported by different tools that share a command line, parent process, and host (closes #68).
- **SSH brute-force-success detection** — flags a successful login following a burst of failures from the same IP (T1110.001).
- **Windows logon-type risk grading** — grades risky logon types (external RDP, network-cleartext, `runas /netonly`) on 4624 events.
- **Lookalike / typosquat domain detection** — offline enrichment flags domains impersonating common brands (T1566/T1583.001).
- **NTFS timestomp detection** — flags MFT $SI/$FN timestamp mismatches indicating timestomping (T1070.006).
- **IOC list pagination** — client-side paging for the IOCs section, matching the timelines.
- **AI-assisted content-tagger rules** — describe a tagger rule in plain English; AI drafts, previews, and adds it.
- **Right-click "Send to DFIR-Companion"** — send selected text, a table, or a link from any page, not just recognized consoles.
- **VolWeb adapter + manual tool override** — extension auto-detects VolWeb and lets you force a different adapter per tab.
- **Live progress for Velociraptor imports** — large imports stream progress instead of blocking silently.
- **Structured, deployable collection directives** — one-click deploy and auto-detected satisfaction for "collect X from host Y" recommendations (investigation-guidance #8).
- **Evidence Gaps dashboard panel + report section** — structured, deployable collection directives for uncovered kill-chain phases (investigation-guidance #9).
- **Zero-yield import warnings** — flags large AI-triaged files that produced zero events (investigation-guidance #10).
- **Second-look loop** — bounded raw re-query against the full super-timeline plus one re-synthesis (investigation-guidance #11).
- **Immediate false-positive cascade** — synchronously re-evaluates dependent questions/next-steps/hypotheses when a finding is marked FP (investigation-guidance #12).
- **Rabbit-hole detection** — flags findings disconnected from the main evidence graph as possible rabbit holes (investigation-guidance #13).
- **ACH-style hypotheses** — tracks contradicting evidence, a discriminator, and hunt-exhaustion (investigation-guidance #14).
- **Per-case prevalence baseline + FP-pattern propagation** — rarity-biased event selection and one-click bulk-dismiss for recurring FP patterns (investigation-guidance #15).
- **Content-based event tagger** — Timesketch-style `tags.yaml` rule engine tags events, raises severity, and unions MITRE techniques.
- **Composite IOC risk score** — weighted critical/high/medium/low/benign tier per indicator (closes #63).
- **KEV / tool-confirmed / unconfirmed-lead confidence badges** — new corroboration signals on findings (closes #61).
- **Synthesis coverage audit** — shows how many in-window events a synthesis run considered vs. omitted (closes #62).
- **Per-source noise/trust scores** — weights sources by reliability in correlation and confidence scoring (closes #66).
- **Learn from dismissed findings** — repeated FP patterns lower (not zero) confidence on similar new activity (closes #65).
- **On-demand hypothesis falsification review** — focused for/against pass over open hypotheses (closes #71).
- **`DFIR_MAX_EVENTS`** — configurable event-ingestion cap, overriding the hardcoded 2000 default (closes #110).
- **Case Statistics panel** — per-case totals, source breakdown, and import velocity in Diagnostics (closes #36).
- **Prompt regression / eval harness** — CI-safe and real-provider golden-output testing for AI extraction/synthesis quality.

### Changed
- **CSV/log AI extraction now uses the text model, not the vision model** — `DFIR_AI_SYNTH_MODEL` handles CSV/log/synthesis; `DFIR_AI_MODEL` is vision-only.
- **Velociraptor timeline events now describe the action, not just a filename** — MFT/USN/browser/shellbags/UserAssist/Shimcache/Amcache/Prefetch/LNK all render human-readable descriptions.
- **Forensic Timeline redesign** — bordered-card rows matching the Findings/IOCs styling.
- **Second-opinion deltas now keyed by semantic content, not exact title** — a stable `semanticKey` prevents reworded findings from showing as spurious new deltas (closes #69).

### Fixed
- **Work-log filter could drop real detections that merely named a tool** — now honours a structured-field gate (closes #67).
- **Large deterministic imports could peg the CPU for an hour** — forensic-timeline dedup is now O(n) instead of O(n²).
- **Large imports could fail with `EPERM` on state-file rename** — atomic-write retry budget widened, tunable via `DFIR_ATOMIC_WRITE_RETRIES`.
- **Evidence drop-folder auto-imports were invisible in the Jobs panel** — now register a background job like manual imports.
- **Tagger rules file wasn't created on first write** — directory is now created on demand.
- **Extension content script failed to load on every page** — content.js/pageHook.js now build as isolated, non-module bundles.
- **`caseId` wasn't validated on lock-status/unlock routes** — closed the gap with the standard case-existence guard.
- **Renaming a manually-added asset was lost** in the asset-graph view.
- **The enrich endpoint falsely reported acceptance when no providers were enabled.**
- **A partial dwell-window update could fail validation instead of merging.**
- **An empty `{}` JSON body on the generic push endpoint was imported instead of rejected.**
- **Notion push didn't normalize env-configured database/parent page IDs.**
- **Dashboard UI cleanups** — fixed synthesis job/status races and a drag-order regression.

## [0.31.0] - 2026-07-10

### Added
- **Case password protection** — lock a case with a password (🔒 in the case lifecycle menu); optional "remember on this computer", enforced server-side via an unlock cookie.
- **Expandable Host & Account Ranking rows** — click a ranked row to see its events/IOCs inline and jump to a cited event in the timeline.
- **DFIR-IRIS push case-name override** — the push dialog shows and lets you edit the target case name, remembered for future pushes.
- **Per-case AI cost tracking** — Settings → Diagnostics shows real per-call cost/tokens by Vision/Synthesis/Other and by model.
- **Per-case IOC exclude list** — exact/suffix/regex rules purge matching IOCs immediately and block their re-import.
- **Import upload-only Velociraptor artifacts** — paste the GUI's "Uploaded Files" tab URL to import THOR/report-only uploads (now also `.csv`/`.txt`/`.log`/`.jsonl`).
- **Timesketch export (Super Timeline)** — push/download the full super-timeline alongside the existing Forensic Timeline export, into separate timelines.
- **Vim-style keyboard navigation for the Forensic Timeline** — `j`/`k`/`f`/`i`/`p`/`n`/`?`; toggle in Settings → General, default on (closes #33).
- **Permanently delete a case** — 🗑️ Delete… in the lifecycle menu, with an optional pre-delete ZIP/encrypted archive.
- **Authoritative IOC-to-event provenance for 5 priority importers** — IOCs tagged with their exact source-event row, shown as "linked" vs "approximate" (closes #26).
- **Evidence drop-folder audit log (`drop-log.txt`)** — every auto-processed file's outcome (imported/failed/pending + reason) is logged.

### Changed
- **Findings and IOCs panels redesigned as dense tables** — grid columns, icon action buttons, and expandable evidence with a real cited-event timeline.
- **Full case export/import is now an encrypted archive, not a JSON snapshot** — `.dfircase` zips the whole case directory under AES-256-GCM.
- **Pinned Findings folded into the Findings panel** — no longer a separate dashboard section.
- **Analyst is now the default dashboard view** — for any case with no saved per-case choice; Custom still sticks once chosen.

### Fixed
- **A case's password wasn't asked for again unless you fully closed the browser** — setting/changing a password no longer auto-unlocks the setter, and a not-remembered unlock is now forgotten on switch-away/refresh/close.
- **"Remove password" always worked even with no password set** — Save/Remove now reflect the case's real lock state.
- **Timeline Anomalies and other deterministic panels didn't refresh on scope change** — they now reload immediately instead of waiting on the next AI re-synthesis.
- **Customer Exposure never auto-discovered a domain from the case's own FQDN hosts** — now added as an "auto" chip, same as auto-discovered emails.
- **DFIR-IRIS push could silently land in an unrelated case** — now only reuses a case on an exact name match.
- **Dotted config/artifact identifiers misclassified as domain IOCs** — the last label must now be a real, commonly-registered TLD.
- **Timeline coverage-gap findings survived a scope change** — gap findings are now back-linked to their bounding events.
- **Structured hostname/fqdn/domain columns skipped internal-zone filtering** — `.lan`/`.local`/`.corp`/etc. are now excluded, matching free-text scraping.
- **Cited-event badges couldn't be right-clicked to open in a new tab** — they now carry a real deep link.
- **Timesketch push failures logged a bare `fetch failed`** — the real network cause (`ECONNREFUSED`/`ENOTFOUND`/TLS error) is now surfaced.
- **A hunt deleted in Velociraptor showed a misleading "collect again later"** — now flagged `stoppedEarly` when terminal well before its scheduled expiry.
- **Duplicate-looking playbook items** — a next step citing a finding that already has its own auto-task is folded into that task instead of duplicated.
- **Marking a finding false positive didn't hide it until the next AI re-synthesis** — it now disappears from the Findings panel instantly.
- **Key Investigative Questions kept a stale "answered" status after their finding was marked false positive** — now force a re-answer or reset to "unknown".
- **Timeline row timestamps stuck to the top instead of centering** — now vertically centers against the full row height, including multi-line rows.

## [0.30.0] - 2026-07-07

### Added
- **IOC provenance chain panel** — per-IOC 🔗 timestamped chain of extraction/enrichment/citing findings, JSON export (part of #247).
- **Per-case activity log** — chronological record of every security-relevant action on a case (closes #238, supersedes #224).
- **Cited AI answers** — findings, Ask-the-case, Explain Event, and AI-suggested hunts show clickable citations to their supporting evidence (closes #222).
- **Background-job registry + cancel** — toolbar badge tracks running imports/synthesis/enrichment; Cancel hard-aborts a stuck job (closes #225).
- **Pinned findings** — pin key findings to a sticky top strip, drag-to-reorder (closes #220).
- **Timeline event-density heatmap** — severity-colored activity bar above the Forensic Timeline; click to zoom (closes #219).
- **Confidence reasoning + persistent min-confidence floor** — findings show a one-line reason for their score; the floor now survives reload (closes #226).
- **Inline IOC quick-actions** — click any detected value to copy, mark benign/malicious, or suggest a hunt (closes #221).
- **Windows account SIDs** — now a detected IOC type.
- **Multi-select bulk actions on Findings** — checkboxes + bulk tag/mark-FP bar, matching IOCs/timeline.
- **Select-all on the false-positive AI candidate list.**
- **Synthesis model config in the setup wizard** — no longer Settings-only.

### Changed
- **Merged the two case-export options** into one shareable-JSON download.
- **2nd-opinion panel gets its own collapse toggle**; "Ask AI for more" renamed "Ask AI for similar".

### Fixed
- **robocopy/xcopy now always grade High (T1074.001)**, so bulk-copy staging/exfil no longer gets buried under noise.
- **Sysmon EID 8 false positives from routine shell/UI brokers** exempted alongside the existing core-OS/Defender list.
- **Concurrent imports for the same case could silently drop events** — now serialized per case via `StateLock`.
- **Swimlane click didn't jump to the event** when it was off-page/filtered/collapsed — now jumps like every other link.
- **Compromised-assets graph truncated long asset/IOC names** — added hover tooltips, stopped truncating in horizontal layout.
- **IOC/chain re-enrichment ran needlessly on every false-positive mark** — skipped when nothing is actually un-enriched.
- **IOC provenance chain panel UI polish** — width, artifact name, jump-to-event/finding links.

## [0.29.0] - 2026-07-04

### Added
- **Chainsaw importer: flat Sigma-mapping JSON** — recognizes the flattened Chainsaw output shape (top-level verdict fields) from tools/Velociraptor artifacts that shell out to Chainsaw.
- **Severity-gated forensic timeline** — Info telemetry now routes to the super-timeline only, configurable via `DFIR_FORENSIC_MIN_SEVERITY` + a per-case override.
- **IOC provenance** — each IOC classed detection-linked vs telemetry-only, with a dashboard badge + filter.
- **Super-Timeline full message + Velociraptor deep-link** — a `[details ▶]` toggle reveals the full event message, plus a `↗ Velociraptor` link back to the originating hunt/flow (closes #8, closes #9).
- **Super-Timeline** — a Timesketch-style complete record of every imported event (filter/label/promote to the forensic timeline) + a "Super-Timeline Triage" Velociraptor bundle.
- **External tool runner (Settings → Tools)** — run local Hayabusa / Velociraptor CLI / Suricata / Snort / YARA against raw files and auto-ingest the output, with a per-import confirmation banner (closes #211).
- **Import external hunt/flow** — pull results from a Velociraptor hunt/collection launched in the GUI by id or URL.
- **Custom tools (Settings → Tools)** — add unlimited user-defined tools beyond the five built-ins, auto-routed by output/extension.
- **YARA CLI output importer** (`yara -s -m`) — rule matches → file-match events + file/hash IOCs.
- **Velociraptor hunt expiry** — hunts launch with a relative expiry (default 1 hour) instead of Velociraptor's week-long default, overridable per bundle/run.
- **Velociraptor hunt status polling** — 30s background poll reflects live hunt state and auto-collects on completion (closes #210).
- **Plain syslog importer** — deterministic RFC 5424/3164 parser, replacing AI log-triage for Linux/Unix syslog.
- **Kerberoasting / AS-REP roasting event verdict** — RC4 TGS-REQ/AS-REQ to user accounts now grades Medium + T1558.003/.004.
- **AWS CloudTrail priv-esc actions** — `PassRole`+Lambda `CreateFunction` (Medium) and STS `GetSessionToken` (Low, T1078.004) added to the severity table.
- **Kubernetes audit-log importer** (`k8sAuditImport.ts`) — deterministic parser, severity derived from the (verb, resource) tuple.
- **osquery result-log importer** (`osqueryImport.ts`) — deterministic differential/snapshot log parser, Info-by-default.
- **IOC list noise-reduction controls (dashboard)** — three composable display-only filters (Hide FP/no-intel, Hide OS system paths, 🎯 Signal only), default on.
- **Exclude filter (dashboard)** — chip-list control hides timeline/IOC/finding rows matching any exclude term (closes #216).
- **Velociraptor deep-link on the forensic timeline** — mirrors the super-timeline's `↗ Velociraptor` link.
- **`Windows.EventLogs.Chainsaw` added to the built-in Best Practice bundle.**
- **Origins filter on the forensic timeline** — filters by producing artifact, matching the super-timeline's Origins filter.
- **False-positive feedback loop** — "Mark Legitimate" renamed "Mark False Positive" with structured reason + attribution, find-similar-items suggestion, one-click IOC whitelist promotion (closes #227).

### Changed
- **Forensic + super-timeline row redesign** — compact plain-weight title line; description/MITRE/related findings/raw message now collapse into one shared `[details ▶]` panel per row.
- **Super-timeline toolbar merged** — the time-scope bar and the origins/hosts/tags/starred-only bar are now one row.
- **Forensic timeline severity filter drops "Info"** — redundant since `forensicGate` already excludes Info server-side.
- **Forensic timeline pagination moved above the event rows.**

### Fixed
- **Correlated events could show a different tool's artifact as their origin** — `artifactName` now always comes from the same event as the shown description.
- **Dashboard main filter now applies to the super-timeline** (search term, exclude terms, time range).
- **IOC panel header always showed only the flagged count** — now shows "N of M IOCs" when a filter narrows the list.
- **Super-timeline rows showing the tool/origin name twice** — the duplicate leading prefix is now stripped.
- **Forensic timeline's Velociraptor deep-link never appeared** — `importVelociraptor` now accepts `veloUrl` on the forensic-timeline-bound branch too.
- **"Import external hunt/flow" pasting a notebook URL silently imported unfiltered raw rows** — now rejected with guidance to use the extension's "Push rows" button instead.
- **Duplicate clear (✕) icon in the filter / OCR search boxes** — inputs switched from `type="search"` to `type="text"`.
- **`cleanIp` accepted any colon-bearing free text as a "valid" IPv6 IOC** — now validated against a real IPv6 shape.
- **Velociraptor "grpc: received message larger than max" — corrected fix (2nd pass)** — the real setting is `max_grpc_recv_size` in the client's `api_client.yaml`, not a CLI flag or server config.
- **IOC list: duplicate rows and unstable order in the dashboard** — now deduped by id + sorted deterministically; `mergeDelta` dedup is case-insensitive; `npm run dedupe-iocs` cleans up already-corrupted cases.
- **Velociraptor bundle-hunt collection surfaces per-artifact failures** instead of silently dropping them.
- **Velociraptor DetectRaptor hits on `.yms` Sigma-rule files graded Info, not extracted as IOCs.**
- **Combined access-log importer captures the HTTP Referer** — no longer silently dropped.
- **Combined access-log importer captures the HTTP User-Agent** — anomalous UAs now emitted as `other` IOCs.
- **`.env` config resolution unified across read/save (Chocolatey)** — Settings → Save now writes to the exact `.env` the server loaded.

## [0.28.0] - 2026-07-01

### Added
- **Cisco ASA firewall syslog importer** — deterministic Built/Teardown/Deny parsing, replacing AI log-triage for ASA logs.
- **Apache/Nginx/Squid combined access-log importer** — deterministic parsing for web-server and forward-proxy access logs.
- **Deterministic attacker-tradecraft rules** (`tradecraftRules.ts`) from ~95 DFIR Report + 18 Huntress "Rapid Response" intrusions — Defender/AV disable, recovery inhibition, LSA/UAC tampering, credential dumping, reverse-tunnel C2, Impacket lateral movement, cloud exfil, RMM tooling, NTDS.dit/browser-cred theft, hidden accounts, log wipes, ROPC legacy-auth bypass, and more, each graded to the correct ATT&CK technique.
- **Recon-burst ATT&CK tagging** — discovery/credential-access commands now tagged with techniques across Windows/Sysmon, ECAR and bash importers so the enumeration phase shows in the MITRE table (`reconTechniques.ts`).
- **Exfiltration correlation → dedicated "Data Exfiltration" finding** — archive staging (T1560.001) followed by an upload (T1041) on the same host is stitched into one High "confirmed exfiltration" chain (`analysis/exfilCorrelate.ts`).
- **Exfiltration detection (grading + IOC promotion)** — web-client uploads (`irm`/`iwr -InFile`, curl/wget) graded Medium+T1041; command lines now scraped for embedded URL/domain/IP IOCs.
- **Host & account ranking + auto-scope** — signal-weighted host/account ranking panel with a one-click suggested scope window (`analysis/hostRanking.ts`; closes #202).
- **Phishing → host initial-access correlation** — a host later contacting a phishing-linked domain is tagged initial access (T1204.002) and raised to ≥Medium (`analysis/initialAccess.ts`; closes #201).
- **Snort/Suricata IDS alert import** — deterministic `alert_fast` parser, severity from rule Priority.
- **Corroboration filter (lens)** — per-section control (Timeline/IOCs/Findings) to show only items seen by 2+/3+ distinct tools.
- **ECAR (EDR telemetry) import** — deterministic NDJSON mapper for process/flow/logon/registry/module/file/remote-thread events.
- **SIEM import — IOCs scraped from free-text message content**, not just dedicated ip/hash/url fields.
- **Hypotheses — on-demand ✨ Generate button** to force-regenerate from the current timeline (part of #140).
- **Evidence drop folder (auto-import inbox)** — per-case `drop/` folder auto-imports anything copied in, images included (default on; `DFIR_DROP_ENABLED`).
- **Timeline anomalies — self-baseline detection** alongside the existing peer baseline; new Type column (part of #175).
- **Remember import severity** — dialog checkbox to skip the minimum-severity prompt on future imports.
- **Timeline row display toggles** — Settings → General control for which row sub-elements show.
- **Linux shell history import** — `.bash_history`/`.zsh_history` deterministic mapper with tradecraft-aware severity.
- **Windows Event Log XML import** — deterministic parser for Event Viewer/wevtutil/PowerShell XML exports.
- **Screenshot OCR full-text search** — local Tesseract OCR indexing of captures, searchable from the filter bar (closes #176).
- **Presentation / timeline-replay mode** — read-only step-through slide deck for handoff briefings, offline export (closes #177).
- **Actionable mitigations** — MITRE ATT&CK Mitigations checklist ranked by coverage, plus ✨ Generate remediation plan (part of #178).
- **D3FEND defensive countermeasures** — action-first checklist per ATT&CK technique, offline dataset (closes #178).
- **Startup pre-flight diagnostics** — non-blocking self-test of AI/enrichment/Velociraptor on boot (closes #179).
- **Automatic state backup / rotation** with one-click restore from Settings → Diagnostics (closes #180).
- **Setup wizard** — guided first-run config for AI, Velociraptor, IRIS, Timesketch, Notion, ClickUp, push ingest, NSRL, enrichment and notifications (closes #181).
- **Declared Node engine requirement** `>=20` (NSRL SQLite backend needs 22.5+) (closes #185).
- **Full-pipeline integration test** covering capture → import → synthesis → enrichment → report → snapshot (addresses #182).
- **10k-event performance/load test** benchmarking the hot synthesis/report paths (closes #183).
- **Timeline Anomalies panel** — deterministic per-asset event-rate spike detection (closes #175).

### Changed
- **Timeline "⛏ Sources" filter button now shows with a single source too** (was hidden until 2+ tools contributed events).
- **Synthesis anchors on connective IOCs** — context now leads with IOCs ranked by cross-host reach + multi-tool corroboration (`analysis/iocAnchors.ts`; closes #200).
- **Process/command severity is now content-, path- & exfil-aware** — renamed LSASS dumpers, staging-path execution, and DB dumps/uploads now graded correctly (closes #199).
- **Drop-folder banner suppressed** in the dashboard; auto-import itself is unaffected.
- **Global search filter now spans Kill Chain and Attack Phases** too, not just timeline/IOCs/findings.
- **Kill Chain — T1078 credential-reuse logons now bucket under Lateral Movement**, not Initial Access.
- **Timeline anomalies default bucket dropped to 15 min** (was 60) so short bursts aren't diluted.
- **Timeline host de-duplication** — redundant trailing `@ <host>` stripped from descriptions when the host chip is shown.
- **Chocolatey package** — removed unneeded `tools/LICENSE.txt`/`VERIFICATION.txt` per moderator feedback.
- **Demo case** — added an AD-enumeration burst so Timeline Anomalies shows a spike out of the box (part of #175).

### Fixed
- **Bash-history uploads now also tag T1567.002**, not just T1041 (was mislabeling cloud uploads as C2 exfil).
- **Threat-intel verdicts on the case's own infrastructure flagged as a conflict** instead of driving false findings.
- **`logAggregate` truncation now keeps rare/unique lines** instead of silently dropping one-off attack lines.
- **AI log-triage no longer escalates routine sudo/auth activity into a fake "campaign" finding.**
- **Ransomware impact phase now surfaces (Meridian benchmark)** — pid-based process correlation, `vssadmin delete shadows`→T1490, and a ransomware-encryptor heuristic→T1486.
- **Benign Defender CreateRemoteThread no longer escalated to High.**
- **Benign LSASS access from Windows-native processes no longer escalated to High** (closes #198).
- **Zeek per-stream JSON (no `_path`) now routes to the network importer** instead of the generic SIEM mapper (closes #197).
- **Cross-tool process correlation (host+pid)** collapses EDR+Windows-log duplicates into one corroborated event.
- **Mis-dated events re-anchored to the dominant year** when one year clearly dominates (`timeYearClamp.ts`).
- **Timeline coverage gaps now robust to mis-dated strays**, preventing false multi-hundred-day silence findings.
- **Timeline Anomalies "view N events" now shows all N**, not just the first (part of #175).
- **IOC "Flagged only" / timeline "Starred" filters no longer collapse their section.**
- **AI status badge always visible** in the tight/icons-only toolbar.
- **Import into a non-existent case now 404s** instead of orphaning the uploaded bytes.

## [0.27.0] - 2026-06-24

### Added
- **Timeline brushing + evidence-graph filters** — drag a time-range on the swimlane to scope correlated events; evidence graph gains a severity floor + SVG export to declutter/share large graphs (#122).
- **Dashboard view presets** — toolbar ⊞ menu of Analyst/Lead/Executive (role) + Triage/Report/Deep-Dive/Hunt-Prep (phase) layouts that reorder panels, apply a severity floor + top-N cap, and link a report template; per-case, fully editable in Settings → Dashboard Views (closes #142).
- **Persistent case memory** — synthesis logs each run to a durable Investigation Log; a *known-unknowns* block (gaps, uncovered ATT&CK phases, lookalike actors' next techniques) grounds synthesis + hunt suggestions; opt-in `DFIR_SYNTH_ADVERSARY_HINTS` feeds candidate actors as hypotheses (closes #165).
- **Skip AI for disabled report sections** — executive-summary + narrative generators no longer spend tokens when their section is disabled in the report template (409 with the reason); saved content preserved (closes #168).
- **IOC filter by type** — IOC panel "▾ Types" facet (ip/domain/url/hash/file/process/other) with per-type counts, composing with the flagged-only + search filters (closes #169).
- **Geographic IP map** — dashboard 🌍 Leaflet panel plotting geo-located IP IOCs (severity colors, victim→attacker flows, country stats, timeline sync, CSV export) + report §4.10; from GeoIP enrichment, no new auto-calls (closes #133).
- **Geo country-centroid fallback** — IPs with a country but no city coords fall back to the country centroid, shown as a faint dashed "country-level (approx)" marker; regenerate via `npm run data:update-geo` (part of #133).
- **Hypothesis-driven investigation mode** — Hypotheses panel for status-tracked hypotheses (open/supported/refuted/unknown), auto-generated + analyst-authored, with evidence/technique links + report section; open ones steer synthesis, notebook notes promote in, survive synthesis + snapshots (closes #140).
- **Supporting events & IOCs per finding** — each finding lists the events that back it (click to jump, even across pagination) plus its supporting IOC values, derived client-side (part of #139).
- **Hunting feedback loop** — deployed hunts record their outcome per case (new evidence + counts, survives restart); suggestions skip an already-run VQL and pivot on what hit, with a "Hunting Profile" panel of hunted/hit/missed + auto-collect + per-hunt re-collect (closes #157).
- **Regenerate a suggested fleet hunt** — per-card ↻ Regenerate on AI fleet-hunt cards for a fresh VQL when one won't compile (part of #57).

### Fixed
- **Asset↔IoC over-linking on IP substrings** — the asset-graph scan now matches IP IOCs with a digit/dot boundary, so `1.1.1.1` no longer links inside `11.1.1.10`, preventing inflated associations (#133).
- **Hunt VQL `hash()` signature** — fleet/playbook hunt prompts now teach the real `hash(path=…).SHA256` form (no invented `hashselect=` arg) and avoid full-disk globs, cutting "did not launch the hunt" errors (part of #57/#70).
- **`spawn EPERM` launching a hunt** — the velociraptor launch retries a transient Windows lock (`DFIR_VELOCIRAPTOR_SPAWN_RETRIES`, default 6); a persistent EPERM/EACCES (AV/EDR blocking a credential-dump-flavored VQL) now reports an actionable message (add an AV exclusion, or run from the GUI).
- **Corrupted `investigation.json` on concurrent saves** — `atomicWrite` now uses a unique per-call temp file (was a fixed `.tmp`), so two concurrent saves no longer interleave into a malformed file that 500'd every state-loading endpoint; worst case is a lost update.
- **Lost-update on manual add during synthesis** — a per-case `StateLock` serializes load→save critical sections and synthesis re-reads the latest state before persisting, so an event/IOC added mid-synthesis is no longer clobbered.

## [0.26.0] - 2026-06-21

### Added
- **Chocolatey package** — `choco install dfir-companion` installs the portable Windows build and bundles the capture extension on disk for offline "Load unpacked"; `packaging/chocolatey/` template + `build-choco.mjs` fill in both download URLs + SHA256s, data is redirected to `%LOCALAPPDATA%\DFIR-Companion`, and a CI `chocolatey` job packs + attaches the `.nupkg` and pushes once `CHOCOLATEY_API_KEY` is set (part of #137).
- **Chrome Web Store packaging (extension)** — static store icons (16/32/48/128 from the Companion logo) wired into the manifest, a `PRIVACY.md` policy, and a CI `chrome-webstore` job that publishes the built zip on each `v*` tag once OAuth secrets are set (part of #138).

### Changed
- **Extension manifest (extension)** — renamed to "DFIR Companion — Evidence Capture & Push" with a description that discloses the DFIR-console data push, for the listed Web Store submission (part of #138).

## [0.25.0] - 2026-06-20

### Added
- **Demo mode** — `DFIR_DEMO_MODE=true` blocks all mutating API routes (new cases, imports, AI calls, deletions), seeds the demo case on startup, and auto-resets it every hour (`DFIR_DEMO_RESET_HOURS`); `railway.toml` added for one-click Railway deployment.
- **Timeline source filter** — faceted dropdown beside the severity legend to show/hide forensic-timeline events by the tool/source that produced them (built from the distinct `sources`); a multi-source event stays visible unless all its sources are hidden, and the filter respects pagination/search (#131).
- **Enhanced redaction** — tokenize PowerShell encoded-command blobs (`-enc <base64>`/`FromBase64String`) + victim user SIDs (`S-1-5-21-…`) before the AI; new `CMD`/`REG` anon categories, well-known SIDs preserved (closes #128).
- **Draggable push button (extension)** — injected button can be dragged anywhere on the page; position remembered and always clamped on-screen.
- **Security Onion adapter (extension)** — recognizes SOC event views (Alerts/Hunt/Dashboards) and SO's bundled Kibana; one-click Push of individual events (Detections/Cases excluded).
- **Security Onion importer (companion)** — deterministic: `severity_label`→severity, ECS threat→MITRE, source/dest/dns/url/hash→IOCs; detected ahead of Velociraptor/SIEM to fix `_Source` mis-routing.
- **SO-CRATES adapter (extension)** — recognizes the SO-CRATES `socrates.html` page; one-click Push of its network/file events (`/api/events`) and Sigma detections (`/api/sigma-alerts`).
- **SO-CRATES importer (companion)** — deterministic: Suricata `alert` (reuses the network importer), YARA `filealerts`→file-match events + hash IOCs, Sigma→verdict-first severity/MITRE overlaid on the matched Sysmon event (CommandLine/ParentImage/ParentCommandLine + process/hash IOCs via `mapWindows`); tagged `SO-CRATES`, detected ahead of Velociraptor's `_Source` catch-all.
- **Linux AppImage** — single-file build attached to every release; `DFIR_ENV_FILE` override for `.env` outside a read-only mount (#127).
- **Update notice** — opt-in dashboard banner for newer GitHub releases; `DFIR_UPDATE_CHECK` env + Settings toggle, never auto-installs (#127).
- **CI build + test gate** — `.github/workflows/ci.yml` runs `build + test` for `companion/` and `extension/` on every PR and push to master (#126).
- **Scheduled-task mapper** — Velociraptor `TaskScheduler/Analysis` artifacts → `taskscheduler` kind with well-known SID expansion (SYSTEM/LOCAL SERVICE/NETWORK SERVICE).
- **MFT detection `InUse` field** — `DetectRaptor.Windows.Detection.MFT` rows append `[deleted]` when `InUse` is false.
- **Evidence-of-download mapper** — Velociraptor `BrowserDownloads`/`EvidenceOfDownload` → `download` kind; `HostUrl` + `ReferrerUrl` added as URL IOCs.
- **Startup-items mapper** — Velociraptor `StartupItems`/`Autorun` → `startup` kind with T1547; enabled=Low, disabled=Info.
- **CIRCL hashlookup enrichment** — keyless known-file lookup (NSRL-derived + distro packages); `external` scope, `DFIR_HASHLOOKUP_URL` override (closes #154).
- **Timeline pagination** — 100/250/500/all rows per page, user-selectable (#125).
- **Correlation profile** — per-case Strict/Moderate/Aggressive merge-window setting; `PUT /cases/:id/correlation-profile` (#125).
- **Synthesis performance metrics** — `synth-meta.json` records `durationMs`/`eventCount`/`iocCount`; dashboard banner shows them with ⚠ advisory above 5 000 events (#125).

### Fixed
- **Large Plaso import OOM** — files over 200 MB now streamed line-by-line via `import-file` route + `parsePlasoFromLines`; a 555 MB file imports at ~1.3 GB peak RSS instead of OOMing.
- **`DFIR_DISK_WARN_PCT=0` ignored** — setting to 0 now correctly disables the disk-space warning.
- **Import progress bar** — thin strip at the top of the dashboard shows browser-read then server-side import progress.
- **Playbook task flood from burst detections** — `backfillHighSeverityFindings` groups uncovered Critical/High events by short title before creating auto-findings.
- **Velociraptor pslist/pstree import** — NDJSON exports without `_Source`/`Artifact` now route to the Velociraptor importer via `CallChain`+`Pid` presence.
- **Velociraptor netstat import** — `Windows.Network.Netstat` exports now route to a dedicated `mapNetstat` formatter; ESTABLISHED external IP added as IOC.
- **WebSocket over HTTPS** — dashboard now uses `wss://` when served over HTTPS (KillerCoda/Railway proxy); constructor errors caught so a blocked WebSocket doesn't surface as a modal alert.
- **Extension offline message** — Refresh Cases now shows "companion offline — check URL" instead of always reporting success when the companion is unreachable.
- **Enrichment picker** — all 13 known providers always listed; unconfigured ones dimmed with `(key missing: ENVVAR)` hint instead of being hidden.
- **KillerCoda scenario** — switched to pre-built Docker image (~1 min setup); suppressed bash verbose echo; corrected hamburger icon; added port-access instructions.

### Changed
- **Consistent event-field separator** — extension-pushed imports (SIEM/Sysmon, Velociraptor, Security Onion, SO-CRATES, Suricata/Zeek) now join description fields with a single ` - ` (no more mixed `|`/em-dash/space); `ParentCommandLine` added to the standard Windows subject fields.
- **Graph-grounded fleet-hunt suggestions** — `suggestHunts` feeds the causal evidence graph so hunts target relationships fleet-wide, not just leaf indicators (#124).

## [0.23.0] - 2026-06-17

### Added
- **Mattermost & Discord notifications** — two new webhook channels alongside Slack/Teams/Telegram/SMTP; test button + secret redaction (closes #136).
- **Explain This Event** — 💡 button per timeline row fires a focused AI explanation with ATT&CK mapping and 1–3 pivot queries; ephemeral, copy buttons per query (closes #141).
- **IP-infrastructure enrichment** — four IP-only providers: Reverse DNS (keyless), WHOIS/RDAP (keyless), GeoIP (`DFIR_GEOIP_URL`), Shodan (reuses key); all opt-in, `unknown`-verdict badges (closes #134).
- **Chain-of-Thought synthesis** — opt-in extended thinking on synthesis via `DFIR_AI_SYNTH_THINKING_TOKENS` or the 🧠 deep dashboard checkbox; applies to primary + second-opinion passes (#121).
- **Adversary emulation — likely next techniques** — techniques matched groups use that the case hasn't observed, ranked by TF-IDF distinctiveness; ⌖ hunt this generates VQL; `DFIR_ADVERSARY_NEXT_MAX` (closes #121).
- **Case lifecycle & archiving** — open/closed status, ZIP archive with SHA-256 manifest, disk-space banner, toolbar lifecycle menu (closes #119).
- **Custom declarative importers** — drop a JSON importer spec to auto-detect + import like a built-in; LLM-authorable via a built-in prompt, user-selectable precedence.
- **Health / Diagnostics page** — Settings → Diagnostics: disk usage, case count, queue, AI config, importer stats, live AI connectivity test (closes #118).
- **OpenCTI enrichment** — local-scope IOC lookup against a self-hosted OpenCTI instance via GraphQL (closes #152).

## [0.22.0] - 2026-06-15

### Fixed
- **Extension push button on remote / modern Kibana** — handles async-search strategy envelope, bfetch shapes (NDJSON, bfetch compression), and React re-renders via MutationObserver.
- **Pushed Elastic rows from `_source`-disabled indices** — flattens `fields` arrays; SIEM mapper now reads `desc` and summarizes salient fields instead of Elasticsearch metadata.
- **MemProcFS `timeline_all.csv` Net IOCs** — fixed invalid `"network"` IOC type (now correctly `ip`).

### Added
- **Second LLM opinion** — on-demand non-destructive re-synthesis by a second model; per-item analyst accept/reject; accepted deltas survive re-synthesis; `DFIR_AI_SECOND_OPINION_MODEL` (closes #116).
- **Velociraptor data from Elasticsearch** — `detectImportKind` routes `artifact_*` indices and `Detection.*` CSV columns to `importVelociraptor`; normalizes ES-reshaped rows + Kibana display-format timestamps.
- **MemProcFS `timeline_all.csv` importer** — deterministic: ShTask/Net/PROC/WEB rows → severity + ATT&CK; auto-detected by unified Import.
- **MemProcFS `findevil` importer** — deterministic: finding types → severity + ATT&CK (YR_HACKTOOL→Critical/T1588.002, etc.); bulk PRIVATE_RWX pages grouped; auto-detected.

## [0.21.0] - 2026-06-15

### Added
- **GraphRAG for "Ask the case"** — evidence-chain graph serialized as causal edges grounds multi-hop answers; `DFIR_ASK_GRAPH_MAX_EDGES` (closes #98).
- **Memory-forensics "Next-Step" agent** — AI reads Volatility evidence and proposes the exact next `vol` command; ✨ button in a *Memory Next Steps* panel (closes #101).
- **Volatility 3 text-output import** — default `vol <plugin>` TEXT/grid renderer ingested alongside `-r json`; hexdump continuation lines skipped (#101).
- **Natural-language Query Translator** — plain-English → VQL/KQL/ES|QL/SPL/Sigma/YARA/Suricata; VQL one-click deploys via hunt flow (closes #100).
- **One-click artifact push from the browser extension** — MAIN-world fetch/XHR hook on recognized DFIR consoles POSTs to `/import`; cross-case dashboard warning on mismatch (closes #102).
- **Timeline-gap hypotheses & shadow-artifact hunting** — AI hypothesizes silent periods; catalog of shadow artifacts (USN/SRUM/Prefetch/…) each deployable as a Velociraptor collection (closes #96).
- **Sort timeline by date or severity** — per-column ▲/▼ sort arrows; client-side, persisted across reloads (closes #104).
- **Payload deobfuscation** — auto-decodes base64/`-EncodedCommand` PowerShell; extracts hidden IOCs; expandable [Decoded] block per event (closes #97).
- **CISA KEV integration** — cross-reference CVEs against the CISA KEV catalog; surfaces in synthesis context + report §4.5.1; opt-in (closes #99).
- **Import from DFIR-IRIS** — pull IRIS assets/IOCs/timeline into a Companion case; toolbar chooser + `npm run iris:import`; Settings reconnect without restart (closes #88).
- **Webhook push ingest** — `POST /cases/:id/push` with token auth; same import→diff→synthesize pipeline, 202-async (closes #84).
- **Velociraptor live monitoring** — CLIENT_EVENT artifact stream, one endpoint or all; auto-monitor; persisted cursor; 🔴 LIVE badge (closes #84).
- **Velociraptor reconnect** — Settings → Reconnect re-reads `DFIR_VELOCIRAPTOR_*` without restart; startup retry with backoff (#84).
- **IOC block-list export** — plain TXT/CSV/STIX-indicators; min-severity + type filters; `GET /cases/:id/export/ioc-blocklist` (closes #87).
- **Wazuh importer** — `rule.level`→severity, MITRE, asset, IP/hash/URL IOCs; auto-detected (closes #85).
- **TheHive importer** — TheHive 5 case/alert/observable exports; severity from 1–4 scale, MITRE from ATT&CK tags (closes #86).
- **Log gap analysis** — complete all-source silences flagged High, single-source gaps Medium; derived on read; `DFIR_GAP_MIN_MINUTES` (closes #83).
- **Beacon / C2 detection** — median/MAD periodicity check on outbound connections; High for public destinations; `DFIR_BEACON_MIN_COUNT` (closes #82).

### Changed
- **Customer Exposure shows found results only** — hides clean "no breach" rows; providers/targets summary still shown.
- **Demo case enriched** — `seed-demo` adds a ~16h complete-silence gap + seeded narrative/notebook entries for demo coverage.

### Fixed
- **Extension case selection saves without pressing Start** — case dropdown auto-saves on change; floating Push button hides when no case is connected.
- **Demo Customer Exposure rows rendered half-empty** — `seed-demo` rewritten to current `StoredCustomerExposureResult` schema.
- **Velociraptor live-monitor discovery on real servers** — artifact type filtering moved to TypeScript; auto-monitor uses correct VQL `get_client_monitoring()`; new `/velociraptor/diag` endpoint.
- **`seed-demo` now honours `DFIR_CASES_ROOT`** — seed script now loads `.env` before writing the demo case.

## [0.20.0] - 2026-06-13

### Added
- **Import undo/redo** — roll case state back to before an import; per-case stack (`DFIR_IMPORT_UNDO_DEPTH`, default 10); Undo/Redo buttons next to Import (closes #76).
- **AI-suggested playbook hunts** — propose a Velociraptor hunt per endpoint-related Playbook task; host-specific → single-client collection, else fleet hunt (closes #70).
- **Velociraptor client inventory** — enrolled fleet snapshot at startup/on-demand; single-endpoint collections resolve by hostname (#70).
- **Collection results in the dashboard** — single-endpoint collection rows rendered inline with auto-poll, like fleet hunts (#70).
- **Dedicated Velociraptor hunt model** — `DFIR_AI_VELO_PROVIDER`/`_MODEL` for VQL generation, separate from analysis model; configurable in Settings → AI (#70).
- **Persistent + incremental hunt suggestions** — generated hunts survive refresh; re-generate sends only new/changed tasks; `force:true` regenerates all (#70).
- **Playbook task short IDs** — stable `T001`/`T002` display IDs stored in the task record; existing tasks back-filled.
- **Telegram notifications** — Telegram bot channel for findings/playbook/milestone notifications (closes #75).

### Fixed
- **Playbook delete button for auto-derived tasks** — delete now marks task `skipped` instead of silently removing it (closes #78).
- **Playbook-hunt VQL grounded in real artifacts** — prompt lists the server's actual CLIENT artifact names; correct plugin args; no SQL JOIN; `DFIR_PBHUNT_MAX_EVENTS` (#70).
- **Endpoint-side collection errors surfaced** — flow `ERROR` status now shown in the dashboard instead of polling forever (#70).

## [0.19.0] - 2026-06-12

### Added
- **Linux evidence importers** — deterministic auditd, journald, and sysdig/Falco ingest, auto-detected by the unified Import button (closes #62).
- **Mobile companion** — installable read-only PWA at `/mobile` (findings, timeline, IOC verdicts); `/cases/:id/mobile-summary` endpoint, `DFIR_MOBILE_MAX_*` caps (closes #59).
- **AI-suggested fleet hunts** — generate proactive Velociraptor VQL hunts from case findings; review + one-click deploy across all endpoints (closes #57).
- **Memory forensics import** — deterministic Volatility 3 (JSON) + Rekall: pslist/pstree → process tree, netscan → connections, malfind → injected code (T1055), cmdline/svcscan → evidence (closes #61).
- **Investigation snapshot** — one shareable JSON exports/imports the full case (timeline, findings, IOCs, analyst decisions) with no AI keys or machine config (closes #56).
- **Redacted case export** — shareable ZIP: report/CSVs/state tokenized, secrets redacted, screenshot EXIF stripped + PII blurred (closes #54).
- **Dark / light theme** — full-coverage theme toggle; follows OS preference by default, manual choice persists (closes #53).
- **Custom report templates** — global branded layouts (accent colour, header/footer, section reorder); built-ins editable; selected per case; flows to Markdown/HTML/Word (closes #60).
- **Notifications** — Slack/Teams webhooks + SMTP for findings/playbook/milestones; per-channel severity thresholds + event toggles; opt-in (closes #58).
- **NSRL known-good hash checking** — auto-marks matching events + IOCs legitimate on import. Two backends: flat hash set and direct NSRL RDS SQLite query (`DFIR_NSRL_DB`); keys on sha256/md5 (closes #63).

### Changed
- Dashboard: removed **Mobile** toolbar button — navigate to `/mobile` directly.
- Dashboard: finding tag chips reordered; case ID input fixed-width; removed ellipsis from Import button labels.

## [0.18.0] - 2026-06-11

### Added
- **MITRE ATT&CK Navigator layer** export — JSON layer, techniques colored by severity (closes #43).
- **STIX 2.1 bundle** export — report + IOC indicators + ATT&CK + malware/identities; deterministic ids, no library (closes #45).
- **Email / `.eml` / `.msg` import** — deterministic phishing/BEC importer: event at `Date:`, severity from SPF/DKIM/DMARC + spoof heuristics, IOCs (T1566) (closes #44).
- **Adversary group hints** — known ATT&CK groups ranked by technique overlap, offline; sub-technique-aware; dashboard panel + report §4.6.1 (closes #46).

## [0.17.0] - 2026-06-11

### Added
- Dashboard warns when screenshots arrive for a different case than the one you're viewing.
- Anonymization auto-discovery learns entities from screenshots (OCR), grouped by type; each removable.
- Leveled logging to file — global session log + per-case audit trail; `DFIR_LOG_LEVEL` + live Settings toggle.
- Timeline events show affected host chip and clickable finding links; report §3.1 gains a Host column.
- Local OCR screenshot anonymization — Tesseract redacts matching text before sending to the vision model (closes #19).
- Timeline Swimlane view — interactive asset/time chart with selection, scope-to-view, PNG/SVG export (closes #33).
- Global full-text filter + time-range filter behind a toolbar icon.
- Analyst Notebook entries record their author; multi-investigator real-time sync over WebSocket (closes #29).
- IOC bulk select + batch actions, IOC whitelist (auto-mark known-good), and "⊕ N sources" corroboration badges (closes #35).

### Changed
- Anonymization modal: clearer auto-detected panel + dropped the stray scrollbar.
- Dashboard "Search" relabelled "Filter"; responsive toolbar — settings gear pinned top-right, action buttons auto-collapse.

### Fixed
- Duplicate detection now uses exact SHA-256 content hash (was fuzzy perceptual hash); `DFIR_DEDUP=off` disables it.
- OCR redaction was a silent no-op — screenshots had been sent un-redacted.
- "AI on — catching up…" status no longer hangs when there's nothing to analyze.

### Security
- Added `SECURITY.md` (localhost posture, reporting, and deferred dev-only `vitest` audit advisories).

## [0.16.0] - 2026-06-11

### Added
- Response Playbook — turns AI next steps + Critical/High findings into a trackable checklist; optional IR-templates expansion (closes #36).
- Push the Playbook to DFIR-IRIS and to ClickUp (idempotent re-push).

### Changed
- Every `DFIR_*` env var is now configurable from Settings.
- The Playbook takes the prominent dashboard slot; Recommended Next Steps is hidden by default.

### Fixed
- Hunt-pivot VQL uses `OSPath` instead of the deprecated `glob()` `FullPath`.

## [0.15.0] - 2026-06-10

### Added
- Velociraptor triage bundles — pick artifacts → run as a fleet hunt → auto-import + synthesize (closes #30).
- Export a case to Notion, new or existing page (closes #31).
- IOCs: "⚠ Flagged only" filter (show only malicious/suspicious verdicts).

### Changed
- Analyst Notebook section is now reorderable/hideable and sits after Confirmed Legitimate.

### Fixed
- Velociraptor bundle collection survives a too-large artifact (skips it, larger collect cap) and supports concurrent hunts; deep links include `?org_id=`.

## [0.14.0] - 2026-06-09

### Added
- Anthropic prompt caching for the extraction system prompt (closes #18).
- Analyst Notebook — per-case scratchpad for hypotheses/notes/questions, optionally fed to synthesis (closes #8).
- Narrative Timeline — prose story-mode view of the incident.
- Case templates — start a case pre-loaded with investigation questions + artifact hints.
- Per-provider enrichment throttle (`DFIR_ENRICH_DELAY_MS_<PROVIDER>`).
- Configurable companion host/port in the extension Options page (closes #12); `_execute_action` popup shortcut.
- Manual editing of assets and asset ↔ IoC links (persisted, survives synthesis).
- Settings → General: drag-to-reorder dashboard sections; added the missing TLS skip-verify fields.

## [0.13.0] - 2026-06-09

### Added
- Settings modal — all configuration (general, AI, enrichment, exposure, integrations) in one tabbed place.
- Attack Phases — temporal burst detection over the timeline, labelled by dominant ATT&CK tactic.
- Confidence scoring on findings (badge + min-confidence filter).
- Evidence Chain graph phase 2 — file-lineage and network-flow edges.
- MISP export — push IOCs + MITRE techniques to a MISP instance (idempotent).

## [0.12.0] - 2026-06-08

### Added
- Evidence Chain graph — the causal view (process trees + lateral movement), derived deterministically.
- Drag-to-reposition nodes in the asset ↔ IoC graph (positions persist per case).

## [0.11.0] - 2026-06-08

### Added
- Customer exposure / credential-leak check — LeakCheck, HIBP, DeHashed, Shodan; strict customer-only boundary, no raw passwords stored.
- CrowdStrike Falcon threat-intel enrichment provider (Threat Intelligence only).
- Hunting.ch (abuse.ch) enrichment — one key fans out across MalwareBazaar / ThreatFox / URLhaus / YARAify.
- Import change tracking — "📥 last import N ago / +N events / +N IOCs" banners + `NEW` row highlights.
- Hunt-pivot generator adds Elastic ES|QL, YARA, and Suricata; `DFIR_HUNT_PLATFORMS` trims the platform list.
- Safety-net periodic flush so a lone screenshot still gets analyzed.
- Timeline triage controls — star, multi-select, and bulk actions.

### Changed
- Velociraptor pivot offers a runnable notebook query alongside the hunt; asset-graph nodes show a type icon.
- Findings moved above the Forensic Timeline; Kill Chain tactics open in a full-width panel.

### Fixed
- Sub-millisecond timestamp precision preserved through UTC conversion.
- Hunt-pivot harvests indicators from network/IDS event text.
- CSV/log import respects the per-case "AI off" toggle.
- Hayabusa `json-timeline` (concatenated JSON) now imports; relative paths no longer mis-read as accounts.
- Triage-tag icon visibility, "Mark legitimate" button on rows, and bulk-tag race fixed.

## [0.10.0] - 2026-06-06

### Added
- Run hunts across all endpoints via the Velociraptor API.
- Hunt-pivot query generator (Velociraptor VQL, Defender/Sentinel KQL, Splunk SPL, Sigma) — deterministic, offline.
- AI executive summary (management-facing) for the report.
- Synthesis freshness + what-changed diff ("🧠 last synthesized N ago").
- Analyst triage tags on any entity.
- Kill Chain tactic-phase view.

### Fixed
- Asset-graph labels no longer clip at the canvas edge.

## [0.9.1] - 2026-06-06

### Fixed
- `GET /` redirects to the dashboard; Docker image starts on Node 22.
- Windows portable EXE starts correctly (bundled `sharp` runtime deps) and shows the app icon.

## [0.9.0] - 2026-06-06

### Added
- Native Anthropic API provider; per-provider model recommendations in `.env.example`.
- Cyber Triage timeline import.
- Portable Windows EXE (Node SEA) + Docker / Docker Compose install options.
- One-click PDF and Word (.docx) report export; optional company name + logo branding.
- Forensic Timeline: live event count, severity filter checkboxes, and a severity colour legend.

### Changed
- Terminology "Attacker Path" → "Attack Path"; "Synthesize" → "AI Re-synthesize"; "Ask the AI" → "Ask the LLM".
- Velociraptor importer: verdict-first detection mapping with cleaner descriptions/timestamps.
- README: explicit "as-is" / no-liability disclaimer.

### Fixed
- Deterministic imports work without an AI provider; imports don't run synthesis when AI is off.
- Anonymizer auto-detection no longer floods "internal domains" with generic words.
- Velociraptor exports no longer mislabel as "SIEM event"; no `[enrich] health … DOWN` spam while off.

### Security
- [P1] Path-traversal guard on case IDs; markdown link/image injection blocked in the HTML report.

## [0.8.0] - 2026-06-05

### Added
- New deterministic importers: Chainsaw/EVTX, Hayabusa, Velociraptor native JSON, Suricata/Zeek, KAPE/EZ Tools, Microsoft 365 / Entra ID, AWS CloudTrail, GCP/Azure activity, Plaso, and malware-sandbox (CAPEv2 / Falcon Sandbox).

### Changed
- One "Import" button (server auto-detects the file type); one "Export" menu and one "Push" menu.

## [0.7.0] - 2026-06-05

### Added
- AI-input anonymization (reversible tokenization; default on).
- SIEM / EDR JSON import; LiteLLM / any OpenAI-compatible endpoint.
- Timesketch timeline export & push.
- Case creation moved to the dashboard; new-case dialog auto-suggests the next `INC-YYYY-NNN`.
- Enrichment reachability gate (skip a down MISP/YETI).

### Changed
- All forensic timestamps normalized to UTC; AI analysis defaults to OFF per case; captures to an unknown case are rejected.

### Fixed
- Large imports no longer fail with HTTP 413; AI prompts no longer overflow the context window; manual event time no longer shifted by local timezone.

### Removed
- The extension no longer creates cases.

## [0.6.0] - 2026-06-04

### Added
- License: GNU AGPL-3.0; project logo + favicons.
- Manually add an event or IOC the AI missed.
- Push a case to DFIR-IRIS; MITRE techniques link to attack.mitre.org.
- `npm run yeti` CLI lookup; timestamped server log with per-call enrichment audit lines.

### Changed
- Per-source enrichment selection (OPSEC — local-only by default).

### Fixed
- YETI v2 tag parsing; failed enrichment no longer cached as "checked"; `EPERM` on state save in a synced folder.

## [0.5.0] - 2026-06-04

### Added
- Investigator comments; drag-to-reorder dashboard sections; "Ask the AI about the case"; import external screenshots; customizable AI prompts.

### Changed
- Synthesis is cheaper and smarter (skip-if-unchanged, stratified event selection).

## [0.4.0] - 2026-06-04

### Added
- Compromised assets + asset ↔ IoC graph; keyboard shortcut to toggle capture; self-hosted TLS trust for MISP/YETI; full incident-report template.

## [0.3.0] - 2026-06-04

### Added
- Threat-intel IOC enrichment; process-chain validation (RockyRaccoon); cross-source correlation & duplicate collapsing; THOR (Nextron) scanner import.

### Changed
- Bounded AI requests (fixes spurious OpenRouter HTTP 402); synthesis preserves IOCs.

### Fixed
- EDR/XDR and SIEM detections reliably enter the timeline & findings; tolerate truncated AI JSON; no bogus "2 sources" / "unknown source".

## [0.2.0] - 2026-06-02

### Added
- Mark a forensic event legitimate; severity-aware findings; configurable server port; captured tab title in screenshot filenames.

### Changed
- Log import is deduplicated + AI-triaged; extraction prompt rebalanced.

### Fixed
- Analyst-workflow / tool-navigation narration kept out of the timeline; real threats are never dropped.

## [0.1.0] - 2026-06-01

### Added
- Localhost companion server; evidence-first ingest; two-phase AI analysis; provider abstraction; investigation scope; CSV (Velociraptor/EDR) import.

[Unreleased]: https://github.com/hasamba/DFIR-Companion/compare/v0.32.0...HEAD
[0.32.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.31.0...v0.32.0
[0.31.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.30.0...v0.31.0
[0.30.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.29.0...v0.30.0
[0.29.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.28.0...v0.29.0
[0.28.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.27.0...v0.28.0
[0.27.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.26.0...v0.27.0
[0.26.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.25.0...v0.26.0
[0.25.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.23.0...v0.25.0
[0.23.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.22.0...v0.23.0
[0.22.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.21.0...v0.22.0
[0.21.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.20.0...v0.21.0
[0.20.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.19.0...v0.20.0
[0.19.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.18.0...v0.19.0
[0.18.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.17.0...v0.18.0
[0.17.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.16.0...v0.17.0
[0.16.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.15.0...v0.16.0
[0.15.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.14.0...v0.15.0
[0.14.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.9.1...v0.10.0
[0.9.1]: https://github.com/hasamba/DFIR-Companion/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/hasamba/DFIR-Companion/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/hasamba/DFIR-Companion/releases/tag/v0.1.0
