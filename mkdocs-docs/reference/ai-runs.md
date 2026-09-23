# What Each AI Run Sees

Every model-backed action in DFIR Companion, and the two questions that decide whether you
can trust its output: **what is it allowed to read**, and **does it change your case record**.

Of the 27 runs, **12 change your case record** and **5 of those can run
without anyone pressing anything**. 5 are allowed to read the raw archive.

Read with the [AI Analysis](ai-analysis.md) page, which explains what each run is *for*. This one
answers a narrower question: what it is allowed to see, and what it does to your case.

## At a glance

| Run | Trigger | Reads | Changes your record | Model calls |
|---|---|---|---|---|
| **Synthesis** | automatic + button | forensic timeline | **yes** | 2 per real run — synthesis, then finding-tasks |
| **Deep pass** | you press it | forensic timeline | **yes** | 1–30 observe calls, then a forced synthesis — scales with the case |
| **Second look** | you press it | raw archive | **yes** | **Zero** for the search itself — it is keyword matching. 2 if you let it re-synthesise. |
| **Second opinion** | you press it | forensic timeline | **yes** | up to 4 |
| **Explain event** | you press it | raw archive | **yes** | 1 |
| **Starred report** | you press it | raw archive | **yes** | 1 |
| **Narrative** | you press it | forensic timeline | **yes** | 1 |
| **Import extraction (CSV)** | automatic | the imported file | **yes** | 1 per batch — scales with the file |
| **Import extraction (logs)** | automatic | the imported file | **yes** | 1 per batch |
| **Screenshot extraction** | automatic | the imported file | **yes** | 1 per batch |
| **Finding → task** | automatic | findings | **yes** | 1 per synthesis, or 0 |
| **Investigate (MCP agent)** | you press it | anything it chooses | **yes** | an autonomous loop — cost is unbounded in advance |
| **Missed evidence review** | you press it | raw archive | no | one per 40 rows — scales, about 50 calls per 2,000 rows |
| **View summary** | you press it | raw archive | no | 1 |
| **Ask the case** | you press it | forensic timeline | no | 1 |
| **Executive summary** | you press it | forensic timeline | no | 1 |
| **Remediation plan** | you press it | findings | no | 1 |
| **Hypothesis review** | you press it | forensic timeline | no | 1, or 0 when nothing is open |
| **Hypothesize gaps** | you press it | forensic timeline | no | 1 for all gaps, or 0 |
| **Suggest hunts** | you press it | forensic timeline | no | 1, or 0 with nothing to pivot on |
| **Playbook hunts** | you press it | forensic timeline | no | 1 for the whole playbook |
| **Technique hunt** | you press it | barely any case data | no | 1 |
| **Query translation** | you press it | barely any case data | no | 1 for all platforms |
| **Memory next steps** | you press it | forensic timeline | no | 1, or 0 without memory evidence |
| **Suggest tagger rule** | you press it | barely any case data | no | 1 |
| **Ask AI for similar** | you press it | findings | no | 1 |
| **Session summary** | you press it | forensic timeline | no | 1 |

## Runs that change your case record

These rewrite your evidence, your findings or your tasks. Read the limitation on each one before you rely on its output.

### Synthesis

**Where.** AI Re-synthesize — automatic + button.

**Sees.** A stratified *sample* of the forensic timeline — all Critical and High, the earliest events, an even time spread, a rarity bias. Info rows get no seat unless you ask for them.

**Caps.** 600 events (`DFIR_AI_SYNTH_MAX_EVENTS`), burst grouping on, skip-if-unchanged

**Costs.** 2 per real run — synthesis, then finding-tasks, using the synthesis model.

!!! warning "Know this"
    The model sees a sample, not your case. On a big case most rows never reach it. A deterministic backfill is what stops a Critical row vanishing entirely. Toggling anonymisation on or off forces a fresh run.

### Deep pass

**Where.** Deep pass — you press it.

**Sees.** **Every** in-scope event at or above a severity floor you choose, burst-collapsed, split into batches.

**Caps.** 600 rows per batch, 30 batches max (`DFIR_DEEP_PASS_MAX_BATCHES`) — above that it refuses and names a floor that fits

**Costs.** 1–30 observe calls, then a forced synthesis — scales with the case, using the synthesis model.

!!! warning "Know this"
    At the end the model does not re-read the events. It reads its own digest of them. If a batch failed to parse, that slice of your timeline went unread and the conclusions will not say so.

### Second look

**Where.** Second look · Run second look — you press it. The panel sits in the left nav beside Missed Evidence Review.

**Sees.** The raw archive inside the active window, plus the in-scope forensic events. Searches built from your open hypotheses, unanswered questions, top IOCs, and the model's own “I wasn't shown X” requests.

**Caps.** 12 rows per question, 200 per sweep spent round-robin, 3 repeats of any one detection — all constants, no settings

**Costs.** **Zero** for the search itself — it is keyword matching. 2 if you let it re-synthesise., using the synthesis, only for the re-synthesis model.

!!! warning "Know this"
    It changes your evidence record. Untick “re-synthesise afterwards” and your conclusions are now older than your timeline — an export taken in that state is internally inconsistent. Selection is keyword matching; model judgement was tried and rejected.

### Second opinion

**Where.** 2nd opinion — you press it.

**Sees.** The same forensic slice synthesis reads — twice, once per model.

**Caps.** inherits every synthesis cap

**Costs.** up to 4, using the synthesis, second-opinion, reconcile model.

!!! warning "Know this"
    The first thing it does is a **real synthesis** — so pressing this can rewrite your findings before the comparison even exists. That is why it sits with the writers. The rival model's own deltas are different: those reach your case only when you accept them.

**Reconcile referee** — runs inside it, automatically. A third model reads both versions and the disagreement list, and annotates each one: take B, keep A, or review it yourself. It never touches your case — only the comparison record. It is skipped entirely when the two models agree.

!!! warning "Know this"
    Best-effort. If that call fails you get the disagreements with **no rationales** and the panel simply shows fewer annotations. Silence there is not agreement.

### Explain event

**Where.** the lightbulb on a row — you press it.

**Sees.** The one event, up to 15 neighbours in time and on the same host, up to 50 findings, the attacker path.

**Caps.** 15 context events, 50 findings

**Costs.** 1, using the synthesis model.

!!! warning "Know this"
    Clicking the lightbulb on a raw archive row **permanently adds that row to your forensic record**, which changes what the next synthesis reads. Deliberate — but it is a write behind a button that reads like a question.

### Starred report

**Where.** ✨ Starred report — you press it.

**Sees.** Only the events you starred. No scope filter, no false-positive filter — you picked them by hand.

**Caps.** 600 events then token-fitted

**Costs.** 1, using the synthesis model.

!!! warning "Know this"
    Any starred row living only in the archive is promoted into the record before the model sees anything. And if the budget bit, it dropped starred events you explicitly chose — check the used-versus-matched count.

### Narrative

**Where.** ✨ Generate (narrative) — you press it.

**Sees.** The scoped timeline, attacker path, up to 150 findings.

**Caps.** 150 findings, token-fitted

**Costs.** 1, using the synthesis model.

!!! warning "Know this"
    It is the only case report that saves itself, and it **overwrites the previous narrative without asking** — including one you hand-edited.

### Import extraction (CSV)

**Where.** Import — automatic.

**Sees.** The uploaded file only, in batches, with a short case summary for context.

**Caps.** 50 rows per batch, then the token budget

**Costs.** 1 per batch — scales with the file, using the synthesis model.

!!! warning "Know this"
    A year the file never literally contains gets stamped as inferred and becomes clamp-eligible. Cancelling mid-import keeps the batches already merged.

### Import extraction (logs)

**Where.** Import — automatic.

**Sees.** Not your log lines — deduplicated *templates*. The model triages patterns.

**Caps.** 400 templates (`DFIR_LOG_MAX_TEMPLATES`), 120 per batch

**Costs.** 1 per batch, using the synthesis model.

!!! warning "Know this"
    One anomalous line inside a huge template is represented by a single example. Templates past the 400 cap are never shown at all — the import flags that as a coverage gap.

### Screenshot extraction

**Where.** automatic on capture — automatic.

**Sees.** The new screenshots, plus a short case summary.

**Caps.** one call per capture batch; image detail via `DFIR_VISION_IMAGE_DETAIL`

**Costs.** 1 per batch, using the vision model.

!!! warning "Know this"
    This is the only path needing a multimodal model. An install configured with a text-only model silently produces no screenshot events. And if OCR redaction fails, the **unredacted** image is sent.

### Finding → task

**Where.** no button — it just happens — automatic.

**Sees.** Your findings, not your timeline: undismissed Critical and High ones whose task is stale.

**Caps.** 25 findings (`DFIR_FINDING_TASKS_MAX`), 8 events and 6 IOCs each

**Costs.** 1 per synthesis, or 0, using the synthesis model.

!!! warning "Know this"
    Best-effort and **silent**. If the call fails, or a finding falls past the 25 cap, you get the deterministic fallback task instead — and the card looks identical either way.

### Investigate (MCP agent)

**Where.** ▶ Investigate — you press it.

**Sees.** Whatever the agent decides to read through the MCP servers you allowed — evidence files, live hosts, whatever those servers expose. The Companion does not choose the calls.

**Caps.** 40 turns, 1 hour, 8 MB of output

**Costs.** an autonomous loop — cost is unbounded in advance, using the the Claude Code CLI, not a configured provider model.

!!! warning "Know this"
    **No masking anywhere on this path**, and the command allowlist cannot be enforced in this mode — an allowed command-runner tool lets the loop choose its own command lines on your host. Its results merge into the case with an undo checkpoint.

## Runs that only read

Nothing these do reaches your case file. Press them as often as you like; the only cost is the call.

### Missed evidence review

**Where.** Missed evidence · Review — you press it.

**Sees.** The raw archive, minus every row already in your forensic timeline — the rows nothing else looks at.

**Caps.** 2,000 rows by default (`DFIR_JEV_MAX_ROWS`) — a default, not a ceiling; “Read every row” covers the archive

**Costs.** one per 40 rows — scales, about 50 calls per 2,000 rows, using the Jev (a decision model, not a writer) model.

!!! warning "Know this"
    Off unless `DFIR_JEV_ENABLED` is set. The panel **hides rows it scores above 0.5 as your own tooling, ticked by default** — a real finding misjudged that way is invisible until you untick it. And nothing it grades Critical enters your case; you act on it by hand.

### View summary

**Where.** ✨ Summarize view — you press it.

**Sees.** The raw archive directly, filtered the way your screen is filtered. The one sanctioned exception to the boundary rule.

**Caps.** 500 rows, a constant with no setting

**Costs.** 1, using the synthesis model.

!!! warning "Know this"
    The count it reports is what *matched your filters*, not what was read. Filter down to 40,000 rows and you get a summary of 500 of them. The truncation flag deliberately cannot tell the row cap from the token budget.

### Ask the case

**Where.** Ask — you press it.

**Sees.** The scoped forensic timeline, the causal graph, the attacker path, up to 150 findings — and your own work: hypotheses, host scope, dwell windows, prior hunts, tags and comments.

**Caps.** 120 graph edges (`DFIR_ASK_GRAPH_MAX_EDGES`), 150 findings, token-fitted

**Costs.** 1, using the synthesis model.

!!! warning "Know this"
    It answers from the forensic timeline only — **the raw archive is invisible to it**. The used-versus-matched count is your only signal that the prompt was trimmed.

### Executive summary

**Where.** ✨ Generate (exec) — you press it.

**Sees.** The scoped timeline, attacker path, 150 findings.

**Caps.** 150 findings

**Costs.** 1, using the synthesis model.

!!! warning "Know this"
    Findings are passed without ids, so the summary cannot be traced back to specific findings the way a hypothesis review can.

### Remediation plan

**Where.** ✨ Generate remediation plan — you press it.

**Sees.** Up to 100 findings with their techniques, plus the ATT&CK mitigations and D3FEND countermeasures your techniques map to.

**Caps.** 100 findings, 30 mitigations, 40 countermeasures

**Costs.** 1, using the synthesis model.

!!! warning "Know this"
    The mitigations are supplied deterministically — the model builds steps from them and cannot invent one. If a technique is unmapped, the grounding says “none” and the plan turns generic.

### Hypothesis review

**Where.** 🔎 Review — you press it.

**Sees.** Your open, non-exhausted hypotheses, each with its supporting and contradicting event ids, plus the scoped timeline.

**Caps.** answers sanitised against the hypothesis and event ids it was offered

**Costs.** 1, or 0 when nothing is open, using the synthesis model.

!!! warning "Know this"
    Advisory only — it never changes a hypothesis status. And it excludes settled hypotheses, so **it will never tell you one was settled wrongly**.

### Hypothesize gaps

**Where.** ✨ Hypothesize gaps — you press it.

**Sees.** The silent windows a deterministic detector already found, with the events either side, and the catalog of collections it ranks against.

**Caps.** 5 gaps (`DFIR_GAP_HYPOTHESIS_MAX`), 8 events either side

**Costs.** 1 for all gaps, or 0, using the synthesis model.

!!! warning "Know this"
    The recommended collections are deterministic — the model only picks from the catalog. A gap it skips still carries its collections, so an empty answer is not “nothing to collect”.

### Suggest hunts

**Where.** ✨ Suggest hunts — you press it.

**Sees.** The scoped timeline, findings, IOCs, techniques, the causal graph, and the hunt feedback ledger — what previously hit and missed.

**Caps.** 8 suggestions (`DFIR_HUNT_SUGGEST_MAX`)

**Costs.** 1, or 0 with nothing to pivot on, using the velociraptor model.

!!! warning "Know this"
    Any suggestion matching a hunt already deployed in this case is **silently dropped**. You can get fewer than 8, or none, and nothing tells you why.

### Playbook hunts

**Where.** ✨ Suggest Velociraptor hunts — you press it.

**Sees.** Your playbook tasks, the case's observed endpoints, the *real* artifact names from your Velociraptor server, findings, a small timeline sample.

**Caps.** 120 events, 150 artifacts, 30 suggestions

**Costs.** 1 for the whole playbook, using the velociraptor model.

!!! warning "Know this"
    Whether a suggestion deploys to one host or the fleet is decided deterministically from your endpoints, not by the model — and a host it invents is rejected.

### Technique hunt

**Where.** per-technique hunt button — you press it.

**Sees.** No timeline at all — the technique id, your pivotable IOCs, and the hunt feedback.

**Caps.** technique id must be well-formed or it returns nothing

**Costs.** 1, using the velociraptor model.

!!! warning "Know this"
    By definition the technique has *not* been observed in your case. The query is generic detection, not case evidence.

### Query translation

**Where.** Translate — you press it.

**Sees.** Almost nothing about your case: the data sources you have, your pivotable IOCs, and the schema guide. It works on an empty case.

**Caps.** platforms you selected

**Costs.** 1 for all platforms, using the synthesis — deliberately not the hunt model model.

!!! warning "Know this"
    It does not read your timeline. “This host” resolves only through the IOC list handed to it. The hunt-tuned model is avoided here on purpose, because it biases everything toward VQL.

### Memory next steps

**Where.** ✨ Suggest next steps — you press it.

**Sees.** Your in-scope memory-forensics events, worst first, and which plugins you already imported.

**Caps.** 8 suggestions (`DFIR_MEMORY_NEXTSTEP_MAX`)

**Costs.** 1, or 0 without memory evidence, using the synthesis model.

!!! warning "Know this"
    It proposes commands you run yourself, and nothing verifies the plugin exists in your Volatility build.

### Suggest tagger rule

**Where.** ✨ Suggest rule — you press it.

**Sees.** No case data at all — the matchable field list and your plain-English description.

**Caps.** single-event field matches only; it declines anything else

**Costs.** 1, using the synthesis model.

!!! warning "Know this"
    A new rule changes what **future** imports surface, never what past ones did. Your existing evidence is not re-graded.

### Ask AI for similar

**Where.** 🔎 Ask AI for similar — you press it.

**Sees.** The label of the item you are dismissing and a narrowed candidate list of labels. No timeline.

**Caps.** answers validated twice against the candidate list

**Costs.** 1, using the synthesis model.

!!! warning "Know this"
    It sees labels, not evidence. Accepting its suggestions removes those events from **every later AI prompt**.

### Session summary

**Where.** ✨ Summarize session — you press it.

**Sees.** The forensic events of one session, re-derived at the moment you press it.

**Caps.** 600 events then token-fitted

**Costs.** 1, using the synthesis model.

!!! warning "Know this"
    The session is re-segmented at call time, so changing your segmentation settings changes what the same session id covers.


## Passes that are not AI at all

These run with the AI switched off. If you have ever asked why an event has a severity when AI is
off, the answer is the first row.

| Pass | What it does |
|---|---|
| **Content tagger** | A rule set run over the **newly imported** events only, straight after import. It raises severity and adds ATT&CK techniques. **This is why an event has a severity with AI off.** A rule you write next week changes what future imports surface, never what past ones did. |
| **Severity gate** | Splits imports: `Low` and above into the forensic timeline, `Info` into the raw archive only. A row carrying a promotion stamp is exempt whatever its severity, which is why the forensic timeline can hold `Info` rows. |
| **Named demoters** | Lower one narrow class of row to `Info` with a stated reason — a Windows updater talking to a Microsoft edge, for instance. Never lowers High or Critical, never touches a row you promoted. |
| **Burst grouping** | Collapses four or more repeats of the same detection within an hour into one prompt row. Prompt only — your case keeps every row. |
| **Prevalence** | A per-case baseline of command *shapes*. Feeds a rarity bias into what synthesis is shown, and the common/rare tag on a row. |
| **Attack phases** | Groups the timeline into phases by time gap and labels each with its dominant tactic. Pure arithmetic. |
| **High-severity backfill** | Mints findings the model did not: any Critical or High event it left unlinked, Defender episodes, script-block commands, coverage gaps. **A finding can exist with no model involvement at all.** |
| **Refutation gate** | Downgrades a model "refuted" verdict to unknown when the host scope never collected the evidence class being denied. It can only ever weaken a claim. |
| **Screenshot OCR** | Local Tesseract. Makes screenshots searchable, and blacks out entities before an image reaches an external vision model. |

## Masking

Nearly every model call passes one choke point that swaps real hostnames, users, paths and
addresses for tokens before anything leaves the machine, then restores the real values into the
answer.

Three things about that gate are worth knowing. The **system prompt is never masked** — safe for
the shipped prompts, but a custom prompt file holding real case values would go out in the clear.
An **OCR failure forwards the unredacted image** with a warning. And if you turn anonymisation off
for a case, the whole chain is skipped, **including the PII scanner**.

!!! danger "Three paths do not use the gate"
    **Investigate (the MCP agent) is the real bypass.** It reads evidence through MCP servers and
    streams it to the Claude Code CLI. Nothing masks that text, because the Companion never sees
    it. The command allowlist also cannot be enforced in that mode — only the tool list survives.

    **The missed-evidence review masks correctly, by a different route.** No PII scanner on that
    text, and no restore step — which is fine, because a grade is a number.

    **Import extraction skips the PII scanner per batch**, safe only because the whole payload is
    scanned once up front. The skip and the pre-scan are a pair; neither is correct alone.

## The archive boundary

The rule is that the model reads the forensic timeline, and nothing automatic reads the raw
archive. Six paths touch the archive, each under a stated constraint.

| Path | How it stays inside the rule |
|---|---|
| Explain event | Promotes the one event first, then explains from the forensic timeline. |
| Starred report | Promotes the starred rows first, then reports from the forensic timeline. |
| Second look | Analyst-pressed. Deterministic search, promote with provenance, then re-synthesise. |
| View summary | **Exception 1.** Reads the archive directly. Analyst-pressed, ephemeral, capped at 500 rows with the truncation disclosed. |
| Remediation check | **Exception 2.** Reads the archive, but **no model ever sees it**. Persists counts and ids only, never a row's text. |
| Missed evidence review | **Exception 3.** Reads the archive and a model does see it. |

!!! warning "Eviction loses evidence"
    The raw archive is capped and eviction is permanent. It sheds in three tiers, oldest first:
    ordinary rows at any severity go first; rows a named rule deliberately graded `Info` go next,
    bounded so they cannot fill the cap; **rows you starred or tagged are never evicted** and do
    not count against the cap.
