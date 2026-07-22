# AI Analysis

## The AI Runs, One by One

DFIR Companion never makes "one big AI call". The work is split into separate runs, each with its own job, its own cost, and its own trigger. Most of them you never have to think about — they fire on their own. Two of them (**2nd opinion**, **deep pass**) you spend money on deliberately, when a case earns it.

| Run | Trigger | Roughly what it costs | What you get |
|-----|---------|-----------------------|--------------|
| **Screenshot OCR** | automatic, on capture | free — runs locally | searchable screenshot text; redaction before upload |
| **Extraction** | automatic, after import | one call per batch of files/screenshots | forensic events (the timeline) |
| **Synthesis** | automatic + **AI Re-synthesize** | one call | findings, MITRE, attacker path, questions, next steps |
| **Second look** | automatic, inside synthesis | at most one extra call | raw evidence pulled up; collection leads |
| **Deep reasoning** | 🧠 checkbox, before a run | the same call, plus thinking tokens | the same outputs, reasoned harder |
| **Second opinion** | **2nd opinion** button | up to three calls | a rival model's disagreements, to accept or reject |
| **Deep pass** | on demand (API / CLI) | many calls — the expensive one | conclusions drawn from *every* graded event |

### 1. Screenshot OCR

**Why we need it.** Two reasons, both about text sitting inside pixels. First, a screenshot of a console contains hostnames, usernames and IPs that anonymization cannot tokenize because they are not text — OCR finds them and blacks them out before the image is uploaded to an external vision provider. Second, it makes screenshots searchable.

**What it's good for.** "I know I saw that hash / that error / that hostname on a screenshot somewhere."

**When to use it.** Never manually — it runs by itself, locally (Tesseract), after every capture. Nothing leaves the machine and no AI provider is involved. To backfill an older case: `npm run ocr-index -- <caseId>`.

**Settings.** `DFIR_OCR_SEARCH` (full-text search, on by default; set to `off` to disable), `DFIR_OCR_DEBUG` / `DFIR_OCR_DEBUG_DIR` (log each redaction and dump the redacted copies for inspection). The redaction half only runs when an external provider is configured, and follows your anonymization settings (`DFIR_ANONYMIZE`).

### 2. Extraction — evidence into events

**Why we need it.** Screenshots and log files are not a timeline. Extraction is what turns them into dated **forensic events**: a timestamp, a description, a severity, and structured fields (asset, process, hash, IOC references).

**What it's good for.** Everything downstream. Nothing else in the tool works without a timeline.

**When to use it.** Automatic — after each import, and once enough new screenshots have accumulated. Screenshots need a **vision** model; CSV and log triage are text-only and run on the synthesis model.

**Settings.** `DFIR_VISION_PROVIDER` / `DFIR_VISION_MODEL` / `DFIR_VISION_KEY` / `DFIR_VISION_BASE_URL` (screenshots), `DFIR_AI_SYNTH_*` (CSV and log triage), `DFIR_AI_TIMEOUT_MS`, `DFIR_AI_MAX_TOKENS`, `DFIR_AI_CONTEXT_TOKENS`, and `DFIR_AI_SYSTEM_PROMPT_FILE` / `DFIR_AI_CSV_PROMPT_FILE` / `DFIR_AI_LOG_PROMPT_FILE` to override the prompts.

### 3. Synthesis — the normal run

**Why we need it.** Extraction produces rows; nobody draws a conclusion from rows. Synthesis is the one call that reads the whole in-scope forensic timeline at once and says what actually happened.

**What it's good for.** Named **findings**, **MITRE ATT&CK** techniques, the **attacker path**, **kill chain** coverage, **key investigative questions** and **recommended next steps** — i.e. the report.

**When to use it.** It runs on its own after analysis, and you can force it with **AI Re-synthesize** whenever you have added evidence, changed the scope window, or marked false positives.

!!! note "Skip-if-unchanged"
    Synthesis is skipped automatically if nothing in the timeline changed since last time. Click **AI Re-synthesize** → **Force** to override.

**Settings.** `DFIR_AI_SYNTH_PROVIDER` / `DFIR_AI_SYNTH_MODEL` / `DFIR_AI_SYNTH_KEY` / `DFIR_AI_SYNTH_BASE_URL` (a separate, stronger model than the vision one is the recommended setup), `DFIR_AI_SYNTH_MAX_EVENTS` (how many timeline rows fit in the prompt — default 600), `DFIR_SYNTH_INCLUDE_INFO=1` (give Info-severity events prompt space too; off by default), `DFIR_SYNTH_GROUP*` (collapse repeated detection bursts into one row so more of the case fits), `DFIR_AI_SYNTH_PROMPT_FILE`.

### 4. Second look — chasing the questions synthesis just asked

**Why we need it.** Synthesis only ever sees a *sample* of the case: a prompt holds a few hundred rows, while the raw super-timeline can hold hundreds of thousands. The evidence that answers synthesis's own open questions is often in the rows it was never shown.

**What it's good for.** Cases with a large raw super-timeline behind a small forensic timeline — exactly where a quiet recon-or-exfil phase hides.

**When to use it.** Nothing to click. Immediately after every real synthesis, the tool takes that run's own open hypotheses, unanswered key questions, top connecting IOCs and the model's own "I wasn't shown X" requests, turns them into concrete keyword searches, runs them against the raw record, pulls up any matching events (tagged 🔁 in the timeline so you can see why they appeared), and re-synthesizes **exactly once** so the conclusions include them. When a search matches nothing anywhere, that is reported as a **collection lead** — a gap in what you have collected, not a gap in the analysis.

**Settings.** None — the caps are fixed and deliberately conservative (one extra AI call, never a loop). It only has something to search if the case has a super-timeline.

### 5. Deep reasoning — the 🧠 checkbox

**Why we need it.** On a multi-hop case, the difference between a shallow finding and a correct one is the model being allowed to think before it writes. Deep reasoning gives the synthesis model an extended thinking budget (Chain-of-Thought).

**What it's good for.** Complex, multi-host, multi-stage cases; findings that look thin or that miss the link between two hosts.

**When to use it.** Tick 🧠 in the toolbar *before* clicking **AI Re-synthesize** or **2nd opinion** — it applies to the next run on this case only, no `.env` edit and no restart. It is slower and costs extra output tokens, so leave it off for routine re-syntheses. It needs a reasoning-capable synthesis model (e.g. Anthropic or OpenRouter).

**Settings.** `DFIR_AI_SYNTH_THINKING_TOKENS` — the global default budget for *every* synthesis (unset = off). The checkbox is the per-run override; when you tick it without setting the variable, it uses 8000 thinking tokens.

### 6. Second opinion — a rival model

**Why we need it.** A model's mistakes are systematic, not random: re-running the same model gives you the same blind spot twice. A different model, ideally from a different vendor, disagrees in useful places.

**What it's good for.** Quality assurance before you commit to a report, and any finding you would be uncomfortable defending to a client.

**When to use it.** Click **2nd opinion** when the case is essentially done. It runs up to three calls: it first refreshes the primary synthesis if the timeline moved (so you compare two *current* views, not a stale one against a fresh one), then re-analyzes the case with the second model **without writing anything**, then diffs the two and annotates each disagreement with a rationale and a recommendation. See [Second AI Opinion](#second-ai-opinion) below for the accept/reject workflow.

**Settings.** `DFIR_AI_SECOND_OPINION_MODEL` — required; the button stays hidden until it is set. Prefer a model from a **different provider**. `DFIR_AI_RECONCILE_PROMPT_FILE` overrides the comparison prompt.

### 7. Deep pass — read everything

**Why we need it.** Prompt size is finite and row count grows with the number of hosts. Measured on real engagements, a 12-host case needs about 5 prompts' worth of rows and a 14-host case about 13 — so on a big case, normal synthesis reads a fraction of the graded evidence and never knows what it missed.

**What it's good for.** Large, multi-host cases; a case where an entire host or an entire attack phase is suspiciously absent from the findings; the moment before a final report on a big engagement.

**When to use it.** On demand, when the synthesis coverage line tells you events were left out — and knowingly, because it is the expensive run. Always preview first: the preview makes no AI calls and reports, for your actual case, how many events, rows, batches and tokens each severity floor would cost, so you pick the floor against real numbers rather than guessing.

Batches only ever report **observations** — what happened, on which host, when, and which event ids it rests on; they are forbidden from issuing verdicts, precisely so thirteen batches cannot invent thirteen conflicting attack stories. Exactly one final synthesis call draws every conclusion. The run is cancellable between batches, and nothing is written until that final call succeeds — an aborted run leaves the case untouched.

```bash
# In the companion/ folder:
npm run deep-pass -- <caseId>                   # preview only — no AI calls, no spend
npm run deep-pass -- <caseId> --floor Medium    # run it
```

There is also an API: `GET /cases/:id/deep-pass/preview` and `POST /cases/:id/deep-pass` (`{"minSeverity":"Medium"}`).

**Settings.** `DFIR_DEEP_PASS_MAX_BATCHES` (default 30 — a run needing more is refused *before* spending anything, and the error names a floor that would fit), `DFIR_AI_SYNTH_MAX_EVENTS` (rows per batch), `DFIR_AI_OBSERVE_PROMPT_FILE` (the batch prompt). Info-severity events are never included.

---

## AI Providers

DFIR Companion supports multiple AI backends:

| Provider | Setting |
|----------|---------|
| **OpenAI** | `DFIR_VISION_PROVIDER=openai` |
| **Anthropic (Claude)** | `DFIR_VISION_PROVIDER=openai` with `DFIR_VISION_BASE_URL=https://api.anthropic.com/v1` |
| **OpenRouter** | `DFIR_VISION_PROVIDER=openrouter` |
| **Google Gemini** | `DFIR_VISION_PROVIDER=gemini` |
| **Ollama** (local) | `DFIR_VISION_PROVIDER=ollama`, `DFIR_VISION_BASE_URL=http://localhost:11434/v1` |
| **LiteLLM** (local proxy) | `DFIR_VISION_PROVIDER=litellm` |

Configure via the Setup Wizard or in `.env`. All AI calls are made server-side — API keys never go to the browser. (The screenshot/vision vars were renamed from `DFIR_AI_*` to `DFIR_VISION_*`; the legacy `DFIR_AI_*` names still work as a deprecated fallback.)

!!! tip "Using a local model?"
    Only screenshot reading needs a **multimodal** (vision) model — that's `DFIR_VISION_MODEL`. Everything else (CSV/log import, synthesis, and all other text-only AI features) runs on `DFIR_AI_SYNTH_MODEL`, so a text-only model is fine there. Use the two-tier setup (`DFIR_VISION_MODEL` = cheap vision for screenshots, `DFIR_AI_SYNTH_MODEL` = strong reasoning for everything else) — a weak text model fails log triage silently, returning no events at all rather than wrong ones.

---

## What the AI Sees — Anonymization

By default, the Companion **tokenizes identifying information** before sending anything to an external AI provider:

| Data type | Becomes |
|-----------|---------|
| IP addresses | `ANON_IP_1`, `ANON_IP_2`, … |
| Hostnames | `ANON_HOST_1`, … |
| Usernames | `ANON_USER_1`, … |
| Domain names | `ANON_DOMAIN_1`, … |
| File paths | `ANON_PATH_1`, … |
| Hashes | `ANON_HASH_1`, … |
| PowerShell encoded commands | decoded, then the decoded blob is anonymized |
| Windows SIDs | tokenized (well-known SIDs like SYSTEM are preserved) |

This anonymization is applied transparently. The timeline and findings shown to you use the real values (the mapping is maintained per-case).

Toggle: **Settings → AI → Anonymization**, or the per-case AI control panel.

---

## AI Controls (Per Case)

The AI control panel lets you:

- Enable/disable AI analysis for this case
- Enable/disable synthesis
- Enable/disable enrichment
- Toggle the **🧠 Deep** checkbox — enables Chain-of-Thought (extended thinking) for synthesis, giving the model more reasoning budget for complex cases

---

## Second AI Opinion

Click **2nd Opinion** in the toolbar (requires `DFIR_AI_SECOND_OPINION_MODEL` to be configured). A different model re-synthesizes the case independently. The dashboard shows where the two models disagree:

- Added findings (model B found something model A missed)
- Removed findings (model B did not confirm something model A concluded)
- Severity differences
- MITRE technique additions/removals

For each delta you can **Accept** (adopt the second model's view) or **Keep A** (keep the original). Accepted deltas survive future re-syntheses.

!!! tip
    Use a model from a **different provider** for the second opinion. Same-provider models share training blind spots — cross-provider disagreements are the most informative.

---

## Custom AI Prompts

All AI prompts can be overridden without code changes:

1. Run `npm run prompts:eject -- ./prompts` to dump the built-in prompts to files.
2. Edit the files.
3. Set `DFIR_AI_SYSTEM_PROMPT_FILE=./prompts/system.txt` (etc.) in `.env`.
4. Changes are picked up on the next AI call — no restart needed.

Available prompts: `SYSTEM` (extraction), `CSV`, `LOG`, `SYNTH` (synthesis), `ASK`, `EXEC` (executive summary), `NARRATIVE`, `HUNTS`, `PBHUNTS`, `GAPHYP`, `MEMNEXT`, `QUERYXLATE`, `RECONCILE`, `REMEDIATION`.
