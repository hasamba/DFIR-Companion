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
| **Deep pass** | on demand (dashboard / API / CLI) | many calls — the expensive one | conclusions drawn from *every* graded event |

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

**Where it is.** The **Deep pass** toolbar button, or the *Deep Pass* section between Findings and the Forensic Timeline. Opening it measures the case and shows one row per floor — events, prompt rows, batches and estimated input tokens — and you pick the floor there; nothing is spent until you press *Run deep pass*. While it runs, the current batch is shown next to a *Cancel* button and the Re-synthesize / 2nd-opinion buttons are locked, because a deep pass ends in a synthesis of its own and starting another would overwrite it. The result names the floor, events, rows, batches and observations — and, if any batches failed, says so in red: that run read **less** of the case than the numbers suggest. It survives a page reload.

The same thing from the command line, or over HTTP:

```bash
# In the companion/ folder:
npm run deep-pass -- <caseId>                   # preview only — no AI calls, no spend
npm run deep-pass -- <caseId> --floor Medium    # run it
```

There is also an API: `GET /cases/:id/deep-pass/preview` and `POST /cases/:id/deep-pass` (`{"minSeverity":"Medium"}`). A closed or archived case is refused — reopen or restore it first.

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
| IPv4 addresses (internal — RFC1918, loopback, link-local, CGNAT) | `ANON_IP_1`, `ANON_IP_2`, … |
| IPv4 addresses (public, routable) | `ANON_EXTIP_1`, … — masked on the AI wire; see below for the one place they're kept visible, and the known limitation for what "public" excludes |
| IPv6 addresses (internal, or public within `2000::/3` / IPv4-mapped) | `ANON_IP_n` / `ANON_EXTIP_n` — see the IPv6 note below for what's out of scope |
| Hostnames | `ANON_HOST_1`, … |
| Usernames (`DOMAIN\user`, UPNs on an internal domain) | `ANON_USER_1`, … — **ASCII names only**, see below |
| Email addresses | `ANON_EMAIL_1`, … — **ASCII local parts only**, see below |
| Domain names | `ANON_DOMAIN_1`, … |
| User profile paths (`C:\Users\<name>`, `/home/<name>`) | the username segment becomes `ANON_USER_n`; the rest of the path is left readable |
| Credit card numbers | `ANON_CARD_1`, … |
| Phone numbers | `ANON_PHONE_1`, … |
| National ID numbers (currently: Israeli Teudat Zehut) | `ANON_NATID_1`, … |
| PowerShell encoded commands | the base64 blob becomes `ANON_CMD_1`, …; the verb and flag stay visible as tradecraft signal |
| Windows SIDs | tokenized (well-known SIDs like SYSTEM are preserved) |

**Hashes are deliberately NOT tokenized.** They are IOCs — a hash is what makes a finding actionable for the recipient, and it identifies a file, not a victim. The anonymizer has no generic high-entropy rule for exactly this reason: it would clobber them.

This anonymization is applied transparently. The timeline and findings shown to you use the real values (the mapping is maintained per-case).

!!! warning "Known limitation: the account and email detectors are ASCII-only"
    The `DOMAIN\user` and email patterns match `[A-Za-z0-9._%+-]` — **ASCII characters only**. A name written in any other script is not auto-detected, and this is not only about Hebrew or Cyrillic: **any accented Latin name is affected too**.

    - `mail יוסי@example.co.il` → the domain is tokenized, but the local part `יוסי` is sent as-is.
    - `mail josé@example.co.il` → same; `jose@example.co.il` (unaccented) is tokenized in full.
    - `logon CORP\יוסי` → not detected at all.
    - `logon CORP\josé` → **worse: partially matched.** The pattern stops at the unaccented prefix, so this is sent as `ANON_USER_1é` — a dangling accented character next to the token. Treat a trailing stray character after an `ANON_USER_n` token as this bug, not as model output.

    Two things do work regardless of script: **user profile paths** (`C:\Users\יוסי\…` → `C:\Users\ANON_USER_1\…`), because that pattern matches the name segment by exclusion rather than by an allow-list; and **any value on the case's known-entity or custom-entity lists**, which is matched exactly and is script-independent.

    So the escape hatches are intact and are the supported route for a non-Latin name: enable [Presidio](presidio.md), whose whole purpose is catching names the regex layer misses, and approve the value — or add it directly as a **custom entity** in the Anonymization panel. Unlike the IP gaps below, nothing here silently records the value as "handled": it is never written to the known list by these detectors, so Presidio keeps flagging it on every call until you resolve it.

**Every real, routable IP address is now tokenized before it reaches an external AI provider — public ones included**, which the model previously saw in cleartext. A public address becomes `ANON_EXTIP_n` rather than `ANON_IP_n`, so the model can still reason about it being external without being shown it, and it is restored to the real value in the answer you read, same as any other token. Two narrow, deliberate exceptions are worth knowing about — see below.

!!! note "Known limitation: two narrow, deliberate gaps in IP masking"
    **IPv4:** every address is classified and either internal (`ANON_IP_n`) or a genuinely routable public address (`ANON_EXTIP_n`) — *except* `0.0.0.0/8`, multicast (`224.0.0.0/4`), reserved (`240.0.0.0/4`), and the broadcast address `255.255.255.255`, which are left visible unchanged. These ranges are structurally never adversary infrastructure (nothing is assigned or routable there), so masking them would only obscure a four-part software version string like `1.0.0.0` that happens to match the same pattern — a real, common false-positive source in forensic text.

    **IPv6** is narrower: only the globally-routable `2000::/3` range (where adversary infrastructure and documentation examples like `2001:db8::/32` actually live), IPv4-mapped addresses (`::ffff:x.x.x.x`), and NAT64's well-known prefix `64:ff9b::/96` (judged by the IPv4 it embeds) are treated as maskable public addresses, on top of the usual internal ranges (loopback, unique-local `fc00::/7`, link-local `fe80::/10`). An IPv6 literal that is neither internal nor inside `2000::/3` — i.e. unallocated or reserved space — is left **completely untouched**: not tokenized, not reserved from other detectors, exactly as it appeared in the source text. This is a deliberate trade-off, not a bug: IPv6 addresses are frequently mimicked by ordinary code (`[Convert]::FromBase64String(`, `std::cout`, `WIN11::admin` all look like IPv6 literals to a naive pattern), so masking anything that merely matches the shape would blind every other detector across whatever text it swallowed. In practice this means a routable-but-unallocated or experimental IPv6 address would reach the model unmasked.

    The escape hatch for either gap is the same, and it's different from the usual suppression list (which *un*-masks a value — the opposite of what's needed here): add the specific address as a **custom entity** — category `IP` or `EXTIP` — in the Anonymization panel, which tokenizes it by exact match regardless of what the IP detectors decided.

!!! note "The redacted export keeps public IPs visible — on purpose"
    The **redacted case package** (a ZIP built for sharing outside the tool) does *not* mask public IPs. A report handed to a client or another team is expected to name adversary infrastructure, so that export path tokenizes everything internal (hosts, users, internal IPs, domains, paths) but leaves public addresses as attacker infrastructure that stays actionable for the recipient.

!!! warning "Screenshot redaction is one-way — a public IP seen only in an image will not become an IOC"
    Text sent to the AI can always be un-masked, because the anonymizer keeps the real value behind the token. A screenshot is different: OCR finds sensitive text in the image and paints a black box over it *before the image is uploaded*, and there is no token to restore it from afterward. If a public IP (or any other masked value) appears **only** in a screenshot and nowhere in text evidence, it will be redacted from the image and will never be extracted as an indicator. Make sure anything IOC-worthy also lands in a log, CSV, or other text import.

!!! note "National ID numbers: expect the occasional false positive"
    The Israeli Teudat Zehut check digit rules out roughly 9 in 10 arbitrary nine-digit numbers, but the tenth passes by chance. In a case with no Israeli PII, this will occasionally tokenize an unrelated file offset, sequence number, or ID. Untick the **ID numbers** category for the case, or add the specific value to the anonymization suppression list, if it becomes a nuisance.

Toggle: **Settings → AI → Anonymization**, or the per-case AI control panel. For names — the one category no regular expression can catch — see [Presidio & PII Masking](presidio.md), an optional add-on layer.

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
