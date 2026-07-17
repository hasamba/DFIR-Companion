# AI Analysis

## Two-Phase Design

The AI pipeline has two distinct passes that are intentionally kept separate:

### Phase 1 — Extraction (per-batch)

A vision-capable model reads each batch of screenshots and structured files. It extracts raw **forensic events** — dated rows with a timestamp, description, severity, and optional structured fields (asset, process, hash, IOC references). This pass runs automatically after import and after enough new screenshots accumulate.

### Phase 2 — Synthesis (holistic)

One text-only call reads the entire forensic timeline. It produces:

- Named **findings** (conclusions)
- **MITRE ATT&CK** technique assignments
- **Attacker path** narrative
- **Kill chain** phase coverage
- **Key investigative questions**
- **Recommended next steps**

!!! note "Skip-if-unchanged"
    Synthesis is skipped automatically if nothing in the timeline changed since last time. Click **AI Re-synthesize** → **Force** to override.

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
