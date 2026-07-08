# Tips for Analysts

Practical advice for getting the most out of DFIR Companion investigations.

---

**Start with structured imports, not just screenshots.**
Screenshots are useful for context and for tools that don't export raw data. But a Chainsaw JSON export or Hayabusa CSV gives the AI much more structured data to work with and produces better findings.

---

**Use the severity floor on noisy imports.**
When importing a large Velociraptor collection or Plaso super-timeline, set the minimum severity to `medium` or `high`. You can always lower it and re-import if you miss something.

---

**Mark false positives immediately.**
Every time you see an event or finding that's clearly benign, mark it as a false positive. It improves synthesis quality and keeps the timeline clean.

---

**Set the scope.**
If your case has background noise from before the attack window, set the investigation scope to the incident timeframe. Synthesis will focus on that window.

---

**Run enrichment before generating the report.**
Enrichment verdicts appear in the report's IOC table. Flagged IOCs also influence finding severity. Enable the enrichment sources you trust and run them before the final synthesis.

---

**Use the Hunting Profile to avoid duplication.**
Before deploying a hunt, check the Hunting Profile panel to see if a similar VQL has already been run (and whether it found anything).

---

**The second opinion is most useful for high-stakes cases.**
If `DFIR_AI_SECOND_OPINION_MODEL` is set to a model from a different provider, the second opinion catches blind spots the primary model misses. Accept individual deltas selectively — don't bulk-accept everything.

---

**Export an encrypted case archive before closing.**
It's a complete, portable record of the case — evidence included — findings, timeline, IOCs, playbook, notes, hypotheses, screenshots, raw imports. Store it with your case documentation.

---

**Use the Query Translator early.**
When you're not sure what VQL to write for a hunt, describe what you're looking for in plain English. It's faster than looking up VQL syntax.

---

**For presentations, filter by severity first.**
Set the severity filter to `high+` before opening Presentation mode. You get a clean executive deck that covers the most important findings and events without the noise of Info/Low items.

---

**The Diagnostics page is your first stop when something breaks.**
Settings → Diagnostics shows the AI error count by type (auth errors = wrong key, billing errors = quota exceeded, rate limit = slow down), the processing queue state, and integration health — without ever showing your API key.

---

!!! info "More help"
    For technical details, see the [`companion/README.md`](https://github.com/hasamba/DFIR-Companion/blob/master/companion/README.md) in the repository.
