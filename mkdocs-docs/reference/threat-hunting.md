# Threat Hunting

## AI-Generated Hunt Suggestions

After synthesis, the dashboard surfaces four types of hunt suggestions:

| Type | What it does |
|------|--------------|
| **Fleet hunt suggestions** | AI-generated VQL queries to hunt fleet-wide for the threats seen in this case, grounded in the causal evidence graph |
| **Playbook hunt suggestions** | VQL queries tied to specific response playbook tasks |
| **Technique-based hunt suggestions** | Hunts for ATT&CK techniques not yet evidenced in the case (from Adversary Hints) |
| **Shadow artifact suggestions** | When the timeline has suspicious gaps, suggests KAPE/Velociraptor artifacts (Prefetch, SRUM, USN Journal, etc.) that might fill them |

Each suggestion card shows the VQL query with a **Deploy hunt** button (requires Velociraptor connection). A **↻ Regenerate** button refreshes the VQL if it won't compile.

---

## Manual VQL Hunts

**Run hunt (all clients):** Enter a VQL query directly. The dashboard launches a fleet hunt via Velociraptor and waits for results. Results auto-import into the case.

---

## Hunting Feedback Loop

The **Hunting Profile** panel tracks every hunt's outcome:

- Was the VQL deployed?
- Did it find anything (rows returned vs. new events added)?
- Has it been re-collected?

This prevents running the same hunt twice and helps you see what's been covered. Already-deployed hunts are excluded from new suggestions.

---

## Query Translator

Write in plain English. Get VQL, KQL, SPL, ES|QL, Sigma, YARA, or Suricata. One-click deploy for VQL.

See [Dashboard Panels → Query Translator](dashboard.md#query-translator) for details.

---

## Timeline-Gap Hypotheses

When the AI detects suspicious silences (log gaps that don't match expected coverage), it hypothesises what might have happened and suggests shadow artifacts to collect. Each suggestion is deployable as a Velociraptor collection.

!!! tip
    Gaps in the timeline around a known attack window are often the most important leads. A silent endpoint during an active attack usually means either lateral movement to a host without monitoring, or log tampering.
