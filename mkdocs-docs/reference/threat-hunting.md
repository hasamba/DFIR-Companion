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

## Sigma Rule → Fleet Hunt

**Paste a Sigma rule, compile it, launch it.** The hunt-query modal (the 🔍 button on a finding or a
detected value) carries a **Sigma rule → Velociraptor hunt** card. Paste a rule and press
**Compile**. The Companion turns it into VQL deterministically — no AI is involved, and the same
rule always gives the same VQL — and shows it in an editable box with the usual **▶ Run hunt (all
clients)** button. The hunt is recorded in the Hunting Profile like any other fleet hunt.

Two shortcuts feed the same card: the **Compile to VQL** chip beside a finding's **Export as Sigma
draft** action, and the **Compile to VQL** button on the Query Translator's Sigma card.

**What compiles.** One fixed template per `logsource.category`. The compiled VQL opens with a
header that says which one it is:

| Sigma category | Runs on the endpoint as | Covers |
|---|---|---|
| `process_creation` | `pslist()` | running processes only, not process history |
| `network_connection` | `netstat()` | open connections only, not connection history |
| `file_event` | `glob()` | files on disk now, under roots taken from the rule |
| `registry_set` / `registry_event` / `registry_add` / `registry_delete` | `glob(accessor="registry")` | keys and values as they are now; the key must be rooted in a hive |

**What is refused.** Any other category, any field the template has no column for (for example
`DestinationHostname` — `netstat()` has no hostname column), the modifiers `base64`, `windash`,
`fieldref` and the like, aggregations, `near` and `timeframe`. A refusal lists every problem in
the rule, one line each, with the YAML path. Nothing half-translated is ever offered to run.

The card appears when Velociraptor is an enabled hunt platform (`DFIR_HUNT_PLATFORMS`). Compile
works before the Velociraptor API is configured; only **Run** needs it.

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
