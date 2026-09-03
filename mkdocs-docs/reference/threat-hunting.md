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
| `process_creation` | `pslist()` **and** `parse_evtx()` over Sysmon event 1, or Security 4688 where Sysmon is absent — two sources in one hunt | running processes now, plus process history as far back as the endpoint's event logs go |
| `network_connection` | `netstat()` | open connections only, not connection history |
| `file_event` | `glob()` | files on disk now, under roots taken from the rule |
| `registry_set` / `registry_event` / `registry_add` / `registry_delete` | `glob(accessor="registry")` | keys and values as they are now; the key must be rooted in a hive |

**What is refused.** Any other category, any field the template has no column for (for example
`DestinationHostname` — `netstat()` has no hostname column), the modifiers `base64`, `windash`,
`fieldref` and the like, aggregations, `near` and `timeframe`. A refusal lists every problem in
the rule, one line each, with the YAML path. A selection with no fields, a `1 of them` over no
selection, and a `contains` / `endswith` path rooted on a drive or a host (`D:\tools\x.log`,
which a search under `C:` could never find) are refused too. Nothing half-translated is ever
offered to run.

**A selection the condition never names stays out of the hunt.** Only the selections the
`condition` reaches contribute their path roots and lookup stages: an unused `contains` block
cannot turn a prefix hunt into a whole-disk walk, and an unused `ParentImage` block adds no
parent lookup. The block is still parsed and compiled: one that some template could answer (a
file block under a process rule) is simply left out, and the VQL header says so
(`-- Not in the condition, so not in this hunt: …`); one that no template can answer is a broken
block and refuses like any other.

**A rule that spans categories becomes one hunt with several sources.** A finding's **Export as
Sigma draft** writes a `process_creation` rule that also carries a network block and a file block
under `condition: 1 of sel_*`. When the condition is a top-level `1 of …` or `or` of whole
selections, each block compiles against the template that owns its fields — the IP block on
`netstat()`, the path block on `glob()` — and the hunt runs them as separate sources. A block moves
to another category only on a field that category owns (`DestinationIp`, `TargetFilename`,
`TargetObject`…), never on `Image`, `User` or `ProcessId` alone, because every Sigma event names
the process behind it and a bare `Image` under a `file_event` rule is still a file question. A
`not` or an `and` across blocks keeps the one-template rule, and a block no template can answer
(`DestinationHostname`) refuses by itself, with the fix, while the others are left out of the
refusal because they would have compiled.

Every template's VQL has been launched as a real hunt against a Velociraptor 0.77.2 server with a
Windows 11 client, and the rows it returned are pinned in the test suite. To re-prove them after a
template change, point `DFIR_VELOCIRAPTOR_API_CONFIG` and `DFIR_VELOCIRAPTOR_BINARY` at a server
with an enrolled Windows client and run `npm run sigma:live-fixture` from `companion/`.

The card appears when Velociraptor is an enabled hunt platform (`DFIR_HUNT_PLATFORMS`). Compile
works before the Velociraptor API is configured; only **Run** needs it.

**A live-only rule is a snapshot, and the Hunting Profile knows it.** The network, file and
registry templates read the endpoint as it is now, so a connection that closed or a file that was
deleted before the hunt ran will not be there. An empty result from such a rule is therefore shown
as **empty snapshot**, not as *no evidence*: it does not count as a miss, it does not lower a pivot
class's hit rate, and it never counts toward exhausting a hypothesis.

**A `process_creation` rule reads history, so its empty result is a real miss.** Its second source
parses the endpoint's own event log — Sysmon event 1 where the Sysmon log exists, otherwise Security
4688 — so a process that started and exited weeks ago still matches, with the Sysmon fields Sigma
rules are written against (`Image`, `CommandLine`, `ParentImage`, `ParentCommandLine`, `User`,
`Hashes` as the `SHA256=…,MD5=…` string, `OriginalFileName`, `IntegrityLevel`, `CurrentDirectory`).
The branch is chosen on the client by whether the Sysmon log yields an event 1, not by whether the
file exists, so a leftover log after Sysmon was removed does not hide the Security history. A 4688
row carries no hashes, parent command line or PE metadata, and its command line only when
command-line auditing is on. An endpoint with neither log contributes nothing to that source, so on
such a fleet an empty result still reads as a miss; keep Sysmon or 4688 auditing on where this
matters.

Two cases keep the snapshot protection even for `process_creation`. A rule that uses a field only
Sysmon records (`Hashes`, `sha256`, `md5`, `sha1`, `imphash`, `ParentCommandLine`,
`OriginalFileName`, `IntegrityLevel`, `CurrentDirectory`, `Description`, `Product`, `Company`)
runs the history source on the Sysmon branch alone, says so in its coverage line, and stays a
snapshot: a 4688-only endpoint cannot evaluate it, so its empty result is not negative evidence. And
a draft that spans categories stays a snapshot as long as any of its blocks (a network or file
block) has no history source. A field only the event log has compiles to the history source alone.
A regex (`|re`) on `sha256`, `md5`, `sha1` or `imphash` is refused for the event source, because the
`ALG=` tag in front of it would break the regex's own anchors; the live `pslist()` source still
takes it. Only rules for `product: windows` (or with no product) compile; every template is a
Windows plugin.

An AI-suggested hunt (the Velociraptor hunt suggestions and a playbook task's hunt) can have the
same character — a `pslist()` query observes the process list as it is now — but the Companion
cannot tell from arbitrary VQL what it observes, so it does not guess. Each suggestion card carries
a **live snapshot (empty ≠ miss)** checkbox beside Deploy. It is ticked by default only when every
`FROM` in the VQL is one of the live-state plugins (`pslist`, `netstat`, `glob`, `stat`, `hash`,
`read_file`, `yara`, `reg_keys`, `read_reg_key`); a `parse_evtx()`, an `Artifact.<Name>()` or a
`foreach()` wrapper leaves it unticked. The analyst's choice is what the deploy records: ticked,
the hunt is a snapshot and is never linked to an armed **🎯 test via hunt** hypothesis; unticked,
an empty result is a miss as before.

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
