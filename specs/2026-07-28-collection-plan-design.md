# Collection plan — incident-type guided evidence collection (#347)

**Status:** design, awaiting review
**Issue:** #347 (follow-up to #236 / PR #289)
**Date:** 2026-07-28

---

## 1. Problem

Every incident type shipped in #236 carries three fields the product never reads:
`recommendedImportOrder`, `huntBundles`, and `reportFraming`. #347 asked for all three to be
given a surface.

Investigation found their identifiers are almost entirely fictional — they were authored
alongside the type definitions and never reconciled with the tool:

| Field | Names used | Exists |
|---|---|---|
| `huntBundles` | 27 bundle ids | 3 bundles ship (`best-practice`, `super-timeline-triage`, `linux-triage`). **Zero match.** |
| `reportFraming.template` | 8 template ids | 3 templates ship (`standard`, `executive-brief`, `technical-detailed`). **Zero match.** |
| `recommendedImportOrder` | 14 evidence types | ~6 map to real importers; the rest name evidence the tool has no distinct notion of. |

Pre-selecting hunt bundles is meaningless when only three exist and none are incident-specific.
Report framing would mean mapping eight names onto three real templates — so nearly every incident
type resolves to "Executive brief" — or authoring five new report templates, a far larger job than
#347 implies.

**Decision:** build the collection order only. Remove `huntBundles` and `reportFraming` from the
type definitions in the same change, so no dead fields remain. Re-file them if and when the
underlying bundles and templates exist.

---

## 2. Scope

**In**

- A *Collection plan* dashboard panel: the incident type's ordered evidence steps, each showing
  as collected or outstanding, derived from the evidence already in the case.
- Analyst overrides per step (force collected / not applicable) that persist with the case.
- Rewriting all eight shipped types' collection plans in an evidence vocabulary grounded in the
  tool's real source labels.
- Deleting `huntBundles` and `reportFraming` from the schema, the definitions, and the API
  response.

**Out**

- Per-case editing or reordering of steps. To change a plan, edit the type's JSON.
- New importers. A step naming evidence the tool cannot ingest is handled (§5.3), not fixed.
- Hunt bundles and report framing (see §1).
- Auto-detecting the incident type from evidence — still out of scope, as in #236.

---

## 3. Evidence vocabulary

Steps name **evidence, not tools**. An analyst knows they need Windows event logs before they know
which importer produces them, and a tool-named step would sit unticked because they used the other
tool that produces the same evidence.

Each step declares the source labels that satisfy it. Event source labels come from two places,
both of which must be covered or a step under-ticks:

1. **Importer literals** — a fixed label the importer stamps (`MemProcFS`, `Entra ID`,
   `Web Access Log`, …).
2. **`detectTool()`** — CSV, log, and SIEM imports derive the label from the filename, yielding a
   further 32 vendor names (`Splunk`, `SentinelOne`, `Carbon Black`, `KAPE`, …), with the
   fallbacks `CSV import`, `Log import`, `SIEM import`, `Windows Event Log`.

Missing the second source is how the `edr` step would have ticked only for ECAR and Falco while
silently ignoring every Defender, SentinelOne, Carbon Black, and Cortex XDR import. Both sets are
pinned by test (§7).

| Step id | Analyst-facing label | Satisfied by |
|---|---|---|
| `edr` | EDR telemetry | `EDR (ECAR)`, `CrowdStrike Falcon`, `SentinelOne`, `Carbon Black`, `Cortex XDR`, `Microsoft Defender`, `Wazuh`, `Falco` |
| `windows-event-logs` | Windows event logs | `Chainsaw`, `Hayabusa`, `EVTX`, `Sysmon`, `Windows Event Log` |
| `endpoint-triage` | Endpoint triage artifacts | `Velociraptor`, `KAPE`, `Autopsy`, `Cyber Triage`, `MFT`, `UsnJrnl`, `Prefetch`, `Amcache`, `ShimCache`, `LNK`, `JumpLists`, `Shellbags`, `RecycleBin`, `SRUM` |
| `memory` | Memory image | `MemProcFS`, `Volatility`, `Rekall`, `VolWeb` |
| `network` | Network traffic / IDS | `Zeek`, `Suricata`, `Snort`, `Security Onion`, `Cisco ASA`, `Arkime`, `Wireshark` |
| `web-logs` | Web server access logs | `Web Access Log` |
| `m365` | Microsoft 365 / mailbox audit | `Microsoft 365`, `Email` |
| `identity` | Identity sign-in logs | `Entra ID` |
| `cloud-audit` | Cloud control-plane audit | `AWS CloudTrail`, `Azure Activity`, `GCP Audit`, `Kubernetes Audit` |
| `siem` | SIEM / aggregated logs | `SIEM`, `SIEM import`, `Splunk`, `Elastic`, `Microsoft Sentinel`, `QRadar`, `Graylog`, `Syslog`, `journald`, `auditd`, `osquery`, `sysdig` |
| `sandbox` | Malware sandbox report | `CAPEv2`, `Falcon Sandbox` |
| `super-timeline` | Super-timeline | `Plaso`, `Timesketch` |
| `threat-scan` | Threat / YARA scan | `THOR`, `YARA`, `VirusTotal`, `Nessus` |
| `physical-access` | Physical access records | *(none — collected outside the tool, §5.3)* |

`CSV import` and `Log import` are deliberately unmapped: they mean "we could not tell what this
was", so they must not satisfy any step.

A step with no satisfying labels is legitimate: physical badge records matter to an insider case
even though this tool cannot ingest them.

---

## 4. Per-type collection plans

Ordered. This is the IR content and the part most worth a practitioner's review.

| Incident type | Collection plan |
|---|---|
| Ransomware | `edr` → `memory` → `windows-event-logs` → `endpoint-triage` → `network` → `siem` |
| BEC / Email Compromise | `m365` → `identity` → `siem` → `network` |
| Data Exfiltration | `network` → `siem` → `edr` → `cloud-audit` → `m365` → `endpoint-triage` |
| Network Intrusion | `network` → `edr` → `windows-event-logs` → `endpoint-triage` → `siem` |
| Insider Threat | `siem` → `endpoint-triage` → `super-timeline` → `m365` → `cloud-audit` → `physical-access` |
| Cloud Compromise | `cloud-audit` → `identity` → `m365` → `siem` → `edr` |
| Web App Intrusion | `web-logs` → `network` → `edr` → `windows-event-logs` → `siem` |
| Malware Outbreak | `edr` → `memory` → `sandbox` → `windows-event-logs` → `network` → `threat-scan` |

Rationale for the two orderings most likely to be argued:

- **Ransomware puts memory second**, ahead of logs. Memory is the most perishable evidence and is
  destroyed by the isolation and rebuild that follow; logs keep. The type's own next steps already
  say "preserve volatile memory before any remediation".
- **Insider threat leads with SIEM**, not endpoint. The subject is usually still active and the
  first job is preserving centrally-held evidence before access is revoked and the endpoint changes.
  It is also the only plan asking for a super-timeline: insider cases turn on file-access history
  over a long dwell, which is what a Plaso timeline is for.

---

## 5. Behaviour

### 5.1 Panel

A `sec-collection-plan` panel listing the case's steps in order. Each row shows its label, its
state, and — for an outstanding step — what would satisfy it, so "Windows event logs" tells the
analyst that Chainsaw, Hayabusa, or raw EVTX all count.

The next outstanding step is called out as the recommended next collection. That is the whole
point of the feature: the answer to "what do I pull now".

**A case with no incident type does not render the panel.** There is nothing to plan against, and
a generic plan would be guesswork.

### 5.2 State derivation

A step is **collected** when the case's forensic timeline holds at least one event whose `sources`
include any of the step's satisfying labels.

Computed on read from the timeline — no new store, no bookkeeping, no import hook. Importing
something ticks its step on the next load. This is deliberate: `ImportMetaStore` records only the
*last* import, so it cannot answer "what has this case ever received", whereas the timeline can.

The check is on `sources` only. It deliberately does **not** infer from event content: an event
mentioning a mailbox is not evidence that the mailbox audit log was imported.

### 5.3 Steps the tool cannot satisfy

A step with no satisfying labels renders as **collect outside DFIR Companion**. It never
auto-ticks, is never counted as outstanding for the "next step" callout, and never nags. It exists
because the collection still matters to the investigation.

### 5.4 Overrides

Per step, the analyst may set:

- **collected** — "we have this, it just didn't come in through the tool"
- **not-applicable** — "this environment has no EDR"

with an optional short reason. An override always beats the derived state. Clearing it returns the
step to automatic. Overrides persist per case in `state/collection-plan.json`, alongside the
existing incident-type record, and are shown as analyst-set so the derived and asserted states are
never confused.

---

## 6. Structure

New:

- `companion/src/analysis/collectionPlan.ts` — pure. The evidence vocabulary (§3), and
  `buildCollectionPlan(type, events, overrides)` returning the ordered steps with their states. No
  I/O, no AI.
- `companion/src/analysis/collectionPlanStore.ts` — per-case overrides; mirrors
  `IncidentTypeStore`.
- `companion/src/routes/collectionPlan.ts` — `GET /cases/:id/collection-plan` (the built plan),
  `PUT /cases/:id/collection-plan/:stepId` (set an override), `DELETE` the same (clear it).

Changed:

- `companion/data/incident-types/*.json` — `recommendedImportOrder` rewritten to §4's step ids;
  `huntBundles` and `reportFraming` removed.
- `companion/src/analysis/incidentTypes.ts` — drop the two fields from the interface and schema.
- `public/dashboard.html` — the panel.

The New Case picker's preview line currently shows the raw import order. It will show the new
evidence labels, which read better there anyway ("EDR telemetry → Memory image → …").

### 6.1 Panel wiring (CLAUDE.md §8)

Not optional, and the step most often missed:

1. Register `sec-collection-plan` in `DASHBOARD_SECTION_IDS`.
2. Add it to the section-visibility settings editor.
3. Add it to the built-in view profiles — **Triage** and **Hunt-Prep** at minimum; Analyst spreads
   the full list automatically.
4. No report section — the collection plan is working state, not a report finding.

---

## 7. Testing

- **Vocabulary is real** — every source label in §3 is asserted to exist in the importers. A label
  that nothing stamps fails the build. This is the guard against repeating #236's mistake.
- **Every step is satisfiable** — each step in §3 either has ≥1 real satisfying label or is
  explicitly declared collect-outside-the-tool. A step that can never tick fails the build.
- **Every type's plan references defined steps** — a typo'd step id in a JSON file fails the build.
- Derivation: collected / outstanding / mixed timelines; a case with no events; a case with no
  incident type (no plan).
- Overrides: set, clear, override-beats-derived in both directions, persistence across load.
- Routes: the three endpoints, unknown step id, case with no type.
- Removal: the API response no longer carries `huntBundles` or `reportFraming`, and a custom type
  JSON still containing them loads without error (they are ignored, not rejected — an analyst's
  file written against the old shape must not break).

---

## 8. Failure modes

| Risk | Handling |
|---|---|
| A step names evidence nothing produces, so it nags forever | Build-time test (§7) — cannot ship. |
| A source label is renamed in an importer, silently breaking a step | The same test fails on rename. |
| Analyst disagrees with a type's order | Edit the type's JSON; it is analyst-editable data, not code. |
| Timeline is huge, derivation is slow | Single pass collecting distinct `sources`; the timeline is already fully in memory for every other panel. |
| A custom type predates this change | Old fields ignored; a missing `recommendedImportOrder` yields no panel, not an error. |

---

## 9. Open question for review

§4's orderings are my reading of the tradecraft, not yours. The ransomware and insider-threat
orderings in particular encode judgment calls (§4) that a practitioner may want different. The step
*vocabulary* (§3) is constrained by what the tool can see; the *order* is entirely yours to set.
