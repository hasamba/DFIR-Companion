# Dashboard Panels — Reference

All panels are visible by default. Some are collapsed until they have data. Use **Settings → Dashboard Views** to show/hide panels per role or phase.

---

## Now — Decision Cockpit

**Now** is the default dashboard view for a case that has no saved view preference. It answers the
next-decision questions before exposing the full panel inventory:

- the three highest-value active leads, ranked from current findings and open hypotheses;
- evidence that contradicts or weakens the current explanation;
- unresolved questions and uncertainty with the exact evidence or collection action needed next;
- running or failed imports and analyses;
- blockers that prevent the case from being report-ready; and
- a concise digest of findings/imports/synthesis changes since this investigator last marked the
  case reviewed.

Every card opens its owning workspace and, where evidence exists, links to the exact forensic event.
Lead cards can be pinned, dismissed, deferred, or assigned. These actions are kept with the case and
retain their audit history; pinning or assigning a finding also updates the normal Findings panel, so
the two views cannot disagree. **Mark reviewed** records a separate timestamp for each investigator
when a name is configured under Settings.

The existing **Analyst**, **Lead**, **Executive**, **Triage**, **Report**, **Deep-Dive**, and
**Hunt Prep** views remain available from the dashboard-view picker. **Analyst** includes Now above
the full workspace; the focused **Now** view shows only the cockpit.

---

## Summary Bar

The top of the dashboard shows:

- Case name and investigator
- Screenshot count and last capture time
- Last synthesis time and what changed
- Last import time and how many new events/IOCs it added
- A severity summary badge (Critical / High / Medium counts)

**Synthesis coverage audit** — the synth-meta card (next to the last-synthesis time) shows how many in-window events a run actually considered vs. omitted (by prompt-size budget, false-positive filter, or scope window), plus how many budget-omitted events were Critical/High — visibility into what a large-timeline synthesis run left out.

---

## Command Palette

Press **Ctrl+K** (or **⌘K** on macOS) anywhere on the dashboard to open a fuzzy-search overlay over every available action — navigation, exports, settings, and case operations. It stays reachable while an input has focus; the only thing that blocks it is a locked/sealed case.

- Type to fuzzy-match by label or keyword; results rank whole-word and prefix matches above scattered-letter matches.
- Prefix a query with `>` to filter to one category (`>exp csv` filters to Exports, then searches "csv" within it). A bare `>` lists every category.
- Actions you've run recently float to the top of the unfiltered list.
- An action that doesn't apply to the current case (no case loaded, integration not configured, etc.) is hidden rather than shown disabled.

---

## Theme Picker

Click the sun/moon icon beside the **⚙ Settings** button to open the theme menu — over twenty built-in palettes grouped into **Dark**, **Light**, and **Fun**, beyond the plain dark/light toggle. Each entry shows a two-tone swatch before you apply it. The choice is remembered in the browser (`localStorage`) and takes effect instantly, including on canvas-based views (e.g. the timeline swimlane) that bake colours rather than reading CSS variables live.

Every theme — built-in or the vendor-imported palettes (Nord, Gruvbox, Catppuccin, Tokyo Night, Rose Pine, and others) — is generated from one underlying role-based colour system: each UI element maps to a semantic role (e.g. "critical severity text", "hover background") rather than a hardcoded hex value, so a new theme only has to supply values for the roles, not re-derive every colour used across the dashboard.

---

## Findings

Your primary conclusions. Each finding has:

- **Title** — what happened
- **Severity** — Critical / High / Medium / Low / Info
- **Confidence** — a 0–100% badge (color-coded: ≥80% high, ≥50% medium, else low) — the AI's certainty
  this finding is real attacker activity rather than a false positive, weighing evidence strength,
  corroboration from multiple tools, and its own certainty. Hover the badge, or expand the finding's
  evidence details, for the one-line **reason** behind the score. A deterministic auto-flagged finding
  (backfilled from an uncovered Critical/High event — see below) always shows 100%.
- **MITRE techniques** — linked to attack.mitre.org
- **Supporting events** — click to jump to each event in the timeline
- **Supporting IOCs** — the indicators that back this finding
- **Confidence badges** — a finding also shows why it should (or shouldn't) be trusted: **KEV** if independently corroborated by a CISA-KEV actively-exploited CVE, **tool-confirmed** if a tool graded the underlying detection itself, or **unconfirmed lead** if it's supported only by raw Info telemetry with no verdict or threat-intel hit. These are confidence-lowering signals only — never a boost.
- **Possible rabbit hole** — findings disconnected from the case's main corroborated evidence graph (a planted red herring, an unrelated benign event) are demoted and badged instead of ranking alongside real leads.
- **Stale — re-synthesis queued** — marking a finding/IOC/event false positive immediately re-evaluates every key question, next step, and hypothesis that depended on it, badging the affected items instead of waiting for the next synthesis run.
- **🚫 Mark False Positive** — exclude from analysis

Findings sit in a dense table (severity / ID / confidence in real grid columns) with inline icon
buttons for comment/tag/pin/false-positive/hunt/explain/chain-provenance, replacing bracket-style
severity text and raw emoji glyphs. The finding list is sorted worst-first. Click a finding to expand
it — the expansion shows the confidence explanation, supporting IOCs, and a real **cited-event
timeline** (timestamp + description per event, each with its own jump link) instead of a bare
`[1][2][3]` footnote line. The **Min confidence** box above the list hides findings below the chosen
floor (findings with no confidence score always show); the floor is a per-case setting, so it's
remembered the next time you open the case.

Two more checkboxes sit beside it. **Hide auto-flagged** hides the deterministic backfill raised for
any in-scope Critical/High-severity event the AI left unlinked to a finding, so a graded detection is
never silently missed. **Hide coverage-gap** hides the deterministic backfill raised for a window
where every log source went silent — the classic signature of cleared logs or a stopped collector.
Both are lenses, not gates: nothing is deleted, a pinned finding stays in the 📌 strip even while
hidden from the list below, and each is a per-case choice remembered like the confidence floor.
Whenever a filter — either of these included — is actually hiding something, the panel header switches
from a plain count to **(N of M findings)**, so a hidden finding is never silently absent.

**Cited AI answers** — supporting events/findings referenced by a finding, Ask-the-case, Explain Event,
or an AI-suggested hunt appear as numbered, clickable citations — click a citation number to jump
straight to the event or finding it's grounded in. Citations carry through to the exported report.

**Bulk actions** — select multiple findings via their checkboxes (or **Select all**) to Modify Tags or
Mark False Positive on the whole batch at once, the same pattern used by IOCs and timeline events.

**Pinned Findings** — pin key findings (📌 on the finding card) to a sticky strip at the top of this
panel that stays visible while you scroll the rest of the findings list. Drag to reorder, click a
pinned title to jump to that finding, or ✕ to unpin. The pinned list is per-case, persisted
server-side, and travels with the investigation snapshot export. Capped at a small curated shortlist
(`DFIR_MAX_PINNED_FINDINGS`, default 5) to keep it from becoming a second findings list.

---

## Attack Path

A narrative paragraph written by the AI describing the full attacker journey — from initial access through the kill chain to last known activity. Plain English.

---

## Narrative Timeline

Rewrites the Attack Path into client-readable prose for stakeholders, then lets you polish the wording before it lands in a report.

**✨ Generate** — one AI call that produces a prose incident narrative and saves it to case state (it is skipped if the panel is hidden, and refused server-side if the report's Timeline section is disabled in the template). **✏ Edit / Save** hand-edits the generated text; the edit survives until the next synthesis.

---

## Kill Chain

Shows which **Cyber Kill Chain phases** are covered by the evidence: Reconnaissance, Weaponization, Delivery, Exploitation, Installation, Command & Control, Actions on Objectives.

Phases with evidence are highlighted. Gaps may indicate coverage blind spots.

---

## Timeline Gaps

Detects suspicious silent periods in the forensic timeline — windows where events go quiet. A **complete** gap, where every source goes dark at once, is flagged as the classic log-tampering signature. Detection is deterministic; the panel labels it a lead, not proof.

**✨ Hypothesize gaps** — one AI call over the detected gaps. For each silent window it hypothesizes what the attacker likely did (inferred from the surrounding events) and pairs it with shadow-artifact collections that could reconstruct the missing window. Each suggested artifact carries a **▶ Deploy collection** button — enabled only when Velociraptor is configured — that launches the collection to recover the missing evidence.

---

## Evidence Gaps

Uncovered kill-chain phases and unanswered key questions rendered as structured, actionable items rather than a prompt-only text list the model saw but the analyst didn't:

- Each gap carries a deterministic **collect directive** (`host` + `artifact`/`log source`) instead of free prose. When the host is a known case asset, a one-click **"Collect on `<host>`"** button launches the matching Velociraptor artifact directly. A later import that satisfies the request is detected automatically, so the recommendation stops re-appearing and the served question is re-evaluated against the new evidence.
- **Zero-yield import warnings** — a large file routed through AI log/CSV triage that produced zero events (a failure mode that can silently drop an incident's recon/exfil front half) shows here as a "blind spot" row naming the file, alongside a red warning on the import banner, suggesting a re-run or manual grep.

The same one-click collect directive also appears wherever a next step or key question names a host+artifact to collect.

---

## Collection Plan

Shown only for a case with an [incident type](cases.md#incident-types). Lists the evidence that type calls for, in collection order, and marks each one:

| Mark | Meaning |
|---|---|
| ✔ | Collected — the case holds evidence from a matching source |
| ○ | Outstanding; the next one is flagged **collect next** |
| ↗ | Collect outside DFIR Companion — the tool cannot import this (e.g. building access records) |
| — | Marked not applicable by an analyst |

Derived from the evidence already imported, with no AI. A step names *evidence*, not a tool, so "Windows event logs" is satisfied whether it arrived via Chainsaw, Hayabusa, or raw event logs — the row lists what would satisfy it while it is still outstanding.

**Have it** records evidence held outside the tool; **N/A** retires a step this environment can't satisfy (no EDR, no badge system); **Undo** returns a step to automatic. An override always beats the derived state and is remembered with the case.

Distinct from [Evidence Gaps](#evidence-gaps) above: that panel is AI-derived from what the case can't yet answer, this one is a deterministic checklist fixed by the incident type.

---

## Deep Pass

A section (and toolbar button) between **Findings** and the **Forensic Timeline** for an analyst-triggered, batched AI pass that reads **every** graded event at or above a chosen severity floor — full coverage of a large, multi-host case a single synthesis prompt can't show.

A free pre-flight preview reports the events/rows/batches/tokens each severity floor would cost **on this case** before anything is spent. **Run** shows live batch progress with **Cancel**; **Re-synthesize**/**2nd opinion** are locked meanwhile, since a deep pass ends in its own synthesis call. The result card names the floor, events, batches and observations, flags **partial coverage** in red if any batch failed, and survives a page reload; refusals (over the batch ceiling, or a closed/archived case) render as guidance naming a floor that would fit. Gated on the **synthesis** provider, not vision — see [Advanced → Synthesis Grouping & Budget](advanced.md#synthesis-grouping--budget) and [Settings → AI](settings.md#ai) for the tunables (`DFIR_DEEP_PASS_MAX_BATCHES`, `DFIR_AI_OBSERVE_PROMPT_FILE`).

---

## Attacker Sessions

Re-threads the flat forensic timeline into per-host "chapters" — a contiguous run of activity on one host, ending on a long quiet gap (default 5 minutes) or a successful logon under a different account. Deterministic, no AI.

Each session card shows the host, the account established by a logon inside it (when there is one), the dominant ATT&CK tactic across its events, its time span, its row/event count, and its severity range. Click a card to filter the Forensic Timeline below to exactly that session's events. Events whose source tool never reported a host are grouped by time alone under **"(host not recorded)"** — that bucket may span more than one real machine, so it is never rendered as a hostname.

Events sharing a concrete indicator (a hash, path, IP, or decoded-payload IOC) with the running session survive a longer gap before the session splits, so a burst of activity on the same lead doesn't get chopped into unrelated-looking pieces. Tune both thresholds via `DFIR_SESSION_GAP_S` (seconds, default 300) and `DFIR_SESSION_IOC_GRACE` (multiple of the gap, default 3; `1` disables the grace period).

**✨ Summarize session** runs one focused AI call over just that session's events — cheaper and more targeted than a full synthesis or deep-pass run when you only need the story for one chapter.

Has its own report section ("Attacker Sessions") — see [Reports & Exports](reports.md).

---

## Forensic Timeline

The core of the investigation. A table of all forensic events, sorted by timestamp (or severity — click the column header to sort).

Each row shows a compact title line (timestamp, severity badge, description, source tool(s), asset, `NEW` badge if added in the last import); a **[details ▶]** toggle expands the full description, MITRE, related findings, decoded payloads, evidence link, and the raw tool message in one shared panel below the row. Row actions:

- **💡 Explain** button — AI explains this event, gives ATT&CK context, and suggests pivot queries
- **🚫 Mark False Positive** — excludes this event from analysis

### Filters

- **Severity** — Critical / High / Medium / Low / Info
- **Source** — show/hide by tool (e.g. hide all Chainsaw, show only Velociraptor)
- **Origins** — one level more specific than Source: show/hide by the exact artifact that produced the event (e.g. `DetectRaptor.Windows.Detection.MFT`)
- **Date range** — filter by time window (or use the **Scope** bar to set the investigation scope)
- **🔍 Screenshot text** — full-text search across OCR'd screenshots
- **Exclude** — chip-list control next to the toolbar search bar; hides timeline events / IOCs / findings matching any of several exclude terms
- **Corroboration lens** — show only events observed by 2+ or 3+ distinct tools (see below)
- **Pagination** — 100 / 250 / 500 / All rows per page; the Prev/Next bar sits above the event rows

!!! tip
    Drag a time range on the **Timeline Swimlane** (below) to instantly scope the timeline to that window.

### Vim-Style Keyboard Navigation

Toggle in **Settings → General** (default on). With the timeline focused:

| Key | Action |
|-----|--------|
| `j` / `k` | Move the focused-row highlight down / up |
| `f` | Star the focused row |
| `i` | Prefill the manual IOC form from the focused row |
| `p` | Pin the finding cited by the focused row |
| `n` | Open a comment on the focused row |
| `?` | Show the keyboard cheat sheet |

### Event-Density Heatmap

A bar strip above the event rows buckets the **full filtered dataset** (not just the current page) by
time, each bar colored by that bucket's worst severity. Click a bar to zoom the timeline to that
window — a faster way to spot and jump to a burst of activity than paging through hundreds of rows.
Collapses to a thin sparkline on mobile.

### Row Display

**Settings → General → Timeline row display** lets you choose which sub-elements appear on each row (action icons, tag pills, badges, host chip, MITRE, related findings, evidence links). Timestamp and message always show. Per-browser, applies immediately.

---

## Host & Account Ranking

Ranks every host and account by **signal**, not volume: severity-weighted events + ATT&CK techniques + connective IOCs. Chatty-but-benign hosts sink; the entities actually carrying the attack rise to the top.

A one-click **suggested scope** button sets the investigation scope window to cover the top-ranked hosts' activity. The top hosts also feed the synthesis prompt so an automatic run over a noisy multi-host timeline anchors its narrative on the right hosts instead of the loudest one.

Click a ranked row to expand it inline and see the events and IOCs behind that score (capped at 50 each, with a "+N more" note beyond that). Click an event in the expansion to jump straight to it in the Forensic Timeline. Only one row expands at a time.

---

## Host Scope & Clearance

Per-host status derived from the evidence, with analyst-owned clearance on top. Before a host can be
cleared, an eligibility checklist names the evidence class that is still missing, so "cleared" means
"cleared against stated evidence" rather than "nobody looked".

Decisions are append-only and attributed. If new evidence lands on a host that was already cleared,
the panel **flags the host as stale rather than reverting the decision** — the analyst's call stays
on the record and the disagreement becomes visible.

The panel also ranks hosts that are **named in the evidence but never collected**, which is the list
that usually decides where collection goes next. Reports carry an evidence-bounded scoping statement
built from the same data.

---

## Attack Phases

Groups the forensic timeline into temporal **bursts** — clusters of activity separated by periods of silence. Each burst is labeled with the dominant MITRE tactic (Initial Access, Execution, Persistence, etc.).

This shows the *when* axis: not just what happened, but which phase of the attack was most active at what time.

No AI — derived deterministically from the timeline data.

---

## Timeline Swimlane

A visual chart with:

- **Y-axis:** compromised assets (hosts)
- **X-axis:** time
- **Color:** event severity

Useful for spotting lateral movement (events jumping between assets) and attack timing. Drag a time range to scope the timeline to that window. Exports as SVG.

---

## Timeline Anomalies

Detects assets whose event rate spikes in a time bucket, using two baselines (shown in the **Type** column):

- **peer** — the asset is far busier than *other* assets in the same bucket (count ≥ spike-factor × the per-bucket median across assets).
- **self** — the asset is bursting above *its own* typical rate (count ≥ self-factor × the median of that asset's own per-bucket counts). Catches a normally-quiet host (a DC, a file server) that suddenly bursts, even when its absolute volume is low — the peer method can miss those, and importing unrelated telemetry can't mask them.

A burst flagged by both is shown once as `peer + self`. Useful for spotting data exfiltration, log flooding, or initial-access beachheads. No AI — purely statistical.

Configure thresholds via `DFIR_ANOMALY_BUCKET_MINUTES` (default 15), `DFIR_ANOMALY_SPIKE_FACTOR` (peer, default 5), `DFIR_ANOMALY_SELF_FACTOR` (self, defaults to the peer factor), `DFIR_ANOMALY_MIN_EVENTS`.

---

## Beacon Candidates

Outbound network connections that are *too regular to be human* — suggesting automated beaconing (C2 keepalives, malware checking in). Ranked by periodicity. A hunting lead, not a verdict.

---

## MITRE ATT&CK

Shows all ATT&CK techniques identified across findings and events, grouped by tactic. Click a technique to jump to the events that evidence it.

---

## Compromised Assets & IoC Graph

A graph showing:

- **Known compromised assets** (hosts, accounts)
- **IoCs that touched each asset**

Assets are derived from events' `asset` field plus account mentions (DOMAIN\user, UPN). Click an asset to see all events and IOCs linked to it.

You can manually add assets or links using the **+** button.

Shares the same interactive Cytoscape view as the [Login Graph](#login-graph) and [Evidence Chain](#evidence-chain) below (5 layouts, live filter, fullscreen, PNG export), replacing the older bespoke asset layouts.

---

## Login Graph

A Timesketch-style directed graph of **who logged on where** — accounts point to the hosts they authenticated to, built from Windows logon events (4624 success / 4625 failure) in the super-timeline. Because plain low-severity 4624 events never reach the forensic timeline, this is often the only place lateral movement is visible. Edges are aggregated per (account, host, logon type, outcome) with a count, first/last-seen, and a risk flag; click an edge to fetch the underlying events.

Fully deterministic — it re-parses the logon descriptions the importers already rendered, so no AI and no re-import are needed.

- **⟳ Refresh** — rebuilds the graph from the whole super-timeline. It re-parses each row's rendered logon description with an injection guard: a logon marker appearing after the first ` - ` separator is rejected, so attacker-controlled command-line text can't plant a fake account→host edge.
- **Hide machine / system-session accounts** — hides nodes the server tagged as noise (machine `name$` accounts, `DWM-*`/`UMFD-*` session accounts, `ANONYMOUS LOGON`). SYSTEM / LOCAL SERVICE / NETWORK SERVICE are deliberately **not** treated as noise.
- **Show failed logons (4625)** — reveals failed-logon edges (drawn dashed).

Edges turn orange for **medium risk** when a backing logon looks risky — external-source RDP, cleartext authentication, or `runas /netonly`.

---

## Evidence Chain

A causal graph showing:

- **Process trees** (parent → child process spawns)
- **File lineage** (file written then executed)
- **Lateral movement** (shared hashes or accounts across hosts)
- **Network flows** (host → IP connections)

This is the "how did we get here" graph — tracing the attack path through actual artifact relationships, not just the AI narrative. No AI — derived from structured event fields.

Shares the same interactive Cytoscape view as the [Login Graph](#login-graph) and [Assets & IoC Graph](#compromised-assets--ioc-graph) above (5 layouts, live filter, fullscreen, PNG export), replacing the old static SVG rendering; its typed, colored, directional edges are preserved on top.

Filters: severity floor.

---

## IOCs (Indicators of Compromise)

Type and value sit in real grid columns, with inline icon buttons for the shared
comment/tag/pin/false-positive/hunt/explain/chain-provenance controls (same pattern as Findings,
above). Every indicator extracted from all evidence:

- IP addresses
- Domains
- URLs
- File hashes (MD5, SHA-1, SHA-256)
- File paths
- Process names

**Filters:** by type (ip/domain/url/hash/file/process/other), by flagged-only, text search, corroboration lens (see below), a **risk score** filter lens (see below), plus three composable noise-reduction toggles (default on, per-browser): **Hide FP/no-intel** (drops IOCs marked false-positive or with no enrichment result), **Hide OS system paths** (drops `file` IOCs under well-known system-binary directories), and **🎯 Signal only** (narrows to flagged, corroborated, or enriched IOCs).

**Composite risk score** — every indicator gets one `critical` / `high` / `medium` / `low` / `benign` tier from a transparent weighted rubric (verdict, corroborating source count, CISA-KEV, an own-infrastructure guard, NSRL/whitelist status), shown as a colour-keyed badge, a risk filter lens, and a Risk column in the CSV/markdown reports.

**Indicator vs. observation** — a value that earned a signal (a Medium+ risk tier, or a reputation verdict) is a threat *indicator*; a bare file path or hash scraped from evidence with no signal is an *observation*. Both stay in the list, but the IOC count badge breaks out observations separately (e.g. "1,204 IOCs · 3 flagged · 980 observations") so the panel header doesn't read as 1,204 things worth chasing when most are untriaged file-system noise.

**Pagination** — the IOC list pages client-side like the timelines (default 100 per page, selectable 50/100/250/500/All) with Prev/Next controls and a "page X of Y" badge, so cases with thousands of IOCs stay responsive. Filters and imports reset to the first page; select-all is page-scoped while selections persist across pages.

**IOC exclude list** — the panel's title bar has a control to permanently remove matching indicators
from this case: exact-value, suffix, or regex rules, scopable to a specific IOC type (e.g. only
domains). Matching IOCs are purged immediately and never re-imported or re-enriched afterward — unlike
the corroboration lens or noise-reduction toggles above, this doesn't just hide items, it deletes them
from the case.

Each IOC shows:

- **Verdict badge** — reputation from enrichment providers (malicious / suspicious / clean / unknown)
- **Source badge** — how many tools corroborated this indicator (e.g. ⊕ 3 sources)
- **🔗 Provenance chain** — opens a panel showing the full timestamped chain for this indicator:
  extraction event(s), enrichment lookups, and the findings that cite it, with a JSON export. For the
  Security Onion, combined-log, network, and Velociraptor importers, each IOC is tagged with the exact
  source-event row that produced it, so the chain shows **"linked"** (authoritative, traced to a real
  event) rather than **"approximate"** (inferred). AI-synthesis output cannot forge a "linked" tag.
  A linked event can still stand for many records: the timeline collapses repeats of the same shape
  into one row and shows the first one's text, and long records are cut short before storage. Each
  extraction row therefore says **"1 of N merged records"** when it is a group, and warns
  **"value not in this event's stored text"** when the indicator appears nowhere in the record as
  stored — open the source artifact for the exact row. Network addresses are exempt from the
  collapse, so two connections to different destinations stay two events.
- **🚫 Mark False Positive** — known-good, excludes from analysis
- Click to run enrichment on demand

**Inline quick-actions** — any detected value (IP/hash/domain/SID/URL/path) inside an event row or an
IOC value is itself clickable, opening a tray to copy it, mark it benign, mark it confirmed-malicious,
or suggest a hunt — without leaving the timeline to find the IOC's own row. Outcomes are recorded to
the investigation log.

---

## Related Cases

The other investigations on this server that share an indicator with this case, strongest overlap
first. One campaign is often split across several cases — the same C2 domain in last month's
phishing case and in today's ransomware case — and every other panel stops at the case boundary.
Each row names the case, links straight to it, and lists what the two have in common. Fully
deterministic; no AI, no network.

The panel stays hidden until this case actually overlaps with another one you may read. It
refreshes when you connect to a case, and again whenever an import settles — so a newly imported
domain that another case already holds surfaces the link straight away.

**Read a row as a lead, not a conclusion.** Two cases in one estate share a DNS resolver and a
domain controller; that is not a shared adversary. The ranking says so numerically: an indicator
carrying a threat-intel verdict counts for more than one without, a file hash counts for more than
a domain or an address, and a private address inside the estate counts for a quarter of an
external one.
Chips marked ⚠ carry a malicious or suspicious verdict; dimmed chips are internal addresses.

Only IPs, domains, URLs and hashes are compared. Process names, file paths and SIDs are deliberately
left out — `powershell.exe` and `S-1-5-18` appear in nearly every Windows investigation, so
including them would link every case to every other one and bury the single domain that matters.

**What you can see is what your account can already read.** In team mode the panel reports only
cases you hold a role on — a reader on case A learns nothing about case B. A password-protected case
contributes nothing until you have unlocked it in the same browser session, whichever case you are
looking at.

Two routes back it, scoped the same way:

- `GET /cases/<id>/related` — the panel's own data.
- `GET /global/iocs?q=<value>` — search one indicator across every case you may read. Optional
  `type=ip,domain,url,hash`, `minCases=<n>` (only values held by at least N cases), `limit=<n>`.

---

## Corroboration Filter (Lens)

**Forensic Timeline**, **IOCs**, and **Findings** each have an independent corroboration lens in their title bar: show only items observed by **2+** or **3+** distinct tools, cutting single-source noise (internet scanners, benign per-tool telemetry) so the multi-source attack path stands out.

It's a **lens, not a gate** — nothing is dropped from state. Single-source evidence (a Sysmon-only process, a syslog-only logon) still shows at the default "any" setting. Each section's choice is remembered independently.

**Findings has two more lenses of its own** — Hide auto-flagged and Hide coverage-gap, next to the Min confidence box (see Findings, above) — that filter by *origin* (AI-concluded vs. deterministic backfill) rather than by corroboration count. Same contract as this one: hidden, not deleted, per-case and remembered, and folded into the same **N of M** header count.

On the timeline, the lens composes with the **Source** filter: it counts only distinct sources still checked, and while active the Source menu lists only the tools present on corroborated events.

**Source trust** — every event source also carries a trust weight (CrowdStrike/Defender detections > Sigma-engine hits > raw Velociraptor artifacts > generic logs), used to pick the canonical wording when correlating duplicate detections and to cap confidence on findings supported only by low-trust sources. Override a source's trust for the case in Settings, or in the dedicated **Source Trust** panel below.

---

## Source Trust

Lists every known evidence source (tool) with its built-in default trust weight (0–1) and a per-case override you can type — for example, lowering a hunt that was noisy on this engagement. **Save trust overrides** persists the per-case map; changes take effect on the next synthesis.

Default tiers: EDR (CrowdStrike / Defender) = 1.0; Sigma engines (Hayabusa / Chainsaw / THOR) = 0.95; DFIR collectors (Velociraptor / Sysmon) = 0.85; SIEM / network sensors ≈ 0.8; intel / screenshots ≈ 0.75; generic log / CSV = 0.6; unknown = 0.7. An event's trust is the **maximum** across its sources, so one high-trust corroborator lifts the whole event. Trust picks the canonical wording when duplicates are merged, and only ever **caps confidence downward** on findings supported solely by low-trust sources — it never boosts.

---

## Recommended Mitigations & Defensive Countermeasures

Two-part panel, fully AI-free and offline:

**ATT&CK Mitigations (M-codes):** Concrete MITRE-recommended mitigations for the case's techniques, ranked by how many techniques each mitigation addresses. Start with the highest-leverage mitigation.

**D3FEND Defensive Countermeasures:** MITRE D3FEND countermeasures grouped into two bands:

- *Harden now* — Prevent, Detect, Contain actions
- *This incident & context* — Evict, Restore, Model, Deceive actions

**✨ Generate remediation plan** button — one AI call produces an incident-specific, prioritized plan (Contain / Eradicate / Harden / Recover / Verify) grounded in the actual findings, ATT&CK mitigations, and D3FEND countermeasures. References real hosts, CVEs, and IOCs from your case.

---

## Adversary Hints

Compares the case's ATT&CK techniques against the MITRE ATT&CK Groups database to find groups with the highest technique overlap. Shows:

- Group name, aliases, and description
- How many techniques overlap (and which ones)
- **Likely next techniques** — techniques that matched groups use that haven't appeared in this case yet, ranked by how distinctive they are to those groups

!!! warning "This is a hypothesis, not attribution"
    Use it to guide hunting — if a matched group tends to pivot via RDP, that's worth looking for. Never use this as attribution evidence.

Offline, no AI, no network calls at runtime.

---

## Playbook Match

Adversary Hints (above) answers "which techniques does this case share with a known group". This answers the harder question: did they happen **in the order** a published playbook describes.

Compares the case's chronological ATT&CK technique sequence against a bundled catalog of ransomware/intrusion chains distilled from MITRE ATT&CK and CISA #StopRansomware advisories — Conti, LockBit, BlackCat (ALPHV), Akira, Scattered Spider, Black Basta, BlackSuit (Royal), and Play. Matching is a **fuzzy subsequence** match: a playbook step counts as satisfied if its technique appears anywhere later in the case's timeline, allowing unrelated activity in between — a real attacker's timeline is noisy and incomplete. Deterministic, offline, no AI.

Each playbook is matched both **case-wide** and against **each known host's own slice** of the timeline, keeping whichever scope scores higher — ransomware chains are typically cross-host (lateral movement, then fleet-wide encryption), so per-host-only matching would miss the chains the feature exists to find. Events with no recorded host are excluded from per-host scoring (they could span several machines) but still count case-wide.

Each step in a matched playbook shows one of:

- ✅ **matched** — observed in order; jumps to the evidencing timeline event. A step matched only at the *base* technique (a different sub-technique of the same base) is marked accordingly and scores partial credit.
- 🟡 **out of order** — the technique appears in the case, just not at a point that keeps the chain together; check host clock skew and collection lag before reading anything into it.
- ❌ **not observed** — never evidenced, either because it didn't happen or because the evidence wasn't collected. Missing steps become [Evidence Gaps](#evidence-gaps) items with a collection directive.

Tune the result list with `DFIR_PLAYBOOK_TOP_N` (how many ranked matches to return, default 5) and `DFIR_PLAYBOOK_MIN_SCORE` (minimum score to be shown at all, default 40); both can also be overridden per request.

!!! warning "Matches the playbook, not the actor"
    A high score says the case's technique sequence resembles a published chain — never that the named group did it. The caveat renders with every match, not as a tooltip.

---

## Compliance Impact

Maps the case's **confirmed findings** — by ATT&CK technique — to control failures and regulatory obligations across NIST 800-53 Rev. 5, PCI-DSS v4.0, HIPAA, GDPR, SEC, and ISO 27001:2022. Read-only, derived on demand, no AI and no network calls.

Genuine breach-notification clocks get a live countdown once you set a discovery date (the clock starts on that legal determination, not on a forensic timestamp — nothing computes until you set it): GDPR Art. 33 (72 hours), HIPAA §164.404 (60 days), Reg S-P (30 days), and Form 8-K Item 1.05 (4 **business** days — weekends are skipped; public holidays are not modelled, since they are jurisdiction/SEC-calendar-specific). Control-cadence rows (back up, train, review) never render a countdown — only rows with a real notification obligation do.

Filter the mapping to one or more frameworks per case. Each response — dashboard panel and report section alike — carries the framework editions in use and a disclaimer that this is not legal advice.

Has its own report section ("Compliance Impact") — see [Reports & Exports](reports.md).

---

## Key Investigative Questions

Open questions the AI thinks you should be pursuing based on the current evidence — gaps, unknowns, and unexplained events.

---

## Recommended Next Steps

Prioritised list of concrete investigation actions: what files to check, what hunts to run, what questions to answer. Synthesis-generated.

---

## Ask the Case

A free-text question box. Type any question in natural language:

- "When did the attacker first access the domain controller?"
- "What credentials were likely stolen?"
- "List all C2 IP addresses and their first-seen times."

The AI answers using the full forensic timeline plus the **evidence-chain graph** — so it can trace multi-hop paths.

---

## Query Translator

Type a plain-English description of what you want to hunt for. Select the output query language:

| Language | Notes |
|----------|-------|
| **VQL** | Velociraptor — can be deployed as a fleet hunt in one click |
| **KQL** | Kibana/Elastic |
| **ES\|QL** | Elasticsearch |
| **SPL** | Splunk |
| **Sigma** | Cross-SIEM |
| **YARA** | File/memory |
| **Suricata** | Network IDS |

---

## Hunt Workbench

The Hunt Workbench searches structured event fields inside either the forensic timeline or the
super-timeline. It supports Boolean conditions, ranges, field existence, safe regex, relative time
windows, grouping, statistics, rare-value detection, saved parameterized hunts, and cursor-paged
results. Event, IOC, finding, and asset rows expose a one-click pivot into it.

Results can be viewed as a table, timeline, or chart, exported as formula-safe CSV, added to the
notebook, or attached to a finding. Super-timeline results remain analyst-only: notebook and
finding-evidence actions stay disabled until the analyst promotes the individual rows.

See [Hunt Workbench and Query Language](hunt-workbench.md) for the full grammar, typed field
catalogue, error codes, safety limits, and examples.

---

## Hunting Profile

What has already been hunted in this case, and whether each hunt found anything. Use it to avoid
re-running a sweep that came back empty, and to show what ground has been covered.

---

## Suggested Fleet Hunts

Turns the case's findings into proposed Velociraptor VQL hunts that sweep every enrolled endpoint
for the same tradecraft. Press **✨ Suggest hunts** to generate them.

!!! warning "Review the VQL before deploying"
    These are AI-proposed queries. Read each one before running it against the fleet.

---

## Investigation Threads

Open and closed investigation threads — chains of related events grouped by the AI. Useful for multi-stage attack sequences.

---

## Hypotheses

Status-tracked investigation hypotheses:

- Auto-generated by AI from the evidence
- Manually added by the analyst
- Promoted from Analyst Notebook notes

Each hypothesis has a status: **Open / Supported / Refuted / Unknown**. Open hypotheses are fed into synthesis to steer the AI's analysis. Hypotheses with evidence links survive re-synthesis.

**ACH-style tracking** — hypotheses also track contradicting evidence, a discriminating host+artifact that would settle the question, and an "exhausted" flag (set once enough linked hunts come back empty). The list is ranked fewest-contradictions-first, the classic Analysis-of-Competing-Hypotheses fix for a red herring winning unopposed.

**Review** button — runs a focused for/against pass over open hypotheses (plain-English case for and against each, plus an advisory recommended status) without re-running full synthesis. Never mutates a hypothesis until you click **Apply**.

---

## Response Playbook

A trackable checklist of response tasks:

- Auto-generated from findings (Critical/High findings generate response steps)
- Analyst-added custom tasks

Each task has: status, assignee, due date, notes.

**IR Templates mode** (Settings → Velociraptor → IR Templates): expands each Critical/High finding into phase-based steps (Critical → Contain / Investigate / Eradicate / Recover; High → Investigate / Contain). The Investigate step is tailored to the finding's dominant ATT&CK tactic.

Push the playbook to **ClickUp** with one click (toolbar → Export → Push playbook to ClickUp).

---

## Hunting Profile

Shows what has been hunted in this case and whether each hunt found anything:

- Hunt title and VQL fingerprint
- Status (hit / miss / deployed / pending)
- Result row count and new events added to the case
- **Re-collect** button to pull fresh results
- **Expand** to view hunt rows inline

Used to track your hunting coverage and avoid running the same hunt twice.

---

## Analyst Notebook

Free-text notes. Supports Markdown. Notes are per-case and survive re-synthesis. Notes can be promoted to Hypotheses.

---

## Investigation Log

A durable log of every synthesis run — what the AI concluded each time and what changed. Useful for tracking how the investigation evolved.

---

## Activity Log

A chronological, filterable record of every security-relevant action taken on the case — broader than
the Investigation Log above, which only tracks synthesis runs. Covers imports, mark/unmark
false-positive, AI runs (synthesis / 2nd opinion / Ask-the-case / …), enrichment and anonymization
toggles, settings changes, playbook edits, comments/tags, hunt runs, and exports, each with a
timestamp and the analyst who did it (where applicable).

---

## Analysis Run Ledger

Open **Export → Analysis run ledger (replay & compare)…** to audit the processing history behind the
current case. Each immutable manifest identifies the source artifact or evidence events, importer or
rules version, prompt or report-template hash, provider/model, filters, anonymization policy,
warnings, and output hashes. **View manifest** exposes the exact evidence IDs and links them back to
the forensic timeline.

The integrity banner verifies both every manifest hash and the case's append-only hash chain.
Changing or deleting a historical manifest makes that check fail. The ledger is included in the
generated report folder and whole-case archives, whose own integrity manifest covers it as well.

**Replay** first checks that the original artifact, evidence, importer/rules, prompt/template, and
provider/model are still available and unchanged. If anything is missing, it names the blockers and
does not start or spend provider credits. A successful replay creates a child run; it never replaces
the historical run. Select two runs and choose **Compare claims** to see added, removed, and changed
claims with links to their supporting evidence.

Each report version pins the analysis runs used to produce it, so regenerating a report later cannot
silently rewrite which analytical history that version represents.

---

## Report Review and Release

Open **Export → Report versions (diff & restore)…** after generating a report. Every generated
version starts as a **Draft** and follows one of these paths:

- Team mode: **Draft → Peer review → Approved → Released**. Select a case reviewer and submit the
  version. The assigned reviewer can attach comments or high-impact uncertainty blockers directly
  to a finding, claim, or evidence event; request changes without editing the investigator's
  evidence; or approve after all high-impact blockers are resolved.
- Solo mode: **Draft → Self-reviewed approval → Released**. The sign-off is explicitly labelled
  self-reviewed. It is never presented as independent peer review.

Release preflight refuses a version when a Critical/High finding lacks a valid evidence-event link,
an analysis run is missing or its ledger is damaged, the custody chain is broken, an artifact is
missing or has changed, or a required template rule is unmet. A successful release freezes the
report text, metadata, findings, IOCs, forensic events, analytical uncertainty, report template,
analysis-run hashes, custody-chain head, sign-offs, and four recipient packs behind one SHA-256
manifest.

The released-report integrity banner verifies the append-only release chain every time the dialog
opens. Later case edits and report regeneration cannot modify an earlier release. To release a
correction, approve a new report version and explicitly supersede the latest release; the original
remains available and the new release links back to it.

Each release provides four downloads built from the same frozen approved evidence set:

- **Executive** — concise material findings and executive summary.
- **Technical** — the exact approved full report.
- **Legal/insurance** — restrictions, limitations, uncertainty, and sign-off record.
- **IOCs** — spreadsheet-safe CSV of the approved indicators.

Use the existing **From / To / Diff** controls for the visual version comparison. The release diff
and release records are also machine-readable through the case API.

---

## Chain of Custody

Every artifact this case has stored, with its SHA-256 and each event that touched it — the same
content as the report's Chain of Custody appendix, live. Artifacts are recorded automatically as
screenshots and imports land; nothing needs to be entered by hand.

Each row expands to the artifact's full chain (collected → transferred → exported, with who, when
and from where). Three controls:

- **Verify now** — re-hash every artifact in this case and re-walk the custody log. Failed artifacts
  are marked ⚠ FAILED in red. On a case holding disk images this takes a while; the button stays
  disabled until it answers.
- **Refresh** — reload the records without re-hashing.
- **Signed manifest** — download `custody-manifest.json` for this case.

The case is also verified automatically in the background whenever you open it (at most once every
four hours). See [Chain of Custody](chain-of-custody.md) for the full picture.

---

## Customer Exposure

Check whether the victim organisation's own domains and email addresses appear in breach databases.

Configure customer domains in this panel. Click **Run exposure check** to query your configured providers (LeakCheck, HIBP, DeHashed, Shodan for attack surface).

!!! info
    Raw passwords from breach results are **never stored** — only a `passwordPresent` flag.

---

## Case Details (for Report)

Human-authored report metadata:

- Distribution / classification
- Business impact assessment
- Executive summary
- Recommendations section
- Glossary
- Custom report sections

These fields appear verbatim in the generated report.

---

## Geographic IP Map

Plots all IP IOCs on an interactive world map:

- Markers colored by severity
- Flow lines showing victim → attacker direction
- Country statistics panel
- Timeline sync (filter map by time range)
- CSV export

Requires GeoIP enrichment to be configured and enabled.

---

## Super-Timeline

A Timesketch-style complete record of **every** imported event, kept separately from the forensic timeline so the AI never synthesizes it — the forensic timeline stays detections-focused while nothing is ever lost.

- **Filter** by time, origin (artifact), or label — e.g. hide Sigma/YARA/Hayabusa detections to see only raw host artifacts
- **Save named timeframes** for quick recall
- **Label** events for your own triage
- **Promote** selected events into the forensic timeline so AI synthesis picks them up
- Each row can expand a **[details ▶]** toggle for the full untruncated message, and a Velociraptor-sourced row shows a **↗ Velociraptor** link back to the originating hunt/flow

A **"Super-Timeline Triage"** Velociraptor bundle collects raw Windows host artifacts (MFT, USN, EVTX, registry, Prefetch, Amcache, LNK, browser history, RecycleBin, scheduled tasks, ActivitiesCache) directly into the super-timeline only.

**Content tagger** — click **Content tagger** in this panel's toolbar to run the content-based event tagger on demand (it also runs automatically after every import). See [Advanced → Content-Based Event Tagger](advanced.md#content-based-event-tagger) for the rule engine and AI-assisted rule authoring.

**Export to Timesketch** — push or download the full super-timeline (forensic timeline + raw
host-triage artifacts), alongside the existing Forensic Timeline export. Both push into the same
Timesketch sketch under separate timelines, so neither clobbers the other — see
[Integrations → Timesketch](integrations.md#timesketch).

!!! info "Why events don't all reach the forensic timeline"
    Info-severity telemetry routes to the super-timeline only by default (the forensic timeline keeps Low+ graded signal) so synthesis isn't swamped by raw noise. Configure the floor via **Settings → General** (`DFIR_FORENSIC_MIN_SEVERITY`) globally, with a per-case override. Promoting an event always bypasses the gate, and IOCs are still extracted from every event regardless.

---

## False Positives (Excluded from Analysis)

Everything you have marked as a false positive or known-good. Shows findings, events, and IOCs with their exclusion reason and analyst attribution. Click any item to reinstate it.

Marking an item asks for a **structured reason** (known-good tool / authorized test / detection misfire / duplicate / other) and offers ranked **"find similar items"** suggestions (shared MITRE technique, process, hash, asset, or IOCs) so the same recurring pattern can be dismissed in one pass — deterministic by default, or AI-assisted for less obvious matches. Marking a single IOC can also **one-click-promote** it to the global IOC whitelist so future imports auto-exclude it.

**Learned patterns** — repeated reasoned dismissals of the same activity pattern accumulate into a per-case ledger. New activity resembling a repeatedly-dismissed pattern is surfaced here with lowered (not zero) confidence unless independently corroborated, and the case's prevalence baseline (how often each normalized activity pattern occurs across the timeline) gives rare events a selection seat over common noise during synthesis.
