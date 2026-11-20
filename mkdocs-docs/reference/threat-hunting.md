# Threat Hunting

## Threat-hunt mode (proactive hunts)

Use threat-hunt mode when there is no incident: a routine sweep of a client's endpoints for things
that should not be there, such as programs the client does not allow, rare or new software, risky
downloads, and early signs of an attacker.

### 1. Create a hunt case

In **New Case**, pick the **Threat hunt (proactive)** template. This:

- puts the case in **hunt mode**. Synthesis and Watson then rank anomalies, state their verdict
  *within coverage* (for example "no compromise found on the 287 hosts that answered; 13 did not
  answer") and do not force a kill chain or attribution;
- sets the case report to the **Threat hunt summary** template (unless you already picked another);
- shows the **Threat Hunt** and **Client Baseline** panels. The **Threat Hunt** dashboard view
  puts them first.

### 2. Link the case to a client

Pick the client in **New Case** (the **Client** box appears for the Threat hunt template), or later
in the **Client Baseline** panel with **Link case to client**. A client is its own record (for
example "Client A"). It keeps the client's reviewed baseline across hunt cases.

- Only the instance administrator can create or edit a client profile. The administrator can
  create one straight from the **New Case** Client box: pick **New client…** at the end of the
  list, type the name, and the new client is selected for the case. A new client has no default
  server set, so the **Servers** box stays as it is. Members do not see **New client…**.
- Linking a case to a client needs case-administrator rights on that case.
- A profile can name a default Velociraptor server set. Picking the client in **New Case** fills
  the **Servers** box with it, unless you already chose a set there. It never changes an existing
  case and never decides which hosts belong to the client.

### 3. Run the hunt

Run the built-in **Threat Hunt Starter** bundle (Fleet Collection panel), or any other hunt. The
starter bundle collects installed software, execution and presence evidence, downloads,
autoruns / services / scheduled tasks, remote-access tools and a signature check. Every result
keeps an honest label: Prefetch and UserAssist mean the program **ran**; ShimCache and Amcache
mean the file was **present**, not that it ran.

### 4. Read the coverage

The Threat Hunt panel and the report say how many hosts answered each hunt cleanly, out of how
many were targeted, and how many did not answer. Only Companion-launched hunts record this. For an
uploaded hunt export the coverage is **unknown**: nothing is called absent, and no percentage is
given.

### 5. Rare, new, policy and download items

Each time hunt rows are imported, the Companion counts on how many hosts each distinct program,
autorun and download appears. It then adds **one summary entry per item** to the forensic
timeline, listing its hosts ("on 3 of 287 answering hosts: WS-01, WS-02, WS-03"). The individual
rows stay searchable in the super-timeline. Each kind is capped at 50 entries, with one visible
"N more" entry, so a routine update on 300 hosts never floods the timeline.

| Item | When |
|---|---|
| **Policy violation** | The client marked it **Not allowed**, or it was downloaded from a blocked site or a blocked category. Default severity Medium (setting below). Labelled as policy, not as malicious activity. |
| **Rare** | At least 20 hosts answered cleanly, and the item is on at most 5% of them and on at most 10 hosts. Below 20 answering hosts, or with unknown or partial coverage, nothing is graded rare. |
| **New since the last comparable hunt** | Not in the baseline and not seen in the last comparable hunt for this client: an earlier hunt case of the same client, with an overlapping bundle, over at least half the same answering hosts. An item is called new only on hosts both hunts covered cleanly. A first hunt has nothing to compare with. |
| **Flagged download** | A runnable or archive file downloaded from a site outside the client's approved sources, or with no source URL. |

**Approved** items get no entry and lose any rare or new flag. The AI is told which programs the
client approved, so it ranks expected use low and only unusual use as an anomaly. An approval
never lowers a detection: a Sigma or tagger hit on an approved tool keeps its grade.

These summaries are recalculated after every import, so an item that looked rare can stop being
rare as more hosts answer; its entry is then removed (unless you promoted it).

### 6. Build the baseline with the client

The **Client Baseline** panel lists every item the baseline does not settle, rarest first, with
its hosts, path, evidence label and publisher (as the endpoint reported it, **not verified**), and why
it is still pending.

1. Press **Export confirm list (CSV)** or **(Markdown)** and send it to the client.
2. When the client answers, tick items and press **Mark Approved**, **Mark Not allowed** or
   **Reset to Unknown**, or import the client's filled CSV (fill the `verdict` column with
   `approved`, `not allowed` or `unknown`). You are asked for the source of the answer, for example
   "client email 2026-11-20".
3. Record blocked download categories (torrent, file-sharing, cloud-storage, paste-sites,
   remote-access) and blocked or approved download sites. Blocking `example.com` also blocks
   `dl.example.com`, never `notexample.com`.

Rules that keep an attacker from hiding behind a name:

- **Seeing a program never approves it.** Only a mark does.
- An approval matches only on the program name **and** its path pattern **and** a verified signer
  or an approved hash. A `chrome.exe` in a Temp folder does not match an approval for `chrome.exe`
  in `\Program Files\Google\`. If one host runs a different hash at the approved path, that item
  is not covered. The path pattern ignores the volume, so a Prefetch path (`\Device\HarddiskVolume3\…`)
  and an Amcache path (`C:\…`) for the same file are one item.
- Publisher text alone never approves anything. A missing hash or signer gives **Unknown**.
- Which artifacts can make an item approvable:
    - **Amcache** (`Windows.Forensics.Amcache`, program files) records a SHA1. Amcache hashes only
      the first 30 MiB of a file, so a SHA1 approval covers a file only when Amcache also recorded
      its size and the file is 30 MiB or smaller. A larger file, or one with no recorded size, stays
      **Unknown**, and the list says why.
    - **Autoruns** (`Windows.Sysinternals.Autoruns`) records the image path, the SHA-256 and the
      signature check. Only a signer that Autoruns reports as `(Verified)` counts. `(Not verified)`
      and the Company name never approve anything. An enabled entry with no verified signer is
      graded Low (persistence, T1547). A verified or disabled entry is Info: it still goes into the
      hunt inventory and the super-timeline.
    - **Downloads** (Zone.Identifier) carry a SHA-256.
    - Prefetch, UserAssist and ShimCache rows carry no hash. A program item is covered only when
      every host it was seen on also has an Amcache row for the same file and path. An Autoruns
      approval covers the autorun entry, not the program.
    - **Amcache installed programs** (the Installed program items) carry no file path and no hash,
      so they can never be approved. The list shows "(no path — cannot be approved)" and says why.
      **Mark Approved** leaves these items out and tells you how many. Approve the program's files
      (its Amcache file rows or Autoruns entries) instead, or use **Mark Not allowed**, which matches
      them by name. The same applies to any item with no path. An Approved row with no path in the
      client's CSV is skipped, and the import message gives the line number and the reason.
- Every host must be covered on its own. One host's approved hash or signer says nothing about a
  host seen only through rows without one. A host seen only through a SHA1 is not covered by an
  approval that names only a SHA-256, and the reverse. A signer approval needs every host verified
  by that same signer, and one failed signature check keeps the item **Unknown**.
- **Mark Approved** saves the item's SHA-256, its usable SHA1 and, when every host is verified by
  one signer, that signer. The confirm-list CSV has `sha1` and `signer_verified` columns for the
  same purpose.
- An approval only stops the rare and new hunt grades. It never lowers a detection.
- **Not allowed** wins over Approved. An approval can carry an expiry date.
- Every change is a new numbered **baseline version**, saved with who made it, when and its source,
  and can be reversed (Reset to Unknown). Unknown items stay on the list in every hunt report,
  with how many hunts they have stayed unconfirmed.

### 7. Earlier cases stay as they were

Each hunt case is graded against the baseline version it was first graded with. A later baseline
change does not alter a delivered report. To apply the current baseline to a case, press
**Re-grade with current baseline** in the Threat Hunt panel. The re-grade is written to the
activity log. It re-reads the case's rows from both the forensic timeline and the super-timeline,
including rows the gate moved out of the forensic timeline. The super-timeline has a size cap, so
on a large hunt some rows may already be gone; the result says how many host observations the raw
record no longer holds. Re-import the hunt to recover them.

### 8. Convert to incident

When the hunt case holds any High or Critical finding, the Threat Hunt panel shows **Convert to
incident**. Conversion keeps all evidence and analyst work, switches the case to the incident type
you choose (Intrusion by default), and marks the current AI conclusions out of date until the next
synthesis.

### Who sees what (team mode)

- Everyone signed in sees the list of client names. The public demo shows no client profiles.
- Only the instance administrator sees and edits a full client profile.
- Earlier hunts of the same client are listed only when you can open them, including their case
  password when they have one.
- The client's name and its blocked and approved domains are masked before every AI call when
  anonymisation is on. Approval notes are never sent to a model.

### What is not done

- Hunt grading reads the rows an import adds to the case. Rows from a super-timeline-only bundle
  never pass that point, so they are counted only by **Re-grade with current baseline**.
- A download's referrer is not recorded on the timeline row, so download rules judge the source
  URL only.
- The Hunt Workbench `prevalence` stage counts hosts in the matched rows; it does not know which
  hosts answered a hunt.


## AI-Generated Hunt Suggestions

After synthesis, the dashboard surfaces four types of hunt suggestions:

| Type | What it does |
|------|--------------|
| **Fleet hunt suggestions** | AI-generated VQL queries to hunt fleet-wide for the threats seen in this case, grounded in the causal evidence graph |
| **Playbook hunt suggestions** | VQL queries tied to specific response playbook tasks |
| **Technique-based hunt suggestions** | Hunts for ATT&CK techniques not yet evidenced in the case (from Adversary Hints) |
| **Shadow artifact suggestions** | When the timeline has suspicious gaps, suggests KAPE/Velociraptor artifacts (Prefetch, SRUM, USN Journal, etc.) that might fill them |

Each suggestion card shows the VQL query with a **Deploy hunt** button (requires Velociraptor connection). A **↻ Regenerate** button refreshes the VQL if it won't compile.

### Run CrowdStrike CQL hunts on Next-Gen SIEM

When the case's main evidence is CrowdStrike Falcon, the hunt cards are written in CrowdStrike Falcon CQL. They are copy-ready by default. If an administrator sets up the [Next-Gen SIEM search client](settings.md#crowdstrike-next-gen-siem-search), each CQL card also gets a **Run in Falcon** button:

1. Press **Run in Falcon**. A confirm step opens inside the card. It shows the exact query that will run, the repository, the time range and the caps.
2. Check or change the time range. It starts with the case's scope window. With no scope window, it starts with the span of the case's High and Critical events (one day added on each side). With neither, it starts with the last 7 days. A range wider than the limit (7 days by default) is refused with a message. It is never cut silently.
3. Press **Run search**. The search runs as a job: it shows in the Jobs panel, waits for the case's other job to finish, and you can cancel it. The card shows what the job is doing and then its result.

What happens to the result:

- The rows Falcon returns are stored first as an evidence file (`NNNN_crowdstrike-ngsiem_<time>.ndjson`, one returned row per line, fields unchanged) and are written to the chain of custody.
- The rows are then imported through the CrowdStrike Falcon importer, like an uploaded Falcon export. Every row goes to the super-timeline. The content tagger grades the rows, and only rows graded above Info stay in the forensic timeline. Each row carries the sources `CrowdStrike Falcon` and `CrowdStrike NG-SIEM`.
- A `table([...])` result keeps only the fields it lists, so its rows often have no event name. When the query filters on one event type (for example `#event_simpleName=ProcessRollup2`) and does not aggregate, the importer reads each row as that event. Rows that are not events (for example `groupBy` totals) stay in the evidence file only. The result message says how many.
- The activity log records the query, the repository, the time range, the row counts, any truncation and who pressed Run.
- **Undo import** takes the rows back out, like any import.

**Open in Falcon.** Next to **Run in Falcon**, each CQL card (and each Watson search card) has an **Open in Falcon** link. It opens Next-Gen SIEM **Advanced event search** in your Falcon console, in a new tab, with the card's query and time range filled in. It is a plain link: nothing runs in the Companion, nothing is imported, and Falcon uses your own console sign-in. The console address follows the SIEM client's cloud (us-1, us-2, eu-1 or gov-us-1). There is no link for gov-us-2. The search-all repository opens as "all"; for another repository, choose it in Falcon.

Limits (Settings → Enrichment → CrowdStrike Next-Gen SIEM search):

| Limit | Default | When it is hit |
|---|---|---|
| Time range | 7 days | The search is refused before anything is sent |
| Rows per search | 10,000 | The first 10,000 rows are imported, and the message says "imported the first N rows (the row cap cut the rest)" |
| Timeout | 5 minutes | The search is cancelled in Falcon, and the rows already read are imported and marked truncated |

Cost: every search runs in your Next-Gen SIEM and counts against its query use. A filter query returns about 200 events per Falcon query job, so a long result is read page by page, and each page is another query job. A `table()` returns at most 200 rows unless the query sets `limit=`.

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

**Dry-run on this case** answers a different question before you hunt the fleet: would this rule
have matched anything the case already holds? It reads the forensic timeline and the
super-timeline, without AI, and writes nothing to the case. It says how many events the rule
matches out of the events in its category (process, network, file or registry), and links the
first 20 matches into the timeline. It tests the fields the stored events keep: `Image`, `User`,
`ProcessId`, `CommandLine`, `ParentImage`, `DestinationIp`, `DestinationPort`,
`DestinationHostname`, `SourceIp`, `SourcePort`, `TargetFilename`, `TargetObject` and `Details`.
Every field the rule reads gets one line: how many events carry it, "no event in this case keeps
it" (for example `ParentImage` on rows that keep only the parent's name), or "not checkable here"
for a field the stored events do not keep. A row that depends on a field that is not checkable is
counted as undecided, never as a match or a miss. Keyword lists and other categories are refused.
The scan stops at 200,000 events and says so when it does.

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

## Sigma Rules at Import

Besides compiling a Sigma rule into a fleet hunt, the Companion runs bundled SigmaHQ rules over AWS
CloudTrail, Entra ID sign-in and audit logs and GCP Cloud Audit Logs **while they are imported**. High and critical rules
raise the matching event's severity; lower levels only tag it. See
[Importing → Sigma rules grade CloudTrail, Entra and GCP imports](importing.md#sigma-rules-grade-cloudtrail-entra-and-gcp-imports).

The Companion ships SigmaHQ release `r2026-07-01`; newer releases are installed from
[Settings → Sigma rules](settings.md#sigma-rules) after you review what changes. The rules are licensed
under the Detection Rule License (DRL) 1.1. Each match names the rule's author and links the rule, as the
license asks.

---

## Hunting Feedback Loop

The **Hunting Profile** panel tracks every hunt's outcome:

- Was the VQL deployed?
- Did it find anything (rows returned vs. new events added)?
- Has it been re-collected?

This prevents running the same hunt twice and helps you see what's been covered. Already-deployed hunts are excluded from new suggestions.

---

## Query Translator

Write in plain English. Get VQL, KQL, SPL, ES|QL, Sigma, YARA, Suricata, CrowdStrike Falcon CQL, Carbon Black Cloud search, Wazuh dashboard search, SentinelOne PowerQuery, Cortex XDR XQL or QRadar AQL. One-click deploy for VQL.

Only the languages allowed by the **Hunt platforms** setting (`DFIR_HUNT_PLATFORMS`) appear; blank means all thirteen. The setting also accepts `falcon`, `cql`, `logscale` or `humio` for CrowdStrike, `cb` or `cbc` for Carbon Black, `s1` or `powerquery` for SentinelOne, `xdr` or `xql` for Cortex XDR, and `aql` for QRadar.

The 🔍 hunt button on an event or IOC also gives a **CrowdStrike Falcon (CQL)** card. It is made from the indicator without AI, with one query per indicator type, using Falcon event names: `ProcessRollup2` for process names, `NetworkConnectIP4` for IPs, `DnsRequest` for domains, `*Written` events for file names, and `SHA256HashData` / `MD5HashData` for hashes. Paste it into Falcon Advanced Event Search or Next-Gen SIEM. It is LogScale CQL, not the older FQL filter syntax. A value that contains `*` is matched as an exact regular expression, so the `*` cannot widen the search.

Every indicator value in the 🔍 hunt cards (paths, URLs, domains, hosts, hashes) is escaped by the rules of that card's language — VQL, KQL, SPL, ES|QL, Sigma YAML, YARA, Suricata or CQL — so a Windows path is written correctly and a crafted value cannot end the string or add query text.

See [Dashboard Panels → Query Translator](dashboard.md#query-translator) for details.

---

## Timeline-Gap Hypotheses

When the AI detects suspicious silences (log gaps that don't match expected coverage), it hypothesises what might have happened and suggests shadow artifacts to collect. Each suggestion is deployable as a Velociraptor collection.

!!! tip
    Gaps in the timeline around a known attack window are often the most important leads. A silent endpoint during an active attack usually means either lateral movement to a host without monitoring, or log tampering.
