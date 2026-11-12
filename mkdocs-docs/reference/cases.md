# Case Management

## Creating a Case

Toolbar → **+ New case**. Fill in Case ID, name, and investigator.

**Main evidence source** (optional, under the servers picker) sets the query language for hunts
before any evidence arrives. Leave it on **Automatic (from evidence)** and the companion picks the
source from the imported files, as before. Pick a source (for example **Splunk**) or **Mixed (per
finding)** and the case starts with that choice. The Suggested Fleet Hunts panel and the playbook
hunt button then use its language at once. Change it later with the **Change main source**
dropdown in the Suggested Fleet Hunts panel. See
[Dashboard → Suggested Fleet Hunts](dashboard.md).

Cases live in the `cases/` folder (location configured by `DFIR_CASES_ROOT`).

## Opening a Case

The toolbar box lists cases by **name**. Pick one and press **Connect** (or Enter). The box shows
the open case's name; the case id stays in the page URL (`?caseId=`) and in every export. Two
cases with the same name are listed as `name (id)`. Password-protected cases carry a 🔒 prefix
and archived ones an `[Archived]` prefix, the latter only when the archive toggle beside the box
is on. Typing a name that matches no case creates a case with that text as its id.

## Incident Types

The **Incident type** dropdown on the New case dialog pre-configures the investigation for a
recurring incident pattern, so the first thirty minutes are not spent rebuilding the same checklist
under pressure. Eight types ship built in:

| Type | Type |
|---|---|
| Ransomware | Insider Threat |
| BEC / Email Compromise | Cloud Compromise |
| Data Exfiltration | Web App Intrusion |
| Network Intrusion | Malware Outbreak |

Picking one seeds the case with:

- **Key questions** tailored to the incident — a BEC case asks about inbox rules and OAuth grants; a
  ransomware case asks about VSS deletion and double extortion.
- **Recommended next steps**, priority-ordered, each with its rationale and where to look.
- **Expected findings** as open *confirm or deny* questions, badged `[type-seed]`, so you work
  through what this incident type usually involves instead of starting from a blank page. Dismiss any
  that don't apply.
- **A collection plan** — the evidence this incident type calls for, in order, shown in its own
  dashboard panel. Each item ticks itself off once matching evidence is imported, whichever tool
  produced it, so "Windows event logs" is satisfied by Chainsaw, Hayabusa, or raw event logs alike.
  Mark an item *N/A* when your environment can't provide it (no EDR, no badge system) and it stops
  being proposed.
- **AI framing** — synthesis is told which incident type this is, so it prioritizes the relevant
  ATT&CK techniques. This is prompt context only; it never appears in your report.

The dropdown also lists any **templates you saved yourself** (Case lifecycle → Save as template).

!!! tip "Changing your mind"
    Re-picking a type from the API (`POST /cases/<id>/incident-type`) *merges* — your own questions
    and answers survive, and nothing is duplicated. Send `{"replace": true}` to start that case's
    questions over from the new type.

### Custom incident types

Drop a `.json` file into the `incident-types/` folder beside your cases root and it appears in the
dropdown, marked ★. Copy any built-in from `companion/data/incident-types/` as a starting point and
edit the questions, next steps, and expected findings for how your organization actually runs that
incident. A file with a broken definition is skipped rather than breaking the dropdown, and a custom
file cannot override a built-in type of the same name.

## Switching Between Cases

The case selector dropdown (top-left of dashboard) lists all cases, newest first. Select one to load it.

When you type in the case box, the dashboard switches case only when the text names a listed case. A new case id takes effect when you leave the box or press Enter.

Hover the case box to see the full case name and case id. The open case is marked **● Current** in the list.

## Case Lifecycle

Each case has a status: **Open** or **Closed**.

Toolbar **☰ Case lifecycle** menu lets you:

- **Close** a case (marks it inactive)
- **Archive** a case — packages it as a ZIP with a SHA-256 manifest. When it finishes, the status line
  shows where the ZIP file was saved (in the cases folder). See [ZIP Case Archive](#zip-case-archive-restore)
  to bring it back.
- **Restore** an archived case — puts it back in the case list. A restored case always comes back
  **Closed**, even if it was open when you archived it. Use **Reopen case** to change it.
- **🔒 Password…** — set, change, or remove a password on this case (see below)
- **🗑️ Delete…** a case — permanently removes the case's directory (see below)

**What a closed or archived case still accepts.** A closed or archived case is the record you hand
over, so it stays as it was when you closed it. Anything that would change it is refused with
"Case … is closed — reopen it before …" (or "archived — restore it before …"). New actions are
refused too, unless they are on the short list below.

- Opening it changes nothing. The playbook and the coach card show the saved tasks; new tasks are
  not added until you reopen the case.
- Closing or archiving stops a synthesis, a deep pass or an enrichment that is still running, so its
  results do not land in the closed case. A running import still finishes and is recorded.
- Refused: new evidence and imports, re-running the content tagger or a Sigma re-grade, applying the
  IOC whitelist or NSRL, applying a second opinion, promoting from the super-timeline, merging hosts,
  restoring a state backup, host-scope decisions, the correlation profile, false-positive marks, the
  scope window, source trust, tags and stars, notebook entries, comments and pinned findings. Reopen
  (or restore) the case to change any of them.
- Still accepted:
    - Reopen, close, archive, restore, delete and the encrypted export.
    - Case password, unlock and "forget this browser's unlock". Removing a push key. Checking,
      detaching or removing the case's cloud credentials.
    - Reports and pushes to IRIS, Timesketch, MISP, Notion, ClickUp, Jira and ServiceNow.
    - Questions and summaries that save nothing: Ask, the view and executive summaries, the
      remediation plan, the hypothesis review, hunt and memory suggestions, super-timeline hunt
      searches, rule previews and dry runs, and custody verification.
    - Stopping work that is already running: cancelling a hunt search, stopping a live monitor,
      discarding an MCP preview, and checking on a Velociraptor hunt that was launched before the
      close.
- If the companion stops in the middle of an archive or a restore, the case folder and its status
  can disagree. At the next start, the companion puts such a case back in the archived state, so
  **Restore** works on it again.

The toolbar also shows a disk-space warning if the cases folder is running low.

## Case Password Protection

**☰ Case lifecycle → 🔒 Password…** sets a password on a case: opening it in the dashboard then
requires that password. A **"remember on this computer"** checkbox skips the prompt on later visits
from the same browser; leave it unchecked and the case re-locks the moment you switch away, refresh,
or close the tab.

Enforced server-side — an unlock cookie gates every `/cases/:id/*` route, not just a UI prompt. That
includes adding evidence: an import into a locked case needs the unlock or the case password.

The capture extension shows a **Case password** field when you pick a locked case. Type the password
once and press **Check**. The extension keeps it in memory until the browser closes, and screenshots
and console pushes then go in as normal. Without the password, screenshots are not thrown away: they
wait in the extension, and the toolbar badge turns amber with a count ("Case is locked — 12 captures
waiting for the case password"). The badge stays amber after you switch to another case, and the
message then names the locked case. They upload after you select that case and enter its password —
the extension retries waiting screenshots on its own about once a minute, and at browser start, so
you do not have to take another capture. A
wrong password is tried only once, so the extension cannot lock you out of your own case. Webhooks
that use a push key keep working on a locked case. Setting or changing a password does not auto-unlock the browser that set it;
you're prompted the same as anyone else. Leaving a case you unlocked without "remember" forgets the unlock in this browser only. To shut out every browser that has unlocked the case, including one that saved a copy of the unlock, change the password. Dashboards that already have the case open are disconnected at once. **Remove password** is only available when the case is
currently unlocked and has a password set.

## Permanently Deleting a Case

**☰ Case lifecycle → 🗑️ Delete…** removes a case's directory for good — this cannot be undone. The
dialog offers an optional ZIP/encrypted archive taken first, so you can keep an off-disk copy before
the case is wiped. Guardrails: it refuses to touch a directory that isn't a real case, and it won't
delete an already-archived case's live folder out from under its archive. While an archive or an
encrypted export of the case is still being built, Delete and Restore are refused with "an import or
an archive in progress — try again" until it finishes.

## ZIP Case Archive (Restore)

**Archive to ZIP** writes `<caseId> (no password).zip` into the cases folder. The ZIP holds one
`<caseId>/` folder with every case file, plus `<caseId>/archive-manifest.json`. The manifest lists
the SHA-256 hash and size of each file. The ZIP has no password.

**Import it:** toolbar → **Import case → ZIP case archive (.zip)**. Pick the file. It restores as a
new case. The import checks the archive before it writes anything:

- Every file must sit inside one case folder, and no path may leave that folder.
- The folder name, the manifest's case ID and `case.json` must name the same case.
- When the manifest is present, every file must match its SHA-256 hash and size. A changed, extra or
  missing file stops the import. A damaged manifest also stops it.
- When the manifest is missing, the import still runs. The result line says
  **"no archive manifest, hashes not verified"**.

If the case ID already exists, you are asked for a different case ID. The result line shows the event,
finding and IOC counts, and whether the hashes were verified.

A few filenames cannot go into a ZIP unchanged (for example, names Windows refuses). The archive
stores those under a portable name, and the manifest records the original name as `originalPath`.
The import keeps the portable name. The `.dfircase` import does the same.

**Restore by hand** (no dashboard):

1. Extract the `<caseId>/` folder from the ZIP into the cases folder.
2. Compare each file with its SHA-256 value in `<caseId>/archive-manifest.json`.
3. Delete `archive-manifest.json` from the case folder. It is not a case file.
4. Refresh the case list in the dashboard.

## Encrypted Case Archive (Export / Import)

**Export archive:** toolbar → **Export → Export encrypted case archive (.dfircase)**. Enter a password (min 8 characters). Produces a single `.dfircase` file containing the ENTIRE case — findings, timeline, IOCs, MITRE, playbook, analyst notes, tags, AND screenshots/raw evidence — encrypted with AES-256-GCM. Only openable via another DFIR Companion's Import.

**Import archive:** toolbar → **Import case → Encrypted case archive (.dfircase)**. Restores as a new case. If the Case ID already exists you get a conflict warning.

**If the archive was exported by v0.31.0–v0.33.0**, the import warns you that it used an older, weaker key derivation. Export the case again afterwards to upgrade the file to the current encryption. See [SECURITY.md](https://github.com/hasamba/DFIR-Companion/blob/master/SECURITY.md) for the detail.

!!! info "What's in the archive"
    Everything under the case directory travels with the export — screenshots, raw imported artifact files, and all analyst decisions. The AI configuration (keys) is never included — keys live in `.env` and never enter the case directory. The recipient's copy inherits settings like external-enrichment opt-in as they were on the exporting machine, since the archive is a verbatim copy.
