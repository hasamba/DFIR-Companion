# Case Management

## Creating a Case

Toolbar → **+ New case**. Fill in Case ID, name, and investigator.

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
- **🔒 Password…** — set, change, or remove a password on this case (see below)
- **🗑️ Delete…** a case — permanently removes the case's directory (see below)

The toolbar also shows a disk-space warning if the cases folder is running low.

## Case Password Protection

**☰ Case lifecycle → 🔒 Password…** sets a password on a case: opening it in the dashboard then
requires that password. A **"remember on this computer"** checkbox skips the prompt on later visits
from the same browser; leave it unchecked and the case re-locks the moment you switch away, refresh,
or close the tab.

Enforced server-side — an unlock cookie gates every `/cases/:id/*` route, not just a UI prompt — but
the capture extension's evidence ingestion keeps working while a case is locked, so screenshots aren't
lost while you're away. Setting or changing a password does not auto-unlock the browser that set it;
you're prompted the same as anyone else. **Remove password** is only available when the case is
currently unlocked and has a password set.

## Permanently Deleting a Case

**☰ Case lifecycle → 🗑️ Delete…** removes a case's directory for good — this cannot be undone. The
dialog offers an optional ZIP/encrypted archive taken first, so you can keep an off-disk copy before
the case is wiped. Guardrails: it refuses to touch a directory that isn't a real case, and it won't
delete an already-archived case's live folder out from under its archive.

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
